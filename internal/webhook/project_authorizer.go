package webhook

import (
	"context"
	"fmt"
	"log/slog"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	iamv1alpha1 "go.datum.net/datum/pkg/apis/iam.datumapis.com/v1alpha1"
	resourcemanagerv1alpha1 "go.datum.net/datum/pkg/apis/resourcemanager.datumapis.com/v1alpha1"
	"go.datum.net/iam/openfga/internal/openfga"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ authorizer.Authorizer = &ProjectControlPlaneAuthorizer{}

type ProjectControlPlaneAuthorizer struct {
	FGAClient  openfgav1.OpenFGAServiceClient
	FGAStoreID string
	K8sClient  client.Client
}

// Contains a mapping of Kubernetes APIGroups to the service name that should be
// used by the webhook to perform authorization checks.
var serviceNameMapping = map[string]string{
	// An empty APIGroup is used for the core/v1 Kubernetes API Group.
	"": "core.datumapis.com",
}

// Authorize implements authorizer.Authorizer.
func (o *ProjectControlPlaneAuthorizer) Authorize(
	ctx context.Context, attributes authorizer.Attributes,
) (authorizer.Decision, string, error) {
	// Validate that the permission exists
	permissionExists, err := o.validatePermissionExists(ctx, attributes)
	if err != nil {
		slog.ErrorContext(ctx, "failed to validate permission", slog.String("error", err.Error()))
		return authorizer.DecisionDeny, "", fmt.Errorf("failed to validate permission: %w", err)
	}

	if !permissionExists {
		permissionString := o.buildPermissionString(attributes)
		slog.WarnContext(ctx, "permission not found for attributes", slog.Any("attributes", attributes), slog.String("permission", permissionString))
		return authorizer.DecisionDeny, "", fmt.Errorf("permission '%s' not registered", permissionString)
	}

	var projectIdentifier string
	projectIdentifiers, set := attributes.GetUser().GetExtra()[ProjectExtraKey] // Assuming ProjectExtraKey is defined
	if !set {
		return authorizer.DecisionDeny, "", fmt.Errorf("extra '%s' is required by project control plane authorizer", ProjectExtraKey)
	} else if len(projectIdentifiers) > 1 {
		return authorizer.DecisionDeny, "", fmt.Errorf("extra '%s' only supports one value, but multiple were provided: %v", ProjectExtraKey, projectIdentifiers)
	} else {
		projectIdentifier = projectIdentifiers[0]
	}

	// Resolve projectIdentifier to UID
	project := &resourcemanagerv1alpha1.Project{}
	projectNamespace := attributes.GetNamespace() // Or a default/configured namespace if projects are not in the request's namespace

	// If projectIdentifier might be in format "projects/name-or-uid", strip prefix first.
	if len(projectIdentifier) > 9 && projectIdentifier[:9] == "projects/" {
		projectIdentifier = projectIdentifier[9:]
	}

	// Attempt to get the project by its identifier (name or ID that isn't UID yet)
	// This assumes Project resources have a standard name field that matches projectIdentifier.
	// And that they are namespaced according to attributes.GetNamespace(). Adjust if cluster-scoped or different namespace.
	if err := o.K8sClient.Get(ctx, client.ObjectKey{Namespace: projectNamespace, Name: projectIdentifier}, project); err != nil {
		slog.ErrorContext(ctx, "failed to get project by identifier", slog.String("identifier", projectIdentifier), slog.String("namespace", projectNamespace), slog.String("error", err.Error()))
		// Depending on policy, could deny or just say no opinion if project not found.
		return authorizer.DecisionDeny, "", fmt.Errorf("failed to resolve project identifier '%s': %w", projectIdentifier, err)
	}

	projectUID := string(project.UID)
	if projectUID == "" {
		slog.ErrorContext(ctx, "project UID is empty after fetching", slog.String("identifier", projectIdentifier), slog.String("name", project.Name))
		return authorizer.DecisionDeny, "", fmt.Errorf("resolved project '%s' has an empty UID", project.Name)
	}

	// Get user UID - this should be provided as an extra field from the authentication system
	var userUID string
	if userUIDs, set := attributes.GetUser().GetExtra()["authentication.datumapis.com/user-uid"]; !set {
		return authorizer.DecisionDeny, "", fmt.Errorf("extra 'authentication.datumapis.com/user-uid' is required by project control plane authorizer")
	} else if len(userUIDs) > 1 {
		return authorizer.DecisionDeny, "", fmt.Errorf("extra 'authentication.datumapis.com/user-uid' only supports one value, but multiple were provided: %v", userUIDs)
	} else {
		userUID = userUIDs[0]
	}

	user := fmt.Sprintf("iam.datumapis.com/InternalUser:%s", userUID)
	resource := o.buildResource(attributes, projectUID)
	relation := o.buildRelation(attributes)

	slog.DebugContext(ctx, "checking OpenFGA authorization for project scope",
		slog.String("user", user),
		slog.String("resource", resource),
		slog.String("relation", relation),
		slog.String("project_uid", projectUID),
	)

	checkReq := &openfgav1.CheckRequest{
		StoreId: o.FGAStoreID,
		TupleKey: &openfgav1.CheckRequestTupleKey{
			User:     user,
			Relation: relation,
			Object:   resource,
		},
	}

	resp, err := o.FGAClient.Check(ctx, checkReq)
	if err != nil {
		slog.ErrorContext(ctx, "failed to check authorization in OpenFGA", slog.String("error", err.Error()))
		return authorizer.DecisionNoOpinion, "", err
	}

	if resp.GetAllowed() {
		slog.DebugContext(ctx, "subject was granted access through OpenFGA")
		return authorizer.DecisionAllow, "", nil
	}

	return authorizer.DecisionDeny, "", nil
}

func (o *ProjectControlPlaneAuthorizer) validatePermissionExists(ctx context.Context, attributes authorizer.Attributes) (bool, error) {
	// permission := o.buildPermissionString(attributes) // This is not used here anymore

	protectedResourceList := &iamv1alpha1.ProtectedResourceList{}
	if err := o.K8sClient.List(ctx, protectedResourceList); err != nil {
		return false, fmt.Errorf("failed to list ProtectedResources: %w", err)
	}

	apiGroup := attributes.GetAPIGroup()
	// Handle core Kubernetes API group
	if apiGroup == "" {
		if override, exists := serviceNameMapping[apiGroup]; exists {
			apiGroup = override
		}
	}
	resource := attributes.GetResource()

	for _, pr := range protectedResourceList.Items {
		// Check if the APIGroup and Resource (Plural) match
		// The service name in serviceNameMapping corresponds to the APIGroup of the ProtectedResource's ServiceRef
		// However, ProtectedResource itself is cluster-scoped and doesn't have an APIGroup in its spec that directly maps to attributes.GetAPIGroup()
		// We need to match based on the service the PR belongs to and the resource kind/plural defined in the PR.
		// For project authorizer, the APIGroup is often not directly the service name.
		// We'll rely on the `buildPermissionString` to create the fully qualified permission and then check against pr.Spec.Permissions

		// The permission string is formatted as "serviceName/resource.verb"
		// We need to check if pr.Spec.Permissions contains this hashed permission string.
		// The relation built for OpenFGA is the hashed permission.
		// hashedPermission := openfga.HashPermission(permission)
		verb := attributes.GetVerb()

		if pr.Spec.ServiceRef.Name == apiGroup || (attributes.GetAPIGroup() == "" && serviceNameMapping[""] == pr.Spec.ServiceRef.Name) {
			if pr.Spec.Plural == resource {
				for _, p := range pr.Spec.Permissions {
					if p == verb {
						return true, nil
					}
				}
			}
		}
	}

	return false, nil
}

func (o *ProjectControlPlaneAuthorizer) buildPermissionString(attributes authorizer.Attributes) string {
	// Get service name from mapping or use API group
	serviceName := attributes.GetAPIGroup()
	if override, exists := serviceNameMapping[serviceName]; exists {
		serviceName = override
	}

	// Map Kubernetes verbs to permissions using the resource plural
	verb := attributes.GetVerb()
	resource := attributes.GetResource()

	// Build the permission string that matches what's stored in OpenFGA
	// Format: service/resource.verb
	return fmt.Sprintf("%s/%s.%s", serviceName, resource, verb)
}

func (o *ProjectControlPlaneAuthorizer) buildResource(attributes authorizer.Attributes, projectUID string) string {
	// Build the resource identifier for OpenFGA using the correct format
	return fmt.Sprintf("resourcemanager.datumapis.com/Project:%s", projectUID)
}

func (o *ProjectControlPlaneAuthorizer) buildRelation(attributes authorizer.Attributes) string {
	// Get service name from mapping or use API group
	serviceName := attributes.GetAPIGroup()
	if override, exists := serviceNameMapping[serviceName]; exists {
		serviceName = override
	}

	// Map Kubernetes verbs to permissions using the resource plural
	verb := attributes.GetVerb()
	resource := attributes.GetResource()

	// Build the permission string that matches what's stored in OpenFGA
	// Format: service/resource.verb
	permission := fmt.Sprintf("%s/%s.%s", serviceName, resource, verb)

	// Hash the permission to match the OpenFGA model
	return openfga.HashPermission(permission)
}
