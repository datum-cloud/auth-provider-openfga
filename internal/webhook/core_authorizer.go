package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	iamv1alpha1 "go.datum.net/datum/pkg/apis/iam.datumapis.com/v1alpha1"
	resourcemanagerv1alpha1 "go.datum.net/datum/pkg/apis/resourcemanager.datumapis.com/v1alpha1"
	"go.datum.net/iam/openfga/internal/openfga"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ authorizer.Authorizer = &CoreControlPlaneAuthorizer{}

// resourceTypeMapping maps Kubernetes resource names (plural) to OpenFGA resource types
var resourceTypeMapping = map[string]string{
	"organizations": "Organization",
	"projects":      "Project",
}

type CoreControlPlaneAuthorizer struct {
	FGAClient  openfgav1.OpenFGAServiceClient
	FGAStoreID string
	K8sClient  client.Client
}

// Authorize implements authorizer.Authorizer.
func (o *CoreControlPlaneAuthorizer) Authorize(ctx context.Context, attributes authorizer.Attributes) (authorizer.Decision, string, error) {
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

	if attributes.GetAPIGroup() != "resourcemanager.datumapis.com" {
		slog.DebugContext(ctx, "No opinion on auth webhook request since API Group is not managed by webhook", slog.String("api_group", attributes.GetAPIGroup()))
		return authorizer.DecisionNoOpinion, "", nil
	}

	var organizationUID string
	if orgUIDs, set := attributes.GetUser().GetExtra()[OrganizationIDExtraKey]; !set {
		return authorizer.DecisionDeny, "", fmt.Errorf("extra '%s' is required by core control plane authorizer", OrganizationIDExtraKey)
	} else if len(orgUIDs) > 1 {
		return authorizer.DecisionDeny, "", fmt.Errorf("extra '%s' only supports one value, but multiple were provided: %v", OrganizationIDExtraKey, orgUIDs)
	} else {
		organizationUID = orgUIDs[0]
	}

	// Get user UID - this should be provided as an extra field from the authentication system
	var userUID string
	if userUIDs, set := attributes.GetUser().GetExtra()["authentication.datumapis.com/user-uid"]; !set {
		return authorizer.DecisionDeny, "", fmt.Errorf("extra 'authentication.datumapis.com/user-uid' is required by core control plane authorizer")
	} else if len(userUIDs) > 1 {
		return authorizer.DecisionDeny, "", fmt.Errorf("extra 'authentication.datumapis.com/user-uid' only supports one value, but multiple were provided: %v", userUIDs)
	} else {
		userUID = userUIDs[0]
	}

	user := fmt.Sprintf("iam.datumapis.com/InternalUser:%s", userUID)
	resource := o.buildResource(attributes, organizationUID)
	relation := o.buildRelation(attributes)

	slog.DebugContext(ctx, "checking OpenFGA authorization",
		slog.String("user", user),
		slog.String("resource", resource),
		slog.String("relation", relation),
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

func (o *CoreControlPlaneAuthorizer) validatePermissionExists(ctx context.Context, attributes authorizer.Attributes) (bool, error) {
	// permission := o.buildPermissionString(attributes) // This is not used here anymore

	protectedResourceList := &iamv1alpha1.ProtectedResourceList{}
	if err := o.K8sClient.List(ctx, protectedResourceList); err != nil {
		return false, fmt.Errorf("failed to list ProtectedResources: %w", err)
	}

	apiGroup := attributes.GetAPIGroup()
	resource := attributes.GetResource()

	for _, pr := range protectedResourceList.Items {
		// Check if the APIGroup and Resource (Plural) match
		if pr.Spec.ServiceRef.Name == apiGroup && pr.Spec.Plural == resource {
			// The relation built for OpenFGA is the hashed permission.
			// hashedPermission := openfga.HashPermission(permission)
			verb := attributes.GetVerb()
			for _, p := range pr.Spec.Permissions {
				if p == verb {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// buildPermissionString constructs the permission string in the format: service/resource.verb
func (o *CoreControlPlaneAuthorizer) buildPermissionString(attributes authorizer.Attributes) string {
	apiGroup := attributes.GetAPIGroup()
	resource := attributes.GetResource()
	verb := attributes.GetVerb()
	return fmt.Sprintf("%s/%s.%s", apiGroup, resource, verb)
}

func (o *CoreControlPlaneAuthorizer) buildResource(attributes authorizer.Attributes, organizationUID string) string {
	// Use the organization resource when acting on resource collections.
	if slices.Contains([]string{"list", "create", "watch"}, attributes.GetVerb()) {
		result := fmt.Sprintf("resourcemanager.datumapis.com/Organization:%s", organizationUID)
		slog.Debug("buildResource for collection operation",
			slog.String("result", result),
			slog.String("verb", attributes.GetVerb()),
		)
		return result
	}

	// For specific resource operations, use the specific resource UID
	resourceName := attributes.GetName()
	if resourceName == "" {
		// For collection operations on specific resource types
		result := fmt.Sprintf("resourcemanager.datumapis.com/Organization:%s", organizationUID)
		slog.Debug("buildResource for empty resource name",
			slog.String("result", result),
		)
		return result
	}

	// Map the Kubernetes resource name (plural) to the OpenFGA resource type (singular, capitalized)
	kubernetesResource := attributes.GetResource()
	openFGAResourceType, exists := resourceTypeMapping[kubernetesResource]
	if !exists {
		// Fallback to using the Kubernetes resource name if no mapping exists
		openFGAResourceType = kubernetesResource
	}

	// Resolve the resource name to its UID
	resourceUID, err := o.resolveResourceUID(context.Background(), kubernetesResource, resourceName)
	if err != nil {
		slog.Error("failed to resolve resource UID",
			slog.String("resource", kubernetesResource),
			slog.String("name", resourceName),
			slog.String("error", err.Error()),
		)
		// Fallback to using the name if UID resolution fails
		resourceUID = resourceName
	}

	// Build the fully qualified resource type using the correct OpenFGA format
	result := fmt.Sprintf("%s/%s:%s", attributes.GetAPIGroup(), openFGAResourceType, resourceUID)
	slog.Debug("buildResource for specific resource",
		slog.String("result", result),
		slog.String("kubernetesResource", kubernetesResource),
		slog.String("openFGAResourceType", openFGAResourceType),
		slog.String("resourceName", resourceName),
		slog.String("resourceUID", resourceUID),
		slog.String("apiGroup", attributes.GetAPIGroup()),
	)
	return result
}

// resolveResourceUID resolves a resource name to its UID by querying the Kubernetes cluster
func (o *CoreControlPlaneAuthorizer) resolveResourceUID(ctx context.Context, resourceType, resourceName string) (string, error) {
	switch resourceType {
	case "projects":
		// Look up the Project resource to get its UID
		project := &resourcemanagerv1alpha1.Project{}
		err := o.K8sClient.Get(ctx, types.NamespacedName{Name: resourceName}, project)
		if err != nil {
			return "", fmt.Errorf("failed to get project %s: %w", resourceName, err)
		}
		return string(project.UID), nil
	case "organizations":
		// Look up the Organization resource to get its UID
		org := &resourcemanagerv1alpha1.Organization{}
		err := o.K8sClient.Get(ctx, types.NamespacedName{Name: resourceName}, org)
		if err != nil {
			return "", fmt.Errorf("failed to get organization %s: %w", resourceName, err)
		}
		return string(org.UID), nil
	default:
		return "", fmt.Errorf("unsupported resource type: %s", resourceType)
	}
}

func (o *CoreControlPlaneAuthorizer) buildRelation(attributes authorizer.Attributes) string {
	// Build permission in the format expected by OpenFGA: service/resource.verb
	permission := o.buildPermissionString(attributes)

	// Hash the permission to match the OpenFGA model
	hashedPermission := openfga.HashPermission(permission)
	slog.Debug("buildRelation",
		slog.String("permission", permission),
		slog.String("hashedPermission", hashedPermission),
		slog.String("apiGroup", attributes.GetAPIGroup()),
		slog.String("resource", attributes.GetResource()),
		slog.String("verb", attributes.GetVerb()),
	)
	return hashedPermission
}
