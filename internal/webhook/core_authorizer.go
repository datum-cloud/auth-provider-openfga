package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ authorizer.Authorizer = &CoreControlPlaneAuthorizer{}

type CoreControlPlaneAuthorizer struct {
	FGAClient  openfgav1.OpenFGAServiceClient
	FGAStoreID string
	K8sClient  client.Client
}

// Authorize implements authorizer.Authorizer.
func (o *CoreControlPlaneAuthorizer) Authorize(ctx context.Context, attributes authorizer.Attributes) (authorizer.Decision, string, error) {
	slog.InfoContext(ctx, "authorizing request", slog.Any("attributes", attributes))

	if attributes.GetUser().GetUID() == "" {
		return authorizer.DecisionDeny, "", fmt.Errorf("user UID is required by core control plane authorizer")
	}

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

	checkReq, err := o.buildCheckRequest(ctx, attributes)
	if err != nil {
		slog.ErrorContext(ctx, "failed to build resource", slog.String("error", err.Error()))
		return authorizer.DecisionDeny, "", fmt.Errorf("failed to build resource: %w", err)
	}

	slog.InfoContext(ctx, "checking OpenFGA authorization",
		slog.String("user", checkReq.TupleKey.User),
		slog.String("resource", checkReq.TupleKey.Object),
		slog.String("relation", checkReq.TupleKey.Relation),
		slog.Any("contextual_tuples", checkReq.ContextualTuples),
	)

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
	protectedResourceList := &iamv1alpha1.ProtectedResourceList{}
	if err := o.K8sClient.List(ctx, protectedResourceList); err != nil {
		return false, fmt.Errorf("failed to list ProtectedResources: %w", err)
	}

	apiGroup := attributes.GetAPIGroup()
	resource := attributes.GetResource()

	for _, pr := range protectedResourceList.Items {
		// Check if the APIGroup and Resource (Plural) match
		if pr.Spec.ServiceRef.Name == apiGroup && pr.Spec.Plural == resource {
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

func (o *CoreControlPlaneAuthorizer) buildParentResource(attributes authorizer.Attributes) (string, error) {
	extra := attributes.GetUser().GetExtra()

	// If a parent is in the context, add a tuple for its parent relationship
	parentAPIGroup, parentAPIGroupOK := extra[iamv1alpha1.ParentAPIGroupExtraKey]
	parentKind, parentKindOK := extra[iamv1alpha1.ParentKindExtraKey]
	parentName, parentNameOK := extra[iamv1alpha1.ParentNameExtraKey]

	if parentAPIGroupOK && parentKindOK && parentNameOK {
		if len(parentAPIGroup) == 1 && len(parentKind) == 1 && len(parentName) == 1 {
			return fmt.Sprintf("%s/%s:%s", parentAPIGroup[0], parentKind[0], parentName[0]), nil
		}
	}

	return "", fmt.Errorf("parent resource not found in extra data")
}

func (o *CoreControlPlaneAuthorizer) buildCheckRequest(ctx context.Context, attributes authorizer.Attributes) (*openfgav1.CheckRequest, error) {
	// First, get the ProtectedResource to understand the correct resource structure
	protectedResource, err := o.getProtectedResource(ctx, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to get protected resource: %w", err)
	}

	// For collection operations, we use the parent resource from the extra data
	// included in the request context.
	if slices.Contains([]string{"list", "create", "watch"}, attributes.GetVerb()) || attributes.GetName() == "" {
		parentResource, err := o.buildParentResource(attributes)
		if err != nil {
			slog.Error("failed to build parent resource", slog.String("error", err.Error()))
			return nil, fmt.Errorf("failed to build parent resource for collection operation: %w", err)
		}

		return &openfgav1.CheckRequest{
			StoreId: o.FGAStoreID,
			TupleKey: &openfgav1.CheckRequestTupleKey{
				User:     o.buildUser(attributes),
				Relation: o.buildRelation(attributes),
				Object:   parentResource,
			},
		}, nil
	}

	// For resource specific operations, we want to use the resource name from the
	// resource as the main object and then add the parent resource as a contextual
	// tuple only if the parent is registered in the ProtectedResource definition.

	// Build the fully qualified resource type using the correct OpenFGA format
	resource := fmt.Sprintf("%s/%s:%s", protectedResource.Spec.ServiceRef.Name, protectedResource.Spec.Kind, attributes.GetName())

	checkRequest := &openfgav1.CheckRequest{
		StoreId: o.FGAStoreID,
		TupleKey: &openfgav1.CheckRequestTupleKey{
			User:     o.buildUser(attributes),
			Relation: o.buildRelation(attributes),
			Object:   resource,
		},
	}

	// Only add contextual tuple if parent resource is registered in ProtectedResource
	parentResource, err := o.buildParentResource(attributes)
	if err != nil {
		slog.Debug("no parent resource in context", slog.String("error", err.Error()))
	} else {
		// Check if this parent resource type is registered in the ProtectedResource
		if o.isParentResourceRegistered(protectedResource, parentResource) {
			checkRequest.ContextualTuples = &openfgav1.ContextualTupleKeys{
				TupleKeys: []*openfgav1.TupleKey{
					{
						User:     parentResource,
						Relation: "parent",
						Object:   resource,
					},
				},
			}
		} else {
			slog.Debug("parent resource not registered in ProtectedResource definition",
				slog.String("parent_resource", parentResource),
				slog.String("protected_resource", protectedResource.Name))
		}
	}

	return checkRequest, nil
}

func (o *CoreControlPlaneAuthorizer) buildUser(attributes authorizer.Attributes) string {
	return fmt.Sprintf("iam.miloapis.com/InternalUser:%s", attributes.GetUser().GetUID())
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

// getProtectedResource retrieves the ProtectedResource for the given attributes
func (o *CoreControlPlaneAuthorizer) getProtectedResource(ctx context.Context, attributes authorizer.Attributes) (*iamv1alpha1.ProtectedResource, error) {
	protectedResourceList := &iamv1alpha1.ProtectedResourceList{}
	if err := o.K8sClient.List(ctx, protectedResourceList); err != nil {
		return nil, fmt.Errorf("failed to list ProtectedResources: %w", err)
	}

	apiGroup := attributes.GetAPIGroup()
	resource := attributes.GetResource()

	for _, pr := range protectedResourceList.Items {
		// Check if the APIGroup and Resource (Plural) match
		if pr.Spec.ServiceRef.Name == apiGroup && pr.Spec.Plural == resource {
			return &pr, nil
		}
	}

	return nil, fmt.Errorf("no ProtectedResource found for APIGroup=%s, Resource=%s", apiGroup, resource)
}

// isParentResourceRegistered checks if the given parent resource type is registered
// in the ProtectedResource's ParentResources list
func (o *CoreControlPlaneAuthorizer) isParentResourceRegistered(protectedResource *iamv1alpha1.ProtectedResource, parentResource string) bool {
	// Extract the parent resource type from the parent resource string
	// Parent resource format: "{APIGroup}/{Kind}:{Name}" (e.g., "resourcemanager.miloapis.com/Organization:org-123")
	// We need to extract the "{APIGroup}/{Kind}" part
	parts := strings.Split(parentResource, ":")
	if len(parts) != 2 {
		return false
	}
	parentResourceType := parts[0] // This is "{APIGroup}/{Kind}"

	// Split the parent resource type into APIGroup and Kind
	typeParts := strings.Split(parentResourceType, "/")
	if len(typeParts) != 2 {
		return false
	}
	parentAPIGroup := typeParts[0]
	parentKind := typeParts[1]

	// Check if this parent resource type is registered in the ProtectedResource
	for _, parentRef := range protectedResource.Spec.ParentResources {
		if parentRef.APIGroup == parentAPIGroup && parentRef.Kind == parentKind {
			return true
		}
	}

	return false
}
