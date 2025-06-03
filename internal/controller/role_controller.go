package controller

import (
	"context"
	"fmt"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	roleFinalizerKey = "iam.miloapis.com/openfga-role"
)

// parsePermissionString splits a permission string into its components.
// Expected format: <apiGroup>/<resourcePlural>.<permissionName>
// Returns apiGroup, resourcePlural, permName, and a boolean indicating if the format is valid.
func parsePermissionString(permStr string) (string, string, string, bool) {
	parts := strings.SplitN(permStr, "/", 2)
	if len(parts) != 2 {
		return "", "", "", false
	}
	apiGroup := parts[0]

	resourceAndPerm := strings.SplitN(parts[1], ".", 2)
	if len(resourceAndPerm) != 2 {
		return apiGroup, "", "", false
	}
	resourcePlural := resourceAndPerm[0]
	permName := resourceAndPerm[1]
	return apiGroup, resourcePlural, permName, true
}

// OpenFGARoleFinalizer handles deletion of OpenFGA tuples for a Role.
type OpenFGARoleFinalizer struct {
	client.Client
	roleReconciler *openfga.RoleReconciler
}

// Finalize ensures that OpenFGA tuples for the Role are removed.
func (f *OpenFGARoleFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx)
	role, ok := obj.(*iamdatumapiscomv1alpha1.Role)
	if !ok {
		return finalizer.Result{}, fmt.Errorf("object is not a Role: %T", obj)
	}

	log.Info("Performing Finalization Tasks for Role before deletion", "Role", role.Name)

	if err := f.roleReconciler.DeleteRole(ctx, *role); err != nil {
		return finalizer.Result{}, fmt.Errorf("failed to delete role configuration: %w", err)
	}

	log.Info("Successfully deleted role configuration during finalization")
	return finalizer.Result{}, nil
}

// RoleReconciler reconciles a Role object
type RoleReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	FgaClient     openfgav1.OpenFGAServiceClient
	StoreID       string
	Finalizers    finalizer.Finalizers
	EventRecorder record.EventRecorder
}

// getAllEffectivePermissions collects all unique permissions for a role, including inherited ones.
func (r *RoleReconciler) getAllEffectivePermissions(ctx context.Context, role *iamdatumapiscomv1alpha1.Role, visited map[string]struct{}) ([]string, error) {
	if visited == nil {
		visited = make(map[string]struct{})
	}

	roleIdentifier := role.Namespace + "/" + role.Name // Ensure uniqueness for visited roles across namespaces
	if _, ok := visited[roleIdentifier]; ok {
		return nil, nil // Prevent cycles
	}
	visited[roleIdentifier] = struct{}{}

	permissionSet := make(map[string]struct{})
	for _, p := range role.Spec.IncludedPermissions {
		permissionSet[p] = struct{}{}
	}

	for _, inheritedRoleRef := range role.Spec.InheritedRoles {
		inheritedRole := &iamdatumapiscomv1alpha1.Role{}

		// Determine the namespace for the inherited role.
		// Default to the current role's namespace if not specified.
		namespace := role.Namespace
		if inheritedRoleRef.Namespace != "" {
			namespace = inheritedRoleRef.Namespace
		}

		err := r.Get(ctx, client.ObjectKey{Namespace: namespace, Name: inheritedRoleRef.Name}, inheritedRole)
		if err != nil {
			if apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("inherited role '%s' not found in namespace '%s'", inheritedRoleRef.Name, namespace)
			}
			return nil, fmt.Errorf("failed to get inherited role %s/%s: %w", namespace, inheritedRoleRef.Name, err)
		}

		inheritedPerms, err := r.getAllEffectivePermissions(ctx, inheritedRole, visited)
		if err != nil {
			return nil, err // Propagate error up
		}
		for _, p := range inheritedPerms {
			permissionSet[p] = struct{}{}
		}
	}

	finalPermissions := make([]string, 0, len(permissionSet))
	for p := range permissionSet {
		finalPermissions = append(finalPermissions, p)
	}
	return finalPermissions, nil
}

// validateRolePermissions checks if all effective permissions in a role are validly defined by known ProtectedResources.
func (r *RoleReconciler) validateRolePermissions(ctx context.Context, role *iamdatumapiscomv1alpha1.Role, protectedResources []iamdatumapiscomv1alpha1.ProtectedResource) ([]string, error) {
	log := logf.FromContext(ctx).WithValues("roleName", role.Name)
	var invalidPermissions []string

	effectivePermissions, err := r.getAllEffectivePermissions(ctx, role, nil)
	if err != nil {
		log.Error(err, "Failed to collect all effective permissions for role validation", "roleName", role.Name)
		return []string{fmt.Sprintf("failed to resolve inherited roles: %s", err.Error())}, nil
	}

	for _, permStr := range effectivePermissions {
		permAPIGroup, permResourcePlural, permName, isValidFormat := parsePermissionString(permStr)
		if !isValidFormat {
			log.Info("Invalid permission format encountered during validation", "permission", permStr, "role", role.Name)
			invalidPermissions = append(invalidPermissions, permStr+" (invalid format)")
			continue
		}

		isPermissionDefined := false
	validationLoop:
		for _, pr := range protectedResources {
			if pr.Spec.ServiceRef.Name == permAPIGroup && pr.Spec.Plural == permResourcePlural {
				for _, definedPerm := range pr.Spec.Permissions {
					if definedPerm == permName {
						isPermissionDefined = true
						break validationLoop
					}
				}
			}
		}
		if !isPermissionDefined {
			invalidPermissions = append(invalidPermissions, permStr)
		}
	}
	return invalidPermissions, nil
}

// isRoleAffectedByProtectedResource checks if a role's effective permissions might be affected by a change
// in the specified ProtectedResource definition.
func (r *RoleReconciler) isRoleAffectedByProtectedResource(ctx context.Context, role *iamdatumapiscomv1alpha1.Role, pr *iamdatumapiscomv1alpha1.ProtectedResource) (bool, error) {
	roleLog := logf.FromContext(ctx).WithValues(
		"roleBeingChecked", role.Name, "roleNamespace", role.Namespace,
		"changedProtectedResource", pr.Name,
		"serviceRef", pr.Spec.ServiceRef.Name, "kindDefined", pr.Spec.Kind,
	)

	effectivePermissions, err := r.getAllEffectivePermissions(ctx, role, nil)
	if err != nil {
		roleLog.V(1).Info("Could not get effective permissions for role, cannot determine if affected by ProtectedResource change", "error", err.Error())
		return false, err
	}

	changedPrAPIGroup := pr.Spec.ServiceRef.Name
	changedPrPlural := pr.Spec.Plural

	if changedPrAPIGroup == "" || changedPrPlural == "" {
		roleLog.Info("ProtectedResource has empty ServiceRef.Name or Plural, cannot determine affected roles.",
			"serviceRefName", changedPrAPIGroup, "plural", changedPrPlural)
		return false, fmt.Errorf("ProtectedResource %s has empty ServiceRef.Name or Plural", pr.Name)
	}

	for _, permStr := range effectivePermissions {
		permAPIGroup, permResourcePlural, permName, isValidFormat := parsePermissionString(permStr)
		if !isValidFormat {
			continue
		}

		if permAPIGroup == changedPrAPIGroup && permResourcePlural == changedPrPlural {
			for _, definedPerm := range pr.Spec.Permissions {
				if definedPerm == permName {
					roleLog.V(1).Info("Role is affected by ProtectedResource change due to matching permission", "permission", permStr)
					return true, nil
				}
			}
		}
	}

	roleLog.V(1).Info("Role is not affected by this ProtectedResource change")
	return false, nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Role object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.4/pkg/reconcile
func (r *RoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("role", req.NamespacedName)

	role := &iamdatumapiscomv1alpha1.Role{}
	if err := r.Get(ctx, req.NamespacedName, role); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Role resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get Role")
		return ctrl.Result{}, err
	}

	currentGeneration := role.Generation

	finalizeResult, err := r.Finalizers.Finalize(ctx, role)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to run finalizers for Role: %w", err)
	}
	if finalizeResult.Updated {
		log.Info("Role updated by finalizer (e.g., finalizer removed or status updated).")
		if err := r.Update(ctx, role); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update Role after finalizer operation: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if role.GetDeletionTimestamp() != nil {
		return ctrl.Result{}, nil
	}

	var protectedResourceList iamdatumapiscomv1alpha1.ProtectedResourceList
	if err := r.List(ctx, &protectedResourceList); err != nil {
		return ctrl.Result{}, err
	}

	invalidPermissions, validationErr := r.validateRolePermissions(ctx, role, protectedResourceList.Items)
	permValidationCondition := metav1.Condition{
		Type: "PermissionsValid", Status: metav1.ConditionTrue, Reason: "ValidationSuccessful",
		Message: "All permissions validated successfully.", LastTransitionTime: metav1.Now(), ObservedGeneration: currentGeneration,
	}
	if validationErr != nil {
		log.Error(validationErr, "Error validating role permissions")
		permValidationCondition.Status = metav1.ConditionFalse
		permValidationCondition.Reason = "ValidationError"
		permValidationCondition.Message = fmt.Sprintf("Error during permission validation: %s", validationErr.Error())
	} else if len(invalidPermissions) > 0 {
		log.Info("Role contains invalid or undefined permissions", "invalidPermissions", invalidPermissions)
		permValidationCondition.Status = metav1.ConditionFalse
		permValidationCondition.Reason = "InvalidPermissions"
		permValidationCondition.Message = fmt.Sprintf("Role contains invalid/undefined permissions: %s", strings.Join(invalidPermissions, ", "))
	}
	meta.SetStatusCondition(&role.Status.Conditions, permValidationCondition)

	if permValidationCondition.Status == metav1.ConditionTrue {
		openFgaReconciler := openfga.RoleReconciler{
			StoreID:      r.StoreID,
			OpenFGA:      r.FgaClient,
			ControlPlane: r.Client,
		}
		if err := openFgaReconciler.ReconcileRole(ctx, role); err != nil {
			log.Error(err, "Failed to reconcile Role with OpenFGA")
			meta.SetStatusCondition(&role.Status.Conditions, metav1.Condition{
				Type: "Ready", Status: metav1.ConditionFalse, Reason: "OpenFGAReconciliationFailed",
				Message: fmt.Sprintf("Failed to reconcile with OpenFGA: %s", err.Error()), LastTransitionTime: metav1.Now(),
			})
			if statusUpdateErr := r.Status().Update(ctx, role); statusUpdateErr != nil {
				log.Error(statusUpdateErr, "Failed to update Role status after OpenFGA reconciliation failure")
			}
			return ctrl.Result{}, err
		}
		log.Info("Role successfully reconciled with OpenFGA")
		meta.SetStatusCondition(&role.Status.Conditions, metav1.Condition{
			Type: "Ready", Status: metav1.ConditionTrue, Reason: "ReconciliationSuccessful",
			Message: "Role reconciled successfully with OpenFGA.", LastTransitionTime: metav1.Now(), ObservedGeneration: currentGeneration,
		})
	} else {
		log.Info("Skipping OpenFGA reconciliation due to invalid permissions.")
		meta.SetStatusCondition(&role.Status.Conditions, metav1.Condition{
			Type: "Ready", Status: metav1.ConditionFalse, Reason: "InvalidPermissions",
			Message: permValidationCondition.Message, LastTransitionTime: metav1.Now(), ObservedGeneration: currentGeneration,
		})
	}

	role.Status.ObservedGeneration = currentGeneration
	if err := r.Status().Update(ctx, role); err != nil {
		log.Error(err, "Failed to update Role status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// enqueueRequestsForProtectedResourceChange is a handler that enqueues Role reconcile requests
// when a ProtectedResource changes.
func (r *RoleReconciler) enqueueRequestsForProtectedResourceChange(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	protectedResource, ok := obj.(*iamdatumapiscomv1alpha1.ProtectedResource)
	if !ok {
		log.Error(fmt.Errorf("unexpected object type in ProtectedResource handler for Roles: %T", obj), "cannot enqueue Roles")
		return []reconcile.Request{}
	}

	log.V(1).Info("ProtectedResource changed, evaluating Roles for re-reconciliation",
		"protectedResourceName", protectedResource.Name,
		"serviceRef", protectedResource.Spec.ServiceRef.Name,
		"kindDefined", protectedResource.Spec.Kind)

	roleList := &iamdatumapiscomv1alpha1.RoleList{}
	if err := r.List(context.Background(), roleList); err != nil {
		log.Error(err, "failed to list Roles for ProtectedResource change handler")
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, 0, len(roleList.Items))
	for i := range roleList.Items {
		role := &roleList.Items[i]
		affected, err := r.isRoleAffectedByProtectedResource(ctx, role, protectedResource)
		if err != nil {
			log.Error(err, "Failed to check if role is affected by ProtectedResource change", "roleName", role.Name, "roleNamespace", role.Namespace)
			continue
		}
		if affected {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKey{Name: role.Name, Namespace: role.Namespace},
			})
			log.V(1).Info("Enqueuing Role due to relevant ProtectedResource change", "roleName", role.Name, "roleNamespace", role.Namespace)
		}
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *RoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Finalizers = finalizer.NewFinalizers()
	if err := r.Finalizers.Register(roleFinalizerKey, &OpenFGARoleFinalizer{
		Client: r.Client,
		roleReconciler: &openfga.RoleReconciler{
			StoreID:      r.StoreID,
			OpenFGA:      r.FgaClient,
			ControlPlane: r.Client,
		},
	}); err != nil {
		return fmt.Errorf("failed to register role finalizer: %w", err)
	}

	controllerBuilder := ctrl.NewControllerManagedBy(mgr).
		For(&iamdatumapiscomv1alpha1.Role{}).
		Named("role")

	controllerBuilder.Watches(
		&iamdatumapiscomv1alpha1.ProtectedResource{},
		handler.EnqueueRequestsFromMapFunc(r.enqueueRequestsForProtectedResourceChange),
	)

	return controllerBuilder.Complete(r)
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=roles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=roles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=roles/finalizers,verbs=update
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=protectedresources,verbs=get;list;watch
