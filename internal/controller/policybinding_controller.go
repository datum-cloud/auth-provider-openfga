// Package controller contains the PolicyBinding controller and its associated logic
// for reconciling PolicyBinding custom resources. It ensures that the desired state,
// as defined by PolicyBinding objects, is reflected in the OpenFGA authorization system.
// This includes validating references to Kubernetes resources (like Users, Groups, and target
// resources) and translating these bindings into OpenFGA tuples.
package controller

import (
	"context"
	"fmt"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	iamdatumapiscomv1alpha1 "go.datum.net/datum/pkg/apis/iam.datumapis.com/v1alpha1"
	"go.datum.net/iam/openfga/internal/openfga"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	policyBindingFinalizerKey = "iam.datumapis.com/policybinding"
	// ConditionTypeSubjectValid represents the condition type for validating the
	// subjects (users or groups) referenced in a PolicyBinding. This condition is
	// True if all subjects are found, recognized by the API server, and have valid UIDs.
	ConditionTypeSubjectValid = "SubjectValid"
	// ConditionTypeTargetValid represents the condition type for validating the
	// TargetRef (the resource to which the policy applies) in a PolicyBinding.
	// This condition is True if the target resource type is registered with the IAM
	// service, the specific resource instance exists, and its UID matches the one
	// specified in the PolicyBinding.
	ConditionTypeTargetValid = "TargetValid"
	// ConditionTypeRoleValid represents the condition type for validating the
	// Role (the role being bound) in a PolicyBinding. This condition is True if
	// the referenced Role is found and can be used in the policy.
	ConditionTypeRoleValid = "RoleValid"
	// ReasonValidationSuccessful indicates that a validation check (e.g., for
	// TargetRef or Subjects) has passed successfully.
	ReasonValidationSuccessful = "ValidationSuccessful"
	// ReasonValidationFailed indicates that a validation check has failed,
	// detailing why the resource or reference is not considered valid.
	ReasonValidationFailed = "ValidationFailed"
)

// MissingNamespaceError is an error type used to indicate that a namespace was
// expected for a given Kubernetes resource kind but was not provided. This is
// critical for looking up namespaced resources.
type MissingNamespaceError struct {
	GroupKind schema.GroupKind
	Name      string
}

// Error implements the error interface for MissingNamespaceError.
func (e *MissingNamespaceError) Error() string {
	return fmt.Sprintf("namespace is required for namespaced kind '%s' but was not provided for resource '%s'", e.GroupKind.String(), e.Name)
}

// RBAC permissions are managed by kubebuilder markers.
// These define the necessary permissions for the controller to interact with
// various Kubernetes resources.
// +kubebuilder:rbac:groups=iam.datumapis.com,resources=policybindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=iam.datumapis.com,resources=policybindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=iam.datumapis.com,resources=policybindings/finalizers,verbs=update
// +kubebuilder:rbac:groups=iam.datumapis.com,resources=protectedresources,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=users;groups,verbs=get;list;watch
// +kubebuilder:rbac:groups="*",resources="*",verbs=get;list;watch

// PolicyBindingReconciler reconciles a PolicyBinding object.
// It ensures that the state of OpenFGA policies reflects the desired state
// specified in PolicyBinding custom resources. This involves validating
// references to Kubernetes resources, managing finalizers for cleanup, and
// creating/deleting tuples in an OpenFGA store.
type PolicyBindingReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	RESTMapper    meta.RESTMapper
	FgaClient     openfgav1.OpenFGAServiceClient
	StoreID       string
	Finalizers    finalizer.Finalizers
	EventRecorder record.EventRecorder
}

// Reconcile is the core reconciliation loop for PolicyBinding resources.
// It is called by the controller-runtime when a PolicyBinding is created,
// updated, or deleted, or when a watched secondary resource changes.
//
// The reconciliation process follows these main steps:
//  1. Fetch the PolicyBinding: Retrieves the current state of the PolicyBinding CR.
//  2. Handle Deletion: If the PolicyBinding is marked for deletion, invokes finalizers
//     to clean up external resources.
//  3. Ensure Finalizer: If not deleting, ensures the custom finalizer is present on
//     the PolicyBinding CR.
//  4. Validate TargetRef: Validates the `spec.targetRef` by checking if the target
//     resource type is registered with an IAM Service, if the target resource
//     instance exists, and if its UID matches the one in the spec. Updates
//     `status.conditions` (TargetValid) accordingly.
//  5. Validate Subjects: Validates each entry in `spec.subjects` by checking if the
//     subject resource (User or Group) exists, its kind is recognized, and its UID
//     is provided and correct. Updates `status.conditions`
//     (SubjectValid) accordingly.
//  6. Reconcile OpenFGA Policy: If all validations pass, synchronizes the
//     PolicyBinding with the OpenFGA store by creating or deleting tuples. This
//     step also implicitly validates the `spec.roleRef` by attempting to use it.
//     Updates `status.conditions` (RoleValid) accordingly.
//  7. Update Status: Persists all changes to `status.conditions` and sets the
//     overall "Ready" condition based on the success or failure of the preceding steps.
//     The `status.observedGeneration` is updated to reflect the generation of the
//     spec that was processed.
//
// The Reconcile function aims to be idempotent and convergence-oriented, meaning
// it can be called multiple times and will eventually drive the system to the
// desired state.
func (r *PolicyBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	policyBinding := &iamdatumapiscomv1alpha1.PolicyBinding{}
	if err := r.Get(ctx, req.NamespacedName, policyBinding); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("PolicyBinding resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get PolicyBinding")
		return ctrl.Result{}, err
	}

	// Store the current generation of the PolicyBinding. This will be used when
	// updating the status to indicate which version of the spec the status reflects.
	currentGeneration := policyBinding.Generation

	// Step 1: Handle deletion if the PolicyBinding is marked for it.
	// This involves running finalizers to clean up external resources.
	if policyBinding.GetDeletionTimestamp() != nil {
		return r.handleDeletion(ctx, policyBinding)
	}
	// If not deleting, 'err' from handleDeletion should be nil if it reached its "not deleted" path.
	// The result.Requeue from handleDeletion's non-deleted path is ignored here as subsequent steps dictate requeue.

	// Step 2: Ensure our custom finalizer is present on the PolicyBinding if it's not being deleted.
	// This is crucial for ensuring cleanup (via OpenFGAFinalizer) when the resource is eventually deleted.
	result, err := r.ensureFinalizer(ctx, policyBinding, currentGeneration)
	if err != nil {
		// An error occurred while trying to add or update the finalizer.
		return result, err
	}
	if result.Requeue {
		// Requeue was requested, likely because the finalizer was just added and the object updated.
		// The next reconciliation cycle will proceed with the finalizer in place.
		log.Info("Requeuing after ensuring finalizer.")
		return result, nil
	}

	// Step 3: Validate the TargetRef.
	// This involves checking if the target type is registered with IAM,
	// if the specific instance exists, and if its UID matches.
	var isValid bool
	isValid, result, err = r.reconcileTargetRefValidation(ctx, policyBinding, currentGeneration)
	if err != nil {
		// An error (e.g., API server communication failure) occurred during TargetRef validation.
		// The reconcileTargetRefValidation function has already set the TargetValid=False condition and updated the status.
		// We now set the overall Ready condition to False before returning.
		meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "TargetRefValidationFailed",
			Message:            fmt.Sprintf("TargetRef validation failed: %s. See TargetValid condition for details.", err.Error()),
			LastTransitionTime: metav1.Now(),
		})
		// Attempt to update status with the Ready=False condition.
		if statusUpdateErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusUpdateErr != nil {
			log.Error(statusUpdateErr, "Failed to update PolicyBinding status after TargetRef validation error")
		}
		return result, err
	}
	if !isValid {
		// TargetRef validation failed cleanly (e.g., target not found, UID mismatch, type not registered).
		// The reconcileTargetRefValidation function has set TargetValid=False and updated status.
		// Set Ready condition to False and stop reconciliation.
		meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "TargetRefValidationFailed",
			Message:            "TargetRef validation failed. See TargetValid condition for details.",
			LastTransitionTime: metav1.Now(),
		})
		// Attempt to update status with the Ready=False condition.
		if statusUpdateErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusUpdateErr != nil {
			log.Error(statusUpdateErr, "Failed to update PolicyBinding status after TargetRef validation failure")
		}
		return result, nil // Stop reconciliation
	}

	// Step 4: Validate the Subjects.
	// This checks if each subject exists, its kind is recognized, and UID is provided and correct.
	isValid, result, err = r.reconcileSubjectValidation(ctx, policyBinding, currentGeneration)
	if err != nil {
		// An error occurred during Subject validation (e.g., API server communication failure).
		// reconcileSubjectValidation has set SubjectValid=False and updated status.
		// Set Ready condition to False before returning.
		meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeSubjectValid,
			Status:             metav1.ConditionFalse,
			Reason:             "SubjectValidationFailed",
			Message:            fmt.Sprintf("Subject validation failed: %s. See SubjectValid condition for details.", err.Error()),
			LastTransitionTime: metav1.Now(),
		})
		// Attempt to update status with the Ready=False condition.
		if statusUpdateErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusUpdateErr != nil {
			log.Error(statusUpdateErr, "Failed to update PolicyBinding status after Subject validation error")
		}
		return result, err
	}
	if !isValid {
		// Subject validation failed cleanly (e.g., a subject not found, UID mismatch).
		// reconcileSubjectValidation has set SubjectValid=False and updated status.
		// Set Ready condition to False and stop reconciliation.
		meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "SubjectValidationFailed",
			Message:            "Subject validation failed. See SubjectValid condition for details.",
			LastTransitionTime: metav1.Now(),
		})
		// Attempt to update status with the Ready=False condition.
		if statusUpdateErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusUpdateErr != nil {
			log.Error(statusUpdateErr, "Failed to update PolicyBinding status after Subject validation failure")
		}
		return result, nil // Stop reconciliation
	}

	// At this juncture, both TargetRef and all Subjects have been successfully validated.
	// Their respective conditions (TargetValid=True, SubjectValid=True) have been set in memory
	// by their validation functions. We need to persist these positive statuses before
	// proceeding to the OpenFGA reconciliation, which is an external call.
	if err := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); err != nil {
		log.Error(err, "Failed to update PolicyBinding status after successful validations before OpenFGA reconciliation")
		return ctrl.Result{}, err
	}

	// Step 5: Reconcile with OpenFGA.
	// This creates/updates/deletes tuples in OpenFGA based on the PolicyBinding.
	// This step also implicitly validates the RoleRef by attempting to use the role.
	result, err = r.reconcileOpenFGAPolicy(ctx, policyBinding, currentGeneration)
	if err != nil {
		// An error occurred during OpenFGA reconciliation (e.g., OpenFGA server unavailable, role not found in FGA).
		// reconcileOpenFGAPolicy has already set Ready=False and RoleValid appropriately, and updated the status.
		return result, err
	}

	// All steps were successful: finalizer ensured, target validated, subjects validated, OpenFGA reconciled.
	log.Info("Successfully reconciled PolicyBinding")
	meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "ReconciliationSuccessful",
		Message:            "PolicyBinding reconciled successfully.",
		LastTransitionTime: metav1.Now(),
	})
	// Use the new status update helper
	if statusErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusErr != nil {
		log.Error(statusErr, "Failed to update PolicyBinding status after successful reconciliation")
		return ctrl.Result{}, statusErr
	}

	return ctrl.Result{}, nil
}

// handleDeletion checks if the PolicyBinding is marked for deletion (i.e., has a
// deletionTimestamp). If so, it triggers the finalization logic. The finalizer
// (OpenFGAFinalizer) is responsible for cleaning up external resources (OpenFGA
// tuples) before the PolicyBinding object is actually removed from Kubernetes.
// This function returns a result indicating whether reconciliation should stop
// (if deletion is complete or in progress) or an error if finalization fails.
func (r *PolicyBindingReconciler) handleDeletion(ctx context.Context, policyBinding *iamdatumapiscomv1alpha1.PolicyBinding) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("PolicyBinding is marked for deletion, performing finalization.")

	// The finalization logic should only run if our specific finalizer is still present on the resource.
	// This prevents issues if multiple finalizers are involved or if the finalizer was already removed.
	if !controllerutil.ContainsFinalizer(policyBinding, policyBindingFinalizerKey) {
		log.Info("PolicyBinding marked for deletion but our finalizer is not present or already processed.", "finalizerKey", policyBindingFinalizerKey)
		return ctrl.Result{}, nil
	}

	log.Info("PolicyBinding is marked for deletion and our finalizer is present, performing finalization logic.", "finalizerKey", policyBindingFinalizerKey)
	finalizerResult, err := r.Finalizers.Finalize(ctx, policyBinding)
	if err != nil {
		// Log error and update status before returning
		log.Error(err, "Finalization failed for PolicyBinding")
		meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
			Type:    "Ready", // Or a more specific finalization condition type
			Status:  metav1.ConditionFalse,
			Reason:  "FinalizationFailed",
			Message: fmt.Sprintf("Finalization failed: %s", err.Error()),
		})
		// Attempt to update status, but prioritize returning the finalization error
		if statusUpdateErr := r.updatePolicyBindingStatus(ctx, policyBinding, policyBinding.Generation); statusUpdateErr != nil {
			log.Error(statusUpdateErr, "Failed to update PolicyBinding status during finalization error")
		}
		return ctrl.Result{}, fmt.Errorf("failed to finalize PolicyBinding: %w", err)
	}
	// If the finalizer updated the PolicyBinding object (e.g., by removing itself or updating status),
	// we need to persist these changes to the API server.
	if finalizerResult.Updated {
		log.Info("PolicyBinding updated by finalizer (e.g. finalizer removed or status updated).")
		if err := r.Update(ctx, policyBinding); err != nil { // Use r.Update, not r.Status().Update() if object itself changed
			log.Error(err, "Failed to update PolicyBinding after finalizer operation")
			return ctrl.Result{}, err
		}
	}

	// If the finalizer is still present after the Finalize call, it means the finalization
	// process is not yet complete (e.g., waiting for external resources to be fully cleaned up).
	// In this case, we must requeue the reconciliation to retry finalization.
	if controllerutil.ContainsFinalizer(policyBinding, policyBindingFinalizerKey) {
		log.Info("Finalizer still present, requeueing for finalization.")
		return ctrl.Result{Requeue: true}, nil
	}

	log.Info("Finalization process complete.")
	// Deletion is complete; stop reconciliation for this resource.
	return ctrl.Result{}, nil
}

// ensureFinalizer checks if the PolicyBinding custom resource has the
// `policyBindingFinalizerKey` finalizer. If not, it adds the finalizer and
// updates the resource in the Kubernetes API. This is crucial because finalizers
// allow the controller to perform cleanup (like removing OpenFGA tuples) before
// Kubernetes physically deletes the resource. An update and requeue are triggered
// if the finalizer is added.
func (r *PolicyBindingReconciler) ensureFinalizer(ctx context.Context, policyBinding *iamdatumapiscomv1alpha1.PolicyBinding, currentGeneration int64) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	if !controllerutil.ContainsFinalizer(policyBinding, policyBindingFinalizerKey) {
		log.Info("Adding Finalizer for the PolicyBinding")
		controllerutil.AddFinalizer(policyBinding, policyBindingFinalizerKey)
		// Persist the change (addition of the finalizer) to the Kubernetes API.
		if err := r.Update(ctx, policyBinding); err != nil {
			log.Error(err, "Failed to update PolicyBinding after adding finalizer")
			meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
				Type:               "Ready",
				Status:             metav1.ConditionFalse,
				Reason:             "FinalizerError",
				Message:            "Failed to add finalizer during update",
				LastTransitionTime: metav1.Now(),
			})
			if statusErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusErr != nil {
				log.Error(statusErr, "Failed to update PolicyBinding status after finalizer add error during main object update failure")
			}
			return ctrl.Result{}, err
		}
		// After successfully adding a finalizer, the PolicyBinding object has been modified.
		// We must requeue the reconciliation request. The next Reconcile call will see
		// the finalizer present and proceed with other validation and reconciliation steps.
		return ctrl.Result{Requeue: true}, nil
	}
	// The finalizer is already present; no action is needed in this function.
	return ctrl.Result{}, nil
}

// reconcileTargetRefValidation performs a multi-step validation of the TargetRef
// specified in the PolicyBinding. It's a critical part of ensuring the
// PolicyBinding refers to a valid and existing target resource.
//
// The validation proceeds as follows:
//  1. Service Registration Check: It verifies that the APIGroup and Kind of the
//     TargetRef are declared by a 'Service' custom resource. This acts as a registry for permissible target types.
//  2. Resource Existence and GVK Resolution: It uses the RESTMapper to resolve the
//     full GroupVersionKind (GVK) for the TargetRef and then attempts to fetch the
//     actual resource instance from the Kubernetes API. This confirms the resource exists.
//  3. UID Match: If the resource is found, its UID is compared against the UID
//     provided in the `TargetRef.UID` field of the PolicyBinding spec. This ensures
//     the PolicyBinding is tied to a specific instance of the resource, preventing
//     issues if the resource is deleted and recreated with the same name but a new UID.
//
// If any of these validation steps fail, an appropriate status condition
// (ConditionTypeTargetValid=False) is set on the PolicyBinding, and the function
// returns `isValid=false`. If an API error occurs that suggests a requeue (e.g.,
// network issue), an error is returned to trigger that.
func (r *PolicyBindingReconciler) reconcileTargetRefValidation(ctx context.Context, policyBinding *iamdatumapiscomv1alpha1.PolicyBinding, currentGeneration int64) (isValid bool, result ctrl.Result, err error) {
	log := logf.FromContext(ctx)

	// Condition to be updated based on validation.
	condition := metav1.Condition{
		Type:               ConditionTypeTargetValid,
		Status:             metav1.ConditionTrue,
		Reason:             ReasonValidationSuccessful,
		Message:            "TargetRef validated successfully.",
		ObservedGeneration: currentGeneration,
	}

	// Fetch all ProtectedResource CRs. These define the resource types managed by IAM.
	var protectedResourceList iamdatumapiscomv1alpha1.ProtectedResourceList
	if err := r.List(ctx, &protectedResourceList); err != nil {
		log.Error(err, "unable to list ProtectedResources")
		condition.Status = metav1.ConditionFalse
		condition.Reason = "ListProtectedResourcesFailed"
		condition.Message = fmt.Sprintf("Failed to list ProtectedResources: %s", err.Error())
		meta.SetStatusCondition(&policyBinding.Status.Conditions, condition)
		// Attempt to update status even on error, then return error.
		if statusUpdateErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusUpdateErr != nil {
			log.Error(statusUpdateErr, "Failed to update PolicyBinding status after ProtectedResource list error")
		}
		return false, ctrl.Result{}, err // Requeue to retry listing.
	}

	// Validate if the target type specified in the PolicyBinding is registered by any ProtectedResource.
	isKnownType, typeValidationReason := r.validatePolicyBindingTargetRefType(ctx, policyBinding.Spec, protectedResourceList.Items)
	if !isKnownType {
		log.Info("TargetRef validation failed: type not registered or ambiguous.", "reason", typeValidationReason)
		condition.Status = metav1.ConditionFalse
		condition.Reason = ReasonValidationFailed
		condition.Message = fmt.Sprintf("Target resource type '%s/%s' is not registered or ambiguously defined: %s",
			policyBinding.Spec.TargetRef.APIGroup, policyBinding.Spec.TargetRef.Kind, typeValidationReason)
		meta.SetStatusCondition(&policyBinding.Status.Conditions, condition)
		if statusUpdateErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusUpdateErr != nil {
			log.Error(statusUpdateErr, "Failed to update PolicyBinding status after type validation failure")
		}
		return false, ctrl.Result{}, nil // No requeue, type definition needs to be fixed.
	}

	// Get the actual target resource instance.
	targetSpec := policyBinding.Spec.TargetRef

	fetchedTarget, mapping, err := r.getUnstructuredResourceAndMapping(ctx, targetSpec.APIGroup, targetSpec.Kind, targetSpec.Name, targetSpec.Namespace)

	if err != nil {
		var errMsg string
		var reason string
		stopReconciliation := true
		requeueError := error(nil)

		if meta.IsNoMatchError(err) {
			errMsg = fmt.Sprintf("Target Kind '%s' in group '%s' not recognized by the API server.", targetSpec.Kind, targetSpec.APIGroup)
			reason = "TargetKindNotRecognized"
		} else if apierrors.IsNotFound(err) {
			errMsg = fmt.Sprintf("Target resource %s/%s (namespace: '%s') not found.", targetSpec.Kind, targetSpec.Name, targetSpec.Namespace)
			reason = "TargetNotFound"
		} else if missingNsErr, ok := err.(*MissingNamespaceError); ok {
			errMsg = missingNsErr.Error()
			reason = "TargetNamespaceMissing"
		} else {
			// An unexpected error occurred (e.g., network connectivity, API server issue).
			// These errors warrant a requeue to allow for recovery.
			log.Error(err, "Failed to get or map target resource", "targetKind", targetSpec.Kind, "targetName", targetSpec.Name, "targetAPIGroup", targetSpec.APIGroup, "targetNamespace", targetSpec.Namespace)
			errMsg = fmt.Sprintf("Error looking up target %s/%s: %s", targetSpec.Kind, targetSpec.Name, err.Error())
			reason = "TargetLookupError"
			stopReconciliation = false // Signal that this error should lead to a requeue.
			requeueError = fmt.Errorf("failed to validate target %s/%s: %w", targetSpec.Kind, targetSpec.Name, err)
		}

		log.Info(errMsg, "policyBindingName", policyBinding.Name)
		condition.Status = metav1.ConditionFalse
		condition.Reason = reason
		condition.Message = errMsg
		meta.SetStatusCondition(&policyBinding.Status.Conditions, condition)
		if statusErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusErr != nil {
			log.Error(statusErr, "Failed to update PolicyBinding status for target validation failure")
			// If status update fails, the original requeueError (if any) is more important, or the new statusErr if no requeueError.
			if requeueError != nil {
				return false, ctrl.Result{}, requeueError
			}
			return false, ctrl.Result{}, statusErr
		}
		if !stopReconciliation {
			// Requeue if the error was deemed transient or requires a retry.
			return false, ctrl.Result{}, requeueError
		}
		// For non-requeueable validation errors (e.g., NotFound, KindNotRecognized), stop reconciliation.
		return false, ctrl.Result{}, nil
	}

	// At this point, the target resource was successfully fetched.
	// The `mapping` variable contains its RESTMapping, which indicates if it's namespaced.
	// `targetSpec.Namespace` is the namespace provided in the PolicyBinding.
	// The `getUnstructuredResourceAndMapping` helper already validated that if the kind is namespaced,
	// `targetSpec.Namespace` was not empty.
	// For constructing clear messages below, `lookupNamespace` reflects the namespace used for the lookup.
	lookupNamespace := targetSpec.Namespace
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace && lookupNamespace == "" {
		// This block should ideally be unreachable if `getUnstructuredResourceAndMapping`
		// correctly returns `MissingNamespaceError`. It's a defensive measure.
	}

	// Third, compare the UID of the fetched target resource with the UID specified in the PolicyBinding.
	// This ensures the PolicyBinding is pinned to a specific instance of the resource.
	if fetchedTarget.GetUID() != types.UID(targetSpec.UID) {
		msg := fmt.Sprintf("Target resource %s/%s (namespace: '%s') found, but UID does not match. Expected: %s, Got: %s.", targetSpec.Kind, targetSpec.Name, lookupNamespace, targetSpec.UID, fetchedTarget.GetUID())
		log.Info(msg, "policyBindingName", policyBinding.Name)
		condition.Status = metav1.ConditionFalse
		condition.Reason = "TargetUIDMismatch"
		condition.Message = msg
		meta.SetStatusCondition(&policyBinding.Status.Conditions, condition)
		if statusErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusErr != nil {
			log.Error(statusErr, "Failed to update PolicyBinding status for target UID mismatch")
			return false, ctrl.Result{}, statusErr
		}
		// UID mismatch is a definitive validation failure. Stop reconciliation.
		return false, ctrl.Result{}, nil
	}

	// All TargetRef validations (type registration, instance existence, UID match) passed.
	condition.Status = metav1.ConditionTrue
	condition.Reason = ReasonValidationSuccessful
	condition.Message = "TargetRef validated successfully."
	meta.SetStatusCondition(&policyBinding.Status.Conditions, condition)
	// The status update to persist ConditionTypeTargetValid=True will be handled
	// by the main Reconcile loop or subsequent helper functions before critical actions
	// like OpenFGA reconciliation.
	return true, ctrl.Result{}, nil
}

// reconcileSubjectValidation orchestrates the validation of all subjects
// (users/groups) listed in the PolicyBinding. It calls the
// `validatePolicyBindingSubjects` helper function to perform the detailed checks.
//
// If `validatePolicyBindingSubjects` returns an error (signaling a need to requeue,
// typically due to an API lookup failure), this function sets the
// ConditionTypeSubjectValid status to False with a "SubjectLookupError" reason
// and propagates the error to the main Reconcile loop.
//
// If `validatePolicyBindingSubjects` indicates that one or more subjects are invalid
// (but no requeue-worthy error occurred), this function sets
// ConditionTypeSubjectValid to False with a "ValidationFailed" reason and detailed
// messages. Reconciliation is stopped in this case.
//
// If all subjects are valid, ConditionTypeSubjectValid is set to True.
//
// The function returns `isValid=true` if all subjects are valid, and `isValid=false`
// otherwise. It also returns a `ctrl.Result` and `error` to guide the main
// Reconcile loop (e.g., to requeue or stop).
func (r *PolicyBindingReconciler) reconcileSubjectValidation(ctx context.Context, policyBinding *iamdatumapiscomv1alpha1.PolicyBinding, currentGeneration int64) (isValid bool, result ctrl.Result, err error) {
	log := logf.FromContext(ctx)
	subjectsAreValid, subjectValidationMessages, subjectRequeueErr := r.validatePolicyBindingSubjects(ctx, policyBinding)

	if subjectRequeueErr != nil {
		log.Error(subjectRequeueErr, "Error validating subjects, requeuing")
		// An error occurred during subject validation that warrants a requeue (e.g., API server unavailable).
		// Set the SubjectValid condition to False. The main Reconcile loop will handle setting Ready=False.
		meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeSubjectValid,
			Status:             metav1.ConditionFalse,
			Reason:             "SubjectLookupError",
			Message:            subjectRequeueErr.Error(),
			LastTransitionTime: metav1.Now(),
		})
		// The main Reconcile loop will handle the overall Ready condition.
		// Update status now to reflect the SubjectValid=False state due to the lookup error.
		if statusErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusErr != nil {
			log.Error(statusErr, "Failed to update PolicyBinding status after subject validation requeue error")
		}
		return false, ctrl.Result{}, subjectRequeueErr
	}

	if !subjectsAreValid {
		msg := fmt.Sprintf("Validation failed: The following subject issues were found: %s", strings.Join(subjectValidationMessages, "; "))
		log.Info(msg, "policyBindingName", policyBinding.Name)
		// One or more subjects are invalid (e.g., not found, UID missing), but no error occurred that requires a requeue.
		// Set the SubjectValid condition to False. The main Reconcile loop will handle setting Ready=False.
		meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeSubjectValid,
			Status:             metav1.ConditionFalse,
			Reason:             ReasonValidationFailed,
			Message:            msg,
			LastTransitionTime: metav1.Now(),
		})
		// The main Reconcile loop will handle the overall Ready condition.
		// Update status now to reflect the SubjectValid=False state due to validation failures.
		if statusErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusErr != nil {
			log.Error(statusErr, "Failed to update PolicyBinding status with subject validation failure")
			// If status update fails, it becomes the primary error to return, as the validation itself was a clean failure.
			return false, ctrl.Result{}, statusErr
		}
		// Validation failed cleanly; stop reconciliation.
		return false, ctrl.Result{}, nil
	}

	// All subjects were found, their kinds recognized, and UIDs were provided as required.
	meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeSubjectValid,
		Status:             metav1.ConditionTrue,
		Reason:             ReasonValidationSuccessful,
		Message:            "All subjects validated successfully.",
		LastTransitionTime: metav1.Now(),
	})
	return true, ctrl.Result{}, nil
}

// reconcileOpenFGAPolicy is responsible for synchronizing the state defined in the
// PolicyBinding custom resource with the OpenFGA authorization system. It
// instantiates an `openfga.PolicyReconciler` and calls its `ReconcilePolicy`
// method.
//
// If `ReconcilePolicy` returns an error, this function updates the
// PolicyBinding's status conditions:
//   - If the error indicates the Role specified in `RoleRef` was not found,
//     `ConditionTypeRoleValid` is set to False with a "RoleNotFoundForBinding" reason.
//   - The main "Ready" condition is set to False with an appropriate reason
//     (e.g., "BindingCreationFailed" or "RoleNotFoundForBinding").
//
// An error is then returned to the main Reconcile loop to trigger a requeue.
//
// If `ReconcilePolicy` is successful, it implies that the referenced Role was
// valid (found and usable). In this case, `ConditionTypeRoleValid` is set to True.
// The main "Ready" condition will be set to True by the calling Reconcile function.
func (r *PolicyBindingReconciler) reconcileOpenFGAPolicy(ctx context.Context, policyBinding *iamdatumapiscomv1alpha1.PolicyBinding, currentGeneration int64) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	policyReconciler := openfga.PolicyReconciler{
		StoreID:   r.StoreID,
		Client:    r.FgaClient,
		K8sClient: r.Client,
	}

	if err := policyReconciler.ReconcilePolicy(ctx, *policyBinding); err != nil {
		log.Error(err, "Failed to reconcile authorization binding")

		// Default reason for failure.
		reason := "BindingCreationFailed"
		// Check if the error from OpenFGA reconciliation is specifically due to the Role not being found.
		// This allows for a more precise status condition.
		if strings.Contains(err.Error(), "not found") && strings.Contains(err.Error(), "role '") {
			reason = "RoleNotFoundForBinding"
			// Set the specific RoleValid condition to False.
			meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
				Type:               ConditionTypeRoleValid,
				Status:             metav1.ConditionFalse,
				Reason:             reason,
				Message:            err.Error(),
				LastTransitionTime: metav1.Now(),
			})
		}

		// Set the overall Ready condition to False due to the OpenFGA reconciliation failure.
		meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             reason,
			Message:            fmt.Sprintf("Failed to create authorization binding: %s", err.Error()),
			LastTransitionTime: metav1.Now(),
		})
		if statusErr := r.updatePolicyBindingStatus(ctx, policyBinding, currentGeneration); statusErr != nil {
			log.Error(statusErr, "Failed to update PolicyBinding status after reconciliation error")
		}
		// Requeue because OpenFGA reconciliation failed.
		return ctrl.Result{}, err
	}

	// If OpenFGA reconciliation was successful, it implies the RoleRef was valid
	// (i.e., the role was found and usable by the OpenFGA policy reconciler).
	// We set ConditionTypeRoleValid to True. This condition is set here because
	// the validation of RoleRef (specifically, its existence and usability for OpenFGA)
	// is intrinsically tied to the OpenFGA reconciliation logic itself.
	// This status is set affirmatively upon success, assuming the preceding TargetRef and Subject
	// validations also passed and the overall Ready condition will become True.
	meta.SetStatusCondition(&policyBinding.Status.Conditions, metav1.Condition{
		Type:               ConditionTypeRoleValid,
		Status:             metav1.ConditionTrue,
		Reason:             ReasonValidationSuccessful,
		Message:            "Role validated successfully.",
		LastTransitionTime: metav1.Now(),
	})

	// OpenFGA reconciliation successful.
	return ctrl.Result{}, nil
}

// updatePolicyBindingStatus is a helper function to consistently update the
// PolicyBinding's status subresource. It sets the ObservedGeneration to the
// current generation of the PolicyBinding resource before performing the update.
// This is crucial for Kubernetes controllers to signal that the status reflects
// the latest spec.
func (r *PolicyBindingReconciler) updatePolicyBindingStatus(ctx context.Context, policyBinding *iamdatumapiscomv1alpha1.PolicyBinding, observedGen int64) error {
	policyBinding.Status.ObservedGeneration = observedGen
	return r.Status().Update(ctx, policyBinding)
}

// getUnstructuredResourceAndMapping is a helper function to resolve the
// GroupVersionKind (GVK) of a resource reference and then fetch the resource
// as an unstructured.Unstructured object. It uses the RESTMapper to find the
// correct GVK and determines if a namespace is required for the lookup.
// This function is used for validating the existence and properties of both
// TargetRef and Subject resources.
func (r *PolicyBindingReconciler) getUnstructuredResourceAndMapping(
	ctx context.Context,
	apiGroup string,
	kind string,
	name string,
	namespace string,
) (*unstructured.Unstructured, *meta.RESTMapping, error) {
	gk := schema.GroupKind{Group: apiGroup, Kind: kind}
	mapping, mapErr := r.RESTMapper.RESTMapping(gk)
	if mapErr != nil {
		// Propagate error (e.g., meta.NoMatchError or other RESTMapper errors)
		return nil, nil, mapErr
	}

	key := client.ObjectKey{Name: name}
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		if namespace == "" {
			return nil, mapping, &MissingNamespaceError{GroupKind: gk, Name: name}
		}
		key.Namespace = namespace
	}
	// If cluster-scoped and a namespace is provided, client.Get typically ignores it.
	// No special handling needed here for that case.

	resource := &unstructured.Unstructured{}
	resource.SetGroupVersionKind(mapping.GroupVersionKind)

	getErr := r.Get(ctx, key, resource)
	if getErr != nil {
		// Propagate error (e.g., apierrors.IsNotFound or other Get errors)
		return nil, mapping, getErr
	}

	return resource, mapping, nil
}

// validatePolicyBindingTargetRefType checks if the target resource type (APIGroup/Kind)
// from the PolicyBindingSpec is declared by any of the provided IAM Services.
// This is the part of TargetRef validation that ensures the type is known to the IAM system.
func (r *PolicyBindingReconciler) validatePolicyBindingTargetRefType(
	ctx context.Context, // Added context for potential logging
	bindingSpec iamdatumapiscomv1alpha1.PolicyBindingSpec,
	protectedResources []iamdatumapiscomv1alpha1.ProtectedResource, // Changed from allServices
) (isValid bool, reason string) {
	targetAPIGroup := bindingSpec.TargetRef.APIGroup
	targetKind := bindingSpec.TargetRef.Kind

	if targetAPIGroup == "" || targetKind == "" {
		return false, "TargetRef APIGroup or Kind is empty."
	}

	foundMatchingProtectedResource := false
	for _, pr := range protectedResources {
		// A ProtectedResource defines a specific kind within a service (ServiceRef.Name acts as APIGroup)
		if pr.Spec.ServiceRef.Name == targetAPIGroup && pr.Spec.Kind == targetKind {
			// TODO: consider if singular/plural names from ProtectedResource should be used for anything here.
			// For now, just matching APIGroup (ServiceRef.Name) and Kind is enough to know the type is registered.
			foundMatchingProtectedResource = true
			break
		}
	}

	if !foundMatchingProtectedResource {
		return false, fmt.Sprintf("No ProtectedResource found defining type '%s/%s'.", targetAPIGroup, targetKind)
	}

	return true, "Target resource type is registered."
}

// validatePolicyBindingSubjects iterates through all subjects (users or groups)
// defined in a PolicyBinding's spec. For each subject, it verifies:
// 1. A UID is provided in the spec.
// 2. The subject's Kind and APIGroup are recognized by the Kubernetes API server.
// 3. The subject resource actually exists in the cluster.
// It accumulates validation messages for any invalid subjects. If a subject lookup
// results in an API error that suggests a transient issue (not a simple "not found"
// or "kind not recognized"), it returns an error to trigger a requeue of the
// PolicyBinding.
func (r *PolicyBindingReconciler) validatePolicyBindingSubjects(ctx context.Context, policyBinding *iamdatumapiscomv1alpha1.PolicyBinding) (subjectsValid bool, validationMessages []string, requeueErr error) {
	log := logf.FromContext(ctx)
	subjectsValid = true // Assume valid until proven otherwise.

	for i := range policyBinding.Spec.Subjects {
		subject := policyBinding.Spec.Subjects[i]

		// The controller requires that users explicitly provide the UID for each subject
		// in the PolicyBinding spec. This ensures unambiguous identification.
		if subject.UID == "" {
			msg := fmt.Sprintf("Subject %s/%s must have a UID specified in the spec.", subject.Kind, subject.Name)
			log.Info(msg, "policyBindingName", policyBinding.Name)
			validationMessages = append(validationMessages, fmt.Sprintf("%s/%s (UIDMissing)", subject.Kind, subject.Name))
			subjectsValid = false
			continue
		}

		effectiveAPIGroup := subject.APIGroup
		// Default to "iam.datumapis.com" for User and Group kinds if no APIGroup is specified.
		// This provides a convention for commonly used IAM kinds.
		if effectiveAPIGroup == "" && (subject.Kind == "User" || subject.Kind == "Group") {
			effectiveAPIGroup = "iam.datumapis.com"
		}

		_, _, err := r.getUnstructuredResourceAndMapping(ctx, effectiveAPIGroup, subject.Kind, subject.Name, subject.Namespace)
		if err != nil {
			var subjectMsg string
			var reason string

			if meta.IsNoMatchError(err) {
				subjectMsg = fmt.Sprintf("Subject Kind '%s' in group '%s' not recognized by the API server for subject '%s'.", subject.Kind, effectiveAPIGroup, subject.Name)
				reason = "KindNotRecognized"
			} else if apierrors.IsNotFound(err) {
				subjectMsg = fmt.Sprintf("Subject %s/%s (namespace: '%s') not found.", subject.Kind, subject.Name, subject.Namespace)
				reason = "NotFound"
			} else if missingNsErr, ok := err.(*MissingNamespaceError); ok {
				subjectMsg = missingNsErr.Error()
				reason = "NamespaceMissing"
			} else {
				log.Error(err, "Failed to get or map subject", "subjectKind", subject.Kind, "subjectName", subject.Name, "subjectAPIGroup", effectiveAPIGroup, "subjectNamespace", subject.Namespace)
				subjectMsg = fmt.Sprintf("Error looking up subject %s/%s: %s", subject.Kind, subject.Name, err.Error())
				reason = "LookupError"
				// An unexpected error occurred (e.g., network issue, API server error).
				// This warrants a requeue to retry the validation.
				requeueErr = fmt.Errorf("failed to validate subject %s/%s: %w", subject.Kind, subject.Name, err)
				// For this specific function, if there's a requeueErr, we return it to the main Reconcile loop immediately.
				// The main Reconcile loop will then set the SubjectValid and Ready conditions before requeuing.
				return false, validationMessages, requeueErr
			}

			log.Info(subjectMsg, "policyBindingName", policyBinding.Name, "subjectName", subject.Name)
			validationMessages = append(validationMessages, fmt.Sprintf("%s/%s (%s)", subject.Kind, subject.Name, reason))
			subjectsValid = false
			// Continue to the next subject if it's a validation issue (e.g., NotFound)
			// not requiring an immediate requeue for all subjects.
			continue
		}
		// If err is nil, the subject resource exists and its Kind is recognized by the API server.
		// The UID was already validated to be present in the spec.
		// No UID fetching or spec modification occurs here as UIDs must be user-provided.
	}
	return subjectsValid, validationMessages, nil // requeueErr is nil if we reach this point.
}

// PolicyBindingFinalizer implements the finalizer.Finalizer interface. It is responsible
// for cleaning up authorization tuples associated with a PolicyBinding when the
// PolicyBinding custom resource is deleted from the Kubernetes cluster.
type openFGAFinalizer struct {
	client.Client
	fgaClient openfgav1.OpenFGAServiceClient
	storeID   string
}

// Finalize is called by the controller when the PolicyBinding is being deleted.
// It now delegates the deletion of OpenFGA tuples to the openfga.PolicyReconciler.
func (f *openFGAFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx)
	policyBinding, ok := obj.(*iamdatumapiscomv1alpha1.PolicyBinding)
	if !ok {
		log.Error(fmt.Errorf("unexpected object type for finalization: %T", obj), "cannot finalize PolicyBinding")
		return finalizer.Result{}, fmt.Errorf("unexpected object type %T, expected PolicyBinding", obj)
	}

	log.Info("Finalizing PolicyBinding by calling openfga.PolicyReconciler.DeletePolicy", "policyBindingName", policyBinding.Name)

	// Instantiate the OpenFGA PolicyReconciler from the openfga package
	// The finalizer has the necessary components (k8s client, fga client, storeID)
	policyReconciler := openfga.PolicyReconciler{
		StoreID:   f.storeID,
		Client:    f.fgaClient,
		K8sClient: f.Client, // This is the k8s client.Client from the finalizer struct
	}

	if err := policyReconciler.DeletePolicy(ctx, *policyBinding); err != nil {
		log.Error(err, "Failed to delete OpenFGA policy during finalization", "policyBindingName", policyBinding.Name)
		return finalizer.Result{}, err // Propagate the error
	}

	log.Info("Successfully finalized PolicyBinding (OpenFGA tuples deletion initiated)", "policyBindingName", policyBinding.Name)
	return finalizer.Result{}, nil
}

// enqueuePolicyBindingsForProtectedResourceChange is a handler that enqueues PolicyBinding reconcile requests
// when a ProtectedResource changes. This is because changes to a ProtectedResource (which defines resource types
// and their services) can affect the validity of PolicyBindings targeting those types.
func (r *PolicyBindingReconciler) enqueuePolicyBindingsForProtectedResourceChange(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	protectedResource, ok := obj.(*iamdatumapiscomv1alpha1.ProtectedResource)
	if !ok {
		log.Error(fmt.Errorf("unexpected object type in ProtectedResource handler: %T", obj), "cannot enqueue PolicyBindings")
		return []reconcile.Request{}
	}

	log.V(1).Info("ProtectedResource changed, enqueuing PolicyBindings for re-evaluation",
		"protectedResourceName", protectedResource.Name,
		"serviceRef", protectedResource.Spec.ServiceRef.Name,
		"kindDefined", protectedResource.Spec.Kind)

	policyBindings := &iamdatumapiscomv1alpha1.PolicyBindingList{}
	errs := r.List(context.Background(), policyBindings) // List all policy bindings in the cluster.
	if errs != nil {
		log.Error(errs, "failed to list PolicyBindings for ProtectedResource change")
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, 0)
	for _, pb := range policyBindings.Items {
		// A PolicyBinding should be re-evaluated if its TargetRef APIGroup and Kind
		// match the ServiceRef.Name and Kind of the changed ProtectedResource.
		if pb.Spec.TargetRef.APIGroup == protectedResource.Spec.ServiceRef.Name &&
			pb.Spec.TargetRef.Kind == protectedResource.Spec.Kind {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      pb.Name,
					Namespace: pb.Namespace,
				},
			})
			log.V(1).Info("Enqueuing PolicyBinding due to relevant ProtectedResource change",
				"policyBindingName", pb.Name, "policyBindingNamespace", pb.Namespace)
		}
	}

	// Additionally, if a ProtectedResource is deleted, all PolicyBindings that might have
	// referred to types it defined should be reconciled.
	// The above loop already covers this, as a deletion is a change.

	return requests
}

// enqueuePolicyBindingsForRoleChange is a handler that enqueues PolicyBinding reconcile requests
// when a Role changes. This is because changes to a Role (e.g., its permissions)
// can affect the authorization policy derived from PolicyBindings that reference that Role.
func (r *PolicyBindingReconciler) enqueuePolicyBindingsForRoleChange(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	changedRole, ok := obj.(*iamdatumapiscomv1alpha1.Role)
	if !ok {
		log.Error(fmt.Errorf("unexpected object type in Role handler: %T", obj), "cannot enqueue PolicyBindings for Role change")
		return []reconcile.Request{}
	}

	log.V(1).Info("Role changed, evaluating PolicyBindings for re-enqueue",
		"roleName", changedRole.Name,
		"roleNamespace", changedRole.Namespace)

	policyBindings := &iamdatumapiscomv1alpha1.PolicyBindingList{}
	if err := r.List(ctx, policyBindings); err != nil {
		log.Error(err, "failed to list PolicyBindings for Role change", "roleName", changedRole.Name, "roleNamespace", changedRole.Namespace)
		return []reconcile.Request{}
	}

	requests := make([]reconcile.Request, 0)
	for _, pb := range policyBindings.Items {
		// A PolicyBinding should be re-evaluated if its RoleRef matches the changed Role.
		// The RoleRef in PolicyBindingSpec contains Name and Namespace.
		// An empty RoleRef.Namespace typically refers to a cluster-scoped Role.
		if pb.Spec.RoleRef.Name == changedRole.Name && pb.Spec.RoleRef.Namespace == changedRole.Namespace {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      pb.Name,
					Namespace: pb.Namespace, // This is the PolicyBinding's namespace
				},
			})
			log.V(1).Info("Enqueuing PolicyBinding due to relevant Role change",
				"policyBindingName", pb.Name, "policyBindingNamespace", pb.Namespace,
				"changedRoleName", changedRole.Name, "changedRoleNamespace", changedRole.Namespace)
		}
	}
	return requests
}

// SetupWithManager sets up the controller with the Manager.
// It configures watches for PolicyBinding resources and, if the RESTMapper is available,
// for changes to Service resources, which can affect PolicyBinding validation.
func (r *PolicyBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.RESTMapper == nil {
		r.RESTMapper = mgr.GetRESTMapper()
	}

	// Initialize finalizers
	r.Finalizers = finalizer.NewFinalizers()
	if err := r.Finalizers.Register(policyBindingFinalizerKey, &openFGAFinalizer{
		Client:    r.Client,
		fgaClient: r.FgaClient,
		storeID:   r.StoreID,
	}); err != nil {
		return fmt.Errorf("failed to register policy binding finalizer: %w", err)
	}

	controllerBuilder := ctrl.NewControllerManagedBy(mgr).
		For(&iamdatumapiscomv1alpha1.PolicyBinding{}).
		Named("policybinding")

	// Watch for changes to ProtectedResource CRs and enqueue PolicyBindings that might be affected.
	controllerBuilder.Watches(
		&iamdatumapiscomv1alpha1.ProtectedResource{},
		handler.EnqueueRequestsFromMapFunc(r.enqueuePolicyBindingsForProtectedResourceChange),
	)

	// Watch for changes to Role CRs and enqueue PolicyBindings that might be affected.
	controllerBuilder.Watches(
		&iamdatumapiscomv1alpha1.Role{},
		handler.EnqueueRequestsFromMapFunc(r.enqueuePolicyBindingsForRoleChange),
	)

	return controllerBuilder.Complete(r)
}
