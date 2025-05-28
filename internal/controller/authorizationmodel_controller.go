// Package controller implements Kubernetes controller-runtime controllers for managing
// Datum IAM resources and their interaction with OpenFGA.
package controller

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	iamdatumapiscomv1alpha1 "go.datum.net/datum/pkg/apis/iam.datumapis.com/v1alpha1"
	"go.datum.net/iam/openfga/internal/openfga"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// protectedResourceFinalizerKey is the finalizer key added to ProtectedResource
	// custom resources. This finalizer ensures that associated OpenFGA model
	// configurations are cleaned up before the ProtectedResource is deleted from Kubernetes.
	protectedResourceFinalizerKey = "iam.datumapis.com/protectedresource"
)

// ProtectedResourceFinalizer ensures that when a ProtectedResource custom resource is deleted,
// the corresponding OpenFGA authorization model is appropriately updated to reflect the removal.
// It implements the controller-runtime finalizer.Finalizer interface.
type ProtectedResourceFinalizer struct {
	client.Client
	modelBuilder *openfga.AuthorizationModelReconciler
}

// Finalize contains the logic to execute when a ProtectedResource is pending deletion.
// Its primary responsibility is to ensure the OpenFGA authorization model is reconciled
// by rebuilding it based on all other active (non-deleted) ProtectedResource instances.
// This prevents orphaned configurations in the OpenFGA store.
func (f *ProtectedResourceFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx)
	pr, ok := obj.(*iamdatumapiscomv1alpha1.ProtectedResource)
	if !ok {
		return finalizer.Result{}, fmt.Errorf("unexpected object type %T, expected ProtectedResource", obj)
	}

	log.Info("Finalizing ProtectedResource, triggering OpenFGA model rebuild", "protectedResourceName", pr.Name)

	var currentPRs iamdatumapiscomv1alpha1.ProtectedResourceList
	if err := f.Client.List(ctx, &currentPRs); err != nil {
		log.Error(err, "Failed to list ProtectedResources during finalization")
		return finalizer.Result{}, fmt.Errorf("failed to list ProtectedResources during finalization: %w", err)
	}

	var activePRs []iamdatumapiscomv1alpha1.ProtectedResource
	for _, item := range currentPRs.Items {
		if item.UID != pr.UID {
			activePRs = append(activePRs, item)
		}
	}
	log.Info("Rebuilding FGA model with remaining ProtectedResources", "count", len(activePRs))

	if err := f.modelBuilder.ReconcileAuthorizationModel(ctx, activePRs); err != nil {
		log.Error(err, "Failed to reconcile authorization model during ProtectedResource finalization")
		return finalizer.Result{}, fmt.Errorf("failed to reconcile FGA model during finalization: %w", err)
	}

	log.Info("Successfully triggered model rebuild during ProtectedResource finalization.", "protectedResourceName", pr.Name)
	return finalizer.Result{}, nil
}

// AuthorizationModelReconciler manages the lifecycle of the IAM authorization model.
// It watches for changes to ProtectedResource custom resources and triggers updates to the
// OpenFGA store to ensure the authorization model reflects the state defined by these resources.
type AuthorizationModelReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	FGAClient    openfgav1.OpenFGAServiceClient
	FGAStoreID   string
	modelBuilder *openfga.AuthorizationModelReconciler
	Finalizers   finalizer.Finalizers
}

//+kubebuilder:rbac:groups=iam.datumapis.com,resources=protectedresources,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=iam.datumapis.com,resources=protectedresources/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=iam.datumapis.com,resources=protectedresources/finalizers,verbs=update

// Reconcile is the core reconciliation loop for the AuthorizationModelReconciler.
// It is invoked when changes are detected in ProtectedResource custom resources or when a requeue is requested.
// The method orchestrates fetching the resource, handling its deletion, ensuring finalizers,
// or reconciling its active state with the OpenFGA model.
func (r *AuthorizationModelReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("controller", "AuthorizationModelReconciler", "trigger", req.NamespacedName)
	log.Info("Reconciling IAM Authorization Model due to ProtectedResource change")

	var triggeringPR iamdatumapiscomv1alpha1.ProtectedResource
	if err := r.Get(ctx, req.NamespacedName, &triggeringPR); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Triggering ProtectedResource not found. Assuming it was deleted.", "protectedResourceName", req.NamespacedName)
			return ctrl.Result{}, nil
		}
		log.Error(err, "failed to get triggering ProtectedResource", "protectedResourceName", req.NamespacedName)
		return ctrl.Result{}, err
	}

	if triggeringPR.GetDeletionTimestamp() != nil {
		return r.handleDeletion(ctx, &triggeringPR)
	}

	if !controllerutil.ContainsFinalizer(&triggeringPR, protectedResourceFinalizerKey) {
		return r.ensureFinalizer(ctx, &triggeringPR)
	}

	return r.reconcileProtectedResource(ctx, &triggeringPR)
}

// handleDeletion manages the process for a ProtectedResource that is marked for deletion.
// It ensures that the associated finalizer logic is executed to clean up external dependencies
// (like updating the OpenFGA model) before the resource is fully removed from the system.
func (r *AuthorizationModelReconciler) handleDeletion(ctx context.Context, pr *iamdatumapiscomv1alpha1.ProtectedResource) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("protectedResourceName", pr.Name, "operation", "handleDeletion")

	// Check if our specific finalizer is present. If not, its deletion logic is complete for this reconciler.
	if !controllerutil.ContainsFinalizer(pr, protectedResourceFinalizerKey) {
		log.Info("ProtectedResource marked for deletion but our finalizer is not present or already processed.", "finalizerKey", protectedResourceFinalizerKey)
		return ctrl.Result{}, nil
	}

	log.Info("ProtectedResource is marked for deletion and our finalizer is present, performing finalization logic.", "finalizerKey", protectedResourceFinalizerKey)

	// The finalizer.Finalizers.Finalize method orchestrates the execution of all registered finalizers.
	// For our protectedResourceFinalizerKey, it will call the Finalize method of the ProtectedResourceFinalizer.
	// If ProtectedResourceFinalizer.Finalize returns a nil error, the orchestrator removes
	// the protectedResourceFinalizerKey from the resource's list of finalizers in memory.
	// The finalizerResult.Updated field will then be true, indicating the resource object was modified.
	finalizerResult, err := r.Finalizers.Finalize(ctx, pr)
	if err != nil {
		// This error indicates a failure within the finalization logic of one of the finalizers (e.g., our ProtectedResourceFinalizer).
		log.Error(err, "Finalization process failed for ProtectedResource")
		_ = r.updateTriggeringPRStatus(ctx, pr, false, "FinalizationFailed", fmt.Sprintf("Finalization process failed: %s", err.Error()))
		// Requeue is necessary because the finalization logic encountered an error and needs to be retried.
		return ctrl.Result{}, fmt.Errorf("failed to run finalizers for ProtectedResource: %w", err)
	}

	// If finalizerResult.Updated is true, the pr object in memory has been modified (e.g., our finalizer was removed).
	// This change must be persisted to the Kubernetes API server.
	if finalizerResult.Updated {
		if err := r.Update(ctx, pr); err != nil {
			_ = r.updateTriggeringPRStatus(ctx, pr, false, "FinalizationUpdateFailed", fmt.Sprintf("Failed to update after finalizer: %s", err.Error()))
			// Requeue is necessary because persisting the removal of the finalizer (or other changes made by finalizers) failed.
			return ctrl.Result{}, err
		}
	}

	log.Info("Finalizer removed from ProtectedResource", "name", pr.Name, "finalizerKey", protectedResourceFinalizerKey)
	return ctrl.Result{}, nil
}

// ensureFinalizer checks if the ProtectedResource has the required finalizer.
// If the finalizer is not present, it adds it and updates the resource. This is crucial
// to ensure that cleanup logic (defined in handleDeletion) is executed before the resource
// is physically deleted by the Kubernetes API server.
func (r *AuthorizationModelReconciler) ensureFinalizer(ctx context.Context, pr *iamdatumapiscomv1alpha1.ProtectedResource) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("protectedResourceName", pr.Name, "operation", "ensureFinalizer")
	log.Info("Adding Finalizer for the ProtectedResource")

	controllerutil.AddFinalizer(pr, protectedResourceFinalizerKey)
	if err := r.Update(ctx, pr); err != nil {
		log.Error(err, "Failed to update ProtectedResource after adding finalizer")
		_ = r.updateTriggeringPRStatus(ctx, pr, false, "FinalizerError", "Failed to add finalizer")
		return ctrl.Result{}, err
	}
	log.Info("Finalizer added to ProtectedResource, requeueing.")
	return ctrl.Result{Requeue: true}, nil
}

// reconcileProtectedResource performs the main reconciliation for a ProtectedResource that is not being deleted.
// It gathers all current ProtectedResource instances to build a complete view of the desired authorization state
// and then triggers the ModelBuilder to apply this state to the OpenFGA store.
func (r *AuthorizationModelReconciler) reconcileProtectedResource(ctx context.Context, triggeringPR *iamdatumapiscomv1alpha1.ProtectedResource) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("protectedResourceName", triggeringPR.Name, "operation", "reconcileProtectedResource")
	log.Info("Proceeding with regular reconciliation")

	var prList iamdatumapiscomv1alpha1.ProtectedResourceList
	if err := r.List(ctx, &prList); err != nil {
		log.Error(err, "failed to list ProtectedResources for IAM model reconciliation")
		_ = r.updateTriggeringPRStatus(ctx, triggeringPR, false, "ListResourcesFailed", fmt.Sprintf("Failed to list ProtectedResources: %s", err.Error()))
		return ctrl.Result{}, err
	}

	modelReconciliationErr := r.modelBuilder.ReconcileAuthorizationModel(ctx, prList.Items)
	if modelReconciliationErr != nil {
		log.Error(modelReconciliationErr, "failed to reconcile IAM authorization model")
		_ = r.updateTriggeringPRStatus(ctx, triggeringPR, false, "IAMModelReconciliationFailed", modelReconciliationErr.Error())
		return ctrl.Result{}, modelReconciliationErr
	}

	log.Info("Successfully reconciled IAM authorization model.")
	statusUpdateErr := r.updateTriggeringPRStatus(ctx, triggeringPR, true, "IAMSystemConfigured", "ProtectedResource is part of a successfully configured IAM system.")
	if statusUpdateErr != nil {
		return ctrl.Result{}, statusUpdateErr
	}
	log.Info("Triggering ProtectedResource status updated.")

	return ctrl.Result{}, nil
}

// updateTriggeringPRStatus updates the status subresource of a given ProtectedResource.
// This is used to reflect the outcome of reconciliation attempts, providing visibility
// into whether the resource is correctly configured within the IAM system. It sets the
// ObservedGeneration to match the reconciled generation and updates the Ready condition.
func (r *AuthorizationModelReconciler) updateTriggeringPRStatus(
	ctx context.Context,
	pr *iamdatumapiscomv1alpha1.ProtectedResource,
	isSuccess bool,
	reasonForCondition string,
	messageForCondition string,
) error {
	log := logf.FromContext(ctx).WithValues("protectedResourceNameForStatusUpdate", pr.Name, "targetSuccess", isSuccess, "reason", reasonForCondition)

	prCopy := pr.DeepCopy()
	prCopy.Status.ObservedGeneration = pr.Generation

	conditionStatus := metav1.ConditionFalse
	if isSuccess {
		conditionStatus = metav1.ConditionTrue
	}

	meta.SetStatusCondition(&prCopy.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             conditionStatus,
		Reason:             reasonForCondition,
		Message:            messageForCondition,
		LastTransitionTime: metav1.Now(),
	})

	if err := r.Status().Update(ctx, prCopy); err != nil {
		log.Error(err, "Failed to update ProtectedResource status")
		return err
	}
	log.Info("Successfully updated ProtectedResource status.")
	return nil
}

// SetupWithManager configures the AuthorizationModelReconciler with the provided controller manager.
// This involves setting up watches for ProtectedResource custom resources, initializing the
// OpenFGA model builder if necessary, and registering the finalizer implementation.
func (r *AuthorizationModelReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.FGAClient == nil {
		return fmt.Errorf("FGAClient is not set on AuthorizationModelReconciler")
	}
	if r.FGAStoreID == "" {
		return fmt.Errorf("FGAStoreID is not set on AuthorizationModelReconciler")
	}

	// Always initialize ModelBuilder internally using the FGAClient and FGAStoreID.
	// This component is responsible for interacting with OpenFGA to reconcile the authorization model.
	r.modelBuilder = &openfga.AuthorizationModelReconciler{
		StoreID: r.FGAStoreID,
		OpenFGA: r.FGAClient,
	}

	// Initialize the finalizer manager and register our custom ProtectedResourceFinalizer.
	// This finalizer is responsible for cleaning up OpenFGA configurations when a ProtectedResource is deleted.
	r.Finalizers = finalizer.NewFinalizers()
	if err := r.Finalizers.Register(protectedResourceFinalizerKey, &ProtectedResourceFinalizer{
		Client:       r.Client,
		modelBuilder: r.modelBuilder,
	}); err != nil {
		return fmt.Errorf("failed to register protected resource finalizer: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&iamdatumapiscomv1alpha1.ProtectedResource{}).
		Named("authorizationmodel_controller").
		Complete(r)
}
