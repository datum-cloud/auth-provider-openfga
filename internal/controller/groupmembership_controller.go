package controller

import (
	"context"
	"fmt"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	iammiloapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	groupMembershipFinalizerKey = "iam.miloapis.com/groupmembership"

	ConditionTypeUserRefValid  = "UserRefValid"
	ConditionTypeGroupRefValid = "GroupRefValid"
)

// GroupMembershipReconciler reconciles a GroupMembership object
type GroupMembershipReconciler struct {
	client.Client
	Scheme              *runtime.Scheme
	FgaClient           openfgav1.OpenFGAServiceClient
	StoreID             string
	Finalizers          finalizer.Finalizers
	EventRecorder       record.EventRecorder
	UserGroupReconciler *openfga.UserGroupReconciler
}

// UserGroupFinalizer implements the finalizer.Finalizer interface for GroupMembership cleanup.
// This is used to remove the group membership tuple from the OpenFGA store when the GroupMembership is deleted.
type UserGroupFinalizer struct {
	K8sClient           client.Client
	UserGroupReconciler *openfga.UserGroupReconciler
}

func (f *UserGroupFinalizer) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	log := logf.FromContext(ctx)
	groupMembership, ok := obj.(*iammiloapiscomv1alpha1.GroupMembership)
	if !ok {
		return finalizer.Result{}, fmt.Errorf("unexpected object type %T, expected GroupMembership", obj)
	}

	// Fetch the referenced User and Group to get their UIDs
	user := &iammiloapiscomv1alpha1.User{}
	err := f.K8sClient.Get(ctx, client.ObjectKey{
		Name: groupMembership.Spec.UserRef.Name,
	}, user)
	if err != nil {
		log.Error(err, "Failed to get User for finalization")
		return finalizer.Result{}, nil // Don't block deletion if user is gone
	}
	group := &iammiloapiscomv1alpha1.Group{}
	err = f.K8sClient.Get(ctx, client.ObjectKey{
		Name:      groupMembership.Spec.GroupRef.Name,
		Namespace: groupMembership.Spec.GroupRef.Namespace,
	}, group)
	if err != nil {
		log.Error(err, "Failed to get Group for finalization")
		return finalizer.Result{}, nil // Don't block deletion if group is gone
	}

	groupMembershipRequest := openfga.GroupMembershipRequest{
		GroupUID:  group.UID,
		MemberUID: user.UID,
	}

	log.Info("Removing group membership during finalization", "groupRef", group.UID, "userRef", user.UID)

	// Remove the group membership tuple from the OpenFGA store
	err = f.UserGroupReconciler.RemoveMemberFromGroup(ctx, groupMembershipRequest)
	if err != nil {
		log.Error(err, "Failed to remove group membership during finalization")
		return finalizer.Result{}, err
	}

	log.Info("Successfully finalized GroupMembership (removed from OpenFGA)")
	return finalizer.Result{}, nil
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=groupmemberships,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=groupmemberships/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=groupmemberships/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the GroupMembership object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *GroupMembershipReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.Info("Reconciling GroupMembership")

	groupMembership := &iammiloapiscomv1alpha1.GroupMembership{}
	err := r.Get(ctx, req.NamespacedName, groupMembership)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("GroupMembership resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get GroupMembership")
		return ctrl.Result{}, err
	}

	finalizeResult, err := r.Finalizers.Finalize(ctx, groupMembership)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to run finalizers for GroupMembership: %w", err)
	}

	if finalizeResult.Updated {
		log.Info("finalizer updated the group membership object, updating API server")
		if updateErr := r.Update(ctx, groupMembership); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if groupMembership.GetDeletionTimestamp() != nil {
		log.Info("GroupMembership is marked for deletion, stopping reconciliation")
		return ctrl.Result{}, nil
	}

	isUserRefValid := true
	// Validate UserRef
	user := &iammiloapiscomv1alpha1.User{}
	err = r.Get(ctx, client.ObjectKey{
		Name: groupMembership.Spec.UserRef.Name,
	}, user)
	if err != nil {
		if errors.IsNotFound(err) {
			meta.SetStatusCondition(&groupMembership.Status.Conditions, metav1.Condition{
				Type:               ConditionTypeUserRefValid,
				Status:             metav1.ConditionFalse,
				Reason:             ReasonValidationFailed,
				Message:            fmt.Sprintf("UserRef not found: %v", err),
				LastTransitionTime: metav1.Now(),
			})
			isUserRefValid = false
		} else {
			log.Error(err, "Failed to get User for GroupMembership")
			return ctrl.Result{}, err
		}
	} else {
		meta.SetStatusCondition(&groupMembership.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeUserRefValid,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonValidationSuccessful,
			Message:            "UserRef is valid.",
			LastTransitionTime: metav1.Now(),
		})
	}

	isGroupRefValid := true
	// Validate GroupRef
	group := &iammiloapiscomv1alpha1.Group{}
	err = r.Get(ctx, client.ObjectKey{
		Name:      groupMembership.Spec.GroupRef.Name,
		Namespace: groupMembership.Spec.GroupRef.Namespace,
	}, group)
	if err != nil {
		if errors.IsNotFound(err) {
			meta.SetStatusCondition(&groupMembership.Status.Conditions, metav1.Condition{
				Type:               ConditionTypeGroupRefValid,
				Status:             metav1.ConditionFalse,
				Reason:             ReasonValidationFailed,
				Message:            fmt.Sprintf("GroupRef not found: %v", err),
				LastTransitionTime: metav1.Now(),
			})
			isGroupRefValid = false
		} else {
			log.Error(err, "Failed to get Group for GroupMembership")
			return ctrl.Result{}, err
		}
	} else {
		meta.SetStatusCondition(&groupMembership.Status.Conditions, metav1.Condition{
			Type:               ConditionTypeGroupRefValid,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonValidationSuccessful,
			Message:            "GroupRef is valid.",
			LastTransitionTime: metav1.Now(),
		})
	}

	// Set Ready condition after both validations
	if !isUserRefValid || !isGroupRefValid {
		log.Info("GroupMembership conditions are not valid. Skipping reconciliation.", "userRefValid", isUserRefValid, "groupRefValid", isGroupRefValid)

		meta.SetStatusCondition(&groupMembership.Status.Conditions, metav1.Condition{
			Type:               "Ready",
			Status:             metav1.ConditionFalse,
			Reason:             "ReferenceInvalid",
			Message:            fmt.Sprintf("User and/or Group reference are invalid. See %s and %s conditions for details.", ConditionTypeUserRefValid, ConditionTypeGroupRefValid),
			LastTransitionTime: metav1.Now(),
		})
		err = r.Status().Update(ctx, groupMembership)
		if err != nil {
			log.Error(err, "Failed to update GroupMembership status")
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}
	log.Info("GroupMembership conditions are valid. Proceeding with reconciliation.", "userRefValid", isUserRefValid, "groupRefValid", isGroupRefValid)

	groupMembershipRequest := openfga.GroupMembershipRequest{
		GroupUID:  group.UID,
		MemberUID: user.UID,
	}

	userGroupReconciler := r.UserGroupReconciler

	// Add the group membership tuple to the OpenFGA store
	err = userGroupReconciler.AddMemberToGroup(ctx, groupMembershipRequest)
	if err != nil {
		log.Error(err, "Failed to reconcile group membership")
		r.EventRecorder.Event(groupMembership, "Warning", "OpenFGAError", fmt.Sprintf("Failed to write group membership tuple: %v", err))
		return ctrl.Result{}, fmt.Errorf("failed to write group membership tuple: %w", err)
	}

	// Update status conditions
	meta.SetStatusCondition(&groupMembership.Status.Conditions, metav1.Condition{
		Type:               "Ready",
		Status:             metav1.ConditionTrue,
		Reason:             "Reconciled",
		Message:            "Group membership successfully reconciled",
		LastTransitionTime: metav1.Now(),
	})

	if err := r.Status().Update(ctx, groupMembership); err != nil {
		log.Error(err, "Failed to update GroupMembership status")
		return ctrl.Result{}, err
	}

	log.Info("Successfully reconciled GroupMembership")
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GroupMembershipReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.UserGroupReconciler = &openfga.UserGroupReconciler{
		StoreID:   r.StoreID,
		Client:    r.FgaClient,
		K8sClient: r.Client,
	}

	r.Finalizers = finalizer.NewFinalizers()
	if err := r.Finalizers.Register(groupMembershipFinalizerKey, &UserGroupFinalizer{
		K8sClient:           r.Client,
		UserGroupReconciler: r.UserGroupReconciler,
	}); err != nil {
		return fmt.Errorf("failed to register group membership finalizer: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&iammiloapiscomv1alpha1.GroupMembership{}).
		Named("groupmembership").
		Complete(r)
}
