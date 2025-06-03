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
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	groupMembershipFinalizerKey = "iam.miloapis.com/groupmembership"
)

// GroupMembershipReconciler reconciles a GroupMembership object
type GroupMembershipReconciler struct {
	client.Client
	Scheme        *runtime.Scheme
	FgaClient     openfgav1.OpenFGAServiceClient
	StoreID       string
	Finalizers    finalizer.Finalizers
	EventRecorder record.EventRecorder
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

	user := &iammiloapiscomv1alpha1.User{}
	err = r.Get(ctx, client.ObjectKey{
		Name: groupMembership.Spec.UserRef.Name,
	}, user)
	if err != nil {
		return ctrl.Result{}, err
	}

	group := &iammiloapiscomv1alpha1.Group{}
	err = r.Get(ctx, client.ObjectKey{
		Name: groupMembership.Spec.GroupRef.Name,
		Namespace: groupMembership.Spec.GroupRef.Namespace,
	}, group)
	if err != nil {
		return ctrl.Result{}, err
	}

	groupMembershipRequest := openfga.GroupMembershipRequest{
		GroupUid: group.ObjectMeta.UID,
		MemberUid: user.ObjectMeta.UID,
	}

	userGroupReconciler := openfga.UserGroupReconciler{
		StoreID:   r.StoreID,
		Client:    r.FgaClient,
		K8sClient: r.Client,
	}

	// Check if the resource is being deleted
	if !groupMembership.DeletionTimestamp.IsZero() {
		err = userGroupReconciler.RemoveMemberFromGroup(ctx, groupMembershipRequest)
		if err != nil {
			log.Error(err, "Failed to remove group membership")
		}
		 // Remove the finalizer so the resource can be deleted
		 controllerutil.RemoveFinalizer(groupMembership, groupMembershipFinalizerKey)
		 if err := r.Update(ctx, groupMembership); err != nil {
			 return ctrl.Result{}, err
		 }

		log.Info("Successfully removed group membership.")
		return ctrl.Result{}, nil
	}

	// Add finalizer if it doesn't exist
	if !controllerutil.ContainsFinalizer(groupMembership, groupMembershipFinalizerKey) {
		controllerutil.AddFinalizer(groupMembership, groupMembershipFinalizerKey)
		if err := r.Update(ctx, groupMembership); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
	
	// Add the group membership tuple to the OpenFGA store
	err = userGroupReconciler.AddMemberToGroup(ctx, groupMembershipRequest)
	if err != nil {
		log.Error(err, "Failed to reconcile group membership")
		r.EventRecorder.Event(groupMembership, "Warning", "OpenFGAError", fmt.Sprintf("Failed to write group membership tuple: %v", err))
		return ctrl.Result{}, fmt.Errorf("failed to write group membership tuple: %w", err)
	}

	// Update status conditions
	meta.SetStatusCondition(&groupMembership.Status.Conditions, metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionTrue,
		Reason:  "Reconciled",
		Message: "Group membership successfully reconciled",
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
	return ctrl.NewControllerManagedBy(mgr).
		For(&iammiloapiscomv1alpha1.GroupMembership{}).
		Named("groupmembership").
		Complete(r)
}

