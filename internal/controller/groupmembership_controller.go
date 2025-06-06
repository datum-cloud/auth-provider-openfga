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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	groupMembershipFinalizerKey = "iam.miloapis.com/groupmembership"

	ConditionTypeUserRefValid  = "UserRefValid"
	ConditionTypeGroupRefValid = "GroupRefValid"

	userDeletionAnnotation  = "iam.miloapis.com/user-deleted"
	groupDeletionAnnotation = "iam.miloapis.com/group-deleted"

	userRefNameField  = ".spec.userRef.name"
	groupRefNameField = ".spec.groupRef.name"

	trueAsString = "true"
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
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "Failed to get User for finalization")
		return finalizer.Result{}, err
	}
	group := &iammiloapiscomv1alpha1.Group{}
	err = f.K8sClient.Get(ctx, client.ObjectKey{
		Name:      groupMembership.Spec.GroupRef.Name,
		Namespace: groupMembership.Spec.GroupRef.Namespace,
	}, group)
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "Failed to get Group for finalization")
		return finalizer.Result{}, err
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

	// Check if this reconciliation was triggered by user deletion or group deletion
	isUserOrGroupDeleted := false
	var reason string
	if groupMembership.GetAnnotations() != nil {
		if groupMembership.GetAnnotations()[userDeletionAnnotation] == trueAsString {
			isUserOrGroupDeleted = true
			reason = "Reconciling GroupMembership due to user deletion"
		}
		if groupMembership.GetAnnotations()[groupDeletionAnnotation] == trueAsString {
			isUserOrGroupDeleted = true
			reason = "Reconciling GroupMembership due to group deletion"
		}
	}

	if isUserOrGroupDeleted {
		log.Info(reason,
			"user", groupMembership.Spec.UserRef.Name,
			"group", groupMembership.Spec.GroupRef.Name)

		// Set deletion timestamp if not already set to trigger finalization
		if groupMembership.GetDeletionTimestamp() == nil {
			now := metav1.Now()
			groupMembership.DeletionTimestamp = &now
			if err := r.Update(ctx, groupMembership); err != nil {
				log.Error(err, "failed to set deletion timestamp on GroupMembership")
				return ctrl.Result{}, err
			}
			// Requeue to handle the deletion in the next reconciliation
			return ctrl.Result{Requeue: true}, nil
		}
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

// enqueueGroupMembershipsForChange is a generic helper function that handles both User and Group changes
func (r *GroupMembershipReconciler) enqueueGroupMembershipsForChange(ctx context.Context, obj client.Object, resourceType, fieldName, annotationKey string) []reconcile.Request {
	log := logf.FromContext(ctx)

	isObjectBeingDeleted := obj.GetDeletionTimestamp() != nil
	if isObjectBeingDeleted {
		log.Info(fmt.Sprintf("enqueueing GroupMemberships due to %s deletion", resourceType), resourceType, obj.GetName())
	} else {
		log.Info(fmt.Sprintf("skipping GroupMemberships due to %s update, and not being deleted", resourceType), resourceType, obj.GetName())
		return nil
	}

	var groupMemberships iammiloapiscomv1alpha1.GroupMembershipList
	if err := r.List(ctx, &groupMemberships, client.MatchingFields{fieldName: obj.GetName()}); err != nil {
		log.Error(err, fmt.Sprintf("failed to list GroupMemberships for %s", resourceType), resourceType, obj.GetName())
		return nil
	}

	requests := make([]reconcile.Request, 0)
	for _, gm := range groupMemberships.Items {
		if isObjectBeingDeleted {
			if gm.Annotations == nil {
				gm.Annotations = make(map[string]string)
			}
			gm.Annotations[annotationKey] = trueAsString
			if err := r.Update(ctx, &gm); err != nil {
				log.Error(err, fmt.Sprintf("failed to update GroupMembership with %s deletion annotation", resourceType),
					"groupMembership", gm.Name,
					resourceType, obj.GetName())
			}
		}

		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{
				Name:      gm.Name,
				Namespace: gm.Namespace,
			},
		})
	}

	if len(requests) > 0 {
		log.Info("found GroupMemberships to enqueue", "count", len(requests))
	}

	return requests
}

// enqueueGroupMembershipsForUserChange is a helper function that enqueues GroupMemberships for changes to a User
func (r *GroupMembershipReconciler) enqueueGroupMembershipsForUserChange(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	if _, ok := obj.(*iammiloapiscomv1alpha1.User); !ok {
		log.Error(fmt.Errorf("unexpected object type for user watch: %T", obj), "expected User object")
		return nil
	}

	return r.enqueueGroupMembershipsForChange(ctx, obj, "user", userRefNameField, userDeletionAnnotation)
}

// enqueueGroupMembershipsForGroupChange is a helper function that enqueues GroupMemberships for changes to a Group
func (r *GroupMembershipReconciler) enqueueGroupMembershipsForGroupChange(ctx context.Context, obj client.Object) []reconcile.Request {
	log := logf.FromContext(ctx)
	if _, ok := obj.(*iammiloapiscomv1alpha1.Group); !ok {
		log.Error(fmt.Errorf("unexpected object type for group watch: %T", obj), "expected Group object")
		return nil
	}

	return r.enqueueGroupMembershipsForChange(ctx, obj, "group", groupRefNameField, groupDeletionAnnotation)
}

// SetupWithManager sets up the controller with the Manager.
func (r *GroupMembershipReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Index the GroupMembership by user name
	if err := r.indexGroupMembershipField(mgr, userRefNameField,
		func(gm *iammiloapiscomv1alpha1.GroupMembership) string { return gm.Spec.UserRef.Name }); err != nil {
		return fmt.Errorf("failed to index GroupMembership by user name: %w", err)
	}

	// Index the GroupMembership by group name
	if err := r.indexGroupMembershipField(mgr, groupRefNameField,
		func(gm *iammiloapiscomv1alpha1.GroupMembership) string { return gm.Spec.GroupRef.Name }); err != nil {
		return fmt.Errorf("failed to index GroupMembership by group name: %w", err)
	}

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

	controllerBuilder := ctrl.NewControllerManagedBy(mgr).
		For(&iammiloapiscomv1alpha1.GroupMembership{}).
		Named("groupmembership")

	controllerBuilder.Watches(
		&iammiloapiscomv1alpha1.User{},
		handler.EnqueueRequestsFromMapFunc(r.enqueueGroupMembershipsForUserChange),
	)

	controllerBuilder.Watches(
		&iammiloapiscomv1alpha1.Group{},
		handler.EnqueueRequestsFromMapFunc(r.enqueueGroupMembershipsForGroupChange),
	)

	return controllerBuilder.Complete(r)
}

// indexGroupMembershipField is a helper function to index GroupMembership by a specific field
func (r *GroupMembershipReconciler) indexGroupMembershipField(mgr ctrl.Manager, fieldName string, extractField func(*iammiloapiscomv1alpha1.GroupMembership) string) error {
	return mgr.GetFieldIndexer().IndexField(
		context.Background(), &iammiloapiscomv1alpha1.GroupMembership{},
		fieldName,
		func(rawObj client.Object) []string {
			groupMembership := rawObj.(*iammiloapiscomv1alpha1.GroupMembership)
			fieldValue := extractField(groupMembership)
			if fieldValue == "" {
				return nil
			}
			return []string{fieldValue}
		})
}
