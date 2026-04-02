package controller

import (
	"context"
	"fmt"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	systemGroupFinalizerKey = "iam.miloapis.com/system-group-membership"

	// systemAuthenticatedGroup is the internal group name (post-escape) for
	// system:authenticated. All User resources receive this membership so that
	// authorization checks against InternalUserGroup:system_authenticated resolve
	// correctly via OpenFGA's stored-tuple cache path.
	systemAuthenticatedGroup = "system_authenticated"
)

// SystemGroupReconciler watches User resources and ensures each user has the
// system:authenticated group membership tuple written to OpenFGA. This moves
// tuple writes out of the authorization webhook hot path so that the stored
// tuples are eligible for OpenFGA's check query cache.
type SystemGroupReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	FGAClient  openfgav1.OpenFGAServiceClient
	FGAStoreID string
}

// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users;machineaccounts,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=iam.miloapis.com,resources=users/finalizers;machineaccounts/finalizers,verbs=update

// Reconcile is a no-op as the manager uses resource-specific entry points below.
func (r *SystemGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the reconciler with the Manager. It registers TWO
// separate controllers sharing the same reconciler logic: one for human Users
// and another for cluster-scoped MachineAccounts.
func (r *SystemGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// 1. Controller for human Users (cluster-scoped)
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&iamv1alpha1.User{}).
		Named("systemgroup_user").
		Complete(reconcile.Func(r.reconcileUser)); err != nil {
		return fmt.Errorf("failed to register user systemgroup reconciler: %w", err)
	}

	// 2. Controller for machine accounts (cluster-scoped)
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&iamv1alpha1.MachineAccount{}).
		Named("systemgroup_machineaccount").
		Complete(reconcile.Func(r.reconcileMachineAccount)); err != nil {
		return fmt.Errorf("failed to register machineaccount systemgroup reconciler: %w", err)
	}

	return nil
}

func (r *SystemGroupReconciler) reconcileUser(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	user := &iamv1alpha1.User{}
	if err := r.Get(ctx, req.NamespacedName, user); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	return r.reconcileObject(ctx, user)
}

func (r *SystemGroupReconciler) reconcileMachineAccount(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ma := &iamv1alpha1.MachineAccount{}
	if err := r.Get(ctx, req.NamespacedName, ma); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	return r.reconcileObject(ctx, ma)
}

func (r *SystemGroupReconciler) reconcileObject(ctx context.Context, obj client.Object) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if obj.GetDeletionTimestamp() != nil {
		return r.handleDeletion(ctx, obj)
	}

	// Ensure the finalizer is present so we can clean up on deletion.
	if !controllerutil.ContainsFinalizer(obj, systemGroupFinalizerKey) {
		controllerutil.AddFinalizer(obj, systemGroupFinalizerKey)
		if err := r.Update(ctx, obj); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to add finalizer to %s %s: %w", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetName(), err)
		}
		// Re-queue so we proceed with the write after the update is persisted.
		return ctrl.Result{Requeue: true}, nil
	}

	if err := r.writeSystemGroupTuple(ctx, obj); err != nil {
		log.Error(err, "failed to write system group membership tuple", "name", obj.GetName())
		return ctrl.Result{}, err
	}

	log.Info("reconciled system group memberships", "name", obj.GetName())
	return ctrl.Result{}, nil
}

// handleDeletion removes the system group membership tuple and strips the
// finalizer so the object can be garbage-collected.
func (r *SystemGroupReconciler) handleDeletion(ctx context.Context, obj client.Object) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(obj, systemGroupFinalizerKey) {
		return ctrl.Result{}, nil
	}

	if err := r.deleteSystemGroupTuple(ctx, obj); err != nil {
		log.Error(err, "failed to delete system group membership tuple during finalization", "name", obj.GetName())
		return ctrl.Result{}, err
	}

	controllerutil.RemoveFinalizer(obj, systemGroupFinalizerKey)
	if err := r.Update(ctx, obj); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to remove finalizer from %s %s: %w", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetName(), err)
	}

	log.Info("removed system group memberships on deletion", "name", obj.GetName())
	return ctrl.Result{}, nil
}

// writeSystemGroupTuple writes the system:authenticated membership tuple for
// the given principal. OpenFGA gRPC code 2017 ("already exists") is treated as
// idempotent success.
func (r *SystemGroupReconciler) writeSystemGroupTuple(ctx context.Context, obj client.Object) error {
	log := logf.FromContext(ctx)

	tupleKey := r.systemGroupTupleKey(obj)

	_, err := r.FGAClient.Write(ctx, &openfgav1.WriteRequest{
		StoreId: r.FGAStoreID,
		Writes: &openfgav1.WriteRequestWrites{
			TupleKeys: []*openfgav1.TupleKey{tupleKey},
		},
	})
	if err != nil {
		if isAlreadyExistsErr(err) {
			log.V(1).Info("system group membership tuple already exists in OpenFGA", "name", obj.GetName())
			return nil
		}
		return fmt.Errorf("failed to write system group membership tuple for %s: %w", obj.GetName(), err)
	}

	log.V(1).Info("wrote system group membership tuple", "name", obj.GetName())
	return nil
}

// deleteSystemGroupTuple deletes the system:authenticated membership tuple for
// the given principal. A "not found" response from OpenFGA is treated as success.
func (r *SystemGroupReconciler) deleteSystemGroupTuple(ctx context.Context, obj client.Object) error {
	log := logf.FromContext(ctx)

	tupleKey := r.systemGroupTupleKey(obj)

	_, err := r.FGAClient.Write(ctx, &openfgav1.WriteRequest{
		StoreId: r.FGAStoreID,
		Deletes: &openfgav1.WriteRequestDeletes{
			TupleKeys: []*openfgav1.TupleKeyWithoutCondition{
				{
					User:     tupleKey.User,
					Relation: tupleKey.Relation,
					Object:   tupleKey.Object,
				},
			},
		},
	})
	if err != nil {
		if isTupleNotFoundErr(err) {
			log.V(1).Info("system group membership tuple already absent from OpenFGA", "name", obj.GetName())
			return nil
		}
		return fmt.Errorf("failed to delete system group membership tuple for %s: %w", obj.GetName(), err)
	}

	return nil
}

// systemGroupTupleKey builds the OpenFGA tuple key that represents membership
// of principal in the system:authenticated InternalUserGroup. For a User, the
// resource Name is used as the identity token. For a MachineAccount, the
// Kubernetes UID is used instead.
func (r *SystemGroupReconciler) systemGroupTupleKey(obj client.Object) *openfgav1.TupleKey {
	identityToken := obj.GetName()
	if _, isMA := obj.(*iamv1alpha1.MachineAccount); isMA {
		identityToken = string(obj.GetUID())
	}

	return &openfgav1.TupleKey{
		User:     fmt.Sprintf("iam.miloapis.com/InternalUser:%s", identityToken),
		Relation: "member",
		Object:   fmt.Sprintf("iam.miloapis.com/InternalUserGroup:%s", systemAuthenticatedGroup),
	}
}

// isAlreadyExistsErr reports whether the gRPC error indicates that the tuple
// already exists in OpenFGA (code 2017).
func isAlreadyExistsErr(err error) bool {
	if st, ok := status.FromError(err); ok {
		// OpenFGA uses gRPC application error code 2017 for "already exists".
		return st.Code() == 2017
	}
	// Fallback: check the error message for robustness across SDK versions.
	return strings.Contains(err.Error(), "already exists")
}

// isTupleNotFoundErr reports whether the gRPC error indicates that the tuple
// was not found in OpenFGA (code 2018).
func isTupleNotFoundErr(err error) bool {
	if st, ok := status.FromError(err); ok {
		// OpenFGA uses gRPC application error code 2018 for tuple not found.
		return st.Code() == 2018
	}
	return strings.Contains(err.Error(), "not found")
}
