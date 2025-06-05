package controller

import (
	"context"
	"fmt"
	"sync"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/finalizer"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
)

const (
	resourceOwnerHierarchyFinalizer = "resourceownerhierarchy.iam.miloapis.com/finalizer"
	DefaultAPIVersion               = "v1alpha1"
	RelationName                    = "parent"
	DefaultOpenFGAStoreID           = "default_store_id"
)

// ResourceOwnerHierarchyReconciler reconciles Project objects to establish parent/child relationships in OpenFGA.
type ResourceOwnerHierarchyReconciler struct {
	client.Client
	Scheme               *runtime.Scheme
	FGAClient            openfgav1.OpenFGAServiceClient
	FGAStoreID           string
	EventRecorder        record.EventRecorder
	Mgr                  ctrl.Manager
	AuthzModelReconciler *openfga.AuthorizationModelReconciler
	Finalizers           finalizer.Finalizers

	// mu protects access to ... (if any shared state remains, not for watchedGVKs anymore)
	mu sync.RWMutex
	// Hardcoded valid parent GVKs for a Project.
	// Example: Allow Organization to be a parent of Project.
	validProjectParentGVKs map[schema.GroupVersionKind]struct{}
}

// +kubebuilder:rbac:groups=resourcemanager.miloapis.com,resources=projects,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=resourcemanager.miloapis.com,resources=projects/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=resourcemanager.miloapis.com,resources=projects/finalizers,verbs=update
// Potentially add RBAC for assumed parent types like iam.miloapis.com/organizations if we check their existence (though ownerRef itself doesn't require it)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ResourceOwnerHierarchyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	project := &resourcemanagerv1alpha1.Project{}
	if err := r.Get(ctx, req.NamespacedName, project); err != nil {
		logger = logger.WithValues("resourceownerhierarchy", req.NamespacedName)
		if errors.IsNotFound(err) {
			logger.V(1).Info("Project resource not found. Ignoring since object must be deleted.")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get Project, will retry")
		return ctrl.Result{}, err
	}

	logger = logger.WithValues("resourceownerhierarchy", req.NamespacedName)

	gvk, _, err := r.Client.Scheme().ObjectKinds(project)
	if err != nil || len(gvk) == 0 {
		logger.Error(err, "failed to get GVK for Project", "projectKey", req.String())
		return ctrl.Result{}, fmt.Errorf("failed to get GVK for project %s: %w", req, err)
	}

	logger = logger.WithValues("project", project.Name, "namespace", project.Namespace, "gvk", gvk[0].String())
	logger.Info("Reconciling Project")
	return r.reconcileProject(ctx, project, gvk[0])
}

// --- Project Reconciliation Logic (Parent-Child Hierarchy Sync) ---

func (r *ResourceOwnerHierarchyReconciler) reconcileProject(ctx context.Context, project *resourcemanagerv1alpha1.Project, gvk schema.GroupVersionKind) (ctrl.Result, error) {
	// serviceNameForChildResource is derived from the Project's GVK group.
	// This assumes the FGA type for a project is like "resourcemanager.miloapis.com/Project"
	serviceNameForChildResource := gvk.Group

	// validParentGVKsForChild is now taken from the reconciler's hardcoded map.
	r.mu.RLock()
	validParentGVKs := r.validProjectParentGVKs
	r.mu.RUnlock()

	if !project.GetDeletionTimestamp().IsZero() {
		return r.handleProjectDeletion(ctx, project)
	}

	requeueNeeded, err := r.ensureProjectFinalizer(ctx, project)
	if err != nil {
		return ctrl.Result{}, err
	}
	if requeueNeeded {
		return ctrl.Result{Requeue: true}, nil
	}

	return r.synchronizeFGAHierarchy(ctx, project, gvk, serviceNameForChildResource, validParentGVKs)
}

func (r *ResourceOwnerHierarchyReconciler) handleProjectDeletion(ctx context.Context, project *resourcemanagerv1alpha1.Project) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("project", project.Name, "gvk", project.GetObjectKind().GroupVersionKind().String(), "namespace", project.Namespace)
	logger.Info("Project is being deleted, processing finalizers")

	finalizerResult, err := r.Finalizers.Finalize(ctx, project)
	if err != nil {
		logger.Error(err, "Failed to finalize Project")
		return ctrl.Result{}, err
	}

	if finalizerResult.Updated {
		logger.Info("Project updated by finalizer, updating object")
		if err := r.Update(ctx, project); err != nil {
			logger.Error(err, "Failed to update Project after finalizer operation")
			return ctrl.Result{}, err
		}
	}

	if controllerutil.ContainsFinalizer(project, resourceOwnerHierarchyFinalizer) {
		logger.Info("Finalizer still present on Project, requeueing for finalization.")
		return ctrl.Result{Requeue: true}, nil
	}

	logger.Info("Finalization complete for Project")
	return ctrl.Result{}, nil
}

func (r *ResourceOwnerHierarchyReconciler) ensureProjectFinalizer(ctx context.Context, project *resourcemanagerv1alpha1.Project) (requeueNeeded bool, err error) {
	logger := log.FromContext(ctx).WithValues("project", project.Name, "gvk", project.GetObjectKind().GroupVersionKind().String(), "namespace", project.Namespace)
	if !controllerutil.ContainsFinalizer(project, resourceOwnerHierarchyFinalizer) {
		logger.Info("Adding finalizer to Project")
		controllerutil.AddFinalizer(project, resourceOwnerHierarchyFinalizer)
		if err := r.Update(ctx, project); err != nil {
			logger.Error(err, "Failed to add finalizer to Project")
			return false, err
		}
		logger.Info("Finalizer added to Project")
		return true, nil
	}
	return false, nil
}

func (r *ResourceOwnerHierarchyReconciler) synchronizeFGAHierarchy(ctx context.Context, resource client.Object, gvk schema.GroupVersionKind, serviceNameForChildResource string, validParentGVKsForChild map[schema.GroupVersionKind]struct{}) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("resource", resource.GetName(), "gvk", gvk.String(), "namespace", resource.GetNamespace())

	childFGAObjectStr := buildChildFGAIdentifierForResource(resource, gvk, serviceNameForChildResource)
	desiredParentTuples := r.determineDesiredParentTuplesForResource(resource, validParentGVKsForChild, childFGAObjectStr, RelationName)

	existingFGAParentTupleKeys, err := fetchOpenFGATuples(ctx, r.FGAClient, r.FGAStoreID, &openfgav1.ReadRequestTupleKey{Object: childFGAObjectStr, Relation: RelationName})
	if err != nil {
		return ctrl.Result{}, err
	}

	tuplesToWrite, tuplesToDelete := computeTupleDifferences(desiredParentTuples, existingFGAParentTupleKeys)

	if len(tuplesToDelete) > 0 || len(tuplesToWrite) > 0 {
		if err := applyOpenFGATupleChanges(ctx, r.FGAClient, r.FGAStoreID, tuplesToWrite, tuplesToDelete); err != nil {
			logger.Error(err, "Failed to write/delete tuples in OpenFGA")
			return ctrl.Result{}, err
		}
		logger.Info("Successfully synchronized parent tuples with OpenFGA")
	} else {
		logger.V(1).Info("No changes to parent tuples in OpenFGA needed")
	}

	return ctrl.Result{}, nil
}

// --- OpenFGA Interaction Helpers ---

func buildChildFGAIdentifierForResource(resource client.Object, gvk schema.GroupVersionKind, serviceNameForResource string) string {
	childFGAType := fmt.Sprintf("%s/%s", serviceNameForResource, gvk.Kind)
	childFGAID := string(resource.GetUID())
	return fmt.Sprintf("%s:%s", childFGAType, childFGAID)
}

func (r *ResourceOwnerHierarchyReconciler) determineDesiredParentTuplesForResource(resource client.Object, validParentGVKsForChild map[schema.GroupVersionKind]struct{}, childFGAObjectStr string, relationName string) map[string]*openfgav1.TupleKey {
	logger := log.FromContext(context.TODO()) // Use context.TODO() if real context isn't easily available here, or pass ctx
	desiredParentTuples := make(map[string]*openfgav1.TupleKey)
	accessor, err := apimeta.Accessor(resource)
	if err != nil {
		logger.Error(err, "Failed to get metav1.Object accessor for resource", "resource", resource.GetName())
		return desiredParentTuples
	}
	ownerRefs := accessor.GetOwnerReferences()

	logger.V(1).Info("Determining desired parent tuples",
		"resourceName", resource.GetName(),
		"resourceUID", string(resource.GetUID()),
		"resourceNamespace", resource.GetNamespace(),
		"ownerReferencesCount", len(ownerRefs),
		"validParentGVKsConfigured", fmt.Sprintf("%v", validParentGVKsForChild))

	for i, ownerRef := range ownerRefs {
		ownerGVK := schema.FromAPIVersionAndKind(ownerRef.APIVersion, ownerRef.Kind)
		logger.V(1).Info("Processing ownerReference",
			"index", i,
			"ownerName", ownerRef.Name,
			"ownerUID", string(ownerRef.UID),
			"ownerKind", ownerRef.Kind,
			"ownerAPIVersion", ownerRef.APIVersion,
			"ownerGVK", ownerGVK.String())

		allowed := false
		if len(validParentGVKsForChild) == 0 {
			logger.V(1).Info("No specific parent GVKs configured, so no ownerReferences will be processed into FGA tuples by default.")
			allowed = false
		} else {
			_, allowed = validParentGVKsForChild[ownerGVK]
		}

		if allowed {
			logger.V(1).Info("OwnerReference matched a valid parent GVK", "ownerGVK", ownerGVK.String())
			parentServiceName := ownerGVK.Group
			parentFGAType := fmt.Sprintf("%s/%s", parentServiceName, ownerGVK.Kind)
			parentFGAID := string(ownerRef.UID)

			userStr := fmt.Sprintf("%s:%s", parentFGAType, parentFGAID)
			tuple := &openfgav1.TupleKey{
				User:     userStr,
				Relation: relationName,
				Object:   childFGAObjectStr,
			}
			desiredParentTuples[userStr] = tuple
		} else {
			logger.V(1).Info("OwnerReference did NOT match any valid parent GVK", "ownerGVK", ownerGVK.String())
		}
	}

	if len(desiredParentTuples) == 0 {
		logger.V(1).Info("No desired parent tuples were generated for this resource.", "resourceName", resource.GetName(), "resourceUID", string(resource.GetUID()))
	} else {
		logger.V(1).Info("Generated desired parent tuples.", "resourceName", resource.GetName(), "resourceUID", string(resource.GetUID()), "count", len(desiredParentTuples))
	}
	return desiredParentTuples
}

func fetchOpenFGATuples(ctx context.Context, fgaClient openfgav1.OpenFGAServiceClient, storeID string, tupleKey *openfgav1.ReadRequestTupleKey) ([]*openfgav1.TupleKey, error) {
	logger := log.FromContext(ctx)
	var existingTuples []*openfgav1.TupleKey
	continuationToken := ""

	for {
		readReq := &openfgav1.ReadRequest{
			StoreId:           storeID,
			TupleKey:          tupleKey,
			ContinuationToken: continuationToken,
		}

		readResp, err := fgaClient.Read(ctx, readReq)
		if err != nil {
			s, ok := status.FromError(err)
			if ok && s.Code() == codes.NotFound {
				logger.V(1).Info("No existing tuples found in OpenFGA for the given key.", "tupleKey", tupleKey)
				return existingTuples, nil
			} else if ok {
				logger.Error(err, "Failed to read existing tuples from OpenFGA", "grpc_code", s.Code().String(), "tupleKey", tupleKey)
				return nil, err
			} else {
				logger.Error(err, "Failed to read existing tuples from OpenFGA (non-grpc error)", "tupleKey", tupleKey)
				return nil, err
			}
		}

		if readResp != nil {
			for _, t := range readResp.GetTuples() {
				existingTuples = append(existingTuples, t.GetKey())
			}
		}

		continuationToken = readResp.GetContinuationToken()
		if continuationToken == "" {
			break
		}
	}
	return existingTuples, nil
}

func computeTupleDifferences(desiredParentTuples map[string]*openfgav1.TupleKey, existingFGAParentTupleKeys []*openfgav1.TupleKey) (writes []*openfgav1.TupleKey, deletes []*openfgav1.TupleKeyWithoutCondition) {
	existingParentUsers := make(map[string]*openfgav1.TupleKey)
	for _, tk := range existingFGAParentTupleKeys {
		existingParentUsers[tk.User] = tk
	}

	for userStr, desiredTuple := range desiredParentTuples {
		if _, existsInFGA := existingParentUsers[userStr]; !existsInFGA {
			writes = append(writes, desiredTuple)
		}
	}

	for userStr, existingTuple := range existingParentUsers {
		if _, isDesired := desiredParentTuples[userStr]; !isDesired {
			deletes = append(deletes, &openfgav1.TupleKeyWithoutCondition{
				User: existingTuple.User, Relation: existingTuple.Relation, Object: existingTuple.Object,
			})
		}
	}
	return writes, deletes
}

func applyOpenFGATupleChanges(ctx context.Context, fgaClient openfgav1.OpenFGAServiceClient, storeID string, writes []*openfgav1.TupleKey, deletes []*openfgav1.TupleKeyWithoutCondition) error {
	logger := log.FromContext(ctx)
	if len(deletes) == 0 && len(writes) == 0 {
		return nil
	}

	writeReq := &openfgav1.WriteRequest{
		StoreId: storeID,
	}

	if len(deletes) > 0 {
		writeReq.Deletes = &openfgav1.WriteRequestDeletes{TupleKeys: deletes}
		logger.Info("Deleting stale parent relationship tuples from OpenFGA", "count", len(deletes))
	}
	if len(writes) > 0 {
		writeReq.Writes = &openfgav1.WriteRequestWrites{TupleKeys: writes}
		logger.Info("Writing new parent relationship tuples to OpenFGA", "count", len(writes))
	}

	_, err := fgaClient.Write(ctx, writeReq)
	if err != nil {
		return err
	}
	return nil
}

// --- OpenFGA Finalization Logic ---

type ResourceOwnerHierarchyFinalizerLogic struct {
	client.Client
	FGAClient  openfgav1.OpenFGAServiceClient
	FGAStoreID string
}

func (f *ResourceOwnerHierarchyFinalizerLogic) Finalize(ctx context.Context, obj client.Object) (finalizer.Result, error) {
	logger := log.FromContext(ctx).WithValues("finalizer", "ResourceOwnerHierarchyFinalizerLogic")

	gvk := obj.GetObjectKind().GroupVersionKind()
	if gvk.Kind == "" || gvk.Group == "" {
		u, isUnstructured := obj.(*metav1.PartialObjectMetadata) // Check if it's at least PartialObjectMetadata
		if isUnstructured && u != nil {
			gvk = u.GroupVersionKind()
		} else {
			gvks, _, schemeErr := f.Client.Scheme().ObjectKinds(obj)
			if schemeErr == nil && len(gvks) > 0 {
				gvk = gvks[0]
			} else {
				logger.Error(schemeErr, "Finalizer: Could not determine GVK for object being finalized", "objectName", obj.GetName(), "objectNamespace", obj.GetNamespace())
				if gvk.Group == "" {
					finalizerErr := fmt.Errorf("finalizer: GVK group is empty for object %s/%s, cannot determine FGA service name for type %T", obj.GetNamespace(), obj.GetName(), obj)
					logger.Error(finalizerErr, "Critical GVK info missing for finalization")
					return finalizer.Result{}, finalizerErr
				}
			}
		}
	}

	serviceNameForResource := gvk.Group

	logger = logger.WithValues("cleanup", obj.GetName(), "gvk", gvk.String())
	logger.Info("Cleaning up OpenFGA relationships for deleted resource via finalizer")

	childFGAObjectStr := buildChildFGAIdentifierForResource(obj, gvk, serviceNameForResource)

	existingParentTuples, err := fetchOpenFGATuples(ctx, f.FGAClient, f.FGAStoreID, &openfgav1.ReadRequestTupleKey{Object: childFGAObjectStr, Relation: RelationName})
	if err != nil {
		s, statusOk := status.FromError(err)
		if statusOk && s.Code() == codes.NotFound {
			logger.Info("No parent tuples found in FGA for cleanup. Finalizing.")
			controllerutil.RemoveFinalizer(obj, resourceOwnerHierarchyFinalizer)
			return finalizer.Result{Updated: true}, nil
		}
		logger.Error(err, "Failed to read parent tuples from OpenFGA for cleanup during finalization")
		return finalizer.Result{}, err
	}

	tuplesToDelete := make([]*openfgav1.TupleKeyWithoutCondition, 0, len(existingParentTuples))
	for _, tk := range existingParentTuples {
		tuplesToDelete = append(tuplesToDelete, &openfgav1.TupleKeyWithoutCondition{
			User:     tk.User,
			Relation: tk.Relation,
			Object:   tk.Object,
		})
	}

	if len(tuplesToDelete) > 0 {
		logger.Info("Deleting parent relationship tuples from OpenFGA via finalizer", "count", len(tuplesToDelete))
		if err := applyOpenFGATupleChanges(ctx, f.FGAClient, f.FGAStoreID, nil, tuplesToDelete); err != nil {
			logger.Error(err, "Failed to delete tuples from OpenFGA during finalizer cleanup")
			return finalizer.Result{}, err
		}
		logger.Info("Successfully deleted parent tuples from OpenFGA during finalizer cleanup")
	} else {
		logger.Info("No parent tuples to delete from FGA during finalizer cleanup.")
	}

	logger.Info("Further cleanup of relationships where this resource was a parent might be needed (model dependent). This finalizer only cleans direct parent links.")

	controllerutil.RemoveFinalizer(obj, resourceOwnerHierarchyFinalizer)
	return finalizer.Result{Updated: true}, nil
}

// --- Controller Setup & Utilities ---

func (r *ResourceOwnerHierarchyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Mgr = mgr
	if r.FGAStoreID == "" {
		r.FGAStoreID = DefaultOpenFGAStoreID
		log.Log.Info("FGAStoreID not explicitly set, using default.", "storeID", r.FGAStoreID)
	}

	// Initialize hardcoded valid parent GVKs for Projects.
	// Project is owned by an Organization from the resourcemanager API group.
	r.validProjectParentGVKs = make(map[schema.GroupVersionKind]struct{})
	r.validProjectParentGVKs[schema.GroupVersionKind{
		Group:   resourcemanagerv1alpha1.GroupVersion.Group,
		Version: resourcemanagerv1alpha1.GroupVersion.Version,
		Kind:    "Organization",
	}] = struct{}{}

	r.Finalizers = finalizer.NewFinalizers()
	if err := r.Finalizers.Register(resourceOwnerHierarchyFinalizer, &ResourceOwnerHierarchyFinalizerLogic{
		Client:     r.Client,
		FGAClient:  r.FGAClient,
		FGAStoreID: r.FGAStoreID,
	}); err != nil {
		return fmt.Errorf("failed to register finalizer: %w", err)
	}

	// AuthzModelReconciler might be removed or simplified if FGA model is now static
	// or only needs to ensure types for Project and its hardcoded parents exist.
	if r.FGAClient == nil && r.AuthzModelReconciler != nil { // check AuthzModelReconciler only if it's used
		return fmt.Errorf("FGAClient is not initialized")
	}
	if r.AuthzModelReconciler != nil {
		r.AuthzModelReconciler.OpenFGA = r.FGAClient
		r.AuthzModelReconciler.StoreID = r.FGAStoreID
	}

	projectPredicate := predicate.Funcs{
		CreateFunc: func(_ event.CreateEvent) bool {
			// Always reconcile Project creates for now, ownerRef check is done in reconcileProject
			log.Log.V(2).Info("Predicate: Allowing CreateEvent for Project")
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			objOld := e.ObjectOld
			objNew := e.ObjectNew
			if objOld == nil || objNew == nil {
				log.Log.Error(nil, "Predicate: UpdateEvent with nil objects")
				return false
			}
			if objNew.GetGeneration() != objOld.GetGeneration() ||
				!equalOwnerReferences(objNew.GetOwnerReferences(), objOld.GetOwnerReferences()) ||
				!equalFinalizers(objNew.GetFinalizers(), objOld.GetFinalizers()) ||
				(objNew.GetDeletionTimestamp() != nil && objOld.GetDeletionTimestamp() == nil) ||
				(objNew.GetDeletionTimestamp() == nil && objOld.GetDeletionTimestamp() != nil) {
				log.Log.V(2).Info("Predicate: Allowing UpdateEvent for Project due to spec/metadata/deletion change")
				return true
			}
			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			obj := e.Object
			if obj == nil {
				log.Log.Error(nil, "Predicate: DeleteEvent with nil object")
				return false
			}
			if controllerutil.ContainsFinalizer(obj, resourceOwnerHierarchyFinalizer) || e.DeleteStateUnknown {
				log.Log.V(2).Info("Predicate: Allowing DeleteEvent for Project", "finalizerPresent", controllerutil.ContainsFinalizer(obj, resourceOwnerHierarchyFinalizer), "deleteStateUnknown", e.DeleteStateUnknown)
				return true
			}
			return false // Only reconcile deletes if our finalizer is present or state is unknown
		},
		GenericFunc: func(_ event.GenericEvent) bool {
			log.Log.V(2).Info("Predicate: Allowing GenericEvent for Project")
			return true // Reconcile all generic events for now
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		Named("resourceownerhierarchy-controller").
		For(&resourcemanagerv1alpha1.Project{}, builder.WithPredicates(projectPredicate)).
		Complete(r)
}

func equalFinalizers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	mapA := make(map[string]struct{}, len(a))
	for _, x := range a {
		mapA[x] = struct{}{}
	}
	for _, x := range b {
		if _, found := mapA[x]; !found {
			return false
		}
	}
	return true
}

func equalOwnerReferences(a, b []metav1.OwnerReference) bool {
	if len(a) != len(b) {
		return false
	}

	aMap := make(map[types.UID]metav1.OwnerReference, len(a))
	for _, ref := range a {
		aMap[ref.UID] = ref
	}

	for _, refB := range b {
		refA, found := aMap[refB.UID]
		if !found {
			return false
		}
		if refA.APIVersion != refB.APIVersion || refA.Kind != refB.Kind || refA.Name != refB.Name {
			return false
		}
	}
	return true
}
