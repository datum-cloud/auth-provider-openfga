package openfga

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/protobuf/types/known/wrapperspb"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// PolicyReconciler writes and removes permission tuples in OpenFGA.
//
// Tuples are written as one tuple per (subject × permission) pair directly
// on the target resource object.
type PolicyReconciler struct {
	StoreID   string
	Client    openfgav1.OpenFGAServiceClient
	K8sClient client.Client
}

// ReconcilePolicy ensures the correct tuples for a
// PolicyBinding are present in the OpenFGA store.
func (r *PolicyReconciler) ReconcilePolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	if err := r.reconcilePolicy(ctx, binding); err != nil {
		return fmt.Errorf("reconciliation failed: %w", err)
	}
	return nil
}

// DeletePolicy removes all tuples that were written for a
// PolicyBinding.
func (r *PolicyReconciler) DeletePolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	log := logf.FromContext(ctx)

	targetObject, err := r.getTargetObjectFromResourceSelector(binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to get target object from resource selector: %w", err)
	}

	directTuples, err := r.getExistingTuples(ctx, binding, targetObject)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing direct tuples for deletion: %w", err)
	}

	if len(directTuples) == 0 {
		log.Info("No existing tuples found for PolicyBinding, nothing to delete", "binding", binding.Name)
		return nil
	}

	_, err = r.Client.Write(ctx, &openfgav1.WriteRequest{
		StoreId: r.StoreID,
		Deletes: &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(directTuples),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete policy tuples: %w", err)
	}

	log.Info("Successfully deleted tuples for PolicyBinding", "binding", binding.Name, "tupleCount", len(directTuples))
	return nil
}

// ---------------------------------------------------

// reconcilePolicy computes the full desired tuple set for all
// PolicyBindings that share the same (subject, targetObject) pair as the
// triggering binding, then diffs against the existing tuples in OpenFGA.
//
// This full-set approach prevents one binding from clobbering tuples written
// by sibling bindings. For example, if two bindings both grant the staff-users
// group permissions on Root:Organization, the desired set is the union of both
// bindings' permissions, and the diff only removes tuples that no binding wants.
func (r *PolicyReconciler) reconcilePolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	targetObject, err := r.getTargetObjectFromResourceSelector(binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to get target object from resource selector: %w", err)
	}

	validPerms, err := r.getHierarchicalPermissionsForSelector(ctx, binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to compute hierarchical permissions: %w", err)
	}

	// Find all sibling PolicyBindings that share the same target object and
	// have at least one overlapping subject. The union of their desired tuples
	// is the complete desired state for these subjects on this object.
	siblings, err := r.findSiblingBindings(ctx, binding)
	if err != nil {
		return fmt.Errorf("failed to find sibling bindings: %w", err)
	}

	// Build the union of desired tuples across all sibling bindings.
	var allDesired []*openfgav1.TupleKey
	for i := range siblings {
		role, err := r.fetchRole(ctx, siblings[i])
		if err != nil {
			// Skip bindings with missing roles — they'll be handled by
			// their own reconciliation which will set Ready=False.
			continue
		}
		tuples, err := r.buildPermissionTuples(siblings[i], role, targetObject, validPerms)
		if err != nil {
			continue
		}
		allDesired = append(allDesired, tuples...)
	}

	// Deduplicate: multiple bindings may grant the same permission.
	allDesired = deduplicateTuples(allDesired)

	existingTuples, err := r.getExistingTuples(ctx, binding, targetObject)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing tuples: %w", err)
	}

	added, removed := diffTuples(existingTuples, allDesired)

	writeReq := &openfgav1.WriteRequest{
		StoreId: r.StoreID,
	}

	if len(added) > 0 {
		writeReq.Writes = &openfgav1.WriteRequestWrites{
			TupleKeys: added,
		}
	}

	if len(removed) > 0 {
		writeReq.Deletes = &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(removed),
		}
	}

	if writeReq.Deletes == nil && writeReq.Writes == nil {
		return nil
	}

	_, err = r.Client.Write(ctx, writeReq)
	if err != nil {
		return fmt.Errorf("failed to write permission tuples: %w", err)
	}

	return nil
}

// findSiblingBindings returns all PolicyBindings (including the triggering one)
// that target the same resource object and share at least one subject.
func (r *PolicyReconciler) findSiblingBindings(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) ([]iamdatumapiscomv1alpha1.PolicyBinding, error) {
	var allBindings iamdatumapiscomv1alpha1.PolicyBindingList
	if err := r.K8sClient.List(ctx, &allBindings); err != nil {
		return nil, fmt.Errorf("failed to list PolicyBindings: %w", err)
	}

	targetObject, err := r.getTargetObjectFromResourceSelector(binding.Spec.ResourceSelector)
	if err != nil {
		return nil, err
	}

	// Build subject set for the triggering binding.
	triggerSubjects := make(map[string]struct{})
	for _, s := range binding.Spec.Subjects {
		key := s.Kind + "/" + s.Name
		triggerSubjects[key] = struct{}{}
	}

	var siblings []iamdatumapiscomv1alpha1.PolicyBinding
	for i := range allBindings.Items {
		sibling := allBindings.Items[i]

		// Must target the same resource object.
		siblingTarget, err := r.getTargetObjectFromResourceSelector(sibling.Spec.ResourceSelector)
		if err != nil || siblingTarget != targetObject {
			continue
		}

		// Must share at least one subject.
		for _, s := range sibling.Spec.Subjects {
			key := s.Kind + "/" + s.Name
			if _, ok := triggerSubjects[key]; ok {
				siblings = append(siblings, sibling)
				break
			}
		}
	}

	return siblings, nil
}

// deduplicateTuples removes duplicate tuples from a slice.
func deduplicateTuples(tuples []*openfgav1.TupleKey) []*openfgav1.TupleKey {
	seen := make(map[string]struct{}, len(tuples))
	result := make([]*openfgav1.TupleKey, 0, len(tuples))
	for _, t := range tuples {
		key := t.User + "|" + t.Relation + "|" + t.Object
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, t)
		}
	}
	return result
}

// fetchRole retrieves the Role referenced by the binding.
func (r *PolicyReconciler) fetchRole(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) (*iamdatumapiscomv1alpha1.Role, error) {
	roleNamespace := binding.Spec.RoleRef.Namespace
	if roleNamespace == "" {
		return nil, fmt.Errorf("RoleRef.Namespace is required but was not provided for Role '%s' in PolicyBinding '%s/%s'", binding.Spec.RoleRef.Name, binding.Namespace, binding.Name)
	}

	role := &iamdatumapiscomv1alpha1.Role{}
	if err := r.K8sClient.Get(ctx, types.NamespacedName{
		Name:      binding.Spec.RoleRef.Name,
		Namespace: roleNamespace,
	}, role); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("role '%s' not found: %w", binding.Spec.RoleRef.Name, err)
		}
		return nil, fmt.Errorf("failed to get role '%s': %w", binding.Spec.RoleRef.Name, err)
	}

	return role, nil
}

// buildPermissionTuples expands the Role's effective permissions into one
// OpenFGA tuple per (subject, permission) pair targeting the given object.
//
// Effective permissions are the fully-resolved set of permissions including
// those inherited through InheritedRoles. They are pre-computed by the role
// controller and stored in Status.EffectivePermissions.
//
// For a Role with effective permissions [get, list] on organizations and
// subjects [alice], this produces:
//
//	(InternalUser:alice,  hash(svc/organizations.get),  apiGroup/Organization:org-1)
//	(InternalUser:alice,  hash(svc/organizations.list), apiGroup/Organization:org-1)
func (r *PolicyReconciler) buildPermissionTuples(
	binding iamdatumapiscomv1alpha1.PolicyBinding,
	role *iamdatumapiscomv1alpha1.Role,
	targetObject string,
	validPerms map[string]struct{},
) ([]*openfgav1.TupleKey, error) {
	effectivePerms := role.Status.EffectivePermissions
	if len(effectivePerms) == 0 {
		// Fall back to spec-level permissions if the role controller hasn't
		// computed effective permissions yet.
		effectivePerms = role.Spec.IncludedPermissions
	}

	var tuples []*openfgav1.TupleKey

	for _, subject := range binding.Spec.Subjects {
		tupleUser, err := getTupleUser(subject)
		if err != nil {
			return nil, fmt.Errorf("failed to get tuple user for subject %s: %w", subject.Name, err)
		}

		for _, permName := range effectivePerms {
			// Skip permissions not valid for the target resource type.
			// validPerms contains the hierarchical permission set: the
			// target resource's own permissions plus all descendant
			// resource permissions.
			if len(validPerms) > 0 {
				if _, ok := validPerms[permName]; !ok {
					continue
				}
			}
			hashedPerm := hashPermission(permName)
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     tupleUser,
				Relation: hashedPerm,
				Object:   targetObject,
			})
		}
	}

	return tuples, nil
}

// getHierarchicalPermissionsForSelector computes the full set of permissions
// valid on a target resource type, including permissions inherited from child
// resources in the hierarchy. This mirrors calculateHierarchicalPermissions
// used by the authorization model builder.
func (r *PolicyReconciler) getHierarchicalPermissionsForSelector(ctx context.Context, selector iamdatumapiscomv1alpha1.ResourceSelector) (map[string]struct{}, error) {
	var apiGroup, kind string
	switch {
	case selector.ResourceRef != nil:
		apiGroup = selector.ResourceRef.APIGroup
		kind = selector.ResourceRef.Kind
	case selector.ResourceKind != nil:
		apiGroup = selector.ResourceKind.APIGroup
		kind = selector.ResourceKind.Kind
	default:
		return nil, fmt.Errorf("resourceSelector must specify either resourceRef or resourceKind")
	}

	var prList iamdatumapiscomv1alpha1.ProtectedResourceList
	if err := r.K8sClient.List(ctx, &prList); err != nil {
		return nil, fmt.Errorf("failed to list ProtectedResources: %w", err)
	}

	// Build the resource graph and compute hierarchical permissions, reusing
	// the same logic as the authorization model builder.
	resourceGraph, err := getResourceGraph(prList.Items)
	if err != nil {
		return nil, fmt.Errorf("failed to build resource graph: %w", err)
	}
	hierarchicalPermissions := calculateHierarchicalPermissions(resourceGraph)

	// Find the target resource type in the graph.
	targetResourceType := apiGroup + "/" + kind
	perms, ok := hierarchicalPermissions[targetResourceType]
	if !ok {
		// If the resource type is not in the graph, it might be a
		// Root-scoped resource. Return all permissions across all types.
		allPerms := make(map[string]struct{})
		for _, typePerms := range hierarchicalPermissions {
			for _, p := range typePerms {
				allPerms[p] = struct{}{}
			}
		}
		return allPerms, nil
	}

	permSet := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		permSet[p] = struct{}{}
	}
	return permSet, nil
}

// getExistingTuples reads all tuples owned by this
// PolicyBinding. Because tuples are indexed by subject user
// and target object we query for each subject individually.
func (r *PolicyReconciler) getExistingTuples(
	ctx context.Context,
	binding iamdatumapiscomv1alpha1.PolicyBinding,
	targetObject string,
) ([]*openfgav1.TupleKey, error) {
	var all []*openfgav1.TupleKey

	for _, subject := range binding.Spec.Subjects {
		tupleUser, err := getTupleUser(subject)
		if err != nil {
			return nil, fmt.Errorf("failed to get tuple user for subject %s: %w", subject.Name, err)
		}

		// Read all tuples for (user, *, targetObject) — the relation wildcard
		// returns every permission tuple for this subject on this resource.
		existing, err := getTupleKeys(ctx, r.StoreID, r.Client, &openfgav1.ReadRequestTupleKey{
			User:   tupleUser,
			Object: targetObject,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get existing tuples for subject %s: %w", subject.Name, err)
		}
		all = append(all, existing...)
	}

	return all, nil
}

// --- shared helpers -----------------------------------------------------------

// getTargetObjectFromResourceSelector extracts the target object identifier from ResourceSelector
func (r *PolicyReconciler) getTargetObjectFromResourceSelector(selector iamdatumapiscomv1alpha1.ResourceSelector) (string, error) {
	if selector.ResourceRef != nil {
		// For specific resource instances: apiGroup/Kind:name
		return fmt.Sprintf("%s/%s:%s", selector.ResourceRef.APIGroup, selector.ResourceRef.Kind, selector.ResourceRef.Name), nil
	}

	if selector.ResourceKind != nil {
		// For all instances of a resource kind the permission model
		// targets the kind-level root object in the same format as a specific
		// instance but using the TypeRoot prefix.
		return fmt.Sprintf("%s:%s/%s", TypeRoot, selector.ResourceKind.APIGroup, selector.ResourceKind.Kind), nil
	}

	return "", fmt.Errorf("resourceSelector must specify either resourceRef or resourceKind")
}

func convertTuplesForDelete(tuples []*openfgav1.TupleKey) []*openfgav1.TupleKeyWithoutCondition {
	newTuples := make([]*openfgav1.TupleKeyWithoutCondition, len(tuples))
	for i, tuple := range tuples {
		newTuples[i] = &openfgav1.TupleKeyWithoutCondition{
			User:     tuple.User,
			Relation: tuple.Relation,
			Object:   tuple.Object,
		}
	}
	return newTuples
}

// diffTuples returns the tuples that need to be added and removed.
func diffTuples(existing, current []*openfgav1.TupleKey) (added, removed []*openfgav1.TupleKey) {
	// Any of the current tuples that don't exist in the new set of tuples will
	// need to be removed.
	for _, existingTuple := range existing {
		found := false
		for _, currentTuple := range current {
			if cmp.Equal(existingTuple, currentTuple, cmpopts.IgnoreUnexported(openfgav1.TupleKey{})) {
				found = true
				break
			}
		}
		if !found {
			removed = append(removed, existingTuple)
		}
	}

	for _, currentTuple := range current {
		found := false
		for _, existingTuple := range existing {
			if cmp.Equal(currentTuple, existingTuple, cmpopts.IgnoreUnexported(openfgav1.TupleKey{})) {
				found = true
				break
			}
		}
		if !found {
			added = append(added, currentTuple)
		}
	}
	return added, removed
}

func getTupleKeys(ctx context.Context, storeID string, client openfgav1.OpenFGAServiceClient, tuple *openfgav1.ReadRequestTupleKey) ([]*openfgav1.TupleKey, error) {
	tupleKeys := []*openfgav1.TupleKey{}
	continuationToken := ""
	for {
		resp, err := client.Read(ctx, &openfgav1.ReadRequest{
			StoreId:           storeID,
			ContinuationToken: continuationToken,
			PageSize:          wrapperspb.Int32(100),
			TupleKey:          tuple,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to read existing tuples: %w", err)
		}

		for _, t := range resp.Tuples {
			tupleKeys = append(tupleKeys, t.GetKey())
		}

		continuationToken = resp.ContinuationToken
		if resp.ContinuationToken == "" {
			break
		}
	}

	return tupleKeys, nil
}

// getTupleUser returns the OpenFGA user string for a subject under the
// permission model. Group members are referenced via the #member
// relation (InternalUserGroup:<uid>#member).
func getTupleUser(subject iamdatumapiscomv1alpha1.Subject) (string, error) {
	switch subject.Kind {
	case "User":
		if subject.UID == "" {
			return "", fmt.Errorf("user subject must have a UID")
		}
		// Use the subject name as the OpenFGA user identifier. The user.Name is
		// the Kubernetes resource name, which matches the uid field passed in
		// SubjectAccessReview requests (the system uses names as identity
		// tokens, not the K8s metadata UID).
		return TypeInternalUser + ":" + subject.Name, nil
	case "Group":
		// System groups (names starting with "system:") don't require UID and use the group name directly
		if strings.HasPrefix(subject.Name, "system:") {
			// Replace colons with underscores to avoid OpenFGA tuple parsing issues
			escapedName := strings.ReplaceAll(subject.Name, ":", "_")
			return TypeInternalUserGroup + ":" + escapedName + "#member", nil
		}
		// Regular groups require UID
		if subject.UID == "" {
			return "", fmt.Errorf("group subject must have a UID")
		}
		return TypeInternalUserGroup + ":" + subject.UID + "#member", nil
	default:
		return "", fmt.Errorf("unsupported subject kind: %s", subject.Kind)
	}
}
