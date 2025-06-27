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

type PolicyReconciler struct {
	StoreID   string
	Client    openfgav1.OpenFGAServiceClient
	K8sClient client.Client
}

// ReconcilePolicy will modify an OpenFGA backend to ensure the correct tuples
// exist for the provided IAM policy.
func (r *PolicyReconciler) ReconcilePolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	// Use PolicyBinding UID for the intermediate binding object
	policyBindingObjectIdentifier := "iam.miloapis.com/RoleBinding:" + string(binding.UID)

	// Fetch the Role to get its UID
	roleToFetch := &iamdatumapiscomv1alpha1.Role{}
	roleNamespace := binding.Spec.RoleRef.Namespace
	if roleNamespace == "" {
		// User is required to provide RoleRef.Namespace. If it's empty, it's an error.
		// This check is crucial before any FGA writes.
		return fmt.Errorf("RoleRef.Namespace is required but was not provided for Role '%s' in PolicyBinding '%s/%s'", binding.Spec.RoleRef.Name, binding.Namespace, binding.Name)
	}
	roleNamespacedName := types.NamespacedName{
		Name:      binding.Spec.RoleRef.Name,
		Namespace: roleNamespace,
	}
	if err := r.K8sClient.Get(ctx, roleNamespacedName, roleToFetch); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("role '%s' not found: %w", binding.Spec.RoleRef.Name, err)
		}
		return fmt.Errorf("failed to get role '%s': %w", binding.Spec.RoleRef.Name, err)
	}
	roleUID := roleToFetch.UID

	existingTuples, err := r.getExistingPolicyTuples(ctx, binding, roleUID)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing bindings: %w", err)
	}

	tuples := []*openfgav1.TupleKey{}

	// Get the target object identifier from the resource selector
	targetObject, err := r.getTargetObjectFromResourceSelector(binding.Spec.ResourceSelector)
	if err != nil {
		return fmt.Errorf("failed to get target object from resource selector: %w", err)
	}

	// Only create tuples to bind the role to the resource when we haven't
	// seen this role binding before.
	tuples = append(
		tuples,
		// Associates the resource (e.g. project, folder, organization,
		// etc) to the role binding.
		&openfgav1.TupleKey{
			User:     policyBindingObjectIdentifier, // Use PolicyBinding UID based object
			Relation: "iam.miloapis.com/RoleBinding",
			Object:   targetObject,
		},
		// Associates the role binding to the role that should be bound
		// to the resource.
		&openfgav1.TupleKey{
			User:     "iam.miloapis.com/InternalRole:" + string(roleUID),
			Relation: "iam.miloapis.com/InternalRole",
			Object:   policyBindingObjectIdentifier, // Use PolicyBinding UID based object
		},
	)

	for _, subject := range binding.Spec.Subjects {
		tupleUser, err := getTupleUser(subject)
		if err != nil {
			return fmt.Errorf("failed to get tuple user: %w", err)
		}

		tuples = append(tuples, &openfgav1.TupleKey{
			User:     tupleUser,
			Relation: "iam.miloapis.com/InternalUser",
			Object:   policyBindingObjectIdentifier, // Use PolicyBinding UID based object
		})
	}

	added, removed := diffTuples(existingTuples, tuples)

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
		return fmt.Errorf("failed to write policy tuples: %w", err)
	}

	return nil
}

// getTargetObjectFromResourceSelector extracts the target object identifier from ResourceSelector
func (r *PolicyReconciler) getTargetObjectFromResourceSelector(selector iamdatumapiscomv1alpha1.ResourceSelector) (string, error) {
	if selector.ResourceRef != nil {
		// For specific resource instances: apiGroup/Kind:name
		return fmt.Sprintf("%s/%s:%s", selector.ResourceRef.APIGroup, selector.ResourceRef.Kind, selector.ResourceRef.Name), nil
	}

	if selector.ResourceKind != nil {
		// For all instances of a resource kind: iam.miloapis.com/Root:apiGroup/Kind
		return fmt.Sprintf("iam.miloapis.com/Root:%s/%s", selector.ResourceKind.APIGroup, selector.ResourceKind.Kind), nil
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

// DiffTuples will return a set of Tuples that were added and a set of Tuples
// that have been removed.
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

	// Any of the current tuples that don't exist in the new set of tuples will
	// need to be removed.
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

func (r *PolicyReconciler) getExistingPolicyTuples(ctx context.Context, policy iamdatumapiscomv1alpha1.PolicyBinding, roleUID types.UID) ([]*openfgav1.TupleKey, error) {
	// Use PolicyBinding UID for the intermediate binding object
	policyBindingObjectIdentifier := "iam.miloapis.com/RoleBinding:" + string(policy.UID)

	var allExistingTuples []*openfgav1.TupleKey

	// Get the target object identifier from the resource selector
	targetObject, err := r.getTargetObjectFromResourceSelector(policy.Spec.ResourceSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to get target object from resource selector: %w", err)
	}

	// 1. Get tuples where the binding object is the User (linking binding to target resource)
	tuplesLinkingBindingToResource, err := getTupleKeys(ctx, r.StoreID, r.Client, &openfgav1.ReadRequestTupleKey{
		User:     policyBindingObjectIdentifier,
		Relation: "iam.miloapis.com/RoleBinding",
		Object:   targetObject,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get tuples linking binding to resource: %w", err)
	}
	allExistingTuples = append(allExistingTuples, tuplesLinkingBindingToResource...)

	// 2. Get tuples where the binding object is the Object (linking roles/subjects to binding)
	// This will fetch tuples like:
	//   user: internalRole:ROLE_UID, relation: internalRole, object: policyBindingObjectIdentifier
	//   user: internalUser:SUBJECT_UID, relation: internalUser, object: policyBindingObjectIdentifier

	// Specifically fetch the role linkage tuple
	roleLinkageTuple, err := getTupleKeys(ctx, r.StoreID, r.Client, &openfgav1.ReadRequestTupleKey{
		User:     "iam.miloapis.com/InternalRole:" + string(roleUID),
		Relation: "iam.miloapis.com/InternalRole",
		Object:   policyBindingObjectIdentifier,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get role linkage tuple: %w", err)
	}
	allExistingTuples = append(allExistingTuples, roleLinkageTuple...)

	// Fetch subject linkage tuples
	for _, subject := range policy.Spec.Subjects {
		tupleUser, err := getTupleUser(subject)
		if err != nil {
			return nil, fmt.Errorf("failed to get tuple user: %w", err)
		}

		subjectLinkageTuple, err := getTupleKeys(ctx, r.StoreID, r.Client, &openfgav1.ReadRequestTupleKey{
			User:     tupleUser,
			Relation: "iam.miloapis.com/InternalUser",
			Object:   policyBindingObjectIdentifier,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get subject linkage tuple for %s: %w", subject.UID, err)
		}
		allExistingTuples = append(allExistingTuples, subjectLinkageTuple...)
	}

	return allExistingTuples, nil
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

// DeletePolicy will remove OpenFGA tuples associated with the provided PolicyBinding.
// This is typically called during finalization of the PolicyBinding custom resource.
func (r *PolicyReconciler) DeletePolicy(ctx context.Context, binding iamdatumapiscomv1alpha1.PolicyBinding) error {
	log := logf.FromContext(ctx)

	// Fetch the Role to get its UID
	roleToFetch := &iamdatumapiscomv1alpha1.Role{}
	roleNamespace := binding.Spec.RoleRef.Namespace
	if roleNamespace == "" {
		return fmt.Errorf("RoleRef.Namespace is required but was not provided for Role '%s' in PolicyBinding '%s/%s'", binding.Spec.RoleRef.Name, binding.Namespace, binding.Name)
	}
	roleNamespacedName := types.NamespacedName{
		Name:      binding.Spec.RoleRef.Name,
		Namespace: roleNamespace,
	}
	if err := r.K8sClient.Get(ctx, roleNamespacedName, roleToFetch); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("Role not found during deletion, skipping tuple cleanup", "role", binding.Spec.RoleRef.Name)
			return nil
		}
		return fmt.Errorf("failed to get role '%s': %w", binding.Spec.RoleRef.Name, err)
	}
	roleUID := roleToFetch.UID

	existingTuples, err := r.getExistingPolicyTuples(ctx, binding, roleUID)
	if err != nil {
		return fmt.Errorf("failed to retrieve existing tuples for deletion: %w", err)
	}

	if len(existingTuples) == 0 {
		log.Info("No existing tuples found for PolicyBinding, nothing to delete", "binding", binding.Name)
		return nil
	}

	writeReq := &openfgav1.WriteRequest{
		StoreId: r.StoreID,
		Deletes: &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(existingTuples),
		},
	}

	_, err = r.Client.Write(ctx, writeReq)
	if err != nil {
		return fmt.Errorf("failed to delete policy tuples: %w", err)
	}

	log.Info("Successfully deleted tuples for PolicyBinding", "binding", binding.Name, "tupleCount", len(existingTuples))
	return nil
}

func getTupleUser(subject iamdatumapiscomv1alpha1.Subject) (string, error) {
	switch subject.Kind {
	case "User":
		if subject.UID == "" {
			return "", fmt.Errorf("user subject must have a UID")
		}
		return "iam.miloapis.com/InternalUser:" + subject.Name, nil
	case "Group":
		// System groups (names starting with "system:") don't require UID and use the group name directly
		if strings.HasPrefix(subject.Name, "system:") {
			// Replace colons with underscores to avoid OpenFGA tuple parsing issues
			escapedName := strings.ReplaceAll(subject.Name, ":", "_")
			return "iam.miloapis.com/InternalUserGroup:" + escapedName + "#assignee", nil
		}
		// Regular groups require UID
		if subject.UID == "" {
			return "", fmt.Errorf("group subject must have a UID")
		}
		return "iam.miloapis.com/InternalUserGroup:" + subject.UID + "#assignee", nil
	default:
		return "", fmt.Errorf("unsupported subject kind: %s", subject.Kind)
	}
}
