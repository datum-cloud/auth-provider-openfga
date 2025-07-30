package openfga

import (
	"context"
	"fmt"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
)

type RoleReconciler struct {
	StoreID      string
	OpenFGA      openfgav1.OpenFGAServiceClient
	ControlPlane client.Client
}

func (r *RoleReconciler) getAllPermissions(ctx context.Context, role *iamdatumapiscomv1alpha1.Role, visited map[string]struct{}) ([]string, error) {
	if visited == nil {
		visited = make(map[string]struct{})
	}

	roleIdentifier := role.Namespace + "/" + role.Name // Ensure uniqueness for visited roles across namespaces
	if _, ok := visited[roleIdentifier]; ok {
		return nil, nil // Prevent cycles
	}
	visited[roleIdentifier] = struct{}{}

	// Use a set to ensure permissions are unique
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

		err := r.ControlPlane.Get(ctx, client.ObjectKey{
			Namespace: namespace,
			Name:      inheritedRoleRef.Name,
		}, inheritedRole)
		if err != nil {
			return nil, fmt.Errorf("failed to get inherited role %s/%s: %w", namespace, inheritedRoleRef.Name, err)
		}

		inheritedPerms, err := r.getAllPermissions(ctx, inheritedRole, visited)
		if err != nil {
			return nil, err
		}

		// Add inherited permissions to the set to ensure uniqueness
		for _, p := range inheritedPerms {
			permissionSet[p] = struct{}{}
		}
	}

	// Convert set back to slice
	permissions := make([]string, 0, len(permissionSet))
	for p := range permissionSet {
		permissions = append(permissions, p)
	}

	return permissions, nil
}

func (r *RoleReconciler) ReconcileRole(ctx context.Context, role *iamdatumapiscomv1alpha1.Role) error {
	// Use Role UID for the object identifier
	roleObjectIdentifier := TypeInternalRole + ":" + string(role.UID)

	existingTupleKeys, err := getTupleKeys(ctx, r.StoreID, r.OpenFGA, &openfgav1.ReadRequestTupleKey{
		Object: roleObjectIdentifier,
	})
	if err != nil {
		return fmt.Errorf("failed to get existing tuples: %w", err)
	}

	allPermissions, err := r.getAllPermissions(ctx, role, nil)
	if err != nil {
		return fmt.Errorf("failed to collect permissions: %w", err)
	}

	expectedTuples := make([]*openfgav1.TupleKey, 0, len(allPermissions))
	for _, permission := range allPermissions {
		expectedTuples = append(
			expectedTuples,
			&openfgav1.TupleKey{
				User:     TypeInternalUser + ":*",
				Relation: hashPermission(permission),
				Object:   roleObjectIdentifier,
			},
		)
	}

	added, removed := diffTuples(existingTupleKeys, expectedTuples)

	// Don't do anything if there's no changes to make.
	if len(added) == 0 && len(removed) == 0 {
		return nil
	}

	req := &openfgav1.WriteRequest{
		StoreId: r.StoreID,
	}

	if len(removed) > 0 {
		req.Deletes = &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(removed),
		}
	}

	if len(added) > 0 {
		req.Writes = &openfgav1.WriteRequestWrites{
			TupleKeys: added,
		}
	}

	_, err = r.OpenFGA.Write(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to reconcile roles: %w", err)
	}

	return nil
}

func (r *RoleReconciler) DeleteRole(ctx context.Context, role iamdatumapiscomv1alpha1.Role) error {
	// Use Role UID for the object identifier
	roleObjectIdentifier := TypeInternalRole + ":" + string(role.UID)

	existingTupleKeys, err := getTupleKeys(ctx, r.StoreID, r.OpenFGA, &openfgav1.ReadRequestTupleKey{
		Object: roleObjectIdentifier,
	})
	if err != nil {
		return fmt.Errorf("failed to get existing tuples: %w", err)
	}

	if len(existingTupleKeys) == 0 {
		return nil
	}

	_, err = r.OpenFGA.Write(ctx, &openfgav1.WriteRequest{
		StoreId: r.StoreID,
		Deletes: &openfgav1.WriteRequestDeletes{
			TupleKeys: convertTuplesForDelete(existingTupleKeys),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	return nil
}
