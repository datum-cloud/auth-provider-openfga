package webhook

import (
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// buildGroupContextualTuples previously injected system group membership tuples
// as contextual tuples on every Check request. System groups are now persisted
// to OpenFGA as stored tuples by SystemGroupMaterializer so that OpenFGA's
// check query cache can resolve them. This function returns an empty slice and
// is kept only to avoid changing every call site at once.
//
// Non-system groups handled by the GroupMembership controller are already stored
// tuples and do not need to appear as contextual tuples either.
func buildGroupContextualTuples(_ authorizer.Attributes) []*openfgav1.TupleKey {
	return nil
}

// buildAllContextualTuples creates all contextual tuples (group memberships).
//
// RootBinding tuples are no longer injected as contextual tuples because the
// PolicyBinding reconciler writes them as stored tuples. Stored tuples are
// eligible for OpenFGA's check query cache; contextual tuples are not.
func buildAllContextualTuples(attributes authorizer.Attributes, _, _ string) []*openfgav1.TupleKey {
	return buildGroupContextualTuples(attributes)
}
