package webhook

import (
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// buildGroupContextualTuples creates contextual tuples for user's group memberships
// This is shared between core and project authorizers
func buildGroupContextualTuples(attributes authorizer.Attributes) []*openfgav1.TupleKey {
	var tuples []*openfgav1.TupleKey

	userUID := attributes.GetUser().GetUID()
	for _, group := range attributes.GetUser().GetGroups() {
		// Escape colons in group names to match the format used in policy reconciler
		escapedGroup := strings.ReplaceAll(group, ":", "_")
		tuple := &openfgav1.TupleKey{
			User:     "iam.miloapis.com/InternalUser:" + userUID,
			Relation: "member",
			Object:   "iam.miloapis.com/InternalUserGroup:" + escapedGroup,
		}
		tuples = append(tuples, tuple)
	}

	return tuples
}

// buildRootBindingContextualTuple creates a root binding contextual tuple
// This is shared between core and project authorizers
func buildRootBindingContextualTuple(rootResourceType, targetResource string) *openfgav1.TupleKey {
	return &openfgav1.TupleKey{
		User:     "iam.miloapis.com/Root:" + rootResourceType,
		Relation: "iam.miloapis.com/RootBinding",
		Object:   targetResource,
	}
}

// buildAllContextualTuples creates all contextual tuples (root binding + groups)
// This is shared between core and project authorizers
func buildAllContextualTuples(attributes authorizer.Attributes, rootResourceType, targetResource string) []*openfgav1.TupleKey {
	var contextualTuples []*openfgav1.TupleKey

	// Add root binding contextual tuple
	rootBindingTuple := buildRootBindingContextualTuple(rootResourceType, targetResource)
	contextualTuples = append(contextualTuples, rootBindingTuple)

	// Add group contextual tuples
	groupTuples := buildGroupContextualTuples(attributes)
	contextualTuples = append(contextualTuples, groupTuples...)

	return contextualTuples
}
