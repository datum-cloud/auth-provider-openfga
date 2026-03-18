package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"google.golang.org/grpc/status"
)

// SystemGroupMaterializer persists system group membership tuples to OpenFGA the
// first time a user is encountered. This allows OpenFGA's check query cache to
// resolve group membership paths, which is not possible with contextual tuples
// that bypass the cache entirely.
//
// The materialized set is in-memory and lives for the process lifetime. On
// restart the set is lost, but because OpenFGA's Write API is idempotent for
// existing tuples the materializer will safely re-write the same tuples without
// error.
type SystemGroupMaterializer struct {
	fgaClient    openfgav1.OpenFGAServiceClient
	storeID      string
	materialized sync.Map // key: string userUID, value: struct{}
}

// NewSystemGroupMaterializer creates a materializer that writes system group
// tuples to the given OpenFGA store.
func NewSystemGroupMaterializer(fgaClient openfgav1.OpenFGAServiceClient, storeID string) *SystemGroupMaterializer {
	return &SystemGroupMaterializer{
		fgaClient: fgaClient,
		storeID:   storeID,
	}
}

// EnsureMaterialized writes system group membership tuples for userUID if they
// have not yet been written during this process lifetime. Only groups with the
// "system:" prefix are persisted; all others are left to the GroupMembership
// controller.
//
// Calling this method concurrently for the same userUID is safe: the sync.Map
// check-then-write is optimistic — if two goroutines race on the same UID both
// may call Write, which is harmless because OpenFGA's Write is idempotent for
// pre-existing tuples.
func (m *SystemGroupMaterializer) EnsureMaterialized(ctx context.Context, userUID string, groups []string) error {
	// Fast path: already materialized for this UID.
	if _, loaded := m.materialized.Load(userUID); loaded {
		return nil
	}

	// Build the set of system group tuples that need to be written.
	tupleKeys := make([]*openfgav1.TupleKey, 0, len(groups))
	for _, group := range groups {
		if !strings.HasPrefix(group, "system:") {
			continue
		}
		escapedGroup := strings.ReplaceAll(group, ":", "_")
		tupleKeys = append(tupleKeys, &openfgav1.TupleKey{
			User:     fmt.Sprintf("iam.miloapis.com/InternalUser:%s", userUID),
			Relation: "member",
			Object:   fmt.Sprintf("iam.miloapis.com/InternalUserGroup:%s", escapedGroup),
		})
	}

	if len(tupleKeys) == 0 {
		// No system groups to persist; still mark as materialized to skip future checks.
		m.materialized.Store(userUID, struct{}{})
		return nil
	}

	slog.InfoContext(ctx, "persisting system group memberships to OpenFGA",
		slog.String("user_uid", userUID),
		slog.Int("group_count", len(tupleKeys)),
	)

	_, err := m.fgaClient.Write(ctx, &openfgav1.WriteRequest{
		StoreId: m.storeID,
		Writes: &openfgav1.WriteRequestWrites{
			TupleKeys: tupleKeys,
		},
	})
	if err != nil {
		// OpenFGA returns gRPC code 2017 when a tuple already exists. This is
		// expected after a pod restart (the sync.Map is lost but the tuples
		// persist in the datastore). Treat "already exists" as success and
		// cache the user to avoid re-attempting on every request.
		if st, ok := status.FromError(err); ok && st.Code() == 2017 {
			m.materialized.Store(userUID, struct{}{})
			slog.DebugContext(ctx, "system group memberships already exist in OpenFGA",
				slog.String("user_uid", userUID),
			)
			return nil
		}
		return fmt.Errorf("failed to write system group membership tuples for user %s: %w", userUID, err)
	}

	m.materialized.Store(userUID, struct{}{})
	slog.DebugContext(ctx, "system group memberships persisted",
		slog.String("user_uid", userUID),
		slog.Int("group_count", len(tupleKeys)),
	)
	return nil
}
