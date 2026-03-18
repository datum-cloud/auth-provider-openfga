// generate-fixtures is a standalone Go program that populates an OpenFGA store
// with scale-test fixtures. It writes OpenFGA tuples directly, bypassing the
// Kubernetes controller reconciliation flow, so it can generate millions of
// tuples without creating corresponding Kubernetes objects for organizations
// and projects.
//
// ProtectedResource CRDs are still created as actual Kubernetes objects because
// the webhook's ProtectedResourceCache validates permissions against them before
// building the OpenFGA check request.
//
// Usage:
//
//	OPENFGA_STORE_ID=<id> go run ./test/perf/cmd/generate-fixtures/
//
// All scale parameters are configured via environment variables. See the Config
// struct for the full list.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	internalopenfga "go.miloapis.com/auth-provider-openfga/internal/openfga"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// OpenFGA hard limit on tuples per Write request.
const maxBatchSize = 100

// Config holds all scale parameters read from environment variables.
type Config struct {
	// OpenFGA connection
	OpenFGAAPIURL string
	StoreID       string

	// Scale parameters
	NumOrgs            int
	NumProjectsPerOrg  int
	NumUsers           int
	NumRoles           int
	PermissionsPerRole int
	MembershipsPerUser int
	NumPRTypes         int

	// Concurrency
	Workers int

	// Tool paths
	Kubectl string

	// Output
	ManifestPath string
}

// ScaleManifest is written to ManifestPath after generation and read by the
// k6 scale test to select valid (user, org, project) targets.
type ScaleManifest struct {
	GeneratedAt        string              `json:"generated_at"`
	Params             ManifestParams      `json:"params"`
	Users              []string            `json:"users"`
	Organizations      []string            `json:"organizations"`
	Projects           []string            `json:"projects"`
	Roles              []string            `json:"roles"`
	Permissions        []string            `json:"permissions"`
	UserOrgMemberships map[string][]string `json:"user_org_memberships"`
	DeniedUser         string              `json:"denied_user"`
	TupleCount         int64               `json:"tuple_count"`
}

// ManifestParams records the scale parameters used during generation so
// readers can validate tuple counts against the expected formula.
type ManifestParams struct {
	NumOrgs            int `json:"num_orgs"`
	NumProjectsPerOrg  int `json:"num_projects_per_org"`
	NumUsers           int `json:"num_users"`
	NumRoles           int `json:"num_roles"`
	PermissionsPerRole int `json:"permissions_per_role"`
	OrgsPerUser        int `json:"orgs_per_user"`
}

func main() {
	cfg := loadConfig()

	if cfg.StoreID == "" {
		fmt.Fprintln(os.Stderr, "ERROR: OPENFGA_STORE_ID is required")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Scale parameters:\n")
	fmt.Fprintf(os.Stderr, "  NumOrgs:            %d\n", cfg.NumOrgs)
	fmt.Fprintf(os.Stderr, "  NumProjectsPerOrg:  %d\n", cfg.NumProjectsPerOrg)
	fmt.Fprintf(os.Stderr, "  NumUsers:           %d\n", cfg.NumUsers)
	fmt.Fprintf(os.Stderr, "  NumRoles:           %d\n", cfg.NumRoles)
	fmt.Fprintf(os.Stderr, "  PermissionsPerRole: %d\n", cfg.PermissionsPerRole)
	fmt.Fprintf(os.Stderr, "  MembershipsPerUser: %d\n", cfg.MembershipsPerUser)
	fmt.Fprintf(os.Stderr, "  NumPRTypes:         %d\n", cfg.NumPRTypes)
	fmt.Fprintf(os.Stderr, "  Workers:            %d\n", cfg.Workers)
	fmt.Fprintf(os.Stderr, "  StoreID:            %s\n", cfg.StoreID)
	fmt.Fprintf(os.Stderr, "  ManifestPath:       %s\n", cfg.ManifestPath)

	// Estimate tuple count so the operator knows what to expect.
	bindingTuples := int64(cfg.NumUsers) * int64(cfg.MembershipsPerUser) * 3
	roleTuples := int64(cfg.NumRoles) * int64(cfg.PermissionsPerRole)
	orgRootBindings := int64(cfg.NumOrgs)
	projTuples := int64(cfg.NumOrgs) * int64(cfg.NumProjectsPerOrg) * 2
	estimate := bindingTuples + roleTuples + orgRootBindings + projTuples
	fmt.Fprintf(os.Stderr, "\nEstimated tuple count: %d\n\n", estimate)

	ctx := context.Background()

	// Connect to OpenFGA via gRPC.
	conn, err := grpc.NewClient(cfg.OpenFGAAPIURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: failed to connect to OpenFGA at %s: %v\n", cfg.OpenFGAAPIURL, err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	client := openfgav1.NewOpenFGAServiceClient(conn)

	// Phase 1: Generate ProtectedResource CRDs via kubectl.
	fmt.Fprintln(os.Stderr, "Phase 1: Generating ProtectedResource CRDs...")
	if err := generateProtectedResources(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 1 failed: %v\n", err)
		os.Exit(1)
	}

	// Phase 2: Wait for authorization model to include the new resource types.
	fmt.Fprintln(os.Stderr, "Phase 2: Waiting for authorization model to stabilize...")
	if err := waitForAuthorizationModel(ctx, client, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 2 failed: %v\n", err)
		os.Exit(1)
	}

	var totalWritten atomic.Int64

	// Phase 3: Write InternalRole permission tuples.
	fmt.Fprintln(os.Stderr, "Phase 3: Writing InternalRole permission tuples...")
	roleTupleSlice := buildInternalRoleTuples(cfg)
	if err := writeTuplesBatched(ctx, client, cfg.StoreID, roleTupleSlice, cfg.Workers, &totalWritten); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 3 failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  Wrote %d role permission tuples\n", len(roleTupleSlice))

	// Phase 4: Write organization binding tuples.
	fmt.Fprintln(os.Stderr, "Phase 4: Writing organization binding tuples...")
	membershipMap := buildMembershipMap(cfg)
	orgBindingTuples := buildOrgBindingTuples(cfg, membershipMap)
	if err := writeTuplesBatched(ctx, client, cfg.StoreID, orgBindingTuples, cfg.Workers, &totalWritten); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 4 failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  Wrote %d org binding tuples\n", len(orgBindingTuples))

	// Phase 5: Write RootBinding tuples for organizations.
	fmt.Fprintln(os.Stderr, "Phase 5: Writing RootBinding tuples for organizations...")
	orgRootTuples := buildOrgRootBindingTuples(cfg)
	if err := writeTuplesBatched(ctx, client, cfg.StoreID, orgRootTuples, cfg.Workers, &totalWritten); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 5 failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  Wrote %d org root binding tuples\n", len(orgRootTuples))

	// Phase 6: Write project parent and RootBinding tuples.
	fmt.Fprintln(os.Stderr, "Phase 6: Writing project parent and RootBinding tuples...")
	projectTuples := buildProjectTuples(cfg)
	if err := writeTuplesBatched(ctx, client, cfg.StoreID, projectTuples, cfg.Workers, &totalWritten); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 6 failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "  Wrote %d project tuples\n", len(projectTuples))

	// Phase 7: Write the fixture manifest.
	fmt.Fprintln(os.Stderr, "Phase 7: Writing scale manifest...")
	manifest := buildManifest(cfg, membershipMap, totalWritten.Load())
	if err := writeManifest(manifest, cfg.ManifestPath); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Phase 7 failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "\nDone. Total tuples written: %d\n", totalWritten.Load())
	fmt.Fprintf(os.Stderr, "Manifest written to: %s\n", cfg.ManifestPath)
}

// loadConfig reads scale parameters from environment variables.
func loadConfig() Config {
	cfg := Config{
		OpenFGAAPIURL:      envOrDefault("OPENFGA_API_URL", "localhost:8081"),
		StoreID:            os.Getenv("OPENFGA_STORE_ID"),
		NumOrgs:            envIntOrDefault("PERF_NUM_ORGS", 100),
		NumProjectsPerOrg:  envIntOrDefault("PERF_NUM_PROJECTS_PER_ORG", 10),
		NumUsers:           envIntOrDefault("PERF_NUM_USERS", 500),
		NumRoles:           envIntOrDefault("PERF_NUM_ROLES", 5),
		PermissionsPerRole: envIntOrDefault("PERF_PERMISSIONS_PER_ROLE", 10),
		MembershipsPerUser: envIntOrDefault("PERF_MEMBERSHIPS_PER_USER", 2),
		NumPRTypes:         envIntOrDefault("PERF_NUM_PR_TYPES", 1),
		Workers:            envIntOrDefault("PERF_WORKERS", 20),
		Kubectl:            envOrDefault("KUBECTL", "kubectl"),
		ManifestPath:       envOrDefault("PERF_MANIFEST_PATH", "test/perf/fixtures/scale-manifest.json"),
	}

	// MembershipsPerUser cannot exceed NumOrgs.
	if cfg.MembershipsPerUser > cfg.NumOrgs {
		cfg.MembershipsPerUser = cfg.NumOrgs
	}

	return cfg
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOrDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
		fmt.Fprintf(os.Stderr, "WARNING: invalid value for %s=%q, using default %d\n", key, v, def)
	}
	return def
}

// ---------------------------------------------------------------------------
// Phase 1: ProtectedResource CRD generation
// ---------------------------------------------------------------------------

// protectedResourceTemplate generates ProtectedResource YAML for a single
// perf service. Service names follow the pattern perf-N.miloapis.com with
// resource kinds Resource0 through ResourceM.
var protectedResourceTemplate = template.Must(template.New("pr").Parse(`---
apiVersion: iam.miloapis.com/v1alpha1
kind: ProtectedResource
metadata:
  name: perf-service-{{.ServiceIdx}}-resource-{{.ResourceIdx}}
spec:
  serviceRef:
    name: "perf-{{.ServiceIdx}}.miloapis.com"
  kind: Resource{{.ResourceIdx}}
  plural: resource{{.ResourceIdx}}s
  singular: resource{{.ResourceIdx}}
  permissions:
    - get
    - list
    - create
    - update
    - delete
    - watch
    - patch
    - use
`))

func generateProtectedResources(ctx context.Context, cfg Config) error {
	var buf bytes.Buffer

	for i := 0; i < cfg.NumPRTypes; i++ {
		data := struct {
			ServiceIdx  int
			ResourceIdx int
		}{
			ServiceIdx:  i,
			ResourceIdx: i,
		}
		if err := protectedResourceTemplate.Execute(&buf, data); err != nil {
			return fmt.Errorf("failed to render ProtectedResource template for index %d: %w", i, err)
		}
	}

	// Write to a temp file and apply it.
	tmp, err := os.CreateTemp("", "perf-protected-resources-*.yaml")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// kubectl apply --server-side is idempotent.
	//nolint:gosec // cfg.Kubectl and tmp.Name() are controlled values
	cmd := exec.CommandContext(ctx, cfg.Kubectl, "apply", "--server-side", "-f", tmp.Name())
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("kubectl apply failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "  Applied %d ProtectedResource CRDs\n", cfg.NumPRTypes)
	return nil
}

// ---------------------------------------------------------------------------
// Phase 2: Wait for authorization model
// ---------------------------------------------------------------------------

func waitForAuthorizationModel(ctx context.Context, client openfgav1.OpenFGAServiceClient, cfg Config) error {
	// Wait up to 5 minutes for the controller to update the authorization model.
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		models, err := client.ReadAuthorizationModels(ctx, &openfgav1.ReadAuthorizationModelsRequest{
			StoreId: cfg.StoreID,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ReadAuthorizationModels error (will retry): %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		if len(models.AuthorizationModels) == 0 {
			fmt.Fprintln(os.Stderr, "  No authorization models found yet, waiting...")
			time.Sleep(5 * time.Second)
			continue
		}

		// Count types in the most recent model that match the perf service prefix.
		latest := models.AuthorizationModels[0]
		perfTypeCount := 0
		for _, td := range latest.TypeDefinitions {
			if strings.HasPrefix(td.Type, "perf-") {
				perfTypeCount++
			}
		}

		if perfTypeCount >= cfg.NumPRTypes {
			fmt.Fprintf(os.Stderr, "  Authorization model contains %d perf resource types (need %d) — ready\n", perfTypeCount, cfg.NumPRTypes)
			return nil
		}

		fmt.Fprintf(os.Stderr, "  Authorization model has %d/%d perf resource types, waiting...\n", perfTypeCount, cfg.NumPRTypes)
		time.Sleep(5 * time.Second)
	}

	return fmt.Errorf("authorization model did not stabilize within 5 minutes")
}

// ---------------------------------------------------------------------------
// Phase 3: InternalRole permission tuples
// ---------------------------------------------------------------------------

// buildPermissionString returns the full permission string for a perf resource
// using the same format as getAllPermissions in authorization_model_reconciler.go:
// "<serviceAPIGroup>/<plural>.<verb>"
func buildPermissionString(roleIdx, permIdx int) string {
	// Use the first perf service's permissions as the source for all roles.
	// Each permission index maps to one of the 8 standard verbs.
	verbs := []string{"get", "list", "create", "update", "delete", "watch", "patch", "use"}
	verb := verbs[permIdx%len(verbs)]
	serviceIdx := permIdx / len(verbs)
	return fmt.Sprintf("perf-%d.miloapis.com/resource%ds.%s", serviceIdx, serviceIdx, verb)
}

func buildInternalRoleTuples(cfg Config) []*openfgav1.TupleKey {
	tuples := make([]*openfgav1.TupleKey, 0, cfg.NumRoles*cfg.PermissionsPerRole)
	for r := 0; r < cfg.NumRoles; r++ {
		roleID := fmt.Sprintf("scale-role-%d", r)
		roleObject := internalopenfga.TypeInternalRole + ":" + roleID
		for p := 0; p < cfg.PermissionsPerRole; p++ {
			perm := buildPermissionString(r, p)
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     internalopenfga.TypeInternalUser + ":*",
				Relation: internalopenfga.HashPermission(perm),
				Object:   roleObject,
			})
		}
	}
	return tuples
}

// ---------------------------------------------------------------------------
// Phase 4: Organization binding tuples
// ---------------------------------------------------------------------------

// buildMembershipMap returns a map of userIdx -> []orgIdx using a deterministic
// round-robin assignment. User i belongs to orgs starting at
// (i * MembershipsPerUser) mod NumOrgs, advancing by 1 each time.
func buildMembershipMap(cfg Config) map[int][]int {
	m := make(map[int][]int, cfg.NumUsers)
	for u := 0; u < cfg.NumUsers; u++ {
		orgs := make([]int, cfg.MembershipsPerUser)
		for j := 0; j < cfg.MembershipsPerUser; j++ {
			orgs[j] = (u*cfg.MembershipsPerUser + j) % cfg.NumOrgs
		}
		m[u] = orgs
	}
	return m
}

func buildOrgBindingTuples(cfg Config, membershipMap map[int][]int) []*openfgav1.TupleKey {
	// 3 tuples per (user, org) pair.
	tuples := make([]*openfgav1.TupleKey, 0, cfg.NumUsers*cfg.MembershipsPerUser*3)
	for u := 0; u < cfg.NumUsers; u++ {
		for _, o := range membershipMap[u] {
			bindingID := fmt.Sprintf("scale-binding-%d-%d", u, o)
			bindingObj := internalopenfga.TypeRoleBinding + ":" + bindingID
			orgObj := fmt.Sprintf("resourcemanager.miloapis.com/Organization:scale-org-%d", o)
			roleObj := internalopenfga.TypeInternalRole + fmt.Sprintf(":scale-role-%d", u%cfg.NumRoles)
			userObj := internalopenfga.TypeInternalUser + fmt.Sprintf(":scale-user-%d", u)

			// T1: binding → org
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     bindingObj,
				Relation: internalopenfga.RelationRoleBinding,
				Object:   orgObj,
			})
			// T2: internalRole → binding
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     roleObj,
				Relation: internalopenfga.RelationInternalRole,
				Object:   bindingObj,
			})
			// T3: internalUser → binding
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     userObj,
				Relation: internalopenfga.RelationInternalUser,
				Object:   bindingObj,
			})
		}
	}
	return tuples
}

// ---------------------------------------------------------------------------
// Phase 5: Organization RootBinding tuples
// ---------------------------------------------------------------------------

func buildOrgRootBindingTuples(cfg Config) []*openfgav1.TupleKey {
	tuples := make([]*openfgav1.TupleKey, 0, cfg.NumOrgs)
	for o := 0; o < cfg.NumOrgs; o++ {
		tuples = append(tuples, &openfgav1.TupleKey{
			User:     internalopenfga.TypeRoot + ":resourcemanager.miloapis.com/Organization",
			Relation: internalopenfga.RelationRootBinding,
			Object:   fmt.Sprintf("resourcemanager.miloapis.com/Organization:scale-org-%d", o),
		})
	}
	return tuples
}

// ---------------------------------------------------------------------------
// Phase 6: Project tuples
// ---------------------------------------------------------------------------

func buildProjectTuples(cfg Config) []*openfgav1.TupleKey {
	// 2 tuples per project: RootBinding + parent.
	tuples := make([]*openfgav1.TupleKey, 0, cfg.NumOrgs*cfg.NumProjectsPerOrg*2)
	for o := 0; o < cfg.NumOrgs; o++ {
		for p := 0; p < cfg.NumProjectsPerOrg; p++ {
			projectID := fmt.Sprintf("scale-proj-%d-%d", o, p)
			projectObj := "resourcemanager.miloapis.com/Project:" + projectID
			orgObj := fmt.Sprintf("resourcemanager.miloapis.com/Organization:scale-org-%d", o)

			// RootBinding for the project.
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     internalopenfga.TypeRoot + ":resourcemanager.miloapis.com/Project",
				Relation: internalopenfga.RelationRootBinding,
				Object:   projectObj,
			})
			// Parent relationship: project → org.
			tuples = append(tuples, &openfgav1.TupleKey{
				User:     orgObj,
				Relation: internalopenfga.RelationParent,
				Object:   projectObj,
			})
		}
	}
	return tuples
}

// ---------------------------------------------------------------------------
// Batched concurrent tuple writer
// ---------------------------------------------------------------------------

// writeTuplesBatched chunks tuples into batches of maxBatchSize and writes them
// concurrently using up to workers goroutines. "Already exists" errors are
// treated as success so the generator is idempotent on re-runs.
func writeTuplesBatched(
	ctx context.Context,
	client openfgav1.OpenFGAServiceClient,
	storeID string,
	tuples []*openfgav1.TupleKey,
	workers int,
	totalWritten *atomic.Int64,
) error {
	if len(tuples) == 0 {
		return nil
	}

	// Build batches.
	var batches [][]*openfgav1.TupleKey
	for i := 0; i < len(tuples); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(tuples) {
			end = len(tuples)
		}
		batches = append(batches, tuples[i:end])
	}

	batchCh := make(chan []*openfgav1.TupleKey, len(batches))
	for _, b := range batches {
		batchCh <- b
	}
	close(batchCh)

	errCh := make(chan error, workers)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batch := range batchCh {
				if err := writeBatch(ctx, client, storeID, batch); err != nil {
					errCh <- err
					return
				}
				written := totalWritten.Add(int64(len(batch)))
				// Log progress every 10,000 tuples.
				prev := written - int64(len(batch))
				if prev/10000 < written/10000 {
					fmt.Fprintf(os.Stderr, "  Progress: %d tuples written\n", written)
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	// Return the first error, if any.
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// writeBatch writes a single batch of tuples to OpenFGA. Errors indicating
// that tuples already exist are silently ignored for idempotency.
func writeBatch(ctx context.Context, client openfgav1.OpenFGAServiceClient, storeID string, batch []*openfgav1.TupleKey) error {
	_, err := client.Write(ctx, &openfgav1.WriteRequest{
		StoreId: storeID,
		Writes: &openfgav1.WriteRequestWrites{
			TupleKeys: batch,
		},
	})
	if err != nil {
		// OpenFGA returns an error containing "already exists" when a tuple is
		// written a second time. Treat this as success for idempotency.
		if strings.Contains(err.Error(), "already exists") ||
			strings.Contains(err.Error(), "ErrInvalidWriteInput") {
			return nil
		}
		return fmt.Errorf("OpenFGA Write failed: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Phase 7: Manifest
// ---------------------------------------------------------------------------

func buildManifest(cfg Config, membershipMap map[int][]int, tupleCount int64) ScaleManifest {
	users := make([]string, cfg.NumUsers)
	for i := range users {
		users[i] = fmt.Sprintf("scale-user-%d", i)
	}

	orgs := make([]string, cfg.NumOrgs)
	for i := range orgs {
		orgs[i] = fmt.Sprintf("scale-org-%d", i)
	}

	projects := make([]string, 0, cfg.NumOrgs*cfg.NumProjectsPerOrg)
	for o := 0; o < cfg.NumOrgs; o++ {
		for p := 0; p < cfg.NumProjectsPerOrg; p++ {
			projects = append(projects, fmt.Sprintf("scale-proj-%d-%d", o, p))
		}
	}

	roles := make([]string, cfg.NumRoles)
	for i := range roles {
		roles[i] = fmt.Sprintf("scale-role-%d", i)
	}

	// Collect the set of permission strings used by the roles.
	permSet := make(map[string]struct{})
	for r := 0; r < cfg.NumRoles; r++ {
		for p := 0; p < cfg.PermissionsPerRole; p++ {
			permSet[buildPermissionString(r, p)] = struct{}{}
		}
	}
	permissions := make([]string, 0, len(permSet))
	for perm := range permSet {
		permissions = append(permissions, perm)
	}

	// Build the user → org membership map using names (not indices).
	userOrgMap := make(map[string][]string, cfg.NumUsers)
	for u, orgIdxs := range membershipMap {
		userName := fmt.Sprintf("scale-user-%d", u)
		orgNames := make([]string, len(orgIdxs))
		for i, o := range orgIdxs {
			orgNames[i] = fmt.Sprintf("scale-org-%d", o)
		}
		userOrgMap[userName] = orgNames
	}

	return ScaleManifest{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Params: ManifestParams{
			NumOrgs:            cfg.NumOrgs,
			NumProjectsPerOrg:  cfg.NumProjectsPerOrg,
			NumUsers:           cfg.NumUsers,
			NumRoles:           cfg.NumRoles,
			PermissionsPerRole: cfg.PermissionsPerRole,
			OrgsPerUser:        cfg.MembershipsPerUser,
		},
		Users:              users,
		Organizations:      orgs,
		Projects:           projects,
		Roles:              roles,
		Permissions:        permissions,
		UserOrgMemberships: userOrgMap,
		// scale-denied-user has no tuples; it must not appear in the Users list
		// or UserOrgMemberships map. We record it here so k6 can use it.
		DeniedUser: "scale-denied-user",
		TupleCount: tupleCount,
	}
}

func writeManifest(manifest ScaleManifest, path string) error {
	// Ensure the directory exists.
	dir := path[:strings.LastIndex(path, "/")]
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create manifest directory %s: %w", dir, err)
		}
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	//nolint:gosec // manifest file does not contain secrets
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write manifest to %s: %w", path, err)
	}
	return nil
}
