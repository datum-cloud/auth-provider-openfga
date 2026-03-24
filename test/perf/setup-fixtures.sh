#!/usr/bin/env bash
# setup-fixtures.sh — Apply perf test IAM fixtures and emit the User name to stdout.
#
# All diagnostic output goes to stderr. The only line written to stdout is the
# name of the User/perf-test-user resource so the Taskfile can capture it cleanly:
#
#   PERF_USER_UID=$(KUBECTL="..." ./test/perf/setup-fixtures.sh)
#
# The emitted value is the user NAME ("perf-test-user"), not the Kubernetes
# metadata.uid. This is because the authorization webhook uses the SAR spec.uid
# field as the OpenFGA tuple identifier, and tuples are written keyed by the
# user's resource name (not the Kubernetes UUID). The PolicyBinding subject spec
# still uses the Kubernetes metadata.uid for UID validation.
#
# The script is idempotent: re-running it on an already-configured cluster
# does not fail.
#
# Environment variables:
#   KUBECTL  Path / command used to run kubectl (default: kubectl)

set -euo pipefail

KUBECTL="${KUBECTL:-kubectl}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ---------------------------------------------------------------------------
# Step 1: Apply ProtectedResources (shared with e2e; idempotent)
# ---------------------------------------------------------------------------
echo "Applying ProtectedResources..." >&2
${KUBECTL} apply --server-side -f "${REPO_ROOT}/test/00-setup/setup-protected-resources.yaml" >&2

# ---------------------------------------------------------------------------
# Step 2: Wait for resourcemanager-organization ProtectedResource to be Ready
# ---------------------------------------------------------------------------
echo "Waiting for ProtectedResource/resourcemanager-organization to be Ready..." >&2
${KUBECTL} wait --for=condition=Ready \
  protectedresource/resourcemanager-organization \
  --timeout=5m >&2

# ---------------------------------------------------------------------------
# Step 3: Apply perf Role
# ---------------------------------------------------------------------------
echo "Applying Role resourcemanager.miloapis.com-organizationowner..." >&2
${KUBECTL} apply --server-side -f "${SCRIPT_DIR}/fixtures/role.yaml" >&2

# ---------------------------------------------------------------------------
# Step 4: Wait for Role to be Ready
# ---------------------------------------------------------------------------
echo "Waiting for Role/resourcemanager.miloapis.com-organizationowner to be Ready..." >&2
${KUBECTL} wait --for=condition=Ready \
  role.iam.miloapis.com/resourcemanager.miloapis.com-organizationowner \
  --timeout=5m >&2

# ---------------------------------------------------------------------------
# Step 5: Apply User and Organization fixtures
# ---------------------------------------------------------------------------
echo "Applying User/perf-test-user..." >&2
${KUBECTL} apply --server-side -f "${SCRIPT_DIR}/fixtures/user.yaml" >&2

echo "Applying Organization/perf-test-org..." >&2
${KUBECTL} apply --server-side -f "${SCRIPT_DIR}/fixtures/organization.yaml" >&2

# ---------------------------------------------------------------------------
# Step 6 & 7: Poll until User and Organization have non-empty UIDs
# ---------------------------------------------------------------------------
echo "Waiting for User/perf-test-user to have a UID..." >&2
USER_UID=""
for i in $(seq 1 10); do
  USER_UID=$(${KUBECTL} get user.iam.miloapis.com perf-test-user \
    -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
  if [ -n "${USER_UID}" ]; then
    break
  fi
  echo "  Attempt ${i}/10: UID not yet assigned, retrying in 2s..." >&2
  sleep 2
done
if [ -z "${USER_UID}" ]; then
  echo "ERROR: User/perf-test-user did not get a UID within 20 seconds" >&2
  exit 1
fi
echo "User UID: ${USER_UID}" >&2

echo "Waiting for Organization/perf-test-org to have a UID..." >&2
ORG_UID=""
for i in $(seq 1 10); do
  ORG_UID=$(${KUBECTL} get organization.resourcemanager.miloapis.com perf-test-org \
    -o jsonpath='{.metadata.uid}' 2>/dev/null || true)
  if [ -n "${ORG_UID}" ]; then
    break
  fi
  echo "  Attempt ${i}/10: UID not yet assigned, retrying in 2s..." >&2
  sleep 2
done
if [ -z "${ORG_UID}" ]; then
  echo "ERROR: Organization/perf-test-org did not get a UID within 20 seconds" >&2
  exit 1
fi
echo "Organization UID: ${ORG_UID}" >&2

# ---------------------------------------------------------------------------
# Step 8: Apply PolicyBinding inline (requires runtime UIDs)
# ---------------------------------------------------------------------------
echo "Applying PolicyBinding/perf-test-org-admin-binding..." >&2
${KUBECTL} apply --server-side -f - >&2 <<EOF
apiVersion: iam.miloapis.com/v1alpha1
kind: PolicyBinding
metadata:
  name: perf-test-org-admin-binding
spec:
  roleRef:
    name: resourcemanager.miloapis.com-organizationowner
    namespace: default
  subjects:
    - kind: User
      name: perf-test-user
      uid: "${USER_UID}"
  resourceSelector:
    resourceRef:
      apiGroup: resourcemanager.miloapis.com
      kind: Organization
      name: perf-test-org
      uid: "${ORG_UID}"
EOF

# ---------------------------------------------------------------------------
# Step 9: Wait for PolicyBinding to be Ready
# ---------------------------------------------------------------------------
echo "Waiting for PolicyBinding/perf-test-org-admin-binding to be Ready..." >&2
${KUBECTL} wait --for=condition=Ready \
  policybinding.iam.miloapis.com/perf-test-org-admin-binding \
  --timeout=5m >&2

echo "Fixture setup complete." >&2

# ---------------------------------------------------------------------------
# Step 10: Emit only the User NAME to stdout (captured by Taskfile).
# The webhook uses SAR spec.uid to look up the OpenFGA tuple, and tuples are
# written keyed by the user's resource name (not the Kubernetes metadata.uid).
# ---------------------------------------------------------------------------
echo "perf-test-user"
