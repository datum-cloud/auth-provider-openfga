#!/usr/bin/env bash
# annotate.sh — Create a Grafana annotation to mark system tweaks or perf test runs.
#
# Usage:
#   ./test/perf/annotate.sh tweak "Cached ProtectedResource lookups with informer"
#   ./test/perf/annotate.sh perf-test "Baseline: 50 VUs, 5min, postgres-backed OpenFGA"
#
# Environment variables:
#   GRAFANA_URL   Grafana base URL (default: http://localhost:30000)
#   GRAFANA_USER  Grafana username (default: admin)
#   GRAFANA_PASS  Grafana password (default: datum123)

set -euo pipefail

TAG="${1:?Usage: annotate.sh <tag> <text>  (tag: tweak|perf-test)}"
TEXT="${2:?Usage: annotate.sh <tag> <text>}"

GRAFANA_URL="${GRAFANA_URL:-http://localhost:30000}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASS="${GRAFANA_PASS:-datum123}"

# Epoch milliseconds
TIME_MS=$(date +%s)000

echo "Creating annotation: [${TAG}] ${TEXT}" >&2

RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST "${GRAFANA_URL}/api/annotations" \
  -H "Content-Type: application/json" \
  -u "${GRAFANA_USER}:${GRAFANA_PASS}" \
  -d "{
    \"time\": ${TIME_MS},
    \"tags\": [\"${TAG}\"],
    \"text\": \"${TEXT}\"
  }")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)

if [ "$HTTP_CODE" = "200" ]; then
  echo "Annotation created successfully." >&2
else
  echo "ERROR: Failed to create annotation (HTTP ${HTTP_CODE}): ${BODY}" >&2
  exit 1
fi
