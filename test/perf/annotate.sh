#!/usr/bin/env bash
# annotate.sh — Write a perf annotation metric to Victoria Metrics.
#
# Annotations are stored as metric data points in Victoria Metrics so they
# survive Grafana instance rebuilds. The Grafana dashboard queries them via
# a Prometheus datasource annotation using the perf_annotation metric.
#
# Usage:
#   ./test/perf/annotate.sh tweak "Cached ProtectedResource lookups with informer"
#   ./test/perf/annotate.sh perf-test "Baseline: 50 VUs, 5min, postgres-backed OpenFGA"
#
# Environment variables:
#   VM_URL   Victoria Metrics base URL (default: http://localhost:8428)

set -euo pipefail

TAG="${1:?Usage: annotate.sh <tag> <text>  (tag: tweak|perf-test|scale-perf-test)}"
TEXT="${2:?Usage: annotate.sh <tag> <text>}"

VM_URL="${VM_URL:-http://localhost:8428}"

# Epoch milliseconds — Victoria Metrics import/prometheus expects milliseconds
TIMESTAMP_MS=$(date +%s)000

# Escape the description for use as a label value: replace \ with \\, then " with \"
ESCAPED_TEXT=$(printf '%s' "${TEXT}" | sed 's/\\/\\\\/g; s/"/\\"/g')

METRIC="perf_annotation{type=\"${TAG}\",description=\"${ESCAPED_TEXT}\"} 1 ${TIMESTAMP_MS}"

echo "Writing annotation to Victoria Metrics: [${TAG}] ${TEXT}" >&2

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "${VM_URL}/api/v1/import/prometheus" \
  --data-binary "${METRIC}")

if [ "${HTTP_CODE}" = "204" ] || [ "${HTTP_CODE}" = "200" ]; then
  echo "Annotation written successfully (HTTP ${HTTP_CODE})." >&2
else
  echo "ERROR: Failed to write annotation to Victoria Metrics (HTTP ${HTTP_CODE})." >&2
  echo "  URL: ${VM_URL}/api/v1/import/prometheus" >&2
  echo "  Metric: ${METRIC}" >&2
  exit 1
fi
