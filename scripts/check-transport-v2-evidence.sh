#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
report_path="${1:-}"
base_sha="${2:-}"
trust_store_path="$repo_root/testdata/transport_v2/evidence_trust_store.json"
trust_policy_path="$repo_root/testdata/transport_v2/evidence_trust_policy.json"

if [[ -z "$report_path" || -z "$base_sha" ]]; then
	echo "usage: make transport-v2-signed-evidence-check TRANSPORT_V2_EVIDENCE_REPORT=/absolute/report.json TRANSPORT_V2_BASE_SHA=<40-char-sha>" >&2
  exit 2
fi
if [[ "$report_path" != /* ]]; then
  report_path="$repo_root/$report_path"
fi
if [[ ! -f "$report_path" ]]; then
  echo "Transport v2 evidence report not found: $report_path" >&2
  exit 2
fi
if [[ ! -f "$trust_store_path" ]]; then
  echo "Transport v2 evidence trust store not found: $trust_store_path" >&2
  exit 2
fi
if [[ ! -f "$trust_policy_path" ]]; then
	echo "Transport v2 repository trust policy not found: $trust_policy_path" >&2
	exit 2
fi

cd "$repo_root/tools/transportcheck"
go run . evidence \
  -manifest ../../testdata/transport_v2/performance_manifest.json \
  -registry ../../testdata/transport_v2/case_registry.json \
  -report "$report_path" \
  -repo "$repo_root" \
	-base-sha "$base_sha" \
	-trust-store "$trust_store_path" \
	-trust-policy "$trust_policy_path"
