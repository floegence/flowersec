#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)
cd "$repo_root"

release_workflow=.github/workflows/release.yml
rust_workflow=.github/workflows/rust-release.yml
ci_workflow=.github/workflows/ci.yml

for required in "$release_workflow" "$rust_workflow" "$ci_workflow" scripts/release.sh .githooks/pre-push; do
  if [[ ! -f "$required" ]]; then
    echo "missing release policy file: $required" >&2
    exit 1
  fi
done

for forbidden in .github/workflows/swift-release.yml .github/workflows/nightly-stability.yml; do
  if [[ -e "$forbidden" ]]; then
    echo "hosted test workflow must remain removed: $forbidden" >&2
    exit 1
  fi
done

if ! grep -Fq '      - "flowersec-go/v*"' "$release_workflow"; then
  echo "the unified release workflow must be triggered by flowersec-go/v*" >&2
  exit 1
fi
if ! grep -Fq 'uses: ./.github/workflows/rust-release.yml' "$release_workflow"; then
  echo "the unified release workflow must call the reusable Rust publisher" >&2
  exit 1
fi
if ! grep -Fq '  workflow_call:' "$rust_workflow" || ! grep -Fq '  workflow_dispatch:' "$rust_workflow"; then
  echo "the Rust publisher must support reusable publication and manual recovery" >&2
  exit 1
fi
if grep -Eq '^[[:space:]]+push:' "$rust_workflow"; then
  echo "the Rust source tag must not trigger a duplicate workflow" >&2
  exit 1
fi

tag_trigger_files=$(grep -El '^[[:space:]]+tags:' .github/workflows/*.yml || true)
if [[ "$tag_trigger_files" != "$release_workflow" ]]; then
  echo "only $release_workflow may contain a tag trigger" >&2
  exit 1
fi

for workflow in .github/workflows/*.yml; do
  if grep -Eq 'make (check|nightly-check|swift-check|rust-release-check|interop-smoke|interop-stress)|go test|npm test|cargo test|test:coverage|go-test-race|go-vulncheck' "$workflow"; then
    echo "hosted workflow contains a local-only quality gate: $workflow" >&2
    exit 1
  fi
done

echo "release workflow policy is valid"
