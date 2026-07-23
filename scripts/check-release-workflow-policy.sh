#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)
cd "$repo_root"

release_workflow=.github/workflows/release.yml
rust_workflow=.github/workflows/rust-release.yml
ci_workflow=.github/workflows/ci.yml

expected_workflows=$'.github/workflows/ci.yml\n.github/workflows/release.yml\n.github/workflows/rust-release.yml'
actual_workflows=$(find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) -print | LC_ALL=C sort)
if [[ "$actual_workflows" != "$expected_workflows" ]]; then
  echo "the reviewed workflow set changed; expected only ci.yml, release.yml, and rust-release.yml" >&2
  exit 1
fi

version_checker=scripts/check-release-version-consistency.mjs

for required in Makefile .github/dependabot.yml "$release_workflow" "$rust_workflow" "$ci_workflow" scripts/release.sh "$version_checker" scripts/release.test.mjs scripts/check-release-version-consistency.test.mjs scripts/check-container-release-policy.mjs scripts/check-release-workflows.rb scripts/check-security-makefile.mjs scripts/check-transport-v2-evidence.sh .githooks/pre-push; do
  if [[ ! -f "$required" ]]; then
    echo "missing release policy file: $required" >&2
    exit 1
  fi
done

node scripts/check-security-makefile.mjs Makefile >/dev/null

if ! grep -Eq '^node scripts/check-release-version-consistency\.mjs "\$version"$' scripts/release.sh; then
  echo "the release script must validate all maintained version facts" >&2
  exit 1
fi
if ! grep -Fxq 'env -u MAKE -u MAKE_COMMAND -u MAKEFLAGS -u GNUMAKEFLAGS -u MFLAGS -u MAKEFILES -u MAKEFILE_LIST -u MAKEOVERRIDES -u MAKELEVEL -u MAKE_RESTARTS -u MAKECMDGOALS make release-check' scripts/release.sh; then
  echo "the release script must isolate release-check from inherited make controls" >&2
  exit 1
fi
ruby -W0 scripts/check-release-workflows.rb >/dev/null
node scripts/check-container-release-policy.mjs >/dev/null

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
if ! grep -Fq '  workflow_call:' "$rust_workflow" || ! grep -Fq '  workflow_dispatch:' "$rust_workflow"; then
  echo "the Rust publisher must support reusable publication and manual recovery" >&2
  exit 1
fi
if grep -Eq '^[[:space:]]+push:' "$rust_workflow"; then
  echo "the Rust source tag must not trigger a duplicate workflow" >&2
  exit 1
fi

tag_trigger_files=$(find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) -exec grep -El '^[[:space:]]+tags:' {} + || true)
if [[ "$tag_trigger_files" != "$release_workflow" ]]; then
  echo "only $release_workflow may contain a tag trigger" >&2
  exit 1
fi

while IFS= read -r workflow; do
  if grep -Eq 'make (check|nightly-check|swift-check|rust-release-check|interop-smoke|interop-stress)|go test|npm test|cargo test|test:coverage|go-test-race|go-vulncheck' "$workflow"; then
    echo "hosted workflow contains a local-only quality gate: $workflow" >&2
    exit 1
  fi
done <<< "$actual_workflows"

echo "release workflow policy is valid"
