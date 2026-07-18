#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)
cd "$repo_root"

release_workflow=.github/workflows/release.yml
rust_workflow=.github/workflows/rust-release.yml
ci_workflow=.github/workflows/ci.yml

version_checker=scripts/check-release-version-consistency.mjs

for required in Makefile "$release_workflow" "$rust_workflow" "$ci_workflow" scripts/release.sh "$version_checker" scripts/release.test.mjs scripts/check-release-version-consistency.test.mjs .githooks/pre-push; do
  if [[ ! -f "$required" ]]; then
    echo "missing release policy file: $required" >&2
    exit 1
  fi
done

require_make_recipe() {
  local target=$1
  local recipe=$2
  if ! awk -v target="$target:" -v recipe="	$recipe" '
    $0 == target {
      in_target = 1
      target_count++
      next
    }
    in_target && /^[^[:space:]]/ {
      in_target = 0
    }
    in_target && $0 == recipe {
      recipe_count++
    }
    END {
      exit !(target_count == 1 && recipe_count == 1)
    }
  ' Makefile; then
    echo "Makefile target $target must run $recipe" >&2
    exit 1
  fi
}

workflow_step_line() {
  local workflow=$1
  local job=$2
  local name=$3
  local field=$4
  local value=$5
  awk -v job="$job" -v name="$name" -v field="$field" -v value="$value" '
    $0 == "  " job ":" {
      in_job = 1
      job_count++
      next
    }
    in_job && /^  [^[:space:]][^:]*:/ {
      in_job = 0
      in_step = 0
    }
    !in_job {
      next
    }
    {
      line = $0
      sub(/^[[:space:]]+/, "", line)
    }
    line == "- name: " name {
      in_step = 1
      step_count++
      next
    }
    in_step && line ~ /^- (name|uses):/ {
      in_step = 0
    }
    in_step && (line ~ /^if:/ || line ~ /^continue-on-error:/) {
      forbidden = 1
    }
    in_step && line == field ": " value {
      field_count++
      field_line = NR
    }
    END {
      if (job_count == 1 && step_count == 1 && field_count == 1 && forbidden == 0) {
        print field_line
        exit 0
      }
      exit 1
    }
  ' "$workflow"
}

workflow_named_step_line() {
  local workflow=$1
  local job=$2
  local name=$3
  awk -v job="$job" -v name="$name" '
    $0 == "  " job ":" {
      in_job = 1
      job_count++
      next
    }
    in_job && /^  [^[:space:]][^:]*:/ {
      in_job = 0
    }
    !in_job {
      next
    }
    {
      line = $0
      sub(/^[[:space:]]+/, "", line)
    }
    line == "- name: " name {
      step_count++
      step_line = NR
    }
    END {
      if (job_count == 1 && step_count == 1) {
        print step_line
        exit 0
      }
      exit 1
    }
  ' "$workflow"
}

workflow_job_field_line() {
  local workflow=$1
  local job=$2
  local field=$3
  local value=$4
  awk -v job="$job" -v field="$field" -v value="$value" '
    $0 == "  " job ":" {
      in_job = 1
      job_count++
      next
    }
    in_job && /^  [^[:space:]][^:]*:/ {
      in_job = 0
    }
    in_job && $0 ~ /^    if:/ {
      forbidden = 1
    }
    in_job && $0 == "    " field ": " value {
      field_count++
      field_line = NR
    }
    END {
      if (job_count == 1 && field_count == 1 && forbidden == 0) {
        print field_line
        exit 0
      }
      exit 1
    }
  ' "$workflow"
}

require_make_recipe release-policy-check './scripts/check-release-workflow-policy.sh'
require_make_recipe release-policy-check '$(MAKE) release-version-check'
require_make_recipe release-policy-check '$(MAKE) release-test'
require_make_recipe release-version-check 'node scripts/check-release-version-consistency.mjs'
require_make_recipe release-test 'node --test scripts/check-release-version-consistency.test.mjs scripts/release.test.mjs'
require_make_recipe precommit '$(MAKE) release-policy-check'
require_make_recipe check '$(MAKE) release-policy-check'

if ! grep -Eq '^node scripts/check-release-version-consistency\.mjs "\$version"$' scripts/release.sh; then
  echo "the release script must validate all maintained version facts" >&2
  exit 1
fi
if ! workflow_job_field_line "$release_workflow" prepare runs-on ubuntu-latest >/dev/null; then
  echo "the unified release workflow prepare job must remain unconditional" >&2
  exit 1
fi
if ! workflow_job_field_line "$release_workflow" release runs-on ubuntu-latest >/dev/null; then
  echo "the unified release workflow release job must remain unconditional" >&2
  exit 1
fi
if ! workflow_job_field_line "$release_workflow" rust-publish uses './.github/workflows/rust-release.yml' >/dev/null; then
  echo "the unified release workflow rust-publish job must remain unconditional" >&2
  exit 1
fi
if ! workflow_job_field_line "$rust_workflow" publish runs-on ubuntu-latest >/dev/null; then
  echo "the Rust recovery workflow publish job must remain unconditional" >&2
  exit 1
fi

if ! release_version_line=$(workflow_step_line "$release_workflow" release 'Validate release version facts' run 'node scripts/check-release-version-consistency.mjs "${{ steps.vars.outputs.version }}"'); then
  echo "the unified release workflow must validate all maintained version facts" >&2
  exit 1
fi
if ! release_tag_line=$(workflow_step_line "$release_workflow" release 'Verify all language tags point to this commit' run 'scripts/verify-release-tags.sh "${{ steps.vars.outputs.version }}" "${GITHUB_SHA}"'); then
  echo "the unified release workflow must verify all release tags" >&2
  exit 1
fi
if ! rust_version_line=$(workflow_step_line "$rust_workflow" publish 'Validate release version facts' run 'node scripts/check-release-version-consistency.mjs "${{ steps.version.outputs.version }}"'); then
  echo "the Rust recovery workflow must validate all maintained version facts" >&2
  exit 1
fi
if ! rust_tag_line=$(workflow_step_line "$rust_workflow" publish 'Verify release tags' run 'scripts/verify-release-tags.sh "${{ steps.version.outputs.version }}" "$(git rev-parse HEAD)"'); then
  echo "the Rust recovery workflow must verify all release tags" >&2
  exit 1
fi
if ! release_rust_line=$(workflow_step_line "$release_workflow" release 'Setup Rust' uses 'dtolnay/rust-toolchain@stable'); then
  echo "the unified release workflow must set up Rust before version validation" >&2
  exit 1
fi
if ((release_rust_line >= release_version_line || release_version_line >= release_tag_line)); then
  echo "the unified release workflow must run Rust setup, version validation, and tag verification in order" >&2
  exit 1
fi
if ! rust_setup_line=$(workflow_step_line "$rust_workflow" publish 'Setup Rust' uses 'dtolnay/rust-toolchain@stable'); then
  echo "the Rust recovery workflow must set up Rust before version validation" >&2
  exit 1
fi
if ((rust_setup_line >= rust_version_line || rust_version_line >= rust_tag_line)); then
  echo "the Rust recovery workflow must run Rust setup, version validation, and tag verification in order" >&2
  exit 1
fi
if ! workflow_step_line "$ci_workflow" repository 'Check release workflow policy' run 'scripts/check-release-workflow-policy.sh' >/dev/null; then
  echo "hosted CI must run only the static release workflow policy check" >&2
  exit 1
fi

for publish_step in 'Publish GitHub Release' 'Build and push tunnel image' 'Build and push proxy gateway image' 'Publish npm package'; do
  if ! publish_line=$(workflow_named_step_line "$release_workflow" release "$publish_step") || ((release_version_line >= publish_line || release_tag_line >= publish_line)); then
    echo "the unified release workflow must validate versions and tags before every publication step" >&2
    exit 1
  fi
done
if ! rust_publish_line=$(workflow_named_step_line "$rust_workflow" publish 'Publish crate') || ((rust_version_line >= rust_publish_line || rust_tag_line >= rust_publish_line)); then
  echo "the Rust recovery workflow must validate versions and tags before every publication step" >&2
  exit 1
fi

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
