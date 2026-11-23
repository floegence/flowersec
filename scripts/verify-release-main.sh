#!/usr/bin/env bash

set -euo pipefail

version=${1:?release version required}
release_sha=$(git rev-parse HEAD)

remote_tip() {
  local branch=$1 fetched advertised
  git fetch --quiet --no-tags origin "+refs/heads/$branch:refs/remotes/origin/$branch" || return 1
  fetched=$(git rev-parse "refs/remotes/origin/$branch") || return 1
  advertised=$(git ls-remote --exit-code origin "refs/heads/$branch" | awk '{print $1}') || return 1
  [[ -n "$advertised" && "$fetched" == "$advertised" ]] || {
    echo "remote $branch changed during release ref validation" >&2
    return 1
  }
  printf '%s\n' "$fetched"
}

if [[ "$version" == 5.* ]]; then
  baseline=74e6ae7d5d2a992f4a33bf05259d1b786c386f81
  [[ "$(git rev-parse 'refs/tags/5.6.0^{commit}')" == "$baseline" ]] &&
    git merge-base --is-ancestor "$baseline" "$release_sha" || {
      echo 'maintenance releases require the published 5.6.0 baseline' >&2
      exit 1
    }
  if [[ "$version" == 5.6.0 ]]; then
    previous=6f646fe4a20f9fdee55232a445e7c16fc133442c
    if [[ "$release_sha" != "$baseline" || "$(git rev-parse 'refs/tags/flowersec-go/v5.6.0^{commit}')" != "$baseline" ||
          "$(git rev-parse 'refs/tags/flowersec-go/v5.5.0^{commit}')" != "$previous" ]] ||
       ! git merge-base --is-ancestor "$previous" "$release_sha"; then
      echo '5.6.0 must match its published Go tag and reviewed ancestry' >&2
      exit 1
    fi
    exit 0
  fi
  maintenance_tip=$(remote_tip release/5.x)
  [[ "$release_sha" == "$maintenance_tip" ]] || {
    echo 'maintenance tag must point at the current remote release/5.x tip' >&2
    exit 1
  }
  exit 0
fi

main_tip=$(remote_tip main)
[[ "$release_sha" != "$main_tip" ]] || exit 0
[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch && "${GITHUB_REF:-}" == refs/heads/main &&
   "${GITHUB_SHA:-}" == "$main_tip" && -n "${GITHUB_REPOSITORY:-}" ]] || {
  echo 'an older release commit requires recovery from the current main workflow' >&2
  exit 1
}
case "${GITHUB_WORKFLOW_REF:-}" in
  "$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/heads/main" | \
  "$GITHUB_REPOSITORY/.github/workflows/rust-release.yml@refs/heads/main") ;;
  *) echo 'release recovery requires the reviewed main workflow identity' >&2; exit 1 ;;
esac
git merge-base --is-ancestor "$release_sha" "$main_tip" || {
  echo 'release commit is not an ancestor of main' >&2
  exit 1
}
changed_files=$(git diff --name-only --no-renames --ignore-submodules=none "$release_sha" "$main_tip")
while IFS= read -r changed; do
  [[ -n "$changed" ]] || continue
  case "$changed" in
    .github/workflows/release.yml | .github/workflows/rust-release.yml | \
    scripts/verify-release-main.sh | scripts/verify-crates-release-consumer.mjs | \
    scripts/check-release-workflows.rb | scripts/release.test.mjs) ;;
    *) echo "release recovery cannot cross a product change: $changed" >&2; exit 1 ;;
  esac
done <<< "$changed_files"
echo "release recovery preserves product source at $release_sha"
