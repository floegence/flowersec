#!/usr/bin/env bash

set -euo pipefail

release_sha="$(git rev-parse HEAD)"
git fetch --quiet --no-tags origin main
main_sha="$(git rev-parse refs/remotes/origin/main)"
remote_main_sha="$(git ls-remote origin refs/heads/main | awk '{print $1}')"
[[ -n "$remote_main_sha" && "$main_sha" == "$remote_main_sha" ]] || {
  echo "remote main changed during release ref validation" >&2
  exit 1
}

if [[ "$release_sha" == "$main_sha" ]]; then
  exit 0
fi

# Recovery uses current, reviewed publication tooling while keeping the
# coordinated source tags and registry packages at their original commit.
[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch &&
   "${GITHUB_REF:-}" == refs/heads/main &&
   "${GITHUB_SHA:-}" == "$main_sha" ]] || {
  echo "an older release commit requires recovery from the current main workflow" >&2
  exit 1
}
case "${GITHUB_WORKFLOW_REF:-}" in
  "${GITHUB_REPOSITORY:-}/.github/workflows/release.yml@refs/heads/main" | \
  "${GITHUB_REPOSITORY:-}/.github/workflows/rust-release.yml@refs/heads/main") ;;
  *) echo "release recovery requires the reviewed main workflow identity" >&2; exit 1 ;;
esac
git merge-base --is-ancestor "$release_sha" "$main_sha" || {
  echo "release commit is not an ancestor of main" >&2
  exit 1
}
changed_files="$(git diff --name-only --no-renames "$release_sha" "$main_sha")"
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
