#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)
cd "$repo_root"

version=${1:-}
if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "usage: scripts/release.sh <major.minor.patch>" >&2
  exit 2
fi

if [[ -n "$(git status --short)" ]]; then
  echo "release requires a clean worktree" >&2
  exit 1
fi

branch=$(git symbolic-ref --short -q HEAD || true)
if [[ "$branch" != "main" ]]; then
  echo "release must run from the main worktree" >&2
  exit 1
fi

git fetch origin main --tags
head=$(git rev-parse HEAD)
origin_main=$(git rev-parse origin/main)
if [[ "$head" != "$origin_main" ]]; then
  echo "local main must exactly match origin/main before release" >&2
  exit 1
fi

node scripts/check-release-version-consistency.mjs "$version"
previous_release_tag=$(git tag --list 'flowersec-go/v*' --sort=-v:refname | grep -Fvx "flowersec-go/v$version" | head -1 || true)
release_range="$head"
if [[ -n "$previous_release_tag" ]]; then
  release_range="$previous_release_tag..$head"
fi
if [[ -z "$(git log --format='%s' "$release_range" | sed -n '/[^[:space:]]/p' | head -1)" ]]; then
  echo "release notes require at least one non-empty commit subject" >&2
  exit 1
fi

tags=(
  "flowersec-go/v$version"
  "$version"
  "flowersec-rust/v$version"
)
for tag in "${tags[@]}"; do
  if git show-ref --verify --quiet "refs/tags/$tag"; then
    echo "release tag already exists locally: $tag" >&2
    exit 1
  fi
  if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
    echo "release tag already exists on origin: $tag" >&2
    exit 1
  fi
done

created_tags=()
notes_tmp_dir=""
cleanup_on_exit() {
  local status=$?
  if (( status != 0 )) && [[ ${#created_tags[@]} -gt 0 ]]; then
    git tag -d "${created_tags[@]}" >/dev/null || true
  fi
  if [[ -n "$notes_tmp_dir" && -d "$notes_tmp_dir" ]]; then
    rm -rf "$notes_tmp_dir"
  fi
  return "$status"
}
trap cleanup_on_exit EXIT INT TERM

for tag in "${tags[@]}"; do
  git tag "$tag" "$head"
  created_tags+=("$tag")
done

notes_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/flowersec-release-notes.XXXXXX")
notes_file="$notes_tmp_dir/release-notes.md"
if ! go -C tools/releasenotes run . \
  --repo ../.. \
  --current-tag "flowersec-go/v$version" \
  --current-ref "$head" \
  --output "$notes_file"; then
  echo "release notes preflight failed" >&2
  exit 1
fi
if [[ ! -s "$notes_file" ]]; then
  echo "release notes preflight produced an empty file" >&2
  exit 1
fi

FLOWERSEC_RELEASE_PUSH_SHA="$head" \
FLOWERSEC_RELEASE_VERSION="$version" \
git push --atomic origin \
  "refs/heads/main:refs/heads/main" \
  "refs/tags/${tags[0]}" \
  "refs/tags/${tags[1]}" \
  "refs/tags/${tags[2]}"

created_tags=()
trap - EXIT INT TERM
rm -rf "$notes_tmp_dir"
echo "released Flowersec $version from $head"
