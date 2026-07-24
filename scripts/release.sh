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

evidence_report=${TRANSPORT_V2_EVIDENCE_REPORT:-}
evidence_base_sha=${TRANSPORT_V2_BASE_SHA:-}
if [[ "$evidence_report" != /* || ! -f "$evidence_report" || -L "$evidence_report" || "${evidence_report##*/}" != report.json ]]; then
  echo "release requires TRANSPORT_V2_EVIDENCE_REPORT to name an absolute, regular, non-symlink report.json" >&2
  exit 2
fi
if [[ ! "$evidence_base_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "release requires TRANSPORT_V2_BASE_SHA to be a full lowercase Git SHA" >&2
  exit 2
fi
evidence_report_sha=$(openssl dgst -sha256 -r "$evidence_report" | awk '{print $1}')

git fetch origin main --tags
head=$(git rev-parse HEAD)
origin_main=$(git rev-parse origin/main)
if [[ "$head" != "$origin_main" ]]; then
  echo "local main must exactly match origin/main before release" >&2
  exit 1
fi

node scripts/check-release-version-consistency.mjs "$version"
(
  cd tools/releasenotes
  go run . \
    --repo ../.. \
    --current-tag "flowersec-go/v$version" \
    --current-ref "$head" \
    --output /dev/null
)

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

env -u MAKE -u MAKE_COMMAND -u MAKEFLAGS -u GNUMAKEFLAGS -u MFLAGS -u MAKEFILES -u MAKEFILE_LIST -u MAKEOVERRIDES -u MAKELEVEL -u MAKE_RESTARTS -u MAKECMDGOALS -u TRANSPORT_V2_RELEASE_RUNNER -u TRANSPORT_V2_UNSIGNED_EVIDENCE_REPORT TRANSPORT_V2_EVIDENCE_REPORT="$evidence_report" TRANSPORT_V2_BASE_SHA="$evidence_base_sha" make release-check

if [[ ! -f "$evidence_report" || -L "$evidence_report" || "$(openssl dgst -sha256 -r "$evidence_report" | awk '{print $1}')" != "$evidence_report_sha" ]]; then
  echo "release-check changed the signed Transport v2 evidence report" >&2
  exit 1
fi

if [[ -n "$(git status --short)" ]]; then
  echo "release-check modified the worktree" >&2
  exit 1
fi
if [[ "$(git rev-parse HEAD)" != "$head" ]]; then
  echo "release-check changed HEAD" >&2
  exit 1
fi

created_tags=()
cleanup_tags() {
  if [[ ${#created_tags[@]} -gt 0 ]]; then
    git tag -d "${created_tags[@]}" >/dev/null
  fi
}
trap cleanup_tags ERR INT TERM

for tag in "${tags[@]}"; do
  git tag "$tag" "$head"
  created_tags+=("$tag")
done

FLOWERSEC_RELEASE_GATE_COMMIT="$head" \
FLOWERSEC_RELEASE_VERSION="$version" \
git push --atomic origin \
  "refs/heads/main:refs/heads/main" \
  "refs/tags/${tags[0]}" \
  "refs/tags/${tags[1]}" \
  "refs/tags/${tags[2]}"

created_tags=()
trap - ERR INT TERM
echo "released Flowersec $version from $head"
