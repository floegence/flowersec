#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)
cd "$repo_root"

if [[ -n "$(git status --short)" ]]; then
  echo "main push requires a clean worktree" >&2
  exit 1
fi
branch=$(git symbolic-ref --short -q HEAD || true)
if [[ "$branch" != "main" && "$branch" != "release/5.x" ]]; then
  echo "push must run from main or release/5.x" >&2
  exit 1
fi

head=$(git rev-parse HEAD)
if [[ "$branch" == "release/5.x" ]]; then
  maintenance_base="74e6ae7d5d2a992f4a33bf05259d1b786c386f81"
  [[ "$(git rev-parse '5.6.0^{commit}')" == "$maintenance_base" ]] || exit 1
  git merge-base --is-ancestor "$maintenance_base" "$head"
  node -e 'if (JSON.parse(require("fs").readFileSync("flowersec-ts/package.json")).version.split(".")[0] !== "5") process.exit(1)'
fi

# A maintenance line may be created only from the pinned, validated baseline.
remote_exists=true
if [[ "$branch" == "release/5.x" ]]; then
  remote_ref=$(git ls-remote --heads origin "refs/heads/$branch")
  [[ -n "$remote_ref" ]] || remote_exists=false
fi
if $remote_exists; then
  git fetch origin "$branch"
  origin_main=$(git rev-parse "origin/$branch")
else
  origin_main="$maintenance_base"
fi
if ! git merge-base --is-ancestor "$origin_main" "$head"; then
  echo "local main must be a fast-forward of origin/main" >&2
  exit 1
fi

make test

if [[ -n "$(git status --short)" || "$(git rev-parse HEAD)" != "$head" ]]; then
  echo "main gate changed the worktree or HEAD" >&2
  exit 1
fi
if $remote_exists; then
  git fetch origin "$branch"
  if [[ "$(git rev-parse "origin/$branch")" != "$origin_main" ]]; then
    echo "remote release branch changed while the gate was running; synchronize and validate the new candidate" >&2
    exit 1
  fi
elif [[ -n "$(git ls-remote --heads origin "refs/heads/$branch")" ]]; then
  echo "remote maintenance branch was created while the gate was running; synchronize and validate the new candidate" >&2
  exit 1
fi

FLOWERSEC_PUSH_MAIN_SHA="$head" git push origin "refs/heads/$branch:refs/heads/$branch"
