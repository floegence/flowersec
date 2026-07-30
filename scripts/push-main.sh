#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)
cd "$repo_root"

if [[ -n "$(git status --short)" ]]; then
  echo "main push requires a clean worktree" >&2
  exit 1
fi
if [[ "$(git symbolic-ref --short -q HEAD || true)" != "main" ]]; then
  echo "main push must run from the main worktree" >&2
  exit 1
fi

git fetch origin main
head=$(git rev-parse HEAD)
origin_main=$(git rev-parse origin/main)
if ! git merge-base --is-ancestor "$origin_main" "$head"; then
  echo "local main must be a fast-forward of origin/main" >&2
  exit 1
fi

make check

if [[ -n "$(git status --short)" || "$(git rev-parse HEAD)" != "$head" ]]; then
  echo "main gate changed the worktree or HEAD" >&2
  exit 1
fi
git fetch origin main
if [[ "$(git rev-parse origin/main)" != "$origin_main" ]]; then
  echo "origin/main changed while the main gate was running; synchronize and validate the new candidate" >&2
  exit 1
fi

FLOWERSEC_MAIN_GATE_COMMIT="$head" git push origin "refs/heads/main:refs/heads/main"
