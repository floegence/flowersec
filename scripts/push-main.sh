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

evidence_report=${TRANSPORT_V2_EVIDENCE_REPORT:-}
evidence_base=${TRANSPORT_V2_BASE_SHA:-}
if [[ "$evidence_report" != /* || ! -f "$evidence_report" || -L "$evidence_report" || "${evidence_report##*/}" != report.json ]]; then
  echo "main push requires an absolute, regular, non-symlink signed evidence report" >&2
  exit 2
fi
if [[ ! "$evidence_base" =~ ^[0-9a-f]{40}$ ]]; then
  echo "main push requires a full lowercase evidence base SHA" >&2
  exit 2
fi

git fetch origin main
head=$(git rev-parse HEAD)
origin_main=$(git rev-parse origin/main)
if ! git merge-base --is-ancestor "$origin_main" "$head"; then
  echo "local main must be a fast-forward of origin/main" >&2
  exit 1
fi

TRANSPORT_V2_EVIDENCE_REPORT="$evidence_report" \
TRANSPORT_V2_BASE_SHA="$evidence_base" \
make transport-v2-signed-evidence-check

receipt_script="$repo_root/scripts/main-gate-receipt.mjs"
set +e
node "$receipt_script" verify \
  --head "$head" \
  --evidence-report "$evidence_report" \
  --evidence-base "$evidence_base"
receipt_status=$?
set -e
case "$receipt_status" in
  0)
    echo "[flowersec] reusing the exact main gate receipt for $head"
    ;;
  3)
    make check
    TRANSPORT_V2_EVIDENCE_REPORT="$evidence_report" \
    TRANSPORT_V2_BASE_SHA="$evidence_base" \
    node "$receipt_script" write --head "$head" --origin-main "$origin_main" \
      --evidence-report "$evidence_report" --evidence-base "$evidence_base"
    ;;
  *)
    echo "main gate receipt exists but is invalid; refusing an untracked gate result" >&2
    exit "$receipt_status"
    ;;
esac

if [[ -n "$(git status --short)" || "$(git rev-parse HEAD)" != "$head" ]]; then
  echo "main gate changed the worktree or HEAD" >&2
  exit 1
fi
git fetch origin main
if [[ "$(git rev-parse origin/main)" != "$origin_main" ]]; then
  echo "origin/main changed while the main gate was running; synchronize and validate the new candidate" >&2
  exit 1
fi

git push origin "refs/heads/main:refs/heads/main"
