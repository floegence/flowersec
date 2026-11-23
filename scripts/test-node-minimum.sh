#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)
cd "$repo_root"

minimum_node=${FLOWERSEC_NODE_MINIMUM_BIN:-}
if [[ "$minimum_node" != /*/node || ! -f "$minimum_node" || ! -x "$minimum_node" ]]; then
  echo "set FLOWERSEC_NODE_MINIMUM_BIN to the absolute path of the minimum runtime's node executable declared in toolchains.json" >&2
  exit 2
fi

export PATH="$(dirname -- "$minimum_node"):$PATH"
node scripts/toolchains.mjs --check-runtime node-minimum
make ts-build
make ts-test-short
