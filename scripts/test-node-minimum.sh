#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)
cd "$repo_root"

minimum_node=${FLOWERSEC_NODE_MINIMUM_BIN:-}
if [[ -z "$minimum_node" || "$minimum_node" != /* || ! -x "$minimum_node" ]]; then
  echo "set FLOWERSEC_NODE_MINIMUM_BIN to the absolute path of the Node minimum executable declared in toolchains.json" >&2
  exit 2
fi

export PATH="$(dirname -- "$minimum_node"):$PATH"
"$minimum_node" scripts/toolchains.mjs --check-runtime node-minimum
node scripts/toolchains.mjs --check-runtime node-minimum
make ts-build ts-test-short
