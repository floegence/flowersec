#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
minimum_go=${FLOWERSEC_GO_MINIMUM_BIN:-}
if [[ "$minimum_go" != /*/go || ! -f "$minimum_go" || ! -x "$minimum_go" ]]; then
  echo "set FLOWERSEC_GO_MINIMUM_BIN to the absolute path of the Go SDK minimum compiler declared in toolchains.json" >&2
  exit 2
fi
export PATH="$(dirname -- "$minimum_go"):$PATH" GOTOOLCHAIN=local GOWORK=off
node scripts/toolchains.mjs --check-runtime go-minimum
go -C examples/go/parity test -mod=readonly -timeout=5m ./...
temporary_root=${TMPDIR:-$PWD/.flowersec}
mkdir -p -- "$temporary_root"
consumer=$(mktemp -d "$temporary_root/go-minimum.XXXXXX")
trap 'rm -rf -- "$consumer"' EXIT
core=$(go -C flowersec-go list -m)
adapter=$(go -C flowersec-go/adapters/sqlite list -m)
version=$(go -C flowersec-go/adapters/sqlite list -m -f '{{.Version}}' "$core")
cp flowersec-go/adapters/sqlite/go.{mod,sum} "$consumer/"
go -C "$consumer" mod edit -module=example.com/flowersec-consumer -require="$adapter@$version" \
  -replace="$core=$PWD/flowersec-go" -replace="$adapter=$PWD/flowersec-go/adapters/sqlite"
go -C "$consumer" test -mod=readonly -timeout=5m "$adapter"
go -C flowersec-go test -mod=readonly -timeout=5m . ./controlplane ./cmd/...
