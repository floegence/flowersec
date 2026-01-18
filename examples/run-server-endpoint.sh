#!/usr/bin/env bash
set -euo pipefail

# Starts the demo server endpoint in "control-connected" mode:
# - It maintains a persistent Flowersec direct connection to the controlplane.
# - It receives grant_server over RPC notify.
# - For each grant_server, it attaches to the tunnel as role=server and serves RPC + echo streams.
#
# Notes:
# - Tunnel attach tokens are one-time use. Mint a new channel init for every new connection attempt.
# - For any non-local deployment, prefer wss:// (or TLS terminated at a reverse proxy).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ORIGIN="${FSEC_ORIGIN:-}"
if [[ -z "$ORIGIN" ]]; then
  echo "Missing explicit Origin."
  echo "Set FSEC_ORIGIN to the Origin you want the tunnel to accept, for example:"
  echo "  FSEC_ORIGIN=http://127.0.0.1:5173"
  exit 1
fi

CONTROL_FILE="${1:-}"
if [[ -z "$CONTROL_FILE" ]]; then
  echo "Missing controlplane JSON file." >&2
  echo "Tip (local dev): start controlplane demo and capture its JSON:" >&2
  echo '  CP_JSON="$(mktemp -t fsec-controlplane.XXXXXX.json)"' >&2
  echo '  ./examples/run-controlplane-demo.sh | tee "$CP_JSON"' >&2
  echo "Then start the server endpoint:" >&2
  echo '  FSEC_ORIGIN=http://127.0.0.1:5173 ./examples/run-server-endpoint.sh "$CP_JSON"' >&2
  exit 1
fi
if [[ -n "$CONTROL_FILE" && ! -f "$CONTROL_FILE" ]]; then
  echo "controlplane file not found: $CONTROL_FILE" >&2
  exit 1
fi

cd "$ROOT/examples"
exec go run ./go/server_endpoint --origin "$ORIGIN" --control "$CONTROL_FILE"
