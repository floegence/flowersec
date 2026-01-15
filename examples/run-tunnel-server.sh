#!/usr/bin/env bash
set -euo pipefail

# Starts the real deliverable tunnel server: go/cmd/flowersec-tunnel.
# This script intentionally does NOT generate keys: issuer keys are owned by the controlplane.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AUD="${FSEC_TUNNEL_AUD:-flowersec-tunnel:dev}"
LISTEN="${FSEC_TUNNEL_LISTEN:-127.0.0.1:0}"
WS_PATH="${FSEC_TUNNEL_WS_PATH:-/ws}"

KEYS_FILE="${FSEC_TUNNEL_ISSUER_KEYS_FILE:-}"

if [[ -z "$KEYS_FILE" ]]; then
  echo "Missing issuer keys file."
  echo "Set FSEC_TUNNEL_ISSUER_KEYS_FILE=/path/to/issuer_keys.json"
  echo "Tip (local dev): start controlplane demo which generates it:"
  echo "  ./examples/run-controlplane-demo.sh"
  exit 1
fi

echo "Starting tunnel server (aud=$AUD, listen=$LISTEN, ws_path=$WS_PATH)"
echo "First stdout line is JSON: {\"listen\":\"...\",\"ws_path\":\"...\"}"
cd "$ROOT/go"
exec go run ./cmd/flowersec-tunnel \
  --listen "$LISTEN" \
  --ws-path "$WS_PATH" \
  --issuer-keys-file "$KEYS_FILE" \
  --aud "$AUD"
