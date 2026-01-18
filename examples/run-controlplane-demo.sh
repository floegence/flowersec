#!/usr/bin/env bash
set -euo pipefail

# Starts a minimal controlplane demo:
# - owns issuer private key in-process
# - writes tunnel keyset file (kid->pubkey) for tunnel server to load
# - exposes HTTP endpoint to mint ChannelInitGrant pairs
#
# Tunnel server is intentionally separate and should be started via:
#   FSEC_TUNNEL_ISSUER_KEYS_FILE=... ./examples/run-tunnel-server.sh
#
# Notes:
# - Tokens minted by the controlplane are one-time use. Reusing the same channel JSON will trigger token replay.
# - For any non-local deployment, prefer wss:// (or TLS terminated at a reverse proxy).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AUD="${FSEC_TUNNEL_AUD:-flowersec-tunnel:dev}"
ISSUER_ID="${FSEC_ISSUER_ID:-issuer-demo}"
TUNNEL_LISTEN="${FSEC_TUNNEL_LISTEN:-127.0.0.1:8080}"
TUNNEL_WS_PATH="${FSEC_TUNNEL_WS_PATH:-/ws}"
TUNNEL_SCHEME="${FSEC_TUNNEL_SCHEME:-ws}"
if [[ -z "${FSEC_TUNNEL_URL:-}" ]]; then
  # If the user provided TLS materials for the tunnel server, default to wss://.
  # This keeps the controlplane-issued tunnel_url consistent without requiring manual edits.
  if [[ -n "${FSEC_TUNNEL_TLS_CERT_FILE:-}" || -n "${FSEC_TUNNEL_TLS_KEY_FILE:-}" ]]; then
    TUNNEL_SCHEME="wss"
  fi
  TUNNEL_URL="${TUNNEL_SCHEME}://${TUNNEL_LISTEN}${TUNNEL_WS_PATH}"
else
  TUNNEL_URL="${FSEC_TUNNEL_URL}"
fi
LISTEN="${FSEC_CONTROLPLANE_LISTEN:-127.0.0.1:0}"
KID="${FSEC_ISSUER_KID:-k1}"

TMP_DIR="${FSEC_DEMO_TMP_DIR:-$ROOT/examples/.tmp}"
KEYS_FILE="${FSEC_TUNNEL_ISSUER_KEYS_FILE:-$TMP_DIR/issuer_keys.json}"

mkdir -p "$TMP_DIR"

echo "Starting controlplane demo (listen=$LISTEN)" >&2
echo "It will write tunnel issuer keyset to: $KEYS_FILE" >&2
echo "Tunnel WS URL (hint for grants): $TUNNEL_URL" >&2
echo "First stdout line is JSON (machine-readable)." >&2

cd "$ROOT/examples"
exec go run ./go/controlplane_demo \
  --listen "$LISTEN" \
  --tunnel-url "$TUNNEL_URL" \
  --aud "$AUD" \
  --issuer-id "$ISSUER_ID" \
  --kid "$KID" \
  --issuer-keys-file "$KEYS_FILE"
