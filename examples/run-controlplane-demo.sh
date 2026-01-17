#!/usr/bin/env bash
set -euo pipefail

# Starts a minimal controlplane demo:
# - owns issuer private key in-process
# - writes tunnel keyset file (kid->pubkey) for tunnel server to load
# - exposes HTTP endpoint to mint ChannelInitGrant pairs
#
# Tunnel server is intentionally separate and should be started via:
#   FSEC_TUNNEL_ISSUER_KEYS_FILE=... ./examples/run-tunnel-server.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AUD="${FSEC_TUNNEL_AUD:-flowersec-tunnel:dev}"
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
ISSUER_ID="${FSEC_ISSUER_ID:-issuer-demo}"

TMP_DIR="${FSEC_DEMO_TMP_DIR:-$ROOT/examples/.tmp}"
KEYS_FILE="${FSEC_TUNNEL_ISSUER_KEYS_FILE:-$TMP_DIR/issuer_keys.json}"

mkdir -p "$TMP_DIR"

echo "Starting controlplane demo (listen=$LISTEN)"
echo "It will write tunnel issuer keyset to: $KEYS_FILE"
echo "Tunnel WS URL (hint for grants): $TUNNEL_URL"
echo "First stdout line is JSON: {\"controlplane_http_url\":\"...\",\"issuer_keys_file\":\"...\",\"tunnel_audience\":\"...\",\"tunnel_listen\":\"...\",\"tunnel_ws_path\":\"...\"}"

cd "$ROOT/examples"
exec go run ./go/controlplane_demo \
  --listen "$LISTEN" \
  --tunnel-url "$TUNNEL_URL" \
  --aud "$AUD" \
  --issuer-id "$ISSUER_ID" \
  --kid "$KID" \
  --issuer-keys-file "$KEYS_FILE"
