#!/usr/bin/env bash
set -euo pipefail

# Starts the real deliverable tunnel server: go/cmd/flowersec-tunnel.
# This script intentionally does NOT generate keys: issuer keys are owned by the controlplane.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AUD="${FSEC_TUNNEL_AUD:-flowersec-tunnel:dev}"
LISTEN="${FSEC_TUNNEL_LISTEN:-127.0.0.1:0}"
WS_PATH="${FSEC_TUNNEL_WS_PATH:-/ws}"

KEYS_FILE="${FSEC_TUNNEL_ISSUER_KEYS_FILE:-}"
ALLOW_ORIGIN="${FSEC_TUNNEL_ALLOW_ORIGIN:-}"
TLS_CERT_FILE="${FSEC_TUNNEL_TLS_CERT_FILE:-}"
TLS_KEY_FILE="${FSEC_TUNNEL_TLS_KEY_FILE:-}"

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
ALLOW_ORIGIN_ARGS=()
if [[ -n "$ALLOW_ORIGIN" ]]; then
  ALLOW_ORIGIN_ARGS+=(--allow-origin "$ALLOW_ORIGIN")
fi
TLS_ARGS=()
if [[ -n "$TLS_CERT_FILE" || -n "$TLS_KEY_FILE" ]]; then
  if [[ -z "$TLS_CERT_FILE" || -z "$TLS_KEY_FILE" ]]; then
    echo "TLS is enabled but certificate/key is missing."
    echo "Set both:"
    echo "  FSEC_TUNNEL_TLS_CERT_FILE=/path/to/cert.pem"
    echo "  FSEC_TUNNEL_TLS_KEY_FILE=/path/to/key.pem"
    exit 1
  fi
  TLS_ARGS+=(--tls-cert-file "$TLS_CERT_FILE" --tls-key-file "$TLS_KEY_FILE")
fi
exec go run ./cmd/flowersec-tunnel \
  --listen "$LISTEN" \
  --ws-path "$WS_PATH" \
  --issuer-keys-file "$KEYS_FILE" \
  --aud "$AUD" \
  "${ALLOW_ORIGIN_ARGS[@]}" \
  "${TLS_ARGS[@]}"
