#!/usr/bin/env bash
set -euo pipefail

# Starts the demo server endpoint (yamux server) with a server-side ChannelInitGrant.
# Input can be either:
# - full JSON: {"grant_client":...,"grant_server":...}
# - or grant_server JSON itself
#
# Notes:
# - This endpoint attaches to the tunnel as role=server and should be paired with a role=client tunnel client.
# - Tunnel attach tokens are one-time use. If you reuse a channel JSON, the tunnel will close the connection.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ORIGIN="${FSEC_ORIGIN:-}"
if [[ -z "$ORIGIN" ]]; then
  echo "Missing explicit Origin."
  echo "Set FSEC_ORIGIN to the Origin you want the tunnel to accept, for example:"
  echo "  FSEC_ORIGIN=http://127.0.0.1:5173"
  exit 1
fi

GRANT_FILE="${1:-}"
if [[ -n "$GRANT_FILE" && ! -f "$GRANT_FILE" ]]; then
  echo "grant file not found: $GRANT_FILE" >&2
  exit 1
fi

cd "$ROOT/examples"
if [[ -z "$GRANT_FILE" ]]; then
  exec go run ./go/server_endpoint --origin "$ORIGIN"
else
  exec go run ./go/server_endpoint --origin "$ORIGIN" --grant "$GRANT_FILE"
fi
