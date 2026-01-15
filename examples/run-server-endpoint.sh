#!/usr/bin/env bash
set -euo pipefail

# Starts the demo server endpoint (yamux server) with a server-side ChannelInitGrant.
# Input can be either:
# - full JSON: {"grant_client":...,"grant_server":...}
# - or grant_server JSON itself

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

GRANT_FILE="${1:-}"
if [[ -n "$GRANT_FILE" && ! -f "$GRANT_FILE" ]]; then
  echo "grant file not found: $GRANT_FILE" >&2
  exit 1
fi

cd "$ROOT/examples"
if [[ -z "$GRANT_FILE" ]]; then
  exec go run ./go/server_endpoint
else
  exec go run ./go/server_endpoint --grant "$GRANT_FILE"
fi
