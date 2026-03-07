# Proxy Gateway Deployment Guide

This document describes how to run the deployable Flowersec proxy gateway (`flowersec-proxy-gateway`) as a standalone HTTP/WS gateway.

The gateway is an L7 plaintext component by design: it accepts browser HTTP/WS traffic and forwards it to a Flowersec server endpoint over encrypted Flowersec proxy streams.

See also:

- Proxy protocol details: `docs/PROXY.md`
- Tunnel deployment: `docs/TUNNEL_DEPLOYMENT.md`
- Stable API surface: `docs/API_SURFACE.md`

## Install (no clone)

### Option A: `go install`

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-proxy-gateway@latest
flowersec-proxy-gateway --version
```

Note: `go install` requires Go 1.26.x.

### Option B: GitHub Releases

Download either of these release assets:

- `flowersec-proxy-gateway_X.Y.Z_<os>_<arch>.tar.gz` (or `.zip` on Windows)
- `flowersec-tools_X.Y.Z_<os>_<arch>.tar.gz` (or `.zip`), which also includes `flowersec-proxy-gateway` under `bin/`

### Option C: Docker image (recommended)

```bash
docker pull ghcr.io/floegence/flowersec-proxy-gateway:latest
```

## Configuration model

The gateway is configured with a JSON file passed via `--config` (or `FSEC_PROXY_GATEWAY_CONFIG`).

Example:

```json
{
  "listen": "127.0.0.1:8080",
  "origin": "https://gateway.example.com",
  "routes": [
    {
      "host": "code.example.com",
      "grant": {
        "file": "./grants/code.example.com.json"
      }
    },
    {
      "host": "shell.example.com",
      "grant": {
        "command": ["./bin/mint-gateway-grant", "shell.example.com"],
        "timeout_ms": 10000
      }
    }
  ]
}
```

Fields:

- `listen`: TCP listen address. Empty uses `127.0.0.1:0`.
- `origin`: explicit Origin value used for tunnel connects. It must be allowed by the tunnel.
- `routes[*].host`: canonical route host. Matching is **host-only**; port is ignored.
- `routes[*].grant.file`: read a fresh client grant from a JSON file.
- `routes[*].grant.command`: execute a command and read a fresh client grant JSON object from stdout.
- `routes[*].grant.timeout_ms`: optional timeout for the command source. Default: `10000`.

## Important: grants are one-time

Flowersec tunnel attach tokens are single-use.

This means `flowersec-proxy-gateway` must not rely on a static grant that is reused forever.
Instead, each route must point to a **grant source** capable of providing a fresh `grant_client` when the gateway needs to reconnect.

Recommended patterns:

- **File source**: an external controlplane/sidecar keeps writing the latest fresh `grant_client` JSON to a file path.
- **Command source**: the gateway executes a local minting command that fetches or mints a fresh `grant_client` on demand.

The gateway caches a live Flowersec session per route and reconnects lazily when that session is gone.
If `OpenStream(...)` fails because the cached session is stale, the gateway discards it, fetches a fresh grant from the configured source, reconnects, and retries opening the stream once.

The gateway does **not** replay partially streamed HTTP request bodies after mid-stream failures.
Only the initial stream open is retried.

## Routing semantics

Route matching uses a canonical host key.

Examples:

- `Example.COM` → `example.com`
- `example.com:8443` → `example.com`
- `[::1]:8080` → `::1`

Ports do not create distinct routes.
If two configured routes collapse to the same canonical host, startup fails.

## Health check

The gateway exposes a lightweight health endpoint:

- `GET /_flowersec/healthz` → `200 OK` and `ok`

This endpoint is reserved by the gateway implementation and is not proxied upstream.

## Docker example

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$PWD/gateway.json:/etc/flowersec/gateway.json:ro" \
  -v "$PWD/grants:/etc/flowersec/grants:ro" \
  -e FSEC_PROXY_GATEWAY_CONFIG=/etc/flowersec/gateway.json \
  ghcr.io/floegence/flowersec-proxy-gateway:latest
```

Then probe:

```bash
curl http://127.0.0.1:8080/_flowersec/healthz
```

## Operational notes

- The gateway is plaintext at L7 by design. Place TLS termination in front of it for non-local browser traffic.
- Use a dedicated gateway origin / cookie scope for proxied applications.
- Keep the gateway `origin` value aligned with the tunnel `allow_origin` configuration.
- For production, prefer a grant source that can mint or fetch fresh grants continuously rather than shipping a long-lived static JSON file.
