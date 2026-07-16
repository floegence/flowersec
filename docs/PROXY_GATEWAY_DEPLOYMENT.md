# Proxy Gateway Deployment Guide

This document describes how to run the deployable Flowersec proxy gateway (`flowersec-proxy-gateway`) as a standalone HTTP/WS gateway.

See also:

- Proxy protocol details: `docs/PROXY.md`
- Preset contract: `docs/PRESETS.md`

## Install

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-proxy-gateway@latest
flowersec-proxy-gateway --version
```

Or use the published Docker image:

```bash
docker pull ghcr.io/floegence/flowersec-proxy-gateway:latest
```

## Configuration model

Configuration is a JSON file passed via `--config` or `FSEC_PROXY_GATEWAY_CONFIG`.

Recommended configuration:

```json
{
  "listen": "127.0.0.1:8080",
  "browser": {
    "allowed_origins": ["https://gateway.example.com"]
  },
  "tunnel": {
    "origin": "https://gateway.example.com"
  },
  "proxy": {
    "preset_file": "./reference/presets/default/manifest.json",
    "timeout_ms": 30000
  },
  "routes": [
    {
      "host": "code.example.com",
      "grant": {
        "command": ["./bin/mint-gateway-grant", "code.example.com"],
        "timeout_ms": 10000
      }
    }
  ]
}
```

Important fields:

- `proxy.preset_file`: preset manifest path
- `proxy.timeout_ms`: optional gateway-wide default request timeout override
- `proxy.profile`: deprecated compatibility alias

Rules:

- do not set `proxy.preset_file` and `proxy.profile` together
- `proxy.timeout_ms`, when set, must be a positive integer and overrides the preset `limits.timeout_ms`
- unknown config fields are rejected
- the old top-level `origin` field remains invalid

## Grant source model

Tunnel attach tokens are one-time use.

Each route therefore needs a fresh-grant source:

- `grant.file`
- `grant.command`

The gateway keeps a live session cache per route, reconnects lazily, fetches fresh grant material when needed, and retries stream open once. If the fresh grant load or fresh session open fails, the request fails; the gateway must not fall back to a previous one-time grant or turn reconnect into a generic retry loop.

It does not replay partially streamed HTTP bodies after mid-stream failure.

## Browser and tunnel boundaries

Keep these separate:

- `browser.allowed_origins`: browser -> gateway HTTP/WS boundary
- `tunnel.origin`: gateway -> tunnel attach Origin

The gateway is L7 plaintext by design. Put TLS in front of it for real browser traffic.

For HTTP requests, the gateway rejects unsafe or credentialed browser traffic unless the browser boundary is satisfied, and it preserves the browser's real HTTP `Origin` header upstream instead of rewriting it to `tunnel.origin`.

## Reference presets

First-party preset examples:

- `reference/presets/default/manifest.json`
- `reference/presets/codeserver/manifest.json`

`codeserver` remains available only as a static compatibility manifest. The gateway does not accept it through `proxy.profile` or any Go/TypeScript built-in preset resolver.

## Operational checklist

- use dedicated browser-facing origins
- keep tunnel origin allow-lists aligned
- prefer command/file sources that can mint continuously
- use the health check at `GET /_flowersec/healthz`

## Go reconnect/liveness checklist

- Go tunnel clients and endpoints use acknowledged Yamux PING probes for connection liveness. Policy watch/lease state and authorization state stay outside that path.
- Direct Go connects keep automatic liveness disabled by default unless the caller opts in.
- Encrypted-record `Ping()` reports local send completion only and must not be treated as a peer health check.
- Gateway stream open retries at most once after invalidating the stale cached session and loading fresh grant material.
- Fresh grant failure fails the request and never reuses an old one-time attach token.
- Tunnel replacement keeps compatibility constraints for same `channel_id` attaches: `init_exp`, `idle_timeout_seconds`, tenant, and rate limits remain enforced.
- Tunnel websocket writes use the configured per-frame write timeout so blackholed or half-open peers are closed instead of pinning the relay.
