# Proxy Gateway Deployment Guide

This document describes how to run the deployable Flowersec proxy gateway (`flowersec-proxy-gateway`) as a standalone HTTP/WS gateway.

See also:

- Proxy protocol details: `docs/PROXY.md`
- Preset contract: `docs/PRESETS.md`
- Stable API surface: `docs/API_SURFACE.md`

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

Recommended v0.18.x shape:

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
    "preset_file": "./reference/presets/default/manifest.json"
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

- `proxy.preset_file`: stable preset manifest path
- `proxy.profile`: deprecated compatibility alias

Rules:

- do not set `proxy.preset_file` and `proxy.profile` together
- unknown config fields are rejected
- the old top-level `origin` field remains invalid

## Grant source model

Tunnel attach tokens are one-time use.

Each route therefore needs a fresh-grant source:

- `grant.file`
- `grant.command`

The gateway keeps a live session cache per route, reconnects lazily, fetches fresh grant material when needed, and retries stream open once.

It does not replay partially streamed HTTP bodies after mid-stream failure.

## Browser and tunnel boundaries

Keep these separate:

- `browser.allowed_origins`: browser -> gateway boundary
- `tunnel.origin`: gateway -> tunnel attach Origin

The gateway is L7 plaintext by design. Put TLS in front of it for real browser traffic.

## Reference presets

First-party preset examples:

- `reference/presets/default/manifest.json`
- `reference/presets/codeserver/manifest.json`

`codeserver` remains available as a deprecated migration preset, but named profiles are no longer part of the stable core surface.

## Operational checklist

- use dedicated browser-facing origins
- keep tunnel origin allow-lists aligned
- prefer command/file sources that can mint continuously
- use the health check at `GET /_flowersec/healthz`
