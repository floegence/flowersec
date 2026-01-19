# Tunnel Deployment Guide

This document describes how to run the deployable Flowersec tunnel server (`flowersec-tunnel`) as a standalone service.

The tunnel is an untrusted rendezvous: it verifies one-time attach tokens and forwards bytes between endpoints, but it cannot decrypt application data after the E2EE handshake completes.

## Install (no clone)

### Option A: `go install`

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-tunnel@latest
flowersec-tunnel --version
```

Note: `go install` requires Go 1.25.x.

### Option B: GitHub Releases

Download prebuilt binaries (and `checksums.txt`) from the GitHub Releases page.

### Option C: Docker image (recommended)

```bash
docker pull ghcr.io/floegence/flowersec-tunnel:latest
```

## Required configuration

The tunnel requires these inputs:

- `issuer_keys_file`: JSON keyset containing issuer public keys (`kid -> ed25519 pubkey`)
- `aud`: expected token audience (must match the controlplane-issued token payload)
- `iss`: expected token issuer (must match the controlplane-issued token payload)
- `allow_origin`: Origin allow-list (required; requests without `Origin` are rejected by default)

The issuer keyset is owned by your controlplane (it must publish the issuer public keys so the tunnel can verify tokens).

Allowed Origin entries support:

- Full Origin values (for example `https://example.com` or `http://127.0.0.1:5173`)
- Hostnames (port ignored, for example `example.com`)
- Hostname + port (for example `example.com:5173`)
- Wildcard hostnames (for example `*.example.com`)
- Exact non-standard values (for example `null`)

## Flags and environment variables

All settings are available as flags. For container deployments, the tunnel also supports `FSEC_TUNNEL_*` environment variables as defaults (flags override env).

| Flag | Env var | Notes |
| --- | --- | --- |
| `--listen` | `FSEC_TUNNEL_LISTEN` | default `127.0.0.1:0` |
| `--ws-path` | `FSEC_TUNNEL_WS_PATH` | default `/ws` |
| `--issuer-keys-file` | `FSEC_TUNNEL_ISSUER_KEYS_FILE` | required |
| `--aud` | `FSEC_TUNNEL_AUD` | required |
| `--iss` | `FSEC_TUNNEL_ISS` | required |
| `--allow-origin` (repeatable) | `FSEC_TUNNEL_ALLOW_ORIGIN` | comma-separated list in env |
| `--allow-no-origin` | `FSEC_TUNNEL_ALLOW_NO_ORIGIN` | discouraged; for non-browser clients |
| `--tls-cert-file` | `FSEC_TUNNEL_TLS_CERT_FILE` | enable TLS (requires key file too) |
| `--tls-key-file` | `FSEC_TUNNEL_TLS_KEY_FILE` | enable TLS (requires cert file too) |
| `--metrics-listen` | `FSEC_TUNNEL_METRICS_LISTEN` | empty disables metrics server |
| `--max-conns` | `FSEC_TUNNEL_MAX_CONNS` | `0` uses default |
| `--max-channels` | `FSEC_TUNNEL_MAX_CHANNELS` | `0` uses default |
| `--max-total-pending-bytes` | `FSEC_TUNNEL_MAX_TOTAL_PENDING_BYTES` | `0` disables the global limit |
| `--write-timeout` | `FSEC_TUNNEL_WRITE_TIMEOUT` | `0` disables per-frame write timeout |
| `--max-write-queue-bytes` | `FSEC_TUNNEL_MAX_WRITE_QUEUE_BYTES` | `0` uses default |

See `flowersec-tunnel --help` for the full help text.

## Health checks

The tunnel serves a basic health endpoint:

- `GET /healthz` → `200 OK` and `ok`

## Metrics

The tunnel exposes Prometheus metrics on a dedicated metrics server (disabled by default).

- Enable: set `--metrics-listen 0.0.0.0:9090` (or `FSEC_TUNNEL_METRICS_LISTEN=0.0.0.0:9090`)
- Scrape: `GET /metrics`
- Toggle at runtime:
  - Disable metrics: send `SIGUSR2`
  - Re-enable metrics: send `SIGUSR1`

## Key rotation

To rotate issuer keys without downtime:

1. Update the issuer keyset JSON file on disk (keep overlapping keys during rotation).
2. Send `SIGHUP` to the tunnel process to reload the keyset (`--issuer-keys-file`).

## Docker examples

### Minimal tunnel (no TLS)

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$PWD/issuer_keys.json:/etc/flowersec/issuer_keys.json:ro" \
  -e FSEC_TUNNEL_LISTEN=0.0.0.0:8080 \
  -e FSEC_TUNNEL_WS_PATH=/ws \
  -e FSEC_TUNNEL_ISSUER_KEYS_FILE=/etc/flowersec/issuer_keys.json \
  -e FSEC_TUNNEL_AUD=flowersec-tunnel:prod \
  -e FSEC_TUNNEL_ISS=issuer-prod \
  -e FSEC_TUNNEL_ALLOW_ORIGIN=https://your-web-origin.example \
  ghcr.io/floegence/flowersec-tunnel:latest
```

### Tunnel with metrics

```bash
docker run --rm \
  -p 8080:8080 \
  -p 9090:9090 \
  -v "$PWD/issuer_keys.json:/etc/flowersec/issuer_keys.json:ro" \
  -e FSEC_TUNNEL_LISTEN=0.0.0.0:8080 \
  -e FSEC_TUNNEL_METRICS_LISTEN=0.0.0.0:9090 \
  -e FSEC_TUNNEL_ISSUER_KEYS_FILE=/etc/flowersec/issuer_keys.json \
  -e FSEC_TUNNEL_AUD=flowersec-tunnel:prod \
  -e FSEC_TUNNEL_ISS=issuer-prod \
  -e FSEC_TUNNEL_ALLOW_ORIGIN=https://your-web-origin.example \
  ghcr.io/floegence/flowersec-tunnel:latest
```

## Security notes

- For any non-local deployment, prefer `wss://` (or terminate TLS at a reverse proxy).
- Keep issuer keys and tunnel tokens secret; never log PSKs.
- Avoid `--allow-no-origin` unless you fully control all clients and understand the risk.
