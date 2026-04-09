# Tunnel Deployment Guide

This document describes how to run the deployable Flowersec tunnel server (`flowersec-tunnel`) as a standalone service.

The tunnel is an untrusted rendezvous: it verifies one-time attach tokens and forwards bytes between endpoints, but it cannot decrypt application data after the E2EE handshake completes.

## Install (no clone)

### Option A: `go install`

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-tunnel@latest
flowersec-tunnel --version
```

Note: `go install` requires Go 1.25.9+.

### Option B: GitHub Releases

Download prebuilt binaries (and `checksums.txt`) from the GitHub Releases page.

### Option C: Docker image (recommended)

```bash
docker pull ghcr.io/floegence/flowersec-tunnel:latest
```

## Required configuration

The tunnel requires an attach verifier and an Origin allow-list.

### Verifier mode A: single tenant

The legacy single-tenant mode requires these inputs:

- `issuer_keys_file`: JSON keyset containing issuer public keys (see format below)
- `aud`: expected token audience (must match the controlplane-issued token payload)
- `iss`: expected token issuer (must match the controlplane-issued token payload)
- `allow_origin`: Origin allow-list (required; requests without `Origin` are rejected by default)

### Verifier mode B: multi tenant

The multi-tenant mode replaces `issuer_keys_file + aud + iss` with `tenants_file`.

Tenant file format:

```json
{
  "tenants": [
    {
      "id": "env_env_123",
      "aud": "redeven-custom-tunnel:env_env_123",
      "iss": "https://region.example/custom/env/env_env_123",
      "issuer_keys_file": "/etc/flowersec/issuer_keys.json"
    }
  ]
}
```

Notes:

- `id` is optional and is used only for logs/ops visibility.
- Matching is exact on `(aud, iss)`.
- A single tunnel process and a single websocket URL can therefore serve many environments/tenants safely, as long as each tenant has a distinct auth scope.
- `--tenants-file` is mutually exclusive with `--issuer-keys-file`, `--aud`, and `--iss`.

### Optional policy backend

If you need active blocking instead of verify-only attach, the tunnel can call an external authorizer:

- `attach_authorizer_url`: allow/deny at attach time and return a short lease
- `observe_authorizer_url`: periodically report active channels and receive lease refresh / kill decisions
- `observe_authorizer_url` requires `attach_authorizer_url`

This keeps tunnel token verification generic while allowing a product-specific control plane to enforce binding, quota, revoke, or abuse policies.

The issuer keyset is owned by your controlplane (it must publish the issuer public keys so the tunnel can verify tokens).

Keyset file format (produced by `flowersec-issuer-keygen`):

```json
{
  "keys": [
    { "kid": "k1", "pubkey_b64u": "..." }
  ]
}
```

For local development, you can generate a keypair and the corresponding tunnel keyset file using:

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-issuer-keygen@latest
flowersec-issuer-keygen --out-dir ./keys
```

No-Go option: download and extract `flowersec-tools_X.Y.Z_<os>_<arch>.tar.gz` (or `.zip`) from the GitHub Release and run `./bin/flowersec-issuer-keygen`.

This writes:

- `./keys/issuer_key.json` (private signing key; keep it secret)
- `./keys/issuer_keys.json` (public keyset for the tunnel)

On Unix-like systems, the output directory is created with owner-only permissions (`0700`) by default.

Tip: the helper tools support env defaults (flags override env). See `flowersec-issuer-keygen --help` and `flowersec-channelinit --help`.

Allowed Origin entries support:

- Full Origin values (for example `https://example.com` or `http://127.0.0.1:5173`)
- Hostnames (port ignored, for example `example.com`)
- Hostname + port (for example `example.com:5173`)
- Wildcard hostnames (for example `*.example.com`; subdomains only, does not match `example.com`)
- Exact non-standard values (for example `null`)

## Flags and environment variables

All settings are available as flags. For container deployments, the tunnel also supports `FSEC_TUNNEL_*` environment variables as defaults (flags override env).

| Flag | Env var | Notes |
| --- | --- | --- |
| `--listen` | `FSEC_TUNNEL_LISTEN` | default `127.0.0.1:0` |
| `--advertise-host` | `FSEC_TUNNEL_ADVERTISE_HOST` | public host[:port] used only for ready URLs (useful when listening on `0.0.0.0`) |
| `--ws-path` | `FSEC_TUNNEL_WS_PATH` | default `/ws` |
| `--tenants-file` | `FSEC_TUNNEL_TENANTS_FILE` | multi-tenant verifier config; mutually exclusive with `--issuer-keys-file` + `--aud` + `--iss` |
| `--issuer-keys-file` | `FSEC_TUNNEL_ISSUER_KEYS_FILE` | required |
| `--aud` | `FSEC_TUNNEL_AUD` | required |
| `--iss` | `FSEC_TUNNEL_ISS` | required |
| `--allow-origin` (repeatable) | `FSEC_TUNNEL_ALLOW_ORIGIN` | comma-separated list in env |
| `--allow-no-origin` | `FSEC_TUNNEL_ALLOW_NO_ORIGIN` | discouraged; for non-browser clients |
| `--tls-cert-file` | `FSEC_TUNNEL_TLS_CERT_FILE` | enable TLS (requires key file too) |
| `--tls-key-file` | `FSEC_TUNNEL_TLS_KEY_FILE` | enable TLS (requires cert file too) |
| `--metrics-listen` | `FSEC_TUNNEL_METRICS_LISTEN` | empty disables metrics server |
| `--stats-listen` | `FSEC_TUNNEL_STATS_LISTEN` | empty disables `/stats/v1/bandwidth` server |
| `--max-conns` | `FSEC_TUNNEL_MAX_CONNS` | `>= 0`; `0` uses default |
| `--max-channels` | `FSEC_TUNNEL_MAX_CHANNELS` | `>= 0`; `0` uses default |
| `--max-total-pending-bytes` | `FSEC_TUNNEL_MAX_TOTAL_PENDING_BYTES` | `>= 0`; `0` disables the global limit |
| `--write-timeout` | `FSEC_TUNNEL_WRITE_TIMEOUT` | `>= 0`; `0` disables per-frame write timeout |
| `--max-write-queue-bytes` | `FSEC_TUNNEL_MAX_WRITE_QUEUE_BYTES` | `>= 0`; `0` uses default |
| `--attach-authorizer-url` | `FSEC_TUNNEL_ATTACH_AUTHORIZER_URL` | optional attach policy endpoint |
| `--observe-authorizer-url` | `FSEC_TUNNEL_OBSERVE_AUTHORIZER_URL` | optional runtime policy endpoint |
| `--authorizer-header` (repeatable) | `FSEC_TUNNEL_AUTHORIZER_HEADER` | extra HTTP header(s) forwarded to authorizer requests (comma-separated in env) |
| `--policy-request-timeout` | `FSEC_TUNNEL_POLICY_REQUEST_TIMEOUT` | default `3s` |
| `--policy-observe-interval` | `FSEC_TUNNEL_POLICY_OBSERVE_INTERVAL` | default `10s` |
| `--policy-batch-size` | `FSEC_TUNNEL_POLICY_BATCH_SIZE` | default `256` |

See `flowersec-tunnel --help` for the full help text.

## Health checks

The tunnel serves a basic health endpoint:

- `GET /healthz` → `200 OK` and `ok`

## Metrics

The tunnel exposes Prometheus metrics on a dedicated metrics server (disabled by default).

- Enable: set `--metrics-listen 0.0.0.0:9090` (or `FSEC_TUNNEL_METRICS_LISTEN=0.0.0.0:9090`)
- Scrape: `GET /metrics`
- Toggle at runtime (Unix-like systems only):
  - Disable metrics: send `SIGUSR2`
  - Re-enable metrics: send `SIGUSR1`

## Key rotation

To rotate issuer keys without downtime:

1. Update the issuer keyset JSON file on disk (keep overlapping keys during rotation).
2. On Unix-like systems, send `SIGHUP` to the tunnel process to reload the verifier backing config (`--issuer-keys-file` or `--tenants-file`).

## Policy authorizer

The policy hooks are intentionally protocol-generic:

- attach request: channel identity, `(aud, iss)`, role, endpoint instance, token metadata
- observe request: channel batch with cumulative `bytes_to_client` and `bytes_to_server`
- decision: `allowed` plus `lease_expires_at_unix_ms`

Recommended operating model:

1. Use a short lease (for example 20-30 seconds).
2. Keep `policy_observe_interval` comfortably below the lease duration.
3. Treat missing lease refresh as fail-closed.

This makes it possible to block generic relay abuse without moving product-specific semantics into the Flowersec token schema.

## Scaling and multi-instance deployment

The tunnel is **stateful per channel**:

- Pairing state (client/server websocket conns) lives in process memory.
- Token replay protection (non-empty `token_id`, single-use) is enforced via an in-memory cache by default.

This means that the two endpoints of the same `channel_id` must attach to the **same tunnel instance**.

### Recommended: controlplane sharding (multiple tunnel URLs)

Run multiple tunnel instances with distinct public websocket URLs, then have your controlplane pick a `tunnel_url` per `channel_id` and embed it in the signed grant/token.

This is the simplest approach and matches the current codebase assumptions.

Reference strategy: rendezvous hashing (HRW) to choose a stable tunnel URL (see runnable examples: `examples/go/tunnel_sharding/pick_tunnel_url.go`, `examples/ts/node-tunnel-sharding.mjs`):

Go (controlplane side):

```go
import (
  "crypto/sha256"
  "encoding/binary"
)

func PickTunnelURL(channelID string, urls []string) string {
  // Highest-score wins: score = sha256(channelID + "|" + url)[:8] as big-endian uint64.
  var best string
  var bestScore uint64
  for _, u := range urls {
    h := sha256.Sum256([]byte(channelID + "|" + u))
    score := binary.BigEndian.Uint64(h[:8])
    if best == "" || score > bestScore {
      best, bestScore = u, score
    }
  }
  return best
}
```

Node (TypeScript) (controlplane side):

```ts
import { createHash } from "node:crypto";

export function pickTunnelURL(channelId: string, urls: string[]): string {
  let best = "";
  let bestScore = -1n;
  for (const u of urls) {
    const h = createHash("sha256").update(`${channelId}|${u}`).digest();
    const score =
      (BigInt(h[0]!) << 56n) |
      (BigInt(h[1]!) << 48n) |
      (BigInt(h[2]!) << 40n) |
      (BigInt(h[3]!) << 32n) |
      (BigInt(h[4]!) << 24n) |
      (BigInt(h[5]!) << 16n) |
      (BigInt(h[6]!) << 8n) |
      BigInt(h[7]!);
    if (best === "" || score > bestScore) {
      best = u;
      bestScore = score;
    }
  }
  return best;
}
```

Notes:

- Any consistent hash scheme works (HRW, jump hash, etc). The goal is a stable `channel_id -> tunnel_url` mapping.
- Ensure both endpoints obtain grants from the same controlplane mapping logic, so they attach to the same tunnel URL.

### Alternative: load balancer + shared replay state (advanced)

If you insist on putting tunnels behind a load balancer, you must provide **session affinity** by `channel_id` (so pairing works),
and you should also share token replay state (for example via Redis) to preserve `token_id` single-use semantics across instances.

This repository does not currently ship a built-in shared `TokenUseCache` implementation.

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

### Multi-tenant tunnel with policy backend

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$PWD/tenants.json:/etc/flowersec/tenants.json:ro" \
  -e FSEC_TUNNEL_LISTEN=0.0.0.0:8080 \
  -e FSEC_TUNNEL_WS_PATH=/tunnel/ws \
  -e FSEC_TUNNEL_TENANTS_FILE=/etc/flowersec/tenants.json \
  -e FSEC_TUNNEL_ALLOW_ORIGIN=https://your-web-origin.example \
  -e FSEC_TUNNEL_ATTACH_AUTHORIZER_URL=https://metaserver.internal/api/metaserver/v1/internal/tunnel/authorize-attach \
  -e FSEC_TUNNEL_OBSERVE_AUTHORIZER_URL=https://metaserver.internal/api/metaserver/v1/internal/tunnel/observe-channels \
  -e FSEC_TUNNEL_AUTHORIZER_HEADER='X-Metaserver-Token: secret' \
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
- If you enable a policy backend, make its failure mode explicit. The tunnel already treats missing lease refresh as a close condition.
