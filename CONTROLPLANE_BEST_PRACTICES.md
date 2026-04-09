# Controlplane Best Practices

This document describes recommended controlplane behavior for Flowersec v0.19.x.

## Core responsibilities

Controlplanes should:

- issue paired tunnel materials with shared `channel_id` and PSK
- ensure each connection attempt uses fresh one-time tokens
- expose a client-facing artifact fetch path for modern consumers
- coordinate reconnect so fresh client/server materials stay aligned

## Recommended outputs

Preferred v0.19.x output:

- `connect_artifact`

Compatibility outputs still supported:

- `grant_client`
- wrapper `{grant_client: ...}`

Tunnel server-side material may continue to travel out-of-band to the server endpoint.
For CLI/demo/minting flows, `flowersec-channelinit --format artifact --server-grant-out ...` is the recommended split.

## Correlation guidance

If the caller provides a shared `trace_id`:

- copy it into the issued artifact when valid
- keep it stable across reconnect attempts for the same user-visible session

If the controlplane issues a new session:

- mint a fresh shared `session_id`

If a caller-provided shared ID is malformed:

- treat it as absent in the shared artifact contract
- do not synthesize a replacement shared ID pretending it came from the controlplane

## Reconnect guidance

- never reuse tunnel tokens after failure
- avoid single-end retries that race against the peer with the same role/channel
- artifact-aware adapters may carry `trace_id` forward and absorb a new `session_id`
- framework-agnostic reconnect state machines should stay unaware of controlplane/artifact semantics

## Tunnel-specific guidance

- `ChannelInitGrant` remains pure capability material
- idle timeout must stay aligned between both paired tunnel grants
- `channel_init_expire_at_unix_s` should stay short
- tokens should remain single-use and short-lived

## API shape guidance

Recommended request/response semantics are documented in:

- `docs/CONTROLPLANE_ARTIFACT_FETCH.md`

Helper default paths such as `/v1/connect/artifact` are first-party defaults, not a universal Flowersec protocol requirement.

## Security guidance

- never log PSKs
- rotate issuer keys with overlap
- keep `allowed_suites` explicit
- use `wss://` for non-local deployments
- treat policy hooks and auth decisions as enforcement points, not best-effort logging
