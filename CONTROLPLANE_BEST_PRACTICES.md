# Control Plane Best Practices

This document describes recommended control plane behaviors for issuing ChannelInitGrant pairs and coordinating reconnections. It is aligned with the current tunnel, token, and E2EE behaviors in this repo.

## Scope and goals

- Issue paired grants for role=client and role=server with a shared channel_id and PSK.
- Ensure each connection attempt uses fresh tokens and a single consistent init window.
- Coordinate reconnections to avoid replacement churn and token replay.

## Data model alignment

A ChannelInitGrant includes the fields below (names match the generated IDL):

- tunnel_url
- channel_id
- channel_init_expire_at_unix_s
- idle_timeout_seconds
- role
- token
- e2ee_psk_b64u
- allowed_suites
- default_suite

The tunnel validates the attach token, and the E2EE handshake validates init_exp. Tokens are single-use and should be treated as ephemeral.

## Recommended control plane APIs

- POST /v1/channel/init
  - Returns grant_client and coordinates delivery of the paired grant_server to the server endpoint over a secure channel (for example, a persistent control connection).
  - If channel_id is omitted, generate a random 24-byte base64url ID.
  - Always generate a new PSK and new tokens for each init request.

- Optional: POST /v1/channel/reissue
  - Reissues tokens for an existing grant pair without changing channel_id or PSK.
  - Only valid while channel_init_expire_at_unix_s has not passed.
  - Both endpoints must switch to the reissued tokens together.

## Lifecycle guidance

1. Create a fresh channel via /v1/channel/init.
2. Deliver grant_client to the client endpoint and grant_server to the server endpoint over a secure channel.
3. Both endpoints attach to the tunnel and complete the E2EE handshake.
4. If any layer closes (websocket, secure channel, yamux, or rpc), treat the session as dead and request a new channel.

## Reconnect strategy (weak networks)

- Do not reuse a token after any failure; token replay is rejected by the tunnel.
- Avoid single-end retries that reuse the same channel_id with the same role, which triggers replacement and closes both sides.
- Use exponential backoff with jitter for reconnection attempts.
- Coordinate reconnection so both endpoints receive a new grant pair before reconnecting.
- If you implement /v1/channel/reissue, use it only within the init window and only when both endpoints can switch at the same time.

## Expiry and time sync

- Keep token exp short (default 60s) and never beyond init_exp.
- The init window is short (default 120s). If a reconnect falls outside this window, mint a new channel.
- Ensure all servers and clients are time-synced (NTP). The E2EE handshake validates timestamp skew.

## Security practices

- Treat e2ee_psk_b64u as a secret. Deliver grants only over authenticated and encrypted channels.
- Rotate issuer keys by updating the keyset and reloading the tunnel server. Keep overlapping keys during rotation to avoid validation gaps.
- Limit allowed_suites to the set you can verify and support.

## Deployment considerations

- Single-instance tunnel servers are supported by the in-memory token replay cache.
- If you want to scale without shared replay state, do it at the control plane layer by sharding channels across multiple tunnel endpoints (issue different `tunnel_url` values per channel). Each tunnel can remain a single instance.
- Multi-instance tunnels behind a load balancer require shared token replay state (for example, Redis) or strict session affinity; otherwise token replay protection becomes best-effort and the DoS window increases.
- Prefer `wss://` for any non-local deployment. The tunnel can terminate TLS directly (optional) or sit behind a TLS-terminating reverse proxy.

## Keepalive and idle timeouts

- idle_timeout_seconds is advertised in the grant; the tunnel enforces idle timeouts.
- Send periodic encrypted pings (SecureChannel sendPing) with an interval lower than idle_timeout_seconds.

## Observability and safety limits

- Rate-limit /v1/channel/init to protect issuer keys and tunnel capacity.
- Record channel_id and token_id in logs for traceability (avoid logging PSK).
- Track metrics for attach failures, token replay, replacement rate limiting, and idle timeout closures.
