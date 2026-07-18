# Flowersec Threat Model and Security Boundaries

This document explains what Flowersec can and cannot protect, based on the current repository implementation.
It is written for integrators and operators deploying either the tunnel path or the direct path.

## System model

Flowersec builds an end-to-end encrypted, multiplexed connection over WebSocket:

- **Tunnel path**: client and server connect to an (untrusted) tunnel, authenticate with a one-time token, then run the encrypted protocol stack through the tunnel's byte-forwarding.
- **Direct path**: client connects directly to the server WebSocket endpoint, then runs the encrypted protocol stack directly (no tunnel).

Roles:

- **Controlplane (trusted)**: issues signed one-time tunnel attach tokens and distributes session configuration (for example `ChannelInitGrant`).
- **Tunnel (untrusted rendezvous)**: verifies attach tokens and forwards bytes between endpoints, but must not learn plaintext application data.
- **Server endpoint (trusted)**: terminates E2EE, serves Yamux streams and RPC handlers.
- **Client endpoint (trusted)**: initiates E2EE, opens Yamux streams and RPC calls.

## Proxy: HTTP/WS over Flowersec

Flowersec can also carry application-layer proxy traffic over custom streams (see `docs/PROXY.md`):

- `flowersec-proxy/http1` (HTTP/1.1 request/response over a single stream)
- `flowersec-proxy/ws` (WebSocket over a single stream)

Two deployment modes exist:

- **Runtime mode (recommended)**: the browser runs a proxy runtime (plus a Service Worker) and connects directly to the agent (server endpoint) over Flowersec E2EE. The tunnel remains untrusted and opaque.
- **Gateway mode (L7 reverse proxy)**: a gateway accepts browser HTTPS/WSS and forwards to the agent over Flowersec E2EE.

Important boundary:

- In **gateway mode**, the gateway MUST parse plaintext HTTP/WS to act as an L7 reverse proxy. This means the gateway is a trusted plaintext component and cannot be treated as an "untrusted relay that does not decrypt".
  - If you need an untrusted relay, use runtime mode (browser↔agent E2EE) instead.
- In **gateway mode**, the gateway is the browser-facing origin and will see browser cookies for that origin. Deploy the gateway on a dedicated cookie scope (for example a separate registrable domain) from any product/controlplane authentication context to avoid leaking unrelated auth cookies to the proxied upstream app.
- In **gateway mode**, browser-side HTTP/WS boundary enforcement and gateway -> tunnel attach Origin are separate policies and must be configured independently.

## Security goals (what Flowersec aims to provide)

After the E2EE handshake completes:

- **Confidentiality**: tunnel operators and network observers cannot decrypt application payloads carried inside `FSEC` encrypted records.
- **Integrity**: any modification of encrypted records is detected by AEAD authentication and causes the secure channel to fail.
- **Endpoint authentication (PSK)**: only endpoints that know the 32-byte PSK can complete the handshake.

## Non-goals / limitations (what Flowersec does not guarantee)

Attach layer (tunnel path):

- **Attach is plaintext by design**: the first tunnel message is JSON attach metadata (plus a bearer token) sent over the websocket before E2EE. Anyone who can observe `ws://` traffic can see the attach JSON and token.
- **Tokens are bearer credentials**: do not log tokens, do not store them in client-visible locations, and do not reuse them after any failure.
- **Use `wss://` in production**: for any non-local deployment, always use TLS (`wss://`) or terminate TLS at a trusted reverse proxy.
- **Transport policy is fail-closed by default**: high-level clients use `RequireTLS` when the caller omits a policy. `AllowPlaintextForLoopback` and the host-scoped network plaintext policy are the only explicit plaintext opt-ins; `plaintext_transport` is emitted only when an opt-in policy actually permits `ws://`. The network policy requires canonical non-loopback IP literals plus a typed acceptance of pre-E2EE credential exposure.
- **Loopback means a literal target**: `AllowPlaintextForLoopback` recognizes only `localhost`, canonical `127.0.0.0/8` IPv4 literals, and `::1`. It does not resolve DNS names.
- **Network plaintext is bound to exact IP literals**: the network plaintext policy rejects DNS names, wildcards, loopback, link-local, multicast, unspecified, mapped, zoned, and non-canonical IP forms. It never resolves DNS and does not permit a failed host match to fall back to unrestricted plaintext.
- **Artifact acquisition is HTTPS-only by default**: each SDK permits HTTP only through an explicit artifact option and only for literal loopback targets. Userinfo, non-canonical loopback forms, unsupported schemes, and redirects are rejected so bearer credentials cannot be forwarded to another origin.

Untrusted tunnel:

- **The tunnel can DoS**: it can drop frames, delay, reorder, or close connections. Flowersec does not prevent denial of service.
- **Metadata leakage**: the tunnel sees the channel id, role, endpoint_instance_id, and token timing/usage patterns; it can also observe traffic size and timing.

Multi-instance tunnels:

- **Channel state is in-memory**: pairing state and replay protection live in the tunnel process memory by default.
- **Signed tokens remain locally bounded**: the tunnel limits `exp - iat` and the future `init_exp` horizon even when the token signature is valid. This prevents a compromised or misconfigured issuer from imposing unbounded acceptance windows.
- **Replay state is bounded and fail-closed**: the default cache removes expired entries at capacity, then rejects new attaches instead of evicting still-valid replay keys.
- **Tenant scope is cryptographic, not cosmetic**: queue accounting, active channels, and observe decisions are isolated by exact `(audience, issuer)` scope. Optional tenant IDs do not define authorization boundaries.
- **A load balancer is not enough**: if the two endpoints of the same channel land on different tunnel instances, they cannot pair.
- See `docs/TUNNEL_DEPLOYMENT.md` for the recommended scaling strategy (controlplane sharding).

Key and secret handling:

- **Never log secrets**: do not log `e2ee_psk_b64u`, issuer private keys, or full bearer tokens.
- **Origin policy matters**: browsers enforce Origin rules and the tunnel/server should validate Origins. Avoid allowing `null`/no-Origin unless you fully control your clients. Wildcards like `*.example.com` match subdomains only; list the apex (`example.com`) explicitly if you need it.
- **Resolve before consume**: one-time direct credentials should be resolved without consumption, authenticated through the PSK handshake, and atomically committed before Yamux. Flowersec's `ResolveCredential` contract enforces this ordering but the credential store remains an integrator responsibility.

## Implementation references (current code)

This document aligns with the current implementation:

- Tunnel attach is plaintext JSON and token verification happens before E2EE:
  - Go tunnel: `flowersec-go/tunnel/server/server.go` (`handleWS`)
- Token replay protection is in-memory by default:
  - Go tunnel: `flowersec-go/tunnel/server/tokencache.go`
- E2EE framing and handshake:
  - Go: `flowersec-go/crypto/e2ee/*` (`HandshakeMagic=FSEH`, `RecordMagic=FSEC`)
  - TS: `flowersec-ts/src/e2ee/*`

See also:

- Protocol framing details: `docs/PROTOCOL.md`
- Error contract: `docs/ERROR_MODEL.md`
- Deployment guide: `docs/TUNNEL_DEPLOYMENT.md`
