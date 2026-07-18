# Migrating to Flowersec 0.26

Flowersec 0.26 removes deprecated plaintext and proxy compatibility surfaces and makes artifact transport fail closed. Upgrade application code directly to the supported contracts; do not add local forwarding aliases or fallback paths.

## Artifact Requests

Artifact URLs must use HTTPS unless the caller explicitly permits literal loopback HTTP. Set the option only at local development or test call sites that actually use loopback:

- Go: `ConnectArtifactRequestConfig.AllowLoopbackHTTP`
- TypeScript: `allowLoopbackHTTP`
- Swift: `ArtifactRequestOptions.allowLoopbackHTTP`
- Rust: `allow_loopback_http`

The default remains `false`. Do not enable loopback HTTP for remote control-plane URLs. Redirects are rejected in every SDK, including custom TypeScript fetch implementations. Rust custom clients must be constructed as `ArtifactHttpClient`; callers can no longer supply an unrestricted `reqwest::Client`.

## Transport Security Policies

Remove every use of the unrestricted plaintext policy:

- Go: `client.AllowPlaintext`, `endpoint.AllowPlaintext`, and `transportsecurity.AllowPlaintext`
- TypeScript: `AllowPlaintext` and its browser, Node.js, facade, or preset exports
- Swift: `TransportSecurityPolicy.allowPlaintext`
- Rust: `TransportSecurityPolicy::allow_plaintext()`

Use `RequireTLS` for remote endpoints. For local development, use the SDK's literal loopback policy. Use host-scoped network plaintext only when a non-loopback IP is unavoidable and the application explicitly accepts the documented pre-E2EE credential exposure risk.

## Proxy Presets And Browser Imports

Replace named profile configuration with a preset manifest file or decoded manifest object. Remove imports of the Go `proxy/profile` package, calls to `preset.ResolveBuiltin`, and gateway `proxy.profile` configuration.

TypeScript applications must remove `connectTunnelProxyBrowser` and `connectTunnelProxyControllerBrowser` plus their grant-based option types. Continue to use the supported raw direct or tunnel grant inputs where required. Import artifact helpers and control-plane errors only from `@floegence/flowersec-core/controlplane`; the browser subpath no longer re-exports aliases.

## Streaming Proxy Servers

Proxy server implementations now forward request and response chunks incrementally. Remove assumptions that the server buffers a complete body before contacting the upstream or replying to the Flowersec stream. Preserve the configured body limits and handle stream reset as the terminal outcome when an error occurs after response metadata has started.

The shared default is 64 concurrent proxy streams. Go exposes `MaxConcurrentStreams`, Rust exposes `max_concurrent_streams`, and TypeScript and Swift continue to use `maxConcurrentStreams`. Set a different value only from measured deployment requirements.

## Tunnel Server Limits

Review explicit tunnel settings against the new defaults:

- `MaxTokenLifetime`: `2m`
- `MaxInitHorizon`: `2m`
- `MaxReplayEntries`: `4 * MaxConns`, or `48000` with the default connection limit

Token issuers must keep `exp - iat` within `MaxTokenLifetime` and `init_exp` within the current time, clock skew, and `MaxInitHorizon` boundary. Capacity exhaustion rejects a new replay key after expired entries are removed; it does not evict active keys.

Multi-tenant integrations must treat `(audience, issuer)` as the authorization and quota key. Non-empty tenant IDs must be unique metadata. Observe decisions must include `audience`, `issuer`, and `channel_id`; a missing scope, duplicate decision, or tenant ID mismatch invalidates the entire batch.

## Connection Liveness

Go `Connect` no longer performs a synchronous Yamux probe after the E2EE handshake. A successful return confirms the secure channel and RPC bootstrap stream are established. Call the public `ProbeLiveness` API when the application needs an explicit acknowledged liveness check.
