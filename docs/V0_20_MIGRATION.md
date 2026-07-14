# Flowersec v0.20 Migration Guide

Flowersec v0.20 is a breaking release focused on fail-closed connection security, bounded resource use, acknowledged liveness, and one unambiguous reconnect contract.

The following wire contracts are unchanged:

- `ConnectArtifact v1`
- the encrypted-record format
- the Yamux frame format
- application-defined RPC type IDs and payloads

Flowersec remains a generic communication library. The v0.20 APIs expose transport, encryption, multiplexing, RPC, tunnel, reconnect, and observability controls only.

## Release coordinates

- Go module tag: `flowersec-go/v0.20.0`
- npm package: `@floegence/flowersec-core@0.20.0`
- SwiftPM root tag: `0.20.0`

Upgrade downstream dependencies from published registries or releases. Do not use `replace`, `file:`, `link:`, `workspace:`, sibling aliases, or copied source as a completed upgrade path.

## TLS is now the high-level default

Go `client.Connect*` and `endpoint.ConnectTunnel`, TypeScript artifact/grant/direct connect helpers, and Swift `Flowersec.connect*` now reject `ws://` by default. Rejection occurs before DNS resolution, the WebSocket handshake, and tunnel bearer-token transmission.

Remote connections normally require no policy option:

```go
cli, err := client.Connect(ctx, artifact, client.WithOrigin(origin))
```

```ts
const client = await connectNode(artifact, { origin });
```

Local plaintext development must opt in explicitly:

```go
cli, err := client.Connect(
	ctx,
	artifact,
	client.WithOrigin(origin),
	client.WithTransportSecurityPolicy(client.AllowPlaintextForLoopback),
)
```

```ts
const client = await connectNode(artifact, {
  origin,
  transportSecurityPolicy: AllowPlaintextForLoopback,
});
```

`AllowPlaintextForLoopback` accepts only `localhost`, `::1`, and canonical decimal `127.0.0.0/8` literals. It does not resolve DNS or accept non-canonical IPv4 spellings. `AllowPlaintext` is an explicit acceptance of plaintext pre-E2EE metadata exposure.

Low-level WebSocket transports remain scheme-neutral. The `plaintext_transport` diagnostic is emitted only when a high-level caller explicitly allows plaintext and the selected URL actually uses `ws://`.

## Record and transport backpressure

Encrypted-record receive limits remain 1 MiB by default. High-level senders now prefer 64 KiB plaintext chunks:

- Go: `WithOutboundRecordChunkBytes(...)`
- TypeScript: `outboundRecordChunkBytes`
- Swift: `ConnectOptions.outboundRecordChunkBytes`

The configured chunk must fit within the maximum encrypted record.

TypeScript removes `maxWsQueuedBytes`. Use `webSocketLimits` instead:

```ts
const client = await connectNode(artifact, {
  origin,
  webSocketLimits: {
    maxInboundQueuedBytes: 4 * 1024 * 1024,
    outboundLowWatermarkBytes: 256 * 1024,
    outboundHighWatermarkBytes: 1024 * 1024,
    outboundHardLimitBytes: 4 * 1024 * 1024,
    outboundDrainTimeoutMs: 10_000,
  },
});
```

`WebSocketLike.bufferedAmount` is required. Writes are serialized. Crossing the high watermark pauses new sends until the low watermark is reached; crossing the hard limit or drain timeout closes the transport and rejects pending operations. Swift applies an equivalent serialized write queue with a 4 MiB pending hard cap.

## Yamux limits and liveness

Go removes `WithYamuxConfig(...)`. All SDKs use Flowersec-owned `YamuxLimits` instead of exposing a third-party configuration type.

The defaults are:

| Limit | Default |
| --- | ---: |
| active streams | 64 |
| inbound streams | 32 |
| frame bytes | 256 KiB |
| preferred outbound frame bytes | 64 KiB |
| per-stream receive bytes | 256 KiB |
| per-session receive bytes | 16 MiB |

Use `ProbeLiveness` / `probeLiveness()` for an acknowledged Yamux PING round trip. The older encrypted-record `Ping()` remains available but reports only local send completion.

Go:

```go
rtt, err := cli.ProbeLiveness(ctx)
```

TypeScript:

```ts
const rttMs = await client.probeLiveness();
```

Swift:

```swift
let rtt = try await client.probeLiveness(timeout: .seconds(10))
```

Automatic liveness is disabled by default for direct connections. Tunnel connections derive the default interval from half the artifact idle timeout, with a 500 ms minimum, and use a timeout no greater than 10 seconds or the interval. At most one probe is active per session. A liveness timeout closes the RPC client, all streams, the multiplexer, secure channel, and WebSocket.

Remove these old options:

- Go `WithKeepaliveInterval(...)`
- TypeScript `keepaliveIntervalMs`

Use Go `WithLiveness(...)` / `WithLivenessDisabled()`, TypeScript `liveness`, or Swift `ConnectOptions.liveness`.

## RPC scheduling

Go and TypeScript RPC servers now bound handler work:

| Limit | Default |
| --- | ---: |
| concurrent requests | 32 |
| queued requests | 128 |
| queued notifications | 128 |

Go uses `NewServerWithOptions(...)` and `ServerOptions`. TypeScript passes a close-capable `RpcServerTransport` and `RpcServerOptions` to `RpcServer`; the previous pair of bare read/write callbacks is removed so queue overflow and terminal worker failures can close the underlying RPC stream.

Requests execute in a fixed worker pool and responses may complete out of request order. Writes remain serialized. A full request queue returns RPC error `{code: 429, message: "server overloaded"}`. Notifications use a separate FIFO worker; notification queue overflow closes the RPC stream.

## Reconnect sources

Browser and Node reconnect adapters now accept exactly one discriminated source:

```ts
type ArtifactSource =
  | { kind: "once"; artifact: ConnectArtifact }
  | { kind: "refreshable"; acquire(context: ArtifactAcquireContext): Promise<ConnectArtifact> };
```

A one-time source can be consumed once and cannot enable automatic reconnect:

```ts
const reconnectConfig = createNodeReconnectConfig({
  source: { kind: "once", artifact },
  connect: { origin },
});
```

Use the controlplane helper for reconnectable sessions:

```ts
const reconnectConfig = createNodeReconnectConfig({
  source: createControlplaneArtifactSource({
    baseUrl: controlplaneBaseUrl,
    endpointId,
  }),
  connect: { origin },
  autoReconnect: { enabled: true },
});
```

Remove overlapping `artifact`, `getArtifact`, `artifactControlplane`, `grant`, `getGrant`, `directInfo`, and `getDirectInfo` reconnect fields. There is no implicit priority or compatibility shim in v0.20.

## Tunnel queue budgets

Tunnel configuration removes `MaxTotalPendingBytes`. Use aggregate queue budgets that cover both unpaired pending data and paired WebSocket write queues:

- `MaxTenantQueuedBytes`: 64 MiB default
- `MaxTotalQueuedBytes`: 256 MiB default

Existing per-side pending and per-endpoint write queue limits remain 256 KiB and 1 MiB by default.

## Errors and diagnostics

The stable error code `resource_exhausted` identifies a generic transport, Yamux, RPC, or queue limit.

`DiagnosticEvent` adds optional `resource`, `current`, and `limit` fields and the following event codes:

- `liveness_timeout`
- `queue_pressure`
- `stream_rejected`
- `resource_limit_reached`

These names belong to the diagnostics event registry (`code_domain=event`). Stable operation failures continue to use `code_domain=error`, including `resource_exhausted`.

Do not attach URL queries, credentials, tokens, stream kinds, RPC type IDs, or application payloads to diagnostics.

## Upgrade checklist

1. Upgrade all Flowersec SDKs used by one deployment window to v0.20-compatible releases.
2. Remove old keepalive, WebSocket queue, Yamux third-party configuration, and reconnect-source fields.
3. Mark every intentional local `ws://` connection with the loopback policy; keep remote connections TLS-only.
4. Decide whether direct sessions need automatic liveness and configure it explicitly when they do.
5. Review RPC concurrency and tunnel aggregate queue limits against deployment capacity.
6. Update error handling for `resource_exhausted` and diagnostics handling for resource fields.
7. Run Go/TypeScript/Swift interoperability and resource-limit tests before deployment.

Rollback by pinning consumers to the previous published release and reverting the deployment. Do not restore implicit plaintext defaults or otherwise fail open.
