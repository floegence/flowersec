# Flowersec for Go

The Go 2.x module lets services open end-to-end encrypted sessions and use RPC,
notifications, and reliable byte streams without managing connection details.

## Install

```bash
go get github.com/floegence/flowersec/flowersec-go/v2
```

## Public API

```go
artifact, err := flowersec.ParseArtifact(encoded)
lease, err := flowersec.NewArtifactLease(artifact, commitSpend)
handlers, err := flowersec.NewSessionHandlers(flowersec.SessionHandlerOptions{})
err = handlers.HandleRPC(typeID, rpcHandler)
err = handlers.HandleStream(streamKind, streamHandler)
options.Handlers = handlers
session, err := flowersec.Connect(ctx, lease, options)
metadata, err := flowersec.NewStreamMetadata(map[string]any{"request_id": "req-1"})
stream, err := session.OpenStream(ctx, "example", metadata)
err = handlers.Serve(ctx, session)

acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
    AllowedOrigins: []string{"https://app.example"},
    Authorize: authorizeRuntime,
    OnSession: serveSession,
})
httpServer.Handler = acceptor.Handler()

tunnel, err := flowersec.NewTunnelRuntime(flowersec.TunnelRuntimeOptions{
    Listeners: []flowersec.TunnelListener{flowersec.NewWebSocketTunnelListener()},
    Authorize: authorizeTunnelRuntime,
})
httpServer.Handler = tunnel.Handler()

proxy, err := flowersec.NewProxyServer(flowersec.ProxyServerOptions{
    Upstream: upstreamURL,
})
err = proxy.Register(handlers)
```

Register inbound RPC and stream handlers before connecting. Stream kinds are valid UTF-8 values from 1 through 255 encoded bytes; `flowersec.rpc.v2` is reserved. A valid connection attempt freezes both registration sets; later registrations return `ErrSessionHandlersFrozen`. `NewStreamMetadata(...)` validates and defensively copies metadata before a stream is opened; `EmptyStreamMetadata()` represents the empty value, and incoming streams expose the same `StreamMetadata` type. `SessionHandlers.Serve` owns the session lifecycle, supplies bounded stream metadata to application handlers, resets then closes the current stream when its `StreamHandler` returns an error, and continues serving unrelated streams. It also resets unhandled or excess streams. Connection selection and cryptographic state remain private to the SDK. Public connection and operation failures are bounded `ConnectError` and `SessionError` values.

The executable `ExampleConnect` compiles the complete consumer lifecycle,
including an atomically created and synchronized durable spend record. Reusing
the record key fails closed; the record contains no artifact or key material.

An omitted `ConnectorOptions.ConnectTimeout` uses the shared ten-second default. `ConnectorOptions.Origin` may be empty when the artifact uses WSS or raw QUIC; a non-empty absolute HTTP(S) origin registers WebTransport eligibility, whose secure dial path still requires HTTPS. Go's native TLS paths require explicit non-empty `ConnectorOptions.TrustRoots`; load the system pool with `x509.SystemCertPool()` when platform trust is intended. Trust roots may be omitted only when every artifact candidate is a plaintext WebSocket direct candidate on exact loopback; secure or mixed candidate sets still require them. Invalid connector inputs and options are returned as `ConnectError` values. `Session.WaitTermination(...)` is the sole public termination waiting entrypoint and returns a redacted `SessionTermination` with the stable close reason; cancellation of the wait is returned separately. A long-lived connection uses `NewConnectionController(...)` with a refreshable `ArtifactSource`; every attempt acquires a fresh lease and establishes a new one-shot `Session`. Its structured decisions are `terminal`, `retryable`, or an absolute `retry_after` deadline. `RetryNow` only wakes the current wait, and streams, RPCs, and writes from a terminated session are never migrated or replayed.

## Supported Connections

The Go SDK supports WebSocket and raw QUIC on direct and tunnel paths, plus
direct WebTransport connections. It also exposes an optional low-level
WebTransport tunnel listener for browser and mixed-leg workloads, but no runtime
currently claims the complete `webtransport-server` profile. The SDK
provides the direct-only `NewAcceptor` for application-owned server sessions,
the separate `NewTunnelRuntime` for opaque tunnel pairing and forwarding, and
`NewProxyServer` for bounded browser HTTP/WebSocket proxy handling. A tunnel
runtime never owns a `Session`, application handler, or E2EE PSK.

## Server Control Plane

Go service control planes use `github.com/floegence/flowersec/flowersec-go/v2/controlplane` to issue direct artifacts or complementary tunnel pairs and to validate `flowersec-runtime` authorization callbacks. Endpoint sets, issued artifacts, authorization records, runtime requests, and responses are opaque. Artifact and record bytes cross only explicit serialization methods; the caller owns permissions, placement, durable one-time lease state, and upstream selection.

See the executable `controlplane.ExampleIssuer_IssueTunnelPair` example for artifact delivery and authorization-record persistence. The package exposes opaque endpoint, issuance, authorization-record, and runtime callback types.

## Connection Notes

Direct and relayed connections return the same `Session`. WebSocket and raw
QUIC are selected internally for either path; WebTransport is selected only
for direct invitations. The SDK keeps credentials, routing, and transport
state out of the application API.

## Verify

```bash
go test ./...
```

See the [API contract](../docs/API_CONTRACT.md), [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
