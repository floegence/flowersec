# Flowersec for Go

The Go 2.x module lets services open end-to-end encrypted sessions and use RPC,
notifications, and reliable byte streams without managing connection details.

## Install

```bash
go get github.com/floegence/flowersec/flowersec-go/v2
```

## Public API

### One-shot client

```go
artifact, err := flowersec.ParseArtifact(encoded)
lease, err := flowersec.NewArtifactLease(artifact, commitSpend)
rpcHandlers := flowersec.NewRPCHandlers()
err = rpcHandlers.HandleRPC(typeID, rpcHandler)
err = rpcHandlers.HandleNotification(notificationID, notificationHandler)
session, err := flowersec.Connect(ctx, lease, flowersec.ConnectorOptions{
    TrustRoots: trustRoots,
    Origin: "https://app.example",
    RPCHandlers: rpcHandlers,
})
metadata, err := flowersec.NewStreamMetadata(map[string]any{"request_id": "req-1"})
stream, err := session.OpenStream(ctx, "example", metadata)
```

### Long-lived client

```go
rpcHandlers := flowersec.NewRPCHandlers()
_ = rpcHandlers.HandleRPC(typeID, rpcHandler)
controller, err := flowersec.NewConnectionController(source, flowersec.ConnectionControllerOptions{
    Connector: flowersec.ConnectorOptions{
        TrustRoots: trustRoots,
        Origin: "https://app.example",
        RPCHandlers: rpcHandlers,
    },
})
controller.Start(ctx)
snapshot := controller.Snapshot()
```

The same frozen handler definition is installed in every new Session. Each
generation has a fresh router and old Session operations are never replayed.

For the complete durable `ArtifactLease` spend workflow, see the
[Go cookbook](example_client_test.go). The spend record must be committed
before the connector can send connection credentials.

### Accepted server Session

```go
handlers, err := flowersec.NewSessionHandlers(flowersec.SessionHandlerOptions{})
err = handlers.HandleRPC(typeID, rpcHandler)
err = handlers.HandleNotification(notificationID, notificationHandler)
err = handlers.HandleStream("files/read", streamHandler)
acceptor, err := flowersec.NewAcceptor(flowersec.AcceptorOptions{
    AllowedOrigins: []string{"https://app.example"},
    Authorize: authorizeRuntime,
    ResolveHandlers: func(context.Context, controlplane.RuntimeAuthorizationRequest) (*flowersec.SessionHandlers, error) {
        return handlers, nil
    },
    OnSession: serveSession,
})
httpServer.Handler = acceptor.Handler()
```

`SessionHandlers` belongs only to accepted server Sessions. The Acceptor
creates a fresh RPC router and owns `SessionHandlers.Serve(...)` for each
accepted Session.

Additional server runtimes use the same server registry:

```go

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

RPC and notification registrations share one nonzero uint32 namespace. Consuming
a registry freezes it; later registrations return `ErrHandlerRegistryFrozen`.
Stream kinds are valid UTF-8 values from 1 through 255 encoded bytes;
`flowersec.rpc.v2` is reserved. `NewStreamMetadata(...)` validates and
defensively copies metadata before a stream is opened. Handler and connection
state remain private, and public failures are bounded `ConnectError` and
`SessionError` values.

The executable `ExampleConnect` compiles the complete consumer lifecycle,
including an atomically created and synchronized durable spend record. Reusing
the record key fails closed; the record contains no artifact or key material.

An omitted `ConnectorOptions.ConnectTimeout` uses the shared ten-second default. `ConnectorOptions.Origin` may be empty when the artifact uses WSS or raw QUIC; a non-empty absolute HTTP(S) origin registers WebTransport eligibility, whose secure dial path still requires HTTPS. Go's native TLS paths require explicit non-empty `ConnectorOptions.TrustRoots`; load the system pool with `x509.SystemCertPool()` when platform trust is intended. Trust roots may be omitted only when every artifact candidate is a plaintext WebSocket direct candidate on exact loopback; secure or mixed candidate sets still require them. Invalid connector inputs and options are returned as `ConnectError` values. `Session.WaitTermination(...)` is the sole public termination waiting entrypoint and returns a redacted `SessionTermination` with the stable close reason; cancellation of the wait is returned separately. A long-lived connection uses `NewConnectionController(...)` with a refreshable `ArtifactSource`; every attempt acquires a fresh lease and establishes a new one-shot `Session`. Its structured decisions are `terminal`, `retryable`, or an absolute `retry_after` deadline. `RetryNow` only wakes the current wait, and streams, RPCs, and writes from a terminated session are never migrated or replayed.

## Supported Connections

The Go SDK supports WebSocket and raw QUIC on direct and tunnel paths, plus
direct WebTransport connections. `NewWebTransportTunnelListener(...)` is an
optional low-level listener adapter only; it is not a supported endpoint-client
tunnel path or `TunnelRuntime` capability because the production opaque relay
does not provide complete paired WebTransport datagram forwarding. No runtime
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
