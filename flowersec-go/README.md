# Flowersec for Go

The Go 2.x module exposes Flowersec's carrier-neutral v2 consumer API. Applications parse an opaque artifact, attach a durable single-use spend callback, connect, and use only the returned session, RPC, and byte-stream contracts.

Flowersec 2.1.0 is the published coordinated Go module release.

## Install

```bash
go get github.com/floegence/flowersec/flowersec-go/v2@v2.1.0
```

Repository tags for this module use the `flowersec-go/v2.x.y` prefix.

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
```

Register inbound RPC and stream handlers before connecting. A valid connection attempt freezes both registration sets; later registrations return `ErrSessionHandlersFrozen`. `NewStreamMetadata(...)` validates and defensively copies metadata before a stream is opened; `EmptyStreamMetadata()` represents the empty value, and incoming streams expose the same `StreamMetadata` type. `SessionHandlers.Serve` owns the session lifecycle, supplies bounded stream metadata to application handlers, and resets unhandled or excess streams. The root package deliberately hides candidate data, carrier implementations, Yamux, wire messages, cryptographic state, keys, endpoint identities, logical stream IDs, and spend-ledger internals. Public connection and operation failures are bounded `ConnectError` and `SessionError` values.

The executable `ExampleConnect` compiles the complete consumer lifecycle,
including an atomically created and synchronized durable spend record. Reusing
the record key fails closed; the record contains no artifact or key material.

An omitted `ConnectorOptions.ConnectTimeout` uses the shared ten-second default. `ConnectorOptions.Origin` may be empty when the artifact uses WSS or raw QUIC; a non-empty absolute HTTP(S) origin registers WebTransport eligibility, whose secure dial path still requires HTTPS. Go's native TLS paths require explicit non-empty `ConnectorOptions.TrustRoots`; load the system pool with `x509.SystemCertPool()` when platform trust is intended. Invalid connector inputs and options are returned as `ConnectError` values. `Session.WaitTermination(...)` is the sole public termination waiting entrypoint and returns a redacted `SessionTermination` with the stable close reason; cancellation of the wait is returned separately. A long-lived connection uses `NewConnectionController(...)` with a refreshable `ArtifactSource`; every attempt acquires a fresh lease and establishes a new one-shot `Session`. Its structured decisions are `terminal`, `retryable`, or an absolute `retry_after` deadline. `RetryNow` only wakes the current wait, and streams, RPCs, and writes from a terminated session are never migrated or replayed.

## Capability Layers

The portable core is the same application model used by every Flowersec SDK:
opaque artifact parsing, a durable single-use lease, one-shot connection,
carrier-neutral sessions, RPC, reliable streams, redacted public errors, and
the optional `ConnectionController`. The controller is the only Flowersec
retry scheduler; applications provide a refreshable artifact source and
authentication recovery without maintaining a second protocol loop.

Only this portable core is required to align across languages. Complete SDK
profiles and language conveniences intentionally differ by runtime.

The Go SDK profile supports WebSocket, raw QUIC, and WebTransport production
dialing. Its language convenience is `SessionHandlers`, which registers inbound
RPC and stream handlers in a Go-native shape without making handler registration
part of the portable core.

## Server Control Plane

Go service control planes use `github.com/floegence/flowersec/flowersec-go/v2/controlplane` to issue direct artifacts or complementary tunnel pairs and to validate `flowersec-runtime` authorization callbacks. Endpoint sets, issued artifacts, authorization records, runtime requests, and responses are opaque. Artifact and record bytes cross only explicit serialization methods; the caller owns permissions, placement, durable one-time lease state, and upstream selection.

See the executable `controlplane.ExampleIssuer_IssueTunnelPair` example for artifact delivery and authorization-record persistence. The package is v2-only and does not restore removed issuer keys, signed grants, generated DTOs, or channel-init APIs.

## Transport v2 Support

WebSocket, raw QUIC, and WebTransport are equal carrier candidates. This SDK's production profile supports all three; that profile is separate from the portable application API shared by every SDK.

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior. They use native bidirectional streams without Yamux. WebSocket uses hop-local Yamux internally.

Flowersec disables application 0-RTT. Reliable streams never use QUIC DATAGRAM; runtimes with negotiated native DATAGRAM expose it only through carrier-neutral unreliable messages.

Transport v2 production carrier support: WebSocket, raw QUIC, and WebTransport.

The runtime enables only direct and tunnel carrier tuples backed by production code and end-to-end tests. Runtime capability negotiation and listener implementation details are not part of the application-facing root package.

## Verify

```bash
go test ./...
```

See the [API contract](../docs/API_CONTRACT.md), [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
