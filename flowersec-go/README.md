# Flowersec for Go

The Go 2.x module exposes Flowersec's carrier-neutral v2 consumer API. Applications parse an opaque artifact, attach a durable single-use spend callback, connect, and use only the returned session, RPC, and byte-stream contracts.

The current source is a Flowersec 2.0 release candidate and has not yet been published as a 2.0 module tag. The install command below applies after the coordinated 2.0 release; use an existing release tag for production until then.

## Install

```bash
go get github.com/floegence/flowersec/flowersec-go/v2@latest
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
err = handlers.Serve(ctx, session)
```

Register inbound RPC handlers before connecting; `Connect` snapshots them for session establishment. `SessionHandlers.Serve` owns the session lifecycle, supplies bounded stream metadata to application handlers, and resets unhandled or excess streams. The root package deliberately hides candidate data, carrier implementations, Yamux, wire messages, cryptographic state, keys, endpoint identities, logical stream IDs, and spend-ledger internals. Public connection and operation failures are bounded `ConnectError` and `SessionError` values.

The executable `ExampleConnect` compiles the complete consumer lifecycle,
including an atomically created and synchronized durable spend receipt. Reusing
the receipt path fails closed; the receipt contains no artifact or key material.

An omitted `ConnectorOptions.ConnectTimeout` uses the shared ten-second default. Go's native TLS paths require explicit non-empty `ConnectorOptions.TrustRoots`; load the system pool with `x509.SystemCertPool()` when platform trust is intended. `ClassifyConnectError(...)` and `ClassifySessionError(...)` map public errors to `ErrorRetryClassification`: retry the current operation, acquire a fresh artifact and session, or stop. `ConnectExpired` identifies artifact expiry without exposing artifact contents.

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
