# Flowersec for Go

The Go 2.x module exposes Flowersec's carrier-neutral v2 consumer API. Applications parse an opaque artifact, attach a durable single-use spend callback, connect, and use only the returned session, RPC, and byte-stream contracts.

## Install

```bash
go get github.com/floegence/flowersec/flowersec-go/v2@latest
```

Repository tags for this module use the `flowersec-go/v2.x.y` prefix.

## Public API

```go
artifact, err := flowersec.ParseArtifact(encoded)
lease, err := flowersec.NewArtifactLease(artifact, commitSpend)
connector, err := flowersec.NewConnector(lease, options)
session, err := connector.Connect(ctx)
```

The root package deliberately hides candidate data, carrier implementations, Yamux, wire messages, cryptographic state, keys, endpoint identities, logical stream IDs, and spend-ledger internals. Public connection and operation failures are bounded `ConnectError` and `SessionError` values.

## Transport v2 Support

WebSocket, raw QUIC, and WebTransport are equal carrier candidates.

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior. They use native bidirectional streams without Yamux. WebSocket uses hop-local Yamux internally.

Flowersec disables application 0-RTT and does not use QUIC DATAGRAM.

Transport v2 production carrier support: WebSocket, raw QUIC, and WebTransport.

The runtime enables only direct and tunnel carrier tuples backed by production code and end-to-end tests. Runtime capability negotiation and listener implementation details are not part of the application-facing root package.

## Verify

```bash
go test ./...
```

See the [API contract](../docs/API_CONTRACT.md), [Transport v2 architecture](../docs/TRANSPORT_V2_ARCHITECTURE.md), [threat model](../docs/THREAT_MODEL.md), and [error model](../docs/ERROR_MODEL.md).
