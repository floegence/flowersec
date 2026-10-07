# Flowersec for Go

The Go SDK opens end-to-end encrypted sessions with reliable streams, typed
application services, notifications and bounded connection ownership. The
selected module release determines the transport protocol.

## Install

```bash
go get github.com/floegence/flowersec/flowersec-go/v6
```

## Supported Connections

`Connect` establishes authenticated direct or tunneled sessions over the current Flowersec v4 WebSocket and raw QUIC carriers. `NewConnectionController` manages qualified reconnections while preserving each Session's ownership.

## One-shot connections

Trusted host composition supplies the original clock, verification registry,
resource accounts, identity, material source and explicit pool or live spend
authority. Applications use one `TransportEnvironment` for these owners.

```go
environment, err := flowersec.NewTransportEnvironment(environmentOptions)
if err != nil {
    return err
}
session, err := flowersec.Connect(ctx, source, flowersec.ConnectorOptions{
    Environment: environment,
    ConnectOptions: connectOptions,
})
if err != nil {
    return err
}
metadata, err := flowersec.NewStreamMetadata(map[string]any{"request_id": "req-1"})
if err != nil {
    return err
}
stream, err := session.OpenStream(ctx, "example", metadata)
```

A source returns an opaque `ArtifactLease`. `NewArtifactLeaseFromBytes` verifies
bounded signed material with the supplied trust owners; `NewConnectionMaterial`
captures the original lease and identity. `ConnectMaterial` consumes already
acquired material. `ConnectPool` uses only installed, unspent local pool material
and never replenishes it during acquisition. Pool and live authority inputs
remain explicit and cannot silently substitute for one another.

`Session` exposes stream operations, typed service binding, liveness, rekey,
Drain, termination and cleanup observation. Application plans, method contracts
and finite reservations are captured before material acquisition. Each accepted
stream retains its original metadata and owner; cancellation does not replay
an operation or move a stream into a replacement Session.

## Long-lived connections

`NewConnectionController` takes `ConnectionControllerOptions` containing the
original environment and `ControllerOptions`. Its `ControllerSource` creates
one fresh local preparation per attempt. `ControllerCharges` supplies the
admission charges before construction. A source preparation transfers cleanup
responsibility even when it also returns an error.

The controller publishes only qualified Sessions and retains retiring Sessions
until physical cleanup completes. `WaitForSession` observes publication;
`RetryNow` wakes the existing retry wait without bypassing the applicable
absolute deadline. Replacement never inherits or replays streams, RPCs or
writes. See the [connection controller guide](../docs/GO_TRANSPORT_V4.md#connection-controller).

## Accepted Sessions and listeners

`NewAcceptor(ctx, AcceptorOptions{Environment: environment, ServeOptions: options})`
returns the original `ServeHandle`. Its carrier-specific accept methods perform
verification, durable admission, Noise and READY before returning an
authenticated `Session`. `ServeOptions` contains the admitted aggregate
configuration and original reservation.

`NewWebSocketServer`, `NewQUICServer` and `NewWebTransportServer` own the native
listener boundary and finite provider budgets. `ServeHandle.AcceptWebSocket`
reports whether the request was physically hijacked, including on error; a host
must not write another HTTP response after hijack. Shared environments, trust
roots and key providers retain independent ownership. See the
[Go transport guide](../docs/GO_TRANSPORT_V4.md) for complete construction and
cleanup order, accepted material sources and signed-route admission.

Application services are installed in the original application plan. Raw stream
handlers retain their original `StreamOwnership`; typed service and message
handlers retain their own schema, publication and cleanup contracts. The native
`ServeHTTPStream` and `StartHTTPStream` entry points serve HTTP, keep-alive and
upgrade on an already authorized current Stream without opening a listener port.

## Relay and proxy services

`NewTunnelRuntime` owns a bounded set of original relay pairs and routes. Relay
work remains separate from application Sessions and end-to-end keys. Pair and
route registration retains original durable claim, authorization and cleanup
owners.

`NewProxyServer` binds a finite upstream configuration and original handler plan.
HTTP and WebSocket proxy operations keep their cancellation, backpressure and
cleanup ownership. Upstream routing and application authorization remain part
of the supplied current service configuration.

## Cleanup

Close seals new work. Drain preserves already accepted work on its original
Session. `WaitCleanup` observes real completion; canceling a cleanup wait neither
releases provider work nor manufactures completion. Shared clocks, resource
roots, executors, trust stores and durable stores remain caller-owned.

`ExampleConnect` exercises current material acquisition, typed RPC,
notification, reliable streams and cleanup with an engineering host fixture.
It checks the original SQLite spend commitment and writes a separate
synchronized receipt containing no artifact or key material. Its host setup
currently imports the internal interoperability harness, so it is not a
standalone public SDK consumer example.

Public host composition can import bounded signed credentials with
`NewSignedMapCodec` and canonical method contracts with `NewServiceContractCodec`.
Their backing-byte functions expose finite allocation requirements; these
codecs do not grant service access or admission authority. A
`PoolSpendObservation` attached to `PoolSessionInput` reports the original
SQLite consumer's status and cannot replace its durable history.

## Server control plane

Go service control planes use
`github.com/floegence/flowersec/flowersec-go/v6/controlplane` for current issuance,
paired tunnel publication, live authorization and independent durable store
owners. `flowersec-runtime` installs `relay`, `direct-server` or `direct-client`
from independently supplied host inputs. See
[runtime deployment](../docs/RUNTIME_DEPLOYMENT.md) for the finite schema,
service bindings and execution continuity requirements.

## Verify

```bash
go test ./...
```

See the [API contract](../docs/API_CONTRACT.md),
[Go transport guide](../docs/GO_TRANSPORT_V4.md),
[threat model](../docs/THREAT_MODEL.md), and
[error model](../docs/ERROR_MODEL.md).
