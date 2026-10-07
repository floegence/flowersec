# Public Go WSS consumer

This cookbook builds the complete connection and application graph using the
published `github.com/floegence/flowersec/flowersec-go/v6` package. It does not
import repository-internal packages or an engineering client implementation.

Its declared workload is one client-dialed direct WebSocket connection with
TLS 1.3 CA verification, the `services` application profile, a preauthorized
pool invitation, and one independently pinned verification namespace. The
invitation must fit the fixed local bounds: 11–138 active streams, a 4–64 KiB
frame limit, and at most 32 general RPC requests. Other carriers, pin-mode TLS,
relay deployments and live-authority sources require their own explicit
deployment configuration and are rejected by this cookbook.

## Application setup

Call `New` with a `Configuration` containing the independently installed
namespace root and bootstrap endpoint, TLS roots, qualified clock, local
signer and static DH provider, signed invitation bytes, a stable history
identity, and a new absolute history directory. Signed invitation bytes do
not select the root key, local identity or history store.

`New` bootstraps the namespace with a fresh SDK nonce and authenticates the
signed artifact, activation and identity certificates. It creates the original
SQLite consumer, reserves the transport and service graph, and declares the
RPC and notification workload before source acquisition. The application's
authorization hook matches the original authenticated binding and explicitly
grants the finite parity method set.

`Connect` makes one normal `flowersec.Connect` call through the original
`TransportEnvironment` and one-use `ConnectionMaterialSource`. The SDK owns
verification, durable consumption, Noise, READY, stream sequences, retirement,
rekey and internal protocol budgets. The example observes the public
`PoolSpendObservation` only after successful admission; that observation cannot
authorize a second connection.

`Exchange` performs typed RPC `7001`, notification `7002`, the `parity.echo`
stream request `hello` and response `world` through FIN, and a liveness probe.
The canonical service contracts are built by `EncodeServiceContract`, with
explicit application semantics and 4 KiB codec bounds. The returned
`ExchangeResult` retains RPC submission/reference facts, notification progress,
the accepted stream prefix, bounded read outcome, stream close result and
liveness status, including on failure.

Always call `Close` with a fresh bounded cleanup context after setup or
application work returns. `New` may return a non-nil client alongside an error
so the caller can join partial setup. A cleanup timeout retains the original
owners for another `Close` call. Call these example methods serially; they do
not implement concurrent application scheduling or automatic retries.

## Durable history

Provisioning creates the history directory exclusively, synchronizes its
parent, and creates `spend.sqlite` under that directory. An existing directory
is never opened implicitly or replaced. `Close` retires the database connection
and transport owners while retaining the persistent backing and disk charge.
It does not delete history or pretend the resource root is completely empty.

This one-shot cookbook intentionally has no recovery or reprovisioning command.
A long-running application must retain its backing and provide an independent
`SQLiteContinuity` authority before using the SDK's explicit `OpenSQLite` path.
Neither a surviving database nor a receipt file proves rollback-safe history.
An uncertain write or commit must never lead to deleting and reusing the old
history location.

## Repository acceptance fixture

`flowersec-go/example_client_test.go` keeps the runner's `TestExampleConnectE2E`
entry point. `OpenAcceptanceFixture` adapts its explicitly trusted local
deployment manifest and uses only public constructors. The fixture file
contains test identity seeds and independently installed namespace pins; it
must never be accepted as an untrusted invitation in an application.

The runner supplies `FSEC_MATERIAL_PATH`, `FSEC_TRUST_ROOT_PEM_PATH`,
`FSEC_ORIGIN`, and `FSEC_SPEND_RECEIPT_PATH`. `FSEC_EXAMPLE_STREAM_CELL` defaults
to `direct`. The persistent history directory is `<receipt path>.history`.
After READY and definite durable consumption, the example writes the exclusive
`flowersec-v4-material-spent` observation receipt and synchronizes both file and
parent directory. The acceptance runner owns the entire fixture directory;
production transport cleanup must not copy that fixture-disposal policy.
