# Test Matrix

Flowersec tests follow the product ownership boundaries. Tests use stable IDs,
assert behavior and process exit status, and own all processes, ports, browser
instances, namespaces, faults, and temporary files that they create.

| Product semantics | Owning test layer |
| --- | --- |
| Artifact parsing, admission binding, wire vectors, and error vectors | Shared machine-readable vectors executed by Go, Rust, Swift, and TypeScript contract tests |
| Security-negative parser rejection and bounded malformed-input handling | `testdata/transport_v5/` negative vectors, consumed by Go, TypeScript, Swift, and Rust v5 contract tests |
| TLS policy canonicalization, candidate identity, candidate-set hash, FSB5, and admission binding | `testdata/transport_v5/artifact_vectors.json` and per-language v5 codec suites |
| Go issuer artifact, FSB5, admission binding, and acceptor-admissions hash parity | `testdata/transport_v5/go_issuer_admission_vectors.json`, produced by the Go issuer and consumed by Go, TypeScript, Rust, and Swift |
| Strict previous-version rejection and current codec isolation | `testdata/transport_v5/version_isolation_vectors.json`, consumed by production decoders in Go, TypeScript, Rust, and Swift |
| CA, private-CA, self-signed pin, mismatch, expiry, and overlap rotation | Production transport-security adapters and real TLS handshake suites in each supported runtime |
| Runtime security-mode capability and unsupported-candidate filtering | `testdata/transport_v5/capability_vectors.json`, production adapter capability tests, and Chromium provider tests |
| One-shot session lifecycle, stream FIN/reset/STOP_SENDING, DATAGRAM, close, and abort | Per-language memory carrier and native carrier contract tests |
| ConnectionController scheduling, blocked pin policies, one replacement lease, fresh primary artifacts, retry disposition, cancellation, and no replay | `testdata/transport_v5/controller_vectors.json` executed by all four SDKs |
| Client inbound RPC/notification handlers across real Controller generations | Go, Rust, and Node TypeScript loopback WebSocket tests; Swift and Browser remain unsupported |
| Accepted-session RPC, notification, stream dispatch, rejection, concurrency, and cleanup | Go, Rust, and Node TypeScript Acceptor handler suites |
| Declared Go/Rust/Node WebSocket and raw QUIC direct coordinate universe | `stability/interop_matrix.json` defines 18 client/server/carrier cells and each cell's complete executable case set; declaration alone is not a support claim |
| Declared Go/Rust/Node WebSocket and raw QUIC tunnel coordinate universe | `stability/interop_matrix.json` defines 18 endpoint-A/runtime/endpoint-B/carrier topologies and each topology's complete executable case set; declaration alone is not a support claim |
| Current direct and tunnel matrix support | The parameterized release gate exercises all 10 direct cells and 14 tunnel topologies containing Go; the remaining 8 direct and 4 tunnel declarations stay explicitly unverified |
| Scoped carrier, server, and cross-runtime behavior | Capability and product tests use their own stable IDs and remain support evidence for exactly the behavior they execute; they do not promote a complete matrix declaration to supported |
| Go WebTransport H4 | Go production conformance covers encrypted DATAGRAM round trips through direct endpoint/listener and WebTransport-to-raw-QUIC tunnel-runtime paths |
| Node raw-QUIC-only no-origin and Rust rootless loopback profiles | Node native connector one-shot and Controller generations; Rust direct WebSocket plus spend-before-roots validation |
| Swift WSS production connector | The Swift connector suite validates the production adapter; direct and tunneled Swift-to-Go client profiles are separate release-gating units outside the native 18-cell matrix |
| Chromium WebTransport | Local `make browser-smoke` covers direct H3 with encrypted DATAGRAMs and a pinned browser WebTransport leg through the Go relay to a raw QUIC peer. The tunnel case checks request metadata, exact bytes and EOF in both directions, normal session termination, and release of both admission leases. WebTransport-to-WSS is exercised separately by the Go tunnel workload. |
| Firefox and WebKit native WebTransport capability | Local `make browser-compat`; unsupported runtime surfaces are asserted explicitly |
| Fault injector and kernel topology conformance | Four `diagnostic/kernel/*` tests using netns, tc, eBPF counters, and generic socket workloads |
| Real Flowersec weak-network behavior | Production WSS/raw QUIC direct Sessions and representative opaque tunnels in the same netns/tc/eBPF lab |
| Go-owned capacity, resource, soak, and payload throughput | Explicit `make performance`; this is not multi-language performance parity |
| Optional WebTransport and Chromium performance | The optional partition of integrated `make performance`; capability success executes it in the same structured report, a structured missing-WebTransport result records its cases as `UNSUPPORTED`, and browser/runner failures block the suite |
| Manual published Go-to-Node raw QUIC consumer diagnostic | `release/npm-consumer/go-node-raw-quic/direct-session` can install registry packages and the tagged Go module, then verify handshake, RPC, stream FIN, close, and cleanup after publication. No workflow invokes this diagnostic, it is not release-gating evidence, and it is separate from the release workflow's package-integrity and source-commit readback. |
| Apple/browser client-profile WSS interoperability | Four registered units exercise Swift-to-Go and browser-TypeScript-to-Go WSS over direct and tunneled paths; Swift is Darwin-only and browser trust is runner-managed |

The expensive inventory is grouped by execution boundary and has no second manifest:

| Group | Stable runner IDs |
| --- | --- |
| Coverage and race | `coverage/{go,typescript,rust,swift}`, `race/go` |
| Local real browsers | `browser/chromium/webtransport/raw-quic/tunnel` qualifies the mixed tunnel independently of the Chromium direct, proxy and WSS cases. Firefox and WebKit have separate WebTransport capability and WebSocket checks. |
| Userspace Flowersec fault smoke | `diagnostic/weaknet/{raw-quic,websocket}/direct` |
| Kernel fault injector | Four `diagnostic/kernel/*` lifecycle and exact-fault IDs |
| Kernel-backed Flowersec weaknet | `diagnostic/flowersec-weaknet/{websocket,raw-quic}/direct/{delay-jitter,periodic-loss,burst-loss,outage,mtu-large-payload,rate-5mbps,rate-1mbps,reorder-duplicate}` and `diagnostic/flowersec-weaknet/{websocket,raw-quic}/tunnel/representative` |
| Controller weaknet | `diagnostic/flowersec-v3-controller-weaknet/{websocket,raw-quic}/{delay-jitter,periodic-loss,reorder,outage-reconnect,pin-rotation-refresh-backoff-lease}` |
| Required Go performance | Six `performance/capacity/*` WSS/raw-QUIC IDs, raw QUIC migration soak, production WSS soak, `performance/single-connection/{wss,raw-quic}`, and `performance/throughput/{wss,raw-quic}` |
| Optional WebTransport performance | `performance-optional/webtransport-capability`, followed in the integrated plan by six `performance/capacity/*` WebTransport/Chromium IDs, `performance/soak/webtransport`, `performance/single-connection/webtransport`, and `performance/throughput/webtransport`; only a structured missing-WebTransport result records these IDs as `UNSUPPORTED`, while browser path, launch, navigation, runner, or cleanup failures remain `FAIL` |

Coverage and race run with `make coverage-race`. Browser compatibility uses
real native connections: Firefox currently rejects the connection before
admission, while WebKit currently lacks the outgoing DATAGRAM surface. Those
explicit unsupported contracts do not substitute for Chromium smoke.

`make precommit` is the feature-commit gate. It isolates native admission and timed
TypeScript tests from the Go, Swift and Rust compiler workloads. `scripts/push-main.sh` runs bounded single-host
acceptance (`make test`) once. Before that suite on `main`, it checks the minimum
Node and Rust versions and runs the full Rust SDK and native tests. Hosted CI checks repository and workflow policy
and reviews pull-request dependencies. `make check` includes the Node minimum,
all four Rust manifests at MSRV, and stable Rust tests, while nightly, diagnostic, and performance work
stay outside the push path. Release publishes validated source and runs no tests.

`flowersec-test` reads one suite plan, starts at the first incomplete test ID,
and records only the source SHA, suite, plan, and completed IDs. A GREEN test
leaves no output artifact. Ordinary acceptance and diagnostic suites stop
scheduling after the first RED and leave tests that never started as `NOT RUN`,
retaining only bounded output needed to locate the first failure. The
structured performance suite is the deliberate exception: a case-level
`FAIL` that has returned a structured result is recorded as `FAIL`, and later
cases may still run; runner, setup, cleanup, context, or budget errors stop
the suite, and cases that never started remain `NOT RUN`. `make test` starts a
fresh local acceptance plan, while `make test-resume` continues through the
incomplete tail until the next RED or `ALL GREEN`. When the source SHA changes,
resume updates the SHA, clears stale failure output, and preserves the
completed prefix.
