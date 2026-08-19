# Test Matrix

Flowersec tests follow the product ownership boundaries. Tests use stable IDs,
assert behavior and process exit status, and own all processes, ports, browser
instances, namespaces, faults, and temporary files that they create.

| Product semantics | Owning test layer |
| --- | --- |
| Artifact parsing, admission binding, wire vectors, and error vectors | Shared machine-readable vectors executed by Go, Rust, Swift, and TypeScript contract tests |
| Security-negative parser rejection and bounded malformed-input handling | `testdata/transport_v3/` negative vectors, consumed by Go, TypeScript, Swift, and Rust v3 contract tests |
| TLS policy canonicalization, candidate identity, candidate-set hash, FSB3, and admission binding | `testdata/transport_v3/artifact_vectors.json` and per-language v3 codec suites |
| CA, private-CA, self-signed pin, mismatch, expiry, and overlap rotation | Production transport-security adapters and real TLS handshake suites in each supported runtime |
| Runtime security-mode capability and unsupported-candidate filtering | `testdata/transport_v3/capability_vectors.json`, production adapter capability tests, and Chromium provider tests |
| One-shot session lifecycle, stream FIN/reset/STOP_SENDING, DATAGRAM, close, and abort | Per-language memory carrier and native carrier contract tests |
| ConnectionController scheduling, blocked pin policies, one replacement lease, fresh primary artifacts, retry disposition, cancellation, and no replay | `testdata/transport_v3/controller_vectors.json` executed by all four SDKs |
| Client inbound RPC/notification handlers across real Controller generations | Go, Rust, and Node TypeScript loopback WebSocket tests; Swift and Browser remain unsupported |
| Accepted-session RPC, notification, stream dispatch, rejection, concurrency, and cleanup | Go, Rust, and Node TypeScript Acceptor handler suites |
| Declared Go/Rust/Node WebSocket and raw QUIC direct matrix | `stability/interop_matrix.json` defines 18 client/server/carrier cells and each cell's complete executable case set |
| Declared Go/Rust/Node WebSocket and raw QUIC tunnel matrix | `stability/interop_matrix.json` defines 18 endpoint-A/runtime/endpoint-B/carrier topologies and each topology's complete executable case set |
| Current direct and tunnel matrix support | All 36 declarations are unsupported because no single release-gating v3 test exercises the declaration's complete executable case set |
| Scoped carrier, server, and cross-runtime behavior | Capability and product tests use their own stable IDs and remain support evidence for exactly the behavior they execute; they do not promote a complete matrix declaration to supported |
| Optional Go WebTransport direct adapter | Go carrier conformance and Chromium direct checks when the adapter is selected |
| Node raw-QUIC-only no-origin and Rust rootless loopback profiles | Node native connector one-shot and Controller generations; Rust direct WebSocket plus spend-before-roots validation |
| Swift WSS production connector | The v3 Swift connector suite validates the production adapter; scoped Swift-Go interoperability, when registered, remains separate from the complete 18-cell matrix |
| Chromium direct, WebTransport-to-WSS tunnel, and WebTransport-to-QUIC tunnel | Local `make browser-smoke` using Chromium dual-listener bridge workloads; these are not native `TunnelRuntime` declarations |
| Firefox and WebKit native WebTransport capability | Local `make browser-compat`; unsupported runtime surfaces are asserted explicitly |
| Fault injector and kernel topology conformance | Four `diagnostic/kernel/*` tests using netns, tc, eBPF counters, and generic socket workloads |
| Real Flowersec weak-network behavior | Production WSS/raw QUIC direct Sessions and representative opaque tunnels in the same netns/tc/eBPF lab |
| Go-owned capacity, resource, soak, and payload throughput | Explicit `make performance`; this is not multi-language performance parity |
| Optional WebTransport and Chromium performance | Explicit `flowersec-test --suite performance-optional` on the prepared privileged host |
| Published Go-to-Node raw QUIC consumer compatibility | `release/npm-consumer/go-node-raw-quic/direct-session` installs registry packages and the tagged Go module, then verifies handshake, RPC, stream FIN, close, and cleanup; this is release readback, not a repository parity test |
| Apple/browser client-profile WSS interoperability | Registered scoped v3 interop IDs and the Chromium production runner validate only their named paths; Swift is Darwin-only and browser trust is runner-managed |

The expensive inventory is grouped by execution boundary and has no second manifest:

| Group | Stable runner IDs |
| --- | --- |
| Coverage and race | `coverage/{go,typescript,rust,swift}`, `race/go` |
| Local real browsers | Three `browser/chromium/*` topology IDs plus `browser/{firefox,webkit}/webtransport-capability` |
| Userspace Flowersec fault smoke | `diagnostic/weaknet/{raw-quic,websocket}/direct` |
| Kernel fault injector | Four `diagnostic/kernel/*` lifecycle and exact-fault IDs |
| Kernel-backed Flowersec weaknet | `diagnostic/flowersec-weaknet/{websocket,raw-quic}/direct/{delay-jitter,periodic-loss,burst-loss,outage,mtu-large-payload,rate-5mbps,rate-1mbps,reorder-duplicate}` and `diagnostic/flowersec-weaknet/{websocket,raw-quic}/tunnel/representative` |
| v3 Controller weaknet | `diagnostic/flowersec-v3-controller-weaknet/{websocket,raw-quic}/{delay-jitter,periodic-loss,reorder,outage-reconnect,pin-rotation-refresh-backoff-lease}` |
| Required Go performance | Six `performance/capacity/*` WSS/raw-QUIC IDs, raw QUIC migration soak, production WSS soak, and `performance/throughput/{wss,raw-quic}` |
| Optional WebTransport performance | `performance-optional/webtransport-capability`, then six `performance/capacity/*` WebTransport/Chromium IDs plus `performance/soak/webtransport` in `performance-optional` |
| Registry consumer readback | `release/npm-consumer/go-node-raw-quic/direct-session`, executed after publication on each supported native package platform |

Coverage and race run with `make coverage-race`. Browser compatibility uses
real native connections: Firefox currently rejects the connection before
admission, while WebKit currently lacks the outgoing DATAGRAM surface. Those
explicit unsupported contracts do not substitute for Chromium smoke.

`make precommit` is the fast feature-commit gate. `make test` is the bounded,
single-host acceptance gate used by `scripts/push-main.sh`; neither command
requires browsers, root, or an external host. `make check` remains an explicit
complete engineering check, while nightly, diagnostic, and performance work
stay outside the push path. Release publishes validated source and runs no tests.

`flowersec-test` reads one suite plan, starts at the first incomplete test ID,
and records only the source SHA, suite, plan, and completed IDs. A GREEN test
leaves no output artifact. A RED test stops scheduling and retains only bounded
output needed to locate the first failure. `make test` starts a fresh local
acceptance plan, while `make test-resume` continues through the incomplete tail
until the next RED or `ALL GREEN`. When the source SHA changes, resume updates
the SHA, clears stale failure output, and preserves the completed prefix.
