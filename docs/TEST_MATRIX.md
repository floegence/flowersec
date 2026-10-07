# Test Matrix

Flowersec tests follow the product ownership boundaries. Tests use stable IDs,
assert behavior and process exit status, and own all processes, ports, browser
instances, namespaces, faults, and temporary files that they create.

| Product semantics | Owning test layer |
| --- | --- |
| Strict current encoding, signatures, key agreement, Noise, READY, records and rekey | `testdata/transport_v4/` vectors consumed by the four SDKs and current schema tooling |
| Resource admission, flow control, protected work and actual cleanup | Current per-language transport and application ownership suites, plus shared resource vectors |
| Unicode normalization and host validation | Frozen `testdata/unicode15_1/` tables, current text vectors and `testdata/idna/idna_vectors.json` |
| Application JSON utility errors and notification payloads | Shared version-independent fixtures under `testdata/rpc/`, consumed by their declared utility tests |
| Namespace bootstrap, durable restore, revocation and original authority continuity | Per-language namespace suites using independent trust and durable stores |
| Pool spend, live authorization, direct and tunnel admission | Original configured native sources, authenticated control routes and durable admission tests |
| TLS CA, leaf pin, mismatch, expiry and signed local-loopback boundaries | Production provider tests with actual TLS or explicitly local authenticated WebSocket connections |
| Controller initialization, publication, replacement, retained sessions and no replay | Current SDK Controller and native interruption tests |
| Serve authorization, handler publication, Drain and lease cleanup | Current SDK Serve tests; a failed admission must not retire a healthy sibling |
| Unary, streaming, notifications, execution history and resume | Typed service contract and real Session dispatch suites |
| Raw streams, typed message streams, half-close and byte progress | Current native stream, HTTP integration and Duplex bridge suites |
| Browser proxy and controlled Cookie sessions | Original Service Worker/application route, current Session and final upstream authorization tests |
| Direct and tunneled interoperability | Executable entries in `stability/interop_matrix.json` and the registered runner; declarations alone do not establish verified support |
| Swift native Apple provider | Current macOS native Session tests and the same production provider on iOS Simulator |
| Chromium direct and opaque tunnel topologies | Local `make browser-smoke` with original browser carriers and current authenticated material |
| Firefox and WebKit capabilities | Local `make browser-compat`; runtime limitations remain explicit outcomes |
| Fault injector and kernel topology conformance | Four `diagnostic/kernel/*` tests using netns, tc, eBPF counters and generic socket workloads |
| Real Flowersec weak-network behavior | Current native WSS/raw QUIC direct Sessions and representative opaque tunnels in the same kernel lab |
| Go-owned capacity, resource, soak and payload throughput | Explicit `make performance`; this is not multi-language performance parity |
| Optional WebTransport and Chromium performance | Integrated optional performance partition; missing native capability is `UNSUPPORTED`, while provider, browser and cleanup failures fail the suite |
| Manual published Go-to-Node raw QUIC consumer diagnostic | `release/npm-consumer/go-node-raw-quic/direct-session` installs registry packages and the tagged Go module, then exercises their public APIs. No workflow invokes this diagnostic, it is not release-gating evidence, and package-integrity/source-commit readback remains part of publication. |

The expensive inventory is grouped by execution boundary and has no second manifest:

| Group | Stable runner IDs |
| --- | --- |
| Coverage and race | `coverage/{go,typescript,rust,swift}`, `race/go` |
| Local real browsers | Chromium `browser/chromium/webtransport/*` trust and capability cases, `browser/chromium/websocket/self-contained`, `browser/chromium/proxy-service-worker`, and `browser/{firefox,webkit}/{webtransport-pin-capability,websocket/self-contained}` |
| Userspace Flowersec fault smoke | `diagnostic/weaknet/{raw-quic,websocket}/direct` |
| Kernel fault injector | Four `diagnostic/kernel/*` lifecycle and exact-fault IDs |
| Kernel-backed Flowersec weaknet | `diagnostic/flowersec-weaknet/{websocket,raw-quic}/direct/{delay-jitter,periodic-loss,burst-loss,outage,mtu-large-payload,rate-5mbps,rate-1mbps,reorder-duplicate}` and `diagnostic/flowersec-weaknet/{websocket,raw-quic}/tunnel/representative` |
| Controller weaknet | `diagnostic/flowersec-controller-weaknet/{websocket,raw-quic}/{delay-jitter,periodic-loss,reorder,outage-reconnect,pin-rotation-refresh-backoff-lease}` |
| Required Go performance | Six `performance/capacity/*` WSS/raw-QUIC IDs, raw QUIC migration soak, production WSS soak, `performance/single-connection/{wss,raw-quic}`, and `performance/throughput/{wss,raw-quic}` |
| Optional WebTransport performance | `performance-optional/webtransport-capability`, followed in the integrated plan by six `performance/capacity/*` WebTransport/Chromium IDs, `performance/soak/webtransport`, `performance/single-connection/webtransport`, and `performance/throughput/webtransport`; only a structured missing-WebTransport result records these IDs as `UNSUPPORTED`, while browser path, launch, navigation, runner, or cleanup failures remain `FAIL` |

Coverage and race run with `make coverage-race`. Browser compatibility uses
real native connections: Firefox currently rejects the connection before
admission, while WebKit currently lacks the outgoing DATAGRAM surface. Those
explicit unsupported contracts do not substitute for Chromium smoke.

`make precommit` is the fast feature-commit gate. `make test` is the bounded,
single-host acceptance gate used by `scripts/push-main.sh`; neither command
requires browsers, root, or an external host. `make check` remains an explicit
complete engineering check, while nightly, diagnostic, and performance work
stay outside the push path. Release publishes validated source and runs no tests.

Browser public-CA cases and `make check` require independently provisioned TLS
material before execution:

| Environment variable | Required input |
| --- | --- |
| `FLOWERSEC_BROWSER_PUBLIC_CA_HOST` | Canonical lowercase DNS hostname covered by the certificate, without a port or trailing dot |
| `FLOWERSEC_BROWSER_PUBLIC_CA_CERT` | PEM server certificate followed by its intermediate chain, trusted by the system public CA roots |
| `FLOWERSEC_BROWSER_PUBLIC_CA_KEY` | PEM private key matching that certificate |

The leaf must use ECDSA P-256, be currently valid, and have a total lifetime of
at most 14 days. `make final-public-ca-preflight` validates these inputs before
the complete engineering check. Local pin tests do not establish public-CA
acceptance.

Browser cells in the server parity scripts additionally require an absolute
`FLOWERSEC_BROWSER_NATIVE_INSTALLATION` path to the deployment owner's native
carrier declaration and an absolute `FLOWERSEC_TEST_ARTIFACT_DIR` outside both
the repository and system temporary directories. The declaration follows
`BrowserNativeInstallation` in
[`browser_runner_declaration.go`](../flowersec-go/internal/interopharness/browser_runner_declaration.go):
it identifies the exact Chromium runtime, installed module host, carrier,
terminator profile, finite resource limits and independent qualification
evidence. WebTransport also names its HTTP/3 provider, implementation and build.
Runtime observation must agree with this existing declaration; the runner does
not generate qualification from an observed browser. Each parity run provisions
its own application installation and durable history, removes them after actual
process cleanup, and retains only checksummed failure logs when needed.

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
