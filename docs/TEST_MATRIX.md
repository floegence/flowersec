# Test Matrix

Flowersec tests follow the product ownership boundaries. Tests use stable IDs,
assert behavior and process exit status, and own all processes, ports, browser
instances, namespaces, faults, and temporary files that they create.

| Product semantics | Owning test layer |
| --- | --- |
| Artifact parsing, admission binding, wire vectors, and error vectors | Shared machine-readable vectors executed by Go, Rust, Swift, and TypeScript contract tests |
| Security-negative parser rejection and bounded malformed-input handling | `testdata/transport_v2/security_negative_vectors.json`, consumed by `protocol/{go,typescript,swift,rust}` |
| One-shot session lifecycle, stream FIN/reset/STOP_SENDING, DATAGRAM, close, and abort | Per-language memory carrier and native carrier contract tests |
| ConnectionController scheduling, fresh artifact per attempt, retry disposition, cancellation, and no replay | Shared controller vectors executed by all four SDKs |
| Go WebSocket, raw QUIC, and WebTransport in direct and tunnel topologies | Go native carrier and self-contained Go interoperability tests |
| Node WebTransport and WSS against Go | TypeScript-to-Go integration tests using production adapters and session engines |
| Rust raw QUIC against Go | Rust-to-Go direct and tunnel integration tests |
| Swift WSS against Go | Swift-to-Go integration tests |
| Chromium direct, WebTransport-to-WSS tunnel, and WebTransport-to-QUIC tunnel | Local `make browser-smoke` using the Chromium Playwright project |
| Firefox and WebKit native WebTransport capability | Local `make browser-compat`; unsupported runtime surfaces are asserted explicitly |
| Network namespaces, BPF, tc, and weak networks | Explicit `make diagnostic` workloads on a prepared privileged host |
| Capacity, resource, and soak thresholds | Explicit `make performance` workloads |

The expensive inventory has four groups and no second manifest:

| Group | Stable runner IDs |
| --- | --- |
| Coverage and race | `coverage/{go,typescript,rust,swift}`, `race/go` |
| Local real browsers | Three `browser/chromium/*` topology IDs plus `browser/{firefox,webkit}/webtransport-capability` |
| Privileged Linux diagnostics | `diagnostic/weaknet/{raw-quic,websocket}/direct` and four `diagnostic/kernel/*` lifecycle IDs |
| Performance | Twelve `performance/capacity/*` IDs, raw QUIC migration soak, and production WSS/WebTransport soak IDs |

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
