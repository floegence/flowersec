# Test Matrix

Flowersec tests follow the product ownership boundaries. Tests use stable IDs,
assert behavior and process exit status, and own all processes, ports, browser
instances, namespaces, faults, and temporary files that they create.

| Product semantics | Owning test layer |
| --- | --- |
| Artifact parsing, admission binding, wire vectors, and error vectors | Shared machine-readable vectors executed by Go, Rust, Swift, and TypeScript contract tests |
| One-shot session lifecycle, stream FIN/reset/STOP_SENDING, DATAGRAM, close, and abort | Per-language memory carrier and native carrier contract tests |
| ConnectionController scheduling, fresh artifact per attempt, retry disposition, cancellation, and no replay | Shared controller vectors executed by all four SDKs |
| Go WebSocket, raw QUIC, and WebTransport in direct and tunnel topologies | Go native carrier and self-contained Go interoperability tests |
| Node WebTransport and WSS against Go | TypeScript-to-Go integration tests using production adapters and session engines |
| Rust raw QUIC against Go | Rust-to-Go direct and tunnel integration tests |
| Swift WSS against Go | Swift-to-Go integration tests |
| Chromium direct, WebTransport-to-WSS tunnel, and WebTransport-to-QUIC tunnel | Local `make browser-smoke` using the Chromium Playwright project |
| Network namespaces, BPF, tc, weak networks, Firefox, and WebKit | Explicit `make diagnostic` workloads on a prepared privileged host |
| Capacity, resource, and soak thresholds | Explicit `make performance` workloads |

`make precommit` is the fast feature-commit gate. `make test` is the bounded,
single-host acceptance gate used by `scripts/push-main.sh`; neither command
requires browsers, root, or an external host. `make check` remains an explicit
complete engineering check, while nightly, diagnostic, and performance work
stay outside the push path. Release publishes validated source and runs no tests.

`flowersec-test` reads one suite plan, runs the first incomplete test ID, and
records only the source SHA, suite, plan, and completed IDs. A GREEN test leaves
no output artifact. A RED test stops scheduling and retains only bounded output
needed to locate the first failure. `make test` starts a fresh local acceptance
plan, while `make test-resume` advances only its first incomplete ID. A source
SHA change always starts a new plan.
