# Flowersec v0.23 Migration

Flowersec v0.23 keeps the v0.22 wire formats and aligns explicit rekey, stream reset, termination diagnostics, and interoperability gates across Go, TypeScript, Swift, and Rust.

## Public control APIs

All four SDKs now expose the same portable control operations:

| Operation | Go | TypeScript | Swift | Rust |
| --- | --- | --- | --- | --- |
| Client rekey | `Client.Rekey()` | `client.rekey()` | `FlowersecClient.rekey()` | `Client::rekey()` |
| Endpoint rekey | `Session.Rekey()` | `Session.rekey()` | `EndpointSession.rekey()` | `Session::rekey()` |
| Stream reset | `stream.Stream.Reset()` | `stream.reset()` | `FlowersecByteStream.reset()` | `YamuxStream::reset()` |

Reset sends a Yamux RST only. Do not encode a local exception or error message on the wire. Rekey is serialized with normal secure-channel writes. Repeated close/reset/rekey calls either remain idempotent or return a stable typed error; callers must not infer state from error strings.

Go stream APIs now return `stream.Stream`, which combines `io.Reader`, `io.Writer`, `io.Closer`, and `Reset() error`. Downstream mocks that previously implemented only `io.ReadWriteCloser` must add `Reset() error`.

Swift endpoint sessions expose `terminationError()` and Rust endpoint sessions expose `termination_error()` for stable typed abnormal-termination inspection.

Reconnect configuration and shutdown are now strict. Go callers must check the error returned by `Manager.Disconnect()`, and Rust callers must check the `Result` returned by `ReconnectManager::disconnect()`. TypeScript and Rust reject invalid reconnect limits such as an enabled configuration with zero attempts instead of silently clamping them. Client-close failures leave the reconnect manager in an error state and are returned to the caller where the language API permits it.

## Interoperability matrix

The old non-Go pairwise and Yamux-only harnesses are removed. The supported executable matrix is:

- Go -> Go baseline
- TypeScript -> Go and Go -> TypeScript
- Swift -> Go and Go -> Swift
- Rust -> Go and Go -> Rust

This is not a reduction in language importance. Every non-Go SDK must pass both client and server directions. Shared IDL, fixtures, defaults, error registries, and protocol documents remain language-neutral sources of truth.

CI runs the deterministic smoke profile. Before merging or tagging a release, run:

```bash
make interop-smoke
make interop-stress
make check
```

`make interop-stress` requires all four toolchains, uses a fixed seed and workload, runs at most two directed cells concurrently, and has a hard five-minute matrix deadline. It never retries a failed harness, reduces load, or skips a language.

## Harness protocol

Custom harness integrations must implement JSON Lines protocol version 1 with `hello`, `run_client`, `serve`, `ready`, `stop`, `result`, and `fatal` events. Unknown fields, missing fields, duplicate/out-of-order events, early EOF, stderr/stdout mixing, non-zero exit, and deadline expiry are fatal.

Each case runs in a fresh process. stdout is protocol-only and logs belong on stderr. Background tasks must be supervised and joined. A forced process kill remains a failed case even when cleanup succeeds.

## Release tags

The v0.23 release uses three tags on one commit:

- `flowersec-go/v0.23.0` for Go and TypeScript release automation
- `0.23.0` for SwiftPM
- `flowersec-rust/v0.23.0` for crates.io

Upgrade downstream dependencies only after all three tags and release workflows succeed.
