# TS Yamux Alignment Status

This repository contains a TypeScript implementation of the Yamux protocol in `ts/src/yamux/`.
It is designed to be interoperable with HashiCorp's Yamux (protocol version `0`) for the subset of
features required by Flowersec: multiplexing multiple logical byte streams over a single encrypted
transport.

## What “aligned” means here

“Aligned” in this document means:

- **Wire compatibility**: our frames can be understood by `github.com/hashicorp/yamux` and vice versa.
- **Behavioral compatibility (subset)**: stream open/accept, data transfer, and basic flow control work
  correctly when interoperating with HashiCorp Yamux.
- **Not a full spec clone**: some Yamux behaviors are intentionally simplified or currently unimplemented.

## Implemented protocol surface (TS)

Source: `ts/src/yamux/constants.ts`, `ts/src/yamux/header.ts`, `ts/src/yamux/session.ts`, `ts/src/yamux/stream.ts`.

### Header & framing

- 12-byte header (`HEADER_LEN=12`) with:
  - `version: u8`
  - `type: u8`
  - `flags: u16` (big-endian)
  - `stream_id: u32` (big-endian)
  - `length: u32` (big-endian)
- Supported `version`: `0` (`YAMUX_VERSION=0`).
- Unknown `type` or invalid `version` causes session close (strict).

### Frame types & flags

- Types: `DATA(0)`, `WINDOW_UPDATE(1)`, `PING(2)`, `GO_AWAY(3)` (`ts/src/yamux/constants.ts`).
- Flags: `SYN(1)`, `ACK(2)`, `FIN(4)`, `RST(8)`.

### Stream IDs

- Client opens **odd** stream IDs, server opens **even** stream IDs:
  - `opts.client=true` starts at `1`, step `+2`
  - `opts.client=false` starts at `2`, step `+2`
  - (`ts/src/yamux/session.ts`)

### Stream open handshake

- Opening a stream starts by sending a `WINDOW_UPDATE` with `SYN` (length may be `0`).
- Peer creates the stream when it receives `SYN` on either `DATA` or `WINDOW_UPDATE`.
- The peer responds with a `WINDOW_UPDATE` carrying `ACK`, moving both sides into “established”.

### Flow control (per-stream windows)

- Default per-stream max window: `256 KiB` (`DEFAULT_MAX_STREAM_WINDOW=256*1024`).
- Each stream maintains:
  - `recvWindow`: decremented by received `DATA` length; receiving beyond window triggers `RST`.
  - `sendWindow`: incremented by `WINDOW_UPDATE` deltas; writing waits if `sendWindow<=0`.
- `WINDOW_UPDATE` generation strategy:
  - Always send for SYN/ACK transitions.
  - Otherwise, send when replenishment delta reaches at least half the max window.

### FIN/RST semantics

- Local close sends a `WINDOW_UPDATE` with `FIN`.
- Receiving `FIN` transitions the stream to a closed-ish state and unblocks pending reads.
- `RST` is sent as `WINDOW_UPDATE` with `RST` (and length `0`) and terminates the stream.
- If a frame references an unknown stream **without** `SYN`, TS sends `RST`.

### PING / GO_AWAY behavior

- PING:
  - If `SYN` is set, TS replies with `ACK` and the same opaque `length`.
  - TS does not currently initiate pings or track RTT.
- GO_AWAY:
  - Any `GO_AWAY` immediately closes the session (no reason code handling).

## Interop evidence (what is actually tested today)

The TS Yamux implementation is exercised in a real interop scenario:

- **TS client ↔ Go server (HashiCorp Yamux)**:
  - Test: `ts/src/e2e/go_integration.test.ts`
  - Go harness uses `github.com/hashicorp/yamux` as the **server**:
    - `go/cmd/flowersec-e2e-harness/main.go`
  - The test covers:
    - Opening a Yamux stream from TS (`openStream()`).
    - Writing/reading application bytes over that stream (RPC framing).
    - Basic window update behavior on the happy path.

This confirms wire-level interop and the correctness of the “happy-path” subset under real IO.

## Current gaps (not yet proven or intentionally simplified)

These items are either untested or simplified compared to HashiCorp Yamux behavior:

- **Multi-stream concurrency**: no dedicated tests for multiple simultaneous streams, interleaved frames,
  and fairness under contention.
- **Large payload / fragmentation**: no tests for very large writes requiring repeated window updates.
- **Stress & fuzz robustness**: no fuzz tests for invalid headers/flags/lengths and adversarial streams.
- **Session-level behaviors**: GO_AWAY reason handling, keepalive/heartbeats, and more nuanced shutdown.
- **Strictness differences**: unknown frame types trigger session close, which may be stricter than some
  implementations.

## Practical alignment summary

- **Aligned (high confidence)**:
  - Version 0 framing, stream ID parity, open handshake via SYN/ACK, basic DATA transfer, basic window
    updates, and interop with HashiCorp Yamux server for the Flowersec RPC use-case.
- **Aligned but under-tested**:
  - FIN/RST edges, ping handling, and window boundary conditions.
- **Not aligned / out of scope today**:
  - Full Yamux feature parity (advanced GO_AWAY semantics, keepalive, exhaustive error handling).

