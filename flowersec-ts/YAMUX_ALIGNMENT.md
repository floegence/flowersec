# TS Yamux Alignment Status

This repository contains a TypeScript implementation of the Yamux protocol in `flowersec-ts/src/yamux/`.
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

Source: `flowersec-ts/src/yamux/constants.ts`, `flowersec-ts/src/yamux/header.ts`, `flowersec-ts/src/yamux/session.ts`, `flowersec-ts/src/yamux/stream.ts`.

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

- Types: `DATA(0)`, `WINDOW_UPDATE(1)`, `PING(2)`, `GO_AWAY(3)` (`flowersec-ts/src/yamux/constants.ts`).
- Flags: `SYN(1)`, `ACK(2)`, `FIN(4)`, `RST(8)`.

### Stream IDs

- Client opens **odd** stream IDs, server opens **even** stream IDs:
  - `opts.client=true` starts at `1`, step `+2`
  - `opts.client=false` starts at `2`, step `+2`
  - (`flowersec-ts/src/yamux/session.ts`)

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

The TS Yamux implementation is exercised in real interop scenarios:

- **TS client ↔ Go server (minimal Yamux over TCP)**:
  - Test: `flowersec-ts/src/e2e/yamux_interop.test.ts` (minimal tcp mode)
  - Go harness: `flowersec-go/cmd/flowersec-yamux-harness/main.go`
  - Covers: window update race, RST handling, concurrent open/close, session close.
  - Notes: opt-in via `YAMUX_INTEROP=1` (runs Go harnesses).
  - Notes: sizes scale via `YAMUX_INTEROP_SCALE` (e.g. `2` => 20 streams / 1 MiB per stream).
  - Notes: client-initiated RST scenarios run when `YAMUX_INTEROP_CLIENT_RST=1`.
  - Notes: window-update and concurrent-open/close stress runs when `YAMUX_INTEROP_STRESS=1`.
- **TS client ↔ Go server (full chain: E2EE + tunnel + Yamux)**:
  - Test: `flowersec-ts/src/e2e/yamux_interop.test.ts` (full chain mode)
  - Go harness: `flowersec-go/cmd/flowersec-e2e-harness/main.go` with `-scenario`
  - Notes: reduced stream counts/payload sizes to keep end-to-end runtime bounded.
- **Layered close/reset probes (memory + WS + full chain)**:
  - Test: `flowersec-ts/src/e2e/yamux_interop_layers.test.ts`
  - Covers: session-close wakeup, FIN/RST delivery across SecureChannel + WebSocketBinaryTransport,
    and a full-chain FIN/RST probe on `rst_mid_write_go`.
  - Notes: gated by `YAMUX_INTEROP=1`; the full-chain probe additionally requires
    `YAMUX_INTEROP_DEBUG=1`.
- **TS client ↔ Go server (RPC happy path)**:
  - Test: `flowersec-ts/src/e2e/go_integration.test.ts`
  - Go harness: `flowersec-go/cmd/flowersec-e2e-harness/main.go`
  - Covers: single-stream RPC framing and basic window updates.

These confirm wire-level interop and the correctness of the happy-path subset under real IO.

## Current gaps (not yet proven or intentionally simplified)

These items are either untested or simplified compared to HashiCorp Yamux behavior:

- **Multi-stream concurrency**: covered by interop tests, but fairness/priority under heavy contention
  is not proven.
- **Large payload / fragmentation**: covered up to ~1 MiB per stream; larger payloads and pathological
  fragmentation are still untested.
- **Stress & fuzz robustness**: no fuzz tests for invalid headers/flags/lengths and adversarial streams.
- **Session-level behaviors**: GO_AWAY reason handling, keepalive/heartbeats, and more nuanced shutdown.
- **Strictness differences**: unknown frame types trigger session close, which may be stricter than some
  implementations.
- **Server-initiated streams**: Go-initiated streams are not covered by interop tests yet.
- **Bidirectional window-update stress**: current window update tests run TS -> Go only.

## Practical alignment summary

- **Aligned (high confidence)**:
  - Version 0 framing, stream ID parity, open handshake via SYN/ACK, basic DATA transfer, basic window
    updates, and interop with HashiCorp Yamux server for the Flowersec RPC use-case.
- **Aligned but under-tested**:
  - FIN/RST edges, ping handling, and window boundary conditions.
- **Not aligned / out of scope today**:
  - Full Yamux feature parity (advanced GO_AWAY semantics, keepalive, exhaustive error handling).
