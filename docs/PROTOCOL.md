# Flowersec Protocol Contracts (Current Wire Formats)

> The detailed legacy sections below describe the implemented v1 wire. Transport v2 is a separate implemented profile whose architecture, carrier registry, public contract, shared vectors, and migration boundary are maintained in `docs/TRANSPORT_V2_ARCHITECTURE.md`, `stability/transport_v2_contract.json`, `docs/API_CONTRACT.md`, `testdata/transport_v2/`, and `docs/MIGRATION_TRANSPORT_V2.md`.

This document describes the current on-the-wire contracts implemented by this repository, with a focus on:

- **Framing** (what bytes are sent)
- **Ordering** (what happens first)
- **Cross-language alignment** (Go, TypeScript, Swift, and Rust implement the same portable contracts)

For the recommended custom stream patterns (meta + bytes), see `docs/STREAMS.md`.

## 0. Stack overview

The Flowersec stack is:

1. **WebSocket**
2. _(Tunnel path only)_ **Attach (plaintext JSON)**
3. **E2EE handshake** (`FSEH` frames)
4. **E2EE record layer** (`FSEC` frames)
5. **Yamux** multiplexing (over the encrypted byte stream)
6. **Stream hello** (a small per-stream identifier)
7. **RPC** framing (length-prefixed JSON on the `rpc` stream)

## 1. Tunnel attach (tunnel path only)

Before E2EE, tunnel clients send a single **text** websocket message containing JSON:

- Type: `flowersec.tunnel.v1.Attach` (generated)
- Fields include: `v`, `channel_id`, `role`, `token`, `endpoint_instance_id`

Current implementation:

- Go: `flowersec-go/tunnel/protocol/attach.go` (parsing + constraints)
- Go tunnel server: `flowersec-go/tunnel/server/server.go` (`handleWS`)
- TypeScript endpoint/client: `flowersec-ts/src/endpoint` and `flowersec-ts/src/tunnel-client`
- Swift endpoint/client: `flowersec-swift/Sources/Flowersec/Endpoint.swift` and `RPC.swift`
- Rust endpoint/client: `flowersec-rust/src/endpoint.rs` and `client.rs`

If the tunnel rejects the attach, it closes the websocket with a close status and a **reason token**.
Official clients map these reason tokens to shared error codes (see `docs/ERROR_MODEL.md`):

- `too_many_connections`
- `expected_attach`, `invalid_attach`
- `invalid_token`, `channel_mismatch`, `init_exp_mismatch`, `idle_timeout_mismatch`, `role_mismatch`, `token_replay`, `tenant_mismatch`, `policy_denied`, `policy_error`, `replace_rate_limited`, `attach_failed`
- `timeout`, `canceled`

## 2. E2EE handshake framing (`FSEH`)

After attach (tunnel path) or immediately (direct path), endpoints perform a PSK-authenticated handshake.

### 2.1 Handshake frame format

Each handshake websocket **binary** message is:

- `magic` (4 bytes): ASCII `"FSEH"`
- `version` (1 byte): currently `1`
- `handshake_type` (1 byte): `1` (init) / `2` (resp) / `3` (ack)
- `length` (4 bytes): big-endian `uint32` length of the JSON payload
- `payload` (`length` bytes): UTF-8 JSON bytes

Current implementation:

- Go framing: `flowersec-go/crypto/e2ee/framing.go`
- TS framing: `flowersec-ts/src/e2ee/framing.ts`
- Swift framing: `flowersec-swift/Sources/Flowersec/HandshakeFrames.swift`
- Rust framing: `flowersec-rust/src/e2ee.rs`

### 2.2 Handshake message flow

The flow is:

1. Client → Server: `handshake_type=init` (JSON: `E2EE_Init`)
2. Server → Client: `handshake_type=resp` (JSON: `E2EE_Resp`)
3. Client → Server: `handshake_type=ack` (JSON: `E2EE_Ack`)
4. Server → Client: an **encrypted ping record** (`FSEC`, `seq=1`) as a "server-finished" confirmation

The handshake uses:

- A 32-byte PSK (`e2ee_psk_b64u`) shared out of band
- An ephemeral ECDH exchange (suite dependent)
- A transcript hash binding the session keys and rekeys

Clock-skew semantics:

- Implementations may expose a convenience default when callers omit the clock-skew option.
- Once normalized and passed to the E2EE handshake, `clock_skew = 0` means exact timestamp validation, not "use default".
- Negative clock skew is invalid.
- Endpoints that use zero skew should expect legitimate connections to fail unless their clocks are synchronized tightly enough for second-level timestamp checks.

Current implementation:

- Go: `flowersec-go/crypto/e2ee/handshake.go`
- TS: `flowersec-ts/src/e2ee/handshake.ts`
- Swift: `flowersec-swift/Sources/Flowersec/Handshake.swift` and `ServerHandshake.swift`
- Rust: `flowersec-rust/src/e2ee.rs`
- Message schemas: `idl/flowersec/e2ee/v1/e2ee.fidl.json` (generated into `gen/flowersec/e2ee/v1`)

## 3. E2EE record framing (`FSEC`)

After the handshake, all application bytes are carried as encrypted records.

### 3.1 Record frame format

Each record websocket **binary** message is:

- `magic` (4 bytes): ASCII `"FSEC"`
- `version` (1 byte): currently `1`
- `flags` (1 byte):
  - `0`: app payload
  - `1`: ping (keepalive; empty plaintext)
  - `2`: rekey (empty plaintext; updates keys for subsequent records)
- `seq` (8 bytes): big-endian `uint64` record sequence number
- `length` (4 bytes): big-endian `uint32` ciphertext length
- `ciphertext` (`length` bytes): AEAD ciphertext including the auth tag

Nonces are 12 bytes:

- `nonce_prefix` (4 bytes) derived from the handshake keys
- `seq` (8 bytes) big-endian

Sequence numbers are monotonic per direction.
If an implementation would wrap or exhaust the `uint64` record sequence space, it MUST stop sending records and fail the secure connection closed.
It MUST NOT reuse a nonce/key pair by wrapping the sequence number.

Current implementation:

- Go framing + decrypt/encrypt: `flowersec-go/crypto/e2ee/{framing.go,record.go}`
- TS framing + decrypt/encrypt: `flowersec-ts/src/e2ee/{framing.ts,record.ts}`
- Swift framing + decrypt/encrypt: `flowersec-swift/Sources/Flowersec/{RecordCodec.swift,SecureChannel.swift}`
- Rust framing + decrypt/encrypt: `flowersec-rust/src/e2ee.rs`

### 3.2 Rekey semantics

When a peer receives a `flags=2` record at sequence `seq`, it derives a new receive key bound to:

- the handshake transcript hash
- the rekey base secret
- the record sequence number
- the direction label (client→server / server→client)

Current implementation:

- Go: `flowersec-go/crypto/e2ee/record.go` (`DeriveRekeyKey`) and `secureconn.go` (apply on receive)
- TS: `flowersec-ts/src/e2ee/kdf.ts` + `secureChannel.ts`
- Swift: `flowersec-swift/Sources/Flowersec/RecordCodec.swift` + `SecureChannel.swift`
- Rust: `flowersec-rust/src/e2ee.rs`

The high-level controls are Go `Client.Rekey()` / `Session.Rekey()`, TypeScript `client.rekey()` / `Session.rekey()`, Swift `FlowersecClient.rekey()` / `EndpointSession.rekey()`, and Rust `Client::rekey()` / `endpoint::Session::rekey()`. Rekey is serialized with ordinary secure-channel writes and does not expose key material.

## 4. Yamux multiplexing

Once the encrypted byte stream is established, endpoints run Yamux over it to multiplex streams.

Notes:

- Flowersec uses the Hashicorp Yamux framing (`version=0`, 12-byte header).
- The server endpoint acts as the Yamux server; the client endpoint acts as the Yamux client.

Current implementation:

- Go: Flowersec's `flowersec-go/mux/yamux` wrapper over `github.com/libp2p/go-yamux/v5`
- TS: `flowersec-ts/src/yamux/*` (see `flowersec-ts/YAMUX_ALIGNMENT.md` for alignment notes)
- Swift: `flowersec-swift/Sources/Flowersec/Yamux.swift`
- Rust: Flowersec-owned implementation in `flowersec-rust/src/yamux.rs`

All four expose acknowledged PING probes and enforce the six shared limits from `stability/sdk_defaults.json`. The Rust implementation is not based on the upstream `yamux` crate because Flowersec requires explicit ACK correlation and complete resource-limit control.

Stream reset sends Yamux RST without an application error payload. Local causes are diagnostic-only. Go exposes `stream.Stream.Reset()`, TypeScript exposes `stream.reset()`, Swift exposes `FlowersecByteStream.reset()`, and Rust exposes `YamuxStream::reset()`.

## 5. Stream hello

Each opened Yamux stream begins with a small "hello" message identifying the stream kind (for example the reserved `rpc` stream).

Current implementation:

- Go: `flowersec-go/streamhello/*`
- TS: `flowersec-ts/src/streamhello/*`
- Swift: `flowersec-swift/Sources/Flowersec/DataCoding.swift` and `Yamux.swift`
- Rust: `flowersec-rust/src/streamhello.rs`

## 6. RPC framing (on the `rpc` stream)

RPC messages are length-prefixed JSON frames:

- `len` (4 bytes): big-endian `uint32` JSON length
- `json` (`len` bytes): UTF-8 JSON bytes

Current implementation:

- Go framing: `flowersec-go/framing/jsonframe/jsonframe.go`
- TS framing: `flowersec-ts/src/framing/jsonframe.ts`
- Swift framing: `FlowersecJSONFrame` in `flowersec-swift/Sources/Flowersec/RPC.swift`
- Rust framing: `flowersec-rust/src/framing.rs` and `streamio.rs`
- Message schemas: `idl/flowersec/rpc/v1/rpc.fidl.json` (generated into `gen/flowersec/rpc/v1`)

Typed RPC clients and server handlers are generated for all four languages by `tools/idlgen`. Server concurrency, request queues, notification queues, cancellation, and timeouts are bounded by the shared defaults contract.

## 7. Additional stream protocols

Flowersec also defines application protocols layered on top of Yamux custom streams.

- HTTP/WS proxying over custom streams: `docs/PROXY.md` (`flowersec-proxy/http1`, `flowersec-proxy/ws`)

## 8. Go-reference interoperability contract

Flowersec validates portable protocol behavior with exactly seven directed cells:

- Go -> Go
- TypeScript -> Go and Go -> TypeScript
- Swift -> Go and Go -> Swift
- Rust -> Go and Go -> Rust

Go -> Go is mandatory and runs first. If it fails, the matrix is invalid and no failure is attributed to another SDK. Non-Go pairwise edges are deliberately absent; the IDL, shared fixtures, defaults, error registries, and wire documents remain the normative language-neutral contract.

Each cell covers Direct and Tunnel with both X25519 and P-256. The versioned JSON Lines harness rejects unknown fields, missing fields, duplicate or out-of-order events, early EOF, non-zero exit, and deadline expiry. `stability/interop_matrix.json` and `testdata/interop/v1/profiles.json` define the exact cells, cases, diagnostics, and fixed workloads.
