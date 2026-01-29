# Flowersec Protocol Contracts (Current Wire Format)

Status: experimental; not audited.

This document describes the current on-the-wire contracts implemented by this repository, with a focus on:

- **Stable framing** (what bytes are sent)
- **Stable ordering** (what happens first)
- **Cross-language alignment** (Go and TypeScript implement the same contracts)

For the user-facing stable APIs, see `docs/API_SURFACE.md`.
For the recommended custom stream patterns (meta + bytes), see `docs/STREAMS.md`.

## 0. Stack overview

The Flowersec stack is:

1) **WebSocket**
2) *(Tunnel path only)* **Attach (plaintext JSON)**
3) **E2EE handshake** (`FSEH` frames)
4) **E2EE record layer** (`FSEC` frames)
5) **Yamux** multiplexing (over the encrypted byte stream)
6) **Stream hello** (a small per-stream identifier)
7) **RPC** framing (length-prefixed JSON on the `rpc` stream)

## 1. Tunnel attach (tunnel path only)

Before E2EE, tunnel clients send a single **text** websocket message containing JSON:

- Type: `flowersec.tunnel.v1.Attach` (generated)
- Fields include: `v`, `channel_id`, `role`, `token`, `endpoint_instance_id`

Current implementation:

- Go: `flowersec-go/tunnel/protocol/attach.go` (parsing + constraints)
- Go tunnel server: `flowersec-go/tunnel/server/server.go` (`handleWS`)

If the tunnel rejects the attach, it closes the websocket with a close status and a **reason token**.
Official clients map these reason tokens to stable error codes (see `docs/ERROR_MODEL.md`):

- `too_many_connections`
- `expected_attach`, `invalid_attach`
- `invalid_token`, `channel_mismatch`, `init_exp_mismatch`, `idle_timeout_mismatch`, `role_mismatch`, `token_replay`, `replace_rate_limited`, `attach_failed`
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

### 2.2 Handshake message flow

The flow is:

1) Client → Server: `handshake_type=init` (JSON: `E2EE_Init`)
2) Server → Client: `handshake_type=resp` (JSON: `E2EE_Resp`)
3) Client → Server: `handshake_type=ack` (JSON: `E2EE_Ack`)
4) Server → Client: an **encrypted ping record** (`FSEC`, `seq=1`) as a "server-finished" confirmation

The handshake uses:

- A 32-byte PSK (`e2ee_psk_b64u`) shared out of band
- An ephemeral ECDH exchange (suite dependent)
- A transcript hash binding the session keys and rekeys

Current implementation:

- Go: `flowersec-go/crypto/e2ee/handshake.go`
- TS: `flowersec-ts/src/e2ee/handshake.ts`
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

Current implementation:

- Go framing + decrypt/encrypt: `flowersec-go/crypto/e2ee/{framing.go,record.go}`
- TS framing + decrypt/encrypt: `flowersec-ts/src/e2ee/{framing.ts,record.ts}`

### 3.2 Rekey semantics

When a peer receives a `flags=2` record at sequence `seq`, it derives a new receive key bound to:

- the handshake transcript hash
- the rekey base secret
- the record sequence number
- the direction label (client→server / server→client)

Current implementation:

- Go: `flowersec-go/crypto/e2ee/record.go` (`DeriveRekeyKey`) and `secureconn.go` (apply on receive)
- TS: `flowersec-ts/src/e2ee/kdf.ts` + `secureChannel.ts`

## 4. Yamux multiplexing

Once the encrypted byte stream is established, endpoints run Yamux over it to multiplex streams.

Notes:

- Flowersec uses the Hashicorp Yamux framing (`version=0`, 12-byte header).
- The server endpoint acts as the Yamux server; the client endpoint acts as the Yamux client.

Current implementation:

- Go: `github.com/hashicorp/yamux` via `flowersec-go/endpoint/session.go`
- TS: `flowersec-ts/src/yamux/*` (see `flowersec-ts/YAMUX_ALIGNMENT.md` for alignment notes)

## 5. Stream hello

Each opened Yamux stream begins with a small "hello" message identifying the stream kind (for example the reserved `rpc` stream).

Current implementation:

- Go: `flowersec-go/streamhello/*`
- TS: `flowersec-ts/src/streamhello/*`

## 6. RPC framing (on the `rpc` stream)

RPC messages are length-prefixed JSON frames:

- `len` (4 bytes): big-endian `uint32` JSON length
- `json` (`len` bytes): UTF-8 JSON bytes

Current implementation:

- Go framing: `flowersec-go/framing/jsonframe/jsonframe.go`
- TS framing: `flowersec-ts/src/framing/jsonframe.ts`
- Message schemas: `idl/flowersec/rpc/v1/rpc.fidl.json` (generated into `gen/flowersec/rpc/v1`)

## 7. Additional stable stream protocols

Flowersec also defines stable application protocols layered on top of Yamux custom streams.

- HTTP/WS proxying over custom streams: `docs/PROXY.md` (`flowersec-proxy/http1`, `flowersec-proxy/ws`)
