# Flowersec Integration Guide

This guide is for integrating Flowersec into your own application (not just running the demos).
It focuses on the most ergonomic and stable entrypoints across Go and TypeScript.

## Prerequisites

- Go 1.25.x (required)
- Node.js 22 LTS recommended (TypeScript only)

## Install

**Go (library)**

```bash
go get github.com/floegence/flowersec/flowersec-go@latest
```

**Tunnel server (deployable)**

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-tunnel@latest
```

**Controlplane helper tools (optional, local/dev)**

These tools generate an issuer keypair and mint `ChannelInitGrant` pairs for testing.
Keep the private key file secret.

Option A: `go install`:

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-issuer-keygen@latest
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-channelinit@latest
```

Option B: GitHub Releases (no Go):

- Download `flowersec-tools_X.Y.Z_<os>_<arch>.tar.gz` (or `.zip` on Windows) from the GitHub Release tag `flowersec-go/vX.Y.Z`.
- Extract it and run the tools from `bin/`.

Example:

```bash
flowersec-issuer-keygen --out-dir ./keys
flowersec-channelinit \
  --issuer-private-key-file ./keys/issuer_key.json \
  --tunnel-url ws://127.0.0.1:8080/ws \
  --aud flowersec-tunnel:dev \
  --iss issuer-dev \
  > channel.json
```

The resulting `channel.json` contains both `grant_client` and `grant_server` and can be consumed by
`protocolio.DecodeGrantClientJSON` / `protocolio.DecodeGrantServerJSON` and by the TS connect helpers
(they accept the wrapper object).

**TypeScript (ESM, browser-friendly)**

The release assets include an npm tarball so you can install without cloning:

- Download `flowersec-core-X.Y.Z.tgz` from the GitHub Release `flowersec-go/vX.Y.Z`
- Install it:

```bash
npm i ./flowersec-core-X.Y.Z.tgz
```

For Docker deployment examples and operational notes, see `docs/TUNNEL_DEPLOYMENT.md`.

## Recommended entrypoints

**Go**

- Client (role=client):
  - `client.Connect(ctx, input, origin, ...opts)` (auto-detect tunnel vs direct inputs)
  - `client.ConnectTunnel(ctx, grant, origin, ...opts)`
  - `client.ConnectDirect(ctx, info, origin, ...opts)`
- Server endpoint (role=server):
  - `endpoint.ConnectTunnel(ctx, grant, origin, ...opts)`
  - Direct server: `endpoint.AcceptDirectWS(...)`, `endpoint.NewDirectHandler(...)`, or the resolver variants `endpoint.AcceptDirectWSResolved(...)` / `endpoint.NewDirectHandlerResolved(...)`
- Stream runtime (recommended for servers): `endpoint/serve` (RPC stream handler + dispatch)
- Input JSON helpers: `protocolio.DecodeGrantClientJSON(...)`, `protocolio.DecodeDirectConnectInfoJSON(...)`

**TypeScript**

- Stable: `@flowersec/core` → `connect(...)`, `connectTunnel(...)`, `connectDirect(...)`
- Node: `@flowersec/core/node` → `connectNode(...)`, `connectTunnelNode(...)`, `connectDirectNode(...)`
- Browser: `@flowersec/core/browser` → `connectBrowser(...)`, `connectTunnelBrowser(...)`, `connectDirectBrowser(...)`

Note: the TypeScript package currently provides **role=client** connect helpers only. Server endpoints (role=server) are implemented in Go (`flowersec-go/endpoint`).

## Choose a topology

### A) Direct path (no tunnel)

Use this when the server endpoint is directly reachable by the client over WebSocket.

Stack: `WS → E2EE → Yamux → RPC (+ extra streams)`

### B) Tunnel path (controlplane + tunnel)

Use this when you need an untrusted public rendezvous that cannot decrypt data.

Stack: `WS attach (plaintext) → E2EE → Yamux → RPC (+ extra streams)`

You typically have 3 components:

- **Controlplane**: issues `ChannelInitGrant` pairs (client/server) and distributes them securely.
- **Tunnel**: verifies one-time attach tokens and pairs endpoints by `(channel_id, role)`.
- **Server endpoint**: attaches as `role=server` and serves RPC/streams.

## Go: minimal tunnel server endpoint (role=server)

This shows the recommended runtime: `endpoint/serve` dispatches streams by `StreamHello(kind)`, and provides a built-in RPC stream handler.

```go
import (
  "context"
  "log"
  "os"

  "github.com/floegence/flowersec/flowersec-go/endpoint/serve"
  "github.com/floegence/flowersec/flowersec-go/protocolio"
  "github.com/floegence/flowersec/flowersec-go/rpc"
)

type myHandler struct{}

func main() {
  origin := "https://your-web-origin.example"
  grant, err := protocolio.DecodeGrantServerJSON(os.Stdin)
  if err != nil {
    log.Fatal(err)
  }

  srv := serve.New(serve.Options{
    RPC: serve.RPCOptions{
      Register: func(r *rpc.Router, _ *rpc.Server) {
        // Register your type_id handlers here (prefer generated stubs; see IDL section below).
      },
    },
  })

  if err := serve.ServeTunnel(context.Background(), grant, origin, srv); err != nil {
    log.Fatal(err)
  }
}
```

## Go: minimal direct server endpoint (no tunnel)

This is the direct (no-tunnel) equivalent of a server endpoint: upgrade to WebSocket, run the server-side E2EE handshake, then dispatch streams by `StreamHello(kind)`.

```go
import (
  "context"
  "io"
  "log"
  "net/http"
  "time"

  "github.com/floegence/flowersec/flowersec-go/crypto/e2ee"
  "github.com/floegence/flowersec/flowersec-go/endpoint"
  "github.com/floegence/flowersec/flowersec-go/endpoint/serve"
  "github.com/floegence/flowersec/flowersec-go/rpc"
)

func main() {
  channelID := "your-channel-id"
  psk := loadPSKSomehow() // 32 bytes
  initExp := time.Now().Add(120 * time.Second).Unix()

  srv := serve.New(serve.Options{
    OnError: func(err error) { log.Printf("direct server error: %v", err) },
    RPC: serve.RPCOptions{
      Register: func(r *rpc.Router, _ *rpc.Server) {
        // Register your type_id handlers here.
      },
    },
  })

  wsHandler, err := endpoint.NewDirectHandler(endpoint.DirectHandlerOptions{
    AllowedOrigins: []string{"https://your-web-origin.example"},
    Handshake: endpoint.AcceptDirectOptions{
      ChannelID:         channelID,
      PSK:               psk,
      Suite:             e2ee.SuiteX25519HKDFAES256GCM,
      InitExpireAtUnixS: initExp,
      ClockSkew:         30 * time.Second,
    },
    OnStream: func(ctx context.Context, kind string, stream io.ReadWriteCloser) {
      srv.HandleStream(ctx, kind, stream)
    },
    OnError: func(err error) { log.Printf("upgrade/handshake error: %v", err) },
  })
  if err != nil {
    log.Fatal(err)
  }

  mux := http.NewServeMux()
  mux.HandleFunc("/ws", wsHandler)
  log.Fatal(http.ListenAndServe(":8080", mux))
}
```

Your application must distribute the matching `DirectConnectInfo` (ws_url, channel_id, psk, init_exp, suite) to clients out-of-band (often as JSON).

### Go: multi-channel direct server (recommended)

The minimal example above hard-codes `channel_id` and `psk`. In real apps, direct servers usually need to support many channels.

Use `endpoint.NewDirectHandlerResolved` to resolve `{psk, init_exp}` dynamically based on the client's handshake init:

```go
import (
  "context"
  "errors"
  "io"
  "log"
  "net/http"
  "time"

  "github.com/floegence/flowersec/flowersec-go/endpoint"
  "github.com/floegence/flowersec/flowersec-go/endpoint/serve"
)

type secrets struct {
  psk []byte
  initExp int64
}

var byChannel = map[string]secrets{
  // "ch_1": {psk: ..., initExp: ...},
}

func main() {
  srv := serve.New(serve.Options{
    OnError: func(err error) { log.Printf("direct server error: %v", err) },
  })

  wsHandler, err := endpoint.NewDirectHandlerResolved(endpoint.DirectHandlerResolvedOptions{
    AllowedOrigins: []string{"https://your-web-origin.example"},
    Handshake: endpoint.AcceptDirectResolverOptions{
      ClockSkew: 30 * time.Second,
      Resolve: func(ctx context.Context, init endpoint.DirectHandshakeInit) (endpoint.DirectHandshakeSecrets, error) {
        s, ok := byChannel[init.ChannelID]
        if !ok {
          return endpoint.DirectHandshakeSecrets{}, errors.New("unknown channel")
        }
        return endpoint.DirectHandshakeSecrets{PSK: s.psk, InitExpireAtUnixS: s.initExp}, nil
      },
    },
    OnStream: func(ctx context.Context, kind string, stream io.ReadWriteCloser) {
      srv.HandleStream(ctx, kind, stream)
    },
    OnError: func(err error) { log.Printf("upgrade/handshake error: %v", err) },
  })
  if err != nil {
    log.Fatal(err)
  }

  mux := http.NewServeMux()
  mux.HandleFunc("/ws", wsHandler)
  log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Go: minimal client (auto-detect, recommended)

If your input JSON is either a `ChannelInitGrant` wrapper (`{"grant_client":{...}}`) or a `DirectConnectInfo`,
you can pipe it directly into `client.Connect(...)` and let it auto-detect the path:

```go
import (
  "context"
  "log"
  "os"

  "github.com/floegence/flowersec/flowersec-go/client"
)

func main() {
  origin := "https://your-web-origin.example"
  c, err := client.Connect(context.Background(), os.Stdin, origin)
  if err != nil {
    log.Fatal(err)
  }
  defer c.Close()
}
```

## Go: minimal tunnel client (role=client)

If your controlplane returns `{"grant_client":{...}}`, you can pipe it directly into `protocolio.DecodeGrantClientJSON`.

```go
import (
  "context"
  "log"
  "os"

  "github.com/floegence/flowersec/flowersec-go/client"
  "github.com/floegence/flowersec/flowersec-go/protocolio"
)

func main() {
  origin := "https://your-web-origin.example"
  grant, err := protocolio.DecodeGrantClientJSON(os.Stdin)
  if err != nil {
    log.Fatal(err)
  }
  c, err := client.ConnectTunnel(context.Background(), grant, origin)
  if err != nil {
    log.Fatal(err)
  }
  defer c.Close()

  // Use c.RPC() for type_id routing on the "rpc" stream.
  // Use c.OpenStream("your-kind") for extra yamux streams.
}
```

## Go: minimal direct client (role=client)

If your server returns a `DirectConnectInfo` JSON object, decode it and dial the direct endpoint:

```go
import (
  "context"
  "log"
  "os"

  "github.com/floegence/flowersec/flowersec-go/client"
  "github.com/floegence/flowersec/flowersec-go/protocolio"
)

func main() {
  origin := "https://your-web-origin.example"
  info, err := protocolio.DecodeDirectConnectInfoJSON(os.Stdin)
  if err != nil {
    log.Fatal(err)
  }
  c, err := client.ConnectDirect(context.Background(), info, origin)
  if err != nil {
    log.Fatal(err)
  }
  defer c.Close()
}
```

## TypeScript: minimal clients

### Node.js

```ts
import { connectTunnelNode } from "@flowersec/core/node";

const origin = process.env.FSEC_ORIGIN!; // explicit Origin value
const input = JSON.parse(await readStdin());

// Accepts either {"grant_client":{...}} or the raw grant_client object.
const client = await connectTunnelNode(input, { origin });
```

Auto-detect variant (tunnel vs direct):

```ts
import { connectNode } from "@flowersec/core/node";

const origin = process.env.FSEC_ORIGIN!;
const input = JSON.parse(await readStdin()); // ChannelInitGrant wrapper OR DirectConnectInfo
const client = await connectNode(input, { origin });
```

Direct variant:

```ts
import { connectDirectNode } from "@flowersec/core/node";

const origin = process.env.FSEC_ORIGIN!;
const info = JSON.parse(await readStdin()); // DirectConnectInfo
const client = await connectDirectNode(info, { origin });
```

### Browser

```ts
import { connectTunnelBrowser } from "@flowersec/core/browser";

// Uses window.location.origin automatically.
const input = JSON.parse(textarea.value);
const client = await connectTunnelBrowser(input);
```

Auto-detect variant (tunnel vs direct):

```ts
import { connectBrowser } from "@flowersec/core/browser";

const input = JSON.parse(textarea.value); // ChannelInitGrant wrapper OR DirectConnectInfo
const client = await connectBrowser(input);
```

Direct variant:

```ts
import { connectDirectBrowser } from "@flowersec/core/browser";

const info = JSON.parse(textarea.value); // DirectConnectInfo
const client = await connectDirectBrowser(info);
```

## IDL and typed RPC stubs (recommended)

Define your own messages/services under `idl/` and run codegen:

- Spec: `tools/idlgen/IDL_SPEC.md`
- Generate stable outputs: `make gen-core`

With `services` in your `.fidl.json`, `idlgen` generates typed RPC stubs:

- Go: `flowersec-go/gen/flowersec/<domain>/<version>/rpc.gen.go`
- TS: `flowersec-ts/src/gen/flowersec/<domain>/<version>.rpc.gen.ts`
- TS: `flowersec-ts/src/gen/flowersec/<domain>/<version>.facade.gen.ts` (optional ergonomic layer)

## Origin allow-list (tunnel and direct server)

The tunnel and the direct server handler both enforce an Origin allow-list by default.

Allowed entries support:

- Full Origin: `https://example.com` or `http://127.0.0.1:5173`
- Hostname (port ignored): `example.com`
- Hostname + port: `example.com:5173`
- Wildcard hostname: `*.example.com`
- Exact non-standard Origin values: `null`

## Error handling

**Go**

High-level APIs return `*fserrors.Error` (via `errors.As`), which includes `{Path, Stage, Code}`.
Handshake-related codes include: `auth_tag_mismatch`, `timestamp_out_of_skew`, `timestamp_after_init_exp`, `invalid_version`, plus `timeout`/`canceled`.
Secure-layer keepalive failures (explicit ping) use: `ping_failed`.

Input validation codes for tunnel connects include: `missing_token` (for `ChannelInitGrant.token`).
Auto-detect helpers use `path=auto` and `code=invalid_input` when the provided input does not look like either direct or tunnel connect JSON.

For generated Go RPC handlers (`rpc.gen.go`), handler methods return `error`. To return a non-500 wire RPC error, return `&rpc.Error{Code: ..., Message: ...}` (any other error is treated as `code=500` / `"internal error"`).

**TypeScript**

High-level APIs throw `FlowersecError` with `{path, stage, code}`. Codes match the same set for handshake failures.

Handshake fallback code is `handshake_failed`. Secure-layer keepalive failures (explicit ping) use `ping_failed`.

Auto-detect helpers use `path=auto` and `code=invalid_input` when the provided input does not look like either direct or tunnel connect JSON.

## Keepalive (recommended)

Tunnel sessions are subject to an idle timeout (`idle_timeout_seconds`) enforced by the tunnel (from the signed token claim).

High-level connect helpers enable encrypted keepalive pings by default for tunnel connects.
You can override or disable it:

- Go:
  - Disable: `client.ConnectTunnel(..., client.WithKeepaliveInterval(0))`
  - Override: `client.ConnectTunnel(..., client.WithKeepaliveInterval(15*time.Second))`
- TypeScript:
  - Disable: `connectTunnelNode(input, { origin, keepaliveIntervalMs: 0 })`
  - Override: `connectTunnelNode(input, { origin, keepaliveIntervalMs: 15_000 })`

You can also send an explicit keepalive ping:

- Go: `Client.Ping()` / `Session.Ping()`
- TypeScript: `client.ping()`
