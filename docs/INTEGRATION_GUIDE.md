# Flowersec Integration Guide

This guide is for integrating Flowersec into your own application (not just running the demos).
It focuses on the most ergonomic and stable entrypoints across Go and TypeScript.

## Recommended entrypoints

**Go**

- Client (role=client):
  - `client.ConnectTunnel(ctx, grant, origin, ...opts)`
  - `client.ConnectDirect(ctx, info, origin, ...opts)`
- Server endpoint (role=server):
  - `endpoint.ConnectTunnel(ctx, grant, origin, ...opts)`
  - Direct server: `endpoint.AcceptDirectWS(...)` or `endpoint.NewDirectHandler(...)`
- Stream runtime (recommended for servers): `endpoint/serve` (RPC stream handler + dispatch)
- Input JSON helpers: `protocolio.DecodeGrantClientJSON(...)`, `protocolio.DecodeDirectConnectInfoJSON(...)`

**TypeScript**

- Stable: `@flowersec/core` → `connectTunnel(...)`, `connectDirect(...)`
- Node: `@flowersec/core/node` → `connectTunnelNode(...)`, `connectDirectNode(...)`
- Browser: `@flowersec/core/browser` → `connectTunnelBrowser(...)`, `connectDirectBrowser(...)`

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

  "github.com/floegence/flowersec/flowersec-go/endpoint/serve"
  "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
  "github.com/floegence/flowersec/flowersec-go/rpc"
)

type myHandler struct{}

func main() {
  var grant *v1.ChannelInitGrant = loadGrantServerSomehow()
  origin := "https://your-web-origin.example"

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

## Go: minimal client (tunnel or direct)

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

## TypeScript: minimal clients

### Node.js

```ts
import { connectTunnelNode } from "@flowersec/core/node";

const origin = process.env.FSEC_ORIGIN!; // explicit Origin value
const input = JSON.parse(await readStdin());

// Accepts either {"grant_client":{...}} or the raw grant_client object.
const client = await connectTunnelNode(input, { origin });
```

### Browser

```ts
import { connectTunnelBrowser } from "@flowersec/core/browser";

// Uses window.location.origin automatically.
const input = JSON.parse(textarea.value);
const client = await connectTunnelBrowser(input);
```

## IDL and typed RPC stubs (recommended)

Define your own messages/services under `idl/` and run codegen:

- Spec: `tools/idlgen/IDL_SPEC.md`
- Generate stable outputs: `make gen-core`

With `services` in your `.fidl.json`, `idlgen` generates typed RPC stubs:

- Go: `flowersec-go/gen/flowersec/<domain>/<version>/rpc.gen.go`
- TS: `flowersec-ts/src/gen/flowersec/<domain>/<version>.rpc.gen.ts`

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

**TypeScript**

High-level APIs throw `FlowersecError` with `{path, stage, code}`. Codes match the same set for handshake failures.

