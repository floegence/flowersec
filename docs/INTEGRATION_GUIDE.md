# Flowersec Integration Guide

This guide is for integrating Flowersec into your own application (not just running the demos).
It focuses on the most ergonomic and stable entrypoints across Go and TypeScript.

See also:

- Frontend quickstart (TypeScript): `docs/FRONTEND_QUICKSTART.md`
- Stable API surface: `docs/API_SURFACE.md`
- Error contract: `docs/ERROR_MODEL.md`
- Threat model / security boundaries: `docs/THREAT_MODEL.md`
- Protocol framing (wire format): `docs/PROTOCOL.md`
- Custom streams (meta + bytes pattern): `docs/STREAMS.md`

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
# Optional: human-readable JSON.
# flowersec-issuer-keygen --out-dir ./keys --pretty
flowersec-channelinit \
  --issuer-private-key-file ./keys/issuer_key.json \
  --tunnel-url ws://127.0.0.1:8080/ws \
  --aud flowersec-tunnel:dev \
  --iss issuer-dev \
  > channel.json
```

On Unix-like systems, `flowersec-issuer-keygen` creates the output directory with owner-only permissions (`0700`) by default.

Env-defaults variant (flags override env):

```bash
export FSEC_ISSUER_OUT_DIR=./keys
flowersec-issuer-keygen

export FSEC_ISSUER_PRIVATE_KEY_FILE=./keys/issuer_key.json
export FSEC_TUNNEL_URL=ws://127.0.0.1:8080/ws
export FSEC_TUNNEL_AUD=flowersec-tunnel:dev
export FSEC_TUNNEL_ISS=issuer-dev
flowersec-channelinit > channel.json

# Optional: human-readable JSON.
# flowersec-channelinit --pretty > channel.json
```

The resulting `channel.json` contains both `grant_client` and `grant_server` and can be consumed by
`protocolio.DecodeGrantClientJSON` / `protocolio.DecodeGrantServerJSON` and by the TS connect helpers
(they accept the wrapper object).

Tip: every tool supports `--help` which includes copy/paste examples and documents stdout/stderr behavior and exit codes.

**TypeScript (ESM, browser-friendly)**

The release assets include an npm tarball so you can install without cloning:

- Download `floegence-flowersec-core-X.Y.Z.tgz` from the GitHub Release `flowersec-go/vX.Y.Z`
- Install it:

```bash
npm i ./floegence-flowersec-core-X.Y.Z.tgz
```

For Docker deployment examples and operational notes, see `docs/TUNNEL_DEPLOYMENT.md`.

## Recommended entrypoints

**Go**

- Client (role=client):
  - `client.Connect(ctx, input, ...opts)` (auto-detect tunnel vs direct inputs; set Origin via `client.WithOrigin(origin)`)
  - `client.ConnectTunnel(ctx, grant, ...opts)` (Origin via `client.WithOrigin(origin)`)
  - `client.ConnectDirect(ctx, info, ...opts)` (Origin via `client.WithOrigin(origin)`)
- Server endpoint (role=server):
  - `endpoint.ConnectTunnel(ctx, grant, ...opts)` (Origin via `endpoint.WithOrigin(origin)`)
  - Direct server (recommended): `endpoint/serve` → `serve.NewDirectHandler(...)` / `serve.NewDirectHandlerResolved(...)`
  - Direct server (lower-level): `endpoint.AcceptDirectWS(...)`, `endpoint.NewDirectHandler(...)`, or the resolver variants `endpoint.AcceptDirectWSResolved(...)` / `endpoint.NewDirectHandlerResolved(...)`
- Stream runtime (recommended for servers): `endpoint/serve` (RPC stream handler + dispatch)
- Input JSON helpers: `protocolio.DecodeGrantClientJSON(...)`, `protocolio.DecodeDirectConnectInfoJSON(...)`
- Origin helpers (derive Origin values consistently from URLs):
  - `origin.FromWSURL(wsURL)`
  - `origin.ForTunnel(tunnelURL, controlplaneBaseURL)`

**TypeScript**

- Stable: `@floegence/flowersec-core` → `connect(...)`, `connectTunnel(...)`, `connectDirect(...)`
- Node: `@floegence/flowersec-core/node` → `connectNode(...)`, `connectTunnelNode(...)`, `connectDirectNode(...)`
- Browser: `@floegence/flowersec-core/browser` → `connectBrowser(...)`, `connectTunnelBrowser(...)`, `connectDirectBrowser(...)`

Note: the TypeScript package currently provides **role=client** connect helpers only. Server endpoints (role=server) are implemented in Go (`flowersec-go/endpoint`).

## TypeScript: runtime proxy (browser SW + runtime)

If you want to carry an upstream web app (for example code-server) over encrypted Flowersec streams, use **runtime mode** (`flowersec-proxy/http1` and `flowersec-proxy/ws`).

This is an integration pattern on top of a normal Flowersec client connection:

1) Establish a Flowersec client (tunnel or direct):

```ts
import { connectTunnelBrowser } from "@floegence/flowersec-core/browser";
import { createProxyRuntime, createProxyServiceWorkerScript, registerServiceWorkerAndEnsureControl } from "@floegence/flowersec-core/proxy";

const grant = await getFreshGrantSomehow();
const client = await connectTunnelBrowser(grant);
```

2) Start the proxy runtime (in the controlled window):

```ts
const runtime = createProxyRuntime({ client });
// Expose runtime on a global if your injected upstream script needs to access it via window.top[...].
(window as any).__flowersecProxyRuntime = runtime;
```

3) Serve a proxy Service Worker script (same-origin) and register it:

```ts
const swScript = createProxyServiceWorkerScript({
  // Recommended: only proxy same-origin requests (cross-origin should fall through to the network).
  sameOriginOnly: true,
  // Avoid proxy recursion / control-plane mistakes.
  passthrough: {
    prefixes: ["/assets/", "/api/"],
    paths: ["/_proxy/sw.js"],
  },
  // CSP-friendly injection for strict upstream CSP:
  injectHTML: { mode: "external_script", scriptUrl: "/_proxy/inject.js", excludePathPrefixes: ["/_proxy/"] },
});

// You are responsible for serving swScript at "/_proxy/sw.js".
await registerServiceWorkerAndEnsureControl({ scriptUrl: "/_proxy/sw.js", scope: "/" });
```

See `docs/PROXY.md` for the stable wire contracts and security requirements.

Best practice: do not copy/paste and maintain your own proxy Service Worker implementation.
Use `createProxyServiceWorkerScript(...)` + `registerServiceWorkerAndEnsureControl(...)` as the source of truth, and keep your app-specific behavior in options (passthrough/injection mode/prefix rules).

## TypeScript: reconnect (optional)

Tunnel tokens are one-time use. If you want auto reconnect, you typically need to mint a fresh grant for each attempt.

```ts
import { createReconnectManager } from "@floegence/flowersec-core/reconnect";
import { connectTunnelBrowser } from "@floegence/flowersec-core/browser";

const mgr = createReconnectManager();
mgr.subscribe((s) => console.log("status", s.status, "error", s.error));

await mgr.connect({
  autoReconnect: { enabled: true },
  connectOnce: async ({ signal, observer }) => {
    const grant = await getFreshGrantSomehow(); // MUST be fresh on each attempt (one-time tokens)
    return await connectTunnelBrowser(grant, { signal, observer });
  },
});
```

Best practice: if you build a framework or UI layer (e.g. a Solid/React provider), keep UI state management in your app/framework,
but delegate the reconnect state machine to `@floegence/flowersec-core/reconnect` instead of duplicating backoff + cancellation + observer wiring.

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

  "github.com/floegence/flowersec/flowersec-go/endpoint"
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

  srv, err := serve.New(serve.Options{
    RPC: serve.RPCOptions{
      Register: func(r *rpc.Router, _ *rpc.Server) {
        // Register your type_id handlers here (prefer generated stubs; see IDL section below).
      },
    },
  })
  if err != nil {
    log.Fatal(err)
  }

  if err := serve.ServeTunnel(context.Background(), grant, srv, endpoint.WithOrigin(origin)); err != nil {
    log.Fatal(err)
  }
}
```

## Go: minimal direct server endpoint (no tunnel)

This is the direct (no-tunnel) equivalent of a server endpoint: upgrade to WebSocket, run the server-side E2EE handshake, then dispatch streams by `StreamHello(kind)`.

```go
import (
  "log"
  "net/http"
  "time"

  "github.com/floegence/flowersec/flowersec-go/endpoint"
  "github.com/floegence/flowersec/flowersec-go/endpoint/serve"
  "github.com/floegence/flowersec/flowersec-go/rpc"
)

func main() {
  channelID := "your-channel-id"
  psk := loadPSKSomehow() // 32 bytes
  initExp := time.Now().Add(120 * time.Second).Unix()

  srv, err := serve.New(serve.Options{
    OnError: func(err error) { log.Printf("direct server error: %v", err) },
    RPC: serve.RPCOptions{
      Register: func(r *rpc.Router, _ *rpc.Server) {
        // Register your type_id handlers here.
      },
    },
  })
  if err != nil {
    log.Fatal(err)
  }

  wsHandler, err := serve.NewDirectHandler(serve.DirectHandlerOptions{
    Server: srv,
    AllowedOrigins: []string{"https://your-web-origin.example"},
    Handshake: endpoint.AcceptDirectOptions{
      ChannelID:         channelID,
      PSK:               psk,
      Suite:             endpoint.SuiteX25519HKDFAES256GCM,
      InitExpireAtUnixS: initExp,
      ClockSkew:         30 * time.Second,
    },
  })
  if err != nil {
    log.Fatal(err)
  }

  mux := http.NewServeMux()
  mux.HandleFunc("/ws", wsHandler)
  httpSrv := &http.Server{
    Addr:              ":8080",
    Handler:           mux,
    ReadHeaderTimeout: 5 * time.Second,
    ReadTimeout:       10 * time.Second,
    WriteTimeout:      10 * time.Second,
    IdleTimeout:       60 * time.Second,
    MaxHeaderBytes:    32 << 10,
  }
  log.Fatal(httpSrv.ListenAndServe())
}
```

Note: server-side handshake timeout uses a fixed default when unset (`HandshakeTimeout == nil`). To disable the timeout, set `HandshakeTimeout` to a pointer to `0`:

```go
ht := time.Duration(0)
HandshakeTimeout: &ht
```

(And ensure your context can be canceled.)

Your application must distribute the matching `DirectConnectInfo` (ws_url, channel_id, psk, init_exp, suite) to clients out-of-band (often as JSON).

Local/dev shortcut: generate a one-off `DirectConnectInfo` JSON object with the helper CLI:

```bash
go install github.com/floegence/flowersec/flowersec-go/cmd/flowersec-directinit@latest
flowersec-directinit --ws-url ws://127.0.0.1:8080/ws --pretty > direct.json
```

Note: the output contains the PSK; treat it as a secret.

### Go: multi-channel direct server (recommended)

The minimal example above hard-codes `channel_id` and `psk`. In real apps, direct servers usually need to support many channels.

Use `serve.NewDirectHandlerResolved` to resolve `{psk, init_exp}` dynamically based on the client's handshake init:

```go
import (
  "context"
  "errors"
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
  srv, err := serve.New(serve.Options{
    OnError: func(err error) { log.Printf("direct server error: %v", err) },
  })
  if err != nil {
    log.Fatal(err)
  }

  wsHandler, err := serve.NewDirectHandlerResolved(serve.DirectHandlerResolvedOptions{
    Server: srv,
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
  })
  if err != nil {
    log.Fatal(err)
  }

  mux := http.NewServeMux()
  mux.HandleFunc("/ws", wsHandler)
  httpSrv := &http.Server{
    Addr:              ":8080",
    Handler:           mux,
    ReadHeaderTimeout: 5 * time.Second,
    ReadTimeout:       10 * time.Second,
    WriteTimeout:      10 * time.Second,
    IdleTimeout:       60 * time.Second,
    MaxHeaderBytes:    32 << 10,
  }
  log.Fatal(httpSrv.ListenAndServe())
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
  c, err := client.Connect(context.Background(), os.Stdin, client.WithOrigin(origin))
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
  c, err := client.ConnectTunnel(context.Background(), grant, client.WithOrigin(origin))
  if err != nil {
    log.Fatal(err)
  }
  defer c.Close()

  // Use c.RPC() for type_id routing on the "rpc" stream.
  // Use c.OpenStream(context.Background(), "your-kind") for extra yamux streams.
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
  c, err := client.ConnectDirect(context.Background(), info, client.WithOrigin(origin))
  if err != nil {
    log.Fatal(err)
  }
  defer c.Close()
}
```

## TypeScript: minimal clients

### Node.js

```ts
import { connectTunnelNode } from "@floegence/flowersec-core/node";

const origin = process.env.FSEC_ORIGIN!; // explicit Origin value
const input = JSON.parse(await readStdin());

// Accepts either {"grant_client":{...}} or the raw grant_client object.
const client = await connectTunnelNode(input, { origin });
```

Auto-detect variant (tunnel vs direct):

```ts
import { connectNode } from "@floegence/flowersec-core/node";

const origin = process.env.FSEC_ORIGIN!;
const input = JSON.parse(await readStdin()); // ChannelInitGrant wrapper OR DirectConnectInfo
const client = await connectNode(input, { origin });
```

Direct variant:

```ts
import { connectDirectNode } from "@floegence/flowersec-core/node";

const origin = process.env.FSEC_ORIGIN!;
const info = JSON.parse(await readStdin()); // DirectConnectInfo
const client = await connectDirectNode(info, { origin });
```

### Browser

```ts
import { connectTunnelBrowser } from "@floegence/flowersec-core/browser";

// Uses window.location.origin automatically.
const input = JSON.parse(textarea.value);
const client = await connectTunnelBrowser(input);
```

Auto-detect variant (tunnel vs direct):

```ts
import { connectBrowser } from "@floegence/flowersec-core/browser";

const input = JSON.parse(textarea.value); // ChannelInitGrant wrapper OR DirectConnectInfo
const client = await connectBrowser(input);
```

Direct variant:

```ts
import { connectDirectBrowser } from "@floegence/flowersec-core/browser";

const info = JSON.parse(textarea.value); // DirectConnectInfo
const client = await connectDirectBrowser(info);
```

## IDL and typed RPC stubs (recommended)

Define your own messages/services under `idl/` and run codegen:

- Spec: `tools/idlgen/IDL_SPEC.md`
- Generate stable outputs: `make gen-core`

If you want to use the same generator from your own repository (no clone), install or run it directly:

```bash
go install github.com/floegence/flowersec/tools/idlgen@latest
idlgen --version

# Generate code from all *.fidl.json under ./idl (optionally use -manifest to restrict the set).
# Output layout:
# - Go: ./gen/flowersec/<domain>/<version>/*.gen.go
# - TS: ./src/gen/flowersec/<domain>/<version>.*.gen.ts
idlgen -in ./idl -go-out ./gen -ts-out ./src/gen
```

With `services` in your `.fidl.json`, `idlgen` generates typed RPC stubs:

- Go: `flowersec-go/gen/flowersec/<domain>/<version>/rpc.gen.go`
- TS: `flowersec-ts/src/gen/flowersec/<domain>/<version>.rpc.gen.ts`
- TS: `flowersec-ts/src/gen/flowersec/<domain>/<version>.facade.gen.ts` (optional ergonomic layer)

## Origin allow-list (tunnel and direct server)

The tunnel and the direct server handler both enforce an Origin allow-list by default.

Practical guidance:

- Browser clients always send `Origin` (it is the browser's `window.location.origin`). Your allow-list must include that exact value.
- Go/Node clients must set an explicit `Origin` value. Pick a stable origin-like string that represents your app/environment (often the same public web origin you allow for browsers).
- `--allow-no-origin` / `AllowNoOrigin` is additive: it only affects requests that omit the `Origin` header entirely and does not replace the allow-list. The official Go/TS helpers always send `Origin`, so you still must configure `allow-origin` unless you provide a custom `CheckOrigin`.

Allowed entries support:

- Full Origin: `https://example.com` or `http://127.0.0.1:5173`
- Hostname (port ignored): `example.com`
- Hostname + port: `example.com:5173`
- Wildcard hostname: `*.example.com` (subdomains only; does not match `example.com`)
- Exact non-standard Origin values: `null`

## Error handling

For the full cross-language error model (stable `path/stage/code` and recommended aggregation), see `docs/ERROR_MODEL.md`.

**Go**

High-level APIs return `*fserrors.Error` (via `errors.As`), which includes `{Path, Stage, Code}`.
Handshake-related codes include: `auth_tag_mismatch`, `timestamp_out_of_skew`, `timestamp_after_init_exp`, `invalid_version`, plus `timeout`/`canceled`.
Secure-layer keepalive failures (explicit ping) use: `ping_failed`.

Input validation codes for tunnel connects include: `missing_token` (for `ChannelInitGrant.token`).
Auto-detect helpers use `path=auto` and `code=invalid_input` when the provided input does not look like either direct or tunnel connect JSON.
If you accidentally pass a server grant wrapper (`{"grant_server": {...}}`) into a client connect helper, auto-detect routes it to the tunnel path and you should see `path=tunnel` with `code=role_mismatch`.

For generated Go RPC handlers (`rpc.gen.go`), handler methods return `error`. To return a non-500 wire RPC error, return `&rpc.Error{Code: ..., Message: ...}` (any other error is treated as `code=500` / `"internal error"`).

**TypeScript**

High-level APIs throw `FlowersecError` with `{path, stage, code}`. Codes match the same set for handshake failures.

Handshake fallback code is `handshake_failed`. Secure-layer keepalive failures (explicit ping) use `ping_failed`.

Auto-detect helpers use `path=auto` and `code=invalid_input` when the provided input does not look like either direct or tunnel connect JSON.
If you accidentally pass a server grant wrapper (`{"grant_server": {...}}`) into a client connect helper, auto-detect routes it to the tunnel path and you should see `path=tunnel` with `code=role_mismatch`.
If you pass a tunnel-only option (for example `endpointInstanceId`) to a direct connect helper, it fails fast with `code=invalid_option`.

## Keepalive (recommended)

Tunnel sessions are subject to an idle timeout (`idle_timeout_seconds`) enforced by the tunnel (from the signed token claim).

High-level connect helpers enable encrypted keepalive pings by default for tunnel connects.
The default interval is `idle_timeout_seconds / 2` (minimum 500ms) and is always strictly less than the idle timeout.
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
