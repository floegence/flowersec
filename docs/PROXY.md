# flowersec-proxy (HTTP/WS over Flowersec) v1

This document defines the stable, cross-language contract for **flowersec-proxy**:
carrying HTTP/1.1 and WebSocket traffic over Flowersec custom Yamux streams.

Status: experimental; not audited.

See also:

- Stable API surface: `docs/API_SURFACE.md`
- Custom stream baseline pattern: `docs/STREAMS.md`
- Core wire format (WS + E2EE + Yamux): `docs/PROTOCOL.md`
- Threat model and trust boundaries: `docs/THREAT_MODEL.md`

## 0. Roles and modes

Roles:

- **Client endpoint**: opens streams and initiates requests.
- **Server endpoint**: terminates E2EE, accepts streams, and connects to the local upstream service.

Modes:

- **Runtime mode (recommended)**: browser-side runtime + Service Worker (SW) intercepts HTTP and patches WebSocket, then forwards over Flowersec E2EE directly to the agent (server endpoint).
- **Gateway mode (L7 reverse proxy)**: a deployable HTTP/WS gateway accepts browser HTTPS/WSS and forwards to the agent over Flowersec E2EE. The gateway is an L7 plaintext component by design.

This document defines the **stream contracts only**. The mode-specific security boundary is described in `docs/THREAT_MODEL.md`.

## 1. Stream kinds (stable)

Each Yamux stream starts with the standard Flowersec StreamHello identifying the stream kind.

Stable kinds:

- `flowersec-proxy/http1`
- `flowersec-proxy/ws`

Versioning:

- Each JSON meta message includes a required `v: 1`.
- Future breaking changes will use `v: 2` (and/or a new kind suffix).

## 2. Common types

### 2.1 Header representation (lossless)

To preserve header ordering, casing, and duplicates, headers are represented as a list:

```json
{ "name": "content-type", "value": "text/html; charset=utf-8" }
```

Rules:

- `name` is case-insensitive for comparisons/filters.
- Duplicates are allowed (for example multiple `set-cookie`).
- Implementations MUST reject header names containing control characters.

## 3. `flowersec-proxy/http1` (HTTP over a single stream)

Each HTTP request uses **one** Yamux stream of kind `flowersec-proxy/http1`.

### 3.1 Message flow

Client endpoint → server endpoint:

1) `http_request_meta` (JSON frame, length-prefixed)
2) Request body chunks (binary framing; `len=0` terminator)

Server endpoint → client endpoint:

3) `http_response_meta` (JSON frame, length-prefixed)
4) Response body chunks (binary framing; `len=0` terminator)

### 3.2 JSON meta schema

#### 3.2.1 `http_request_meta`

```json
{
  "v": 1,
  "request_id": "uuid-or-rand",
  "method": "GET",
  "path": "/vscode?x=1",
  "headers": [{ "name": "accept", "value": "text/html" }],
  "timeout_ms": 30000
}
```

Fields:

- `v` (required): `1`.
- `request_id` (required): opaque request correlation id (non-empty after trim).
- `method` (required): HTTP method (non-empty after trim).
- `path` (required): absolute-path + optional query (must start with `/`; MUST NOT include scheme/host).
- `headers` (required): list of `{name,value}` pairs.
- `timeout_ms` (optional):
  - `undefined` or `0`: server default timeout.
  - `> 0`: per-request timeout in milliseconds (capped by server max).
  - `< 0`: invalid.

#### 3.2.2 `http_response_meta`

Success:

```json
{
  "v": 1,
  "request_id": "uuid-or-rand",
  "ok": true,
  "status": 200,
  "headers": [{ "name": "content-type", "value": "text/html; charset=utf-8" }]
}
```

Error:

```json
{
  "v": 1,
  "request_id": "uuid-or-rand",
  "ok": false,
  "error": { "code": "upstream_dial_failed", "message": "dial tcp 127.0.0.1:8080: connect: connection refused" }
}
```

Fields:

- `v` (required): `1`.
- `request_id` (required): echoes the request id.
- `ok` (required): success flag.
- `status` (required when `ok=true`): upstream HTTP status.
- `headers` (required when `ok=true`): upstream response headers (filtered; see below).
- `error` (required when `ok=false`): structured error:
  - `code` (required): stable reason token (see 3.6).
  - `message` (required): human-readable message for debugging.

### 3.3 Body chunk framing (binary)

The request and response bodies are transmitted using chunk framing:

- `len` (4 bytes): big-endian `uint32`
- `payload` (`len` bytes)

Rules:

- `len == 0` terminates the body (end-of-body marker).
- Implementations MUST enforce:
  - a maximum single-chunk size (`max_chunk_bytes`)
  - a maximum total body size per stream direction (`max_body_bytes`)
- `len > max_chunk_bytes` is invalid and MUST fail the stream.

### 3.4 Cancellation semantics

- Closing the stream cancels the in-flight HTTP request.
- Server endpoint MUST cancel the upstream request promptly when:
  - the client endpoint closes/resets the stream, or
  - writing the response back fails (peer disconnected).

### 3.5 Header policy (mandatory)

Rationale: the proxy is meant to carry an upstream web app without leaking the product/controlplane authentication context.
This is enforced using a strict **allow-list** on both endpoints.

#### 3.5.1 Request headers (client → server → upstream)

Default allow-list (case-insensitive):

- `accept`
- `accept-language`
- `cache-control`
- `content-type`
- `if-match`
- `if-modified-since`
- `if-none-match`
- `if-unmodified-since`
- `pragma`
- `range`
- `x-requested-with`

Rules:

- `host` MUST NOT be accepted from the client endpoint.
- `authorization` MUST NOT be accepted from the client endpoint.
- `cookie` is mode-specific:
  - Runtime mode: MAY be injected by the runtime CookieJar (see 3.5.3); it MUST NOT be copied from the browser cookie store.
  - Gateway mode: MAY be forwarded from the inbound browser `Cookie` header of the gateway origin (normal browser semantics for that origin).
- Hop-by-hop headers MUST NOT be forwarded (`connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`, `te`, `trailer`).
- Integrations may extend the allow-list explicitly (cross-language options MUST be aligned).

#### 3.5.2 Response headers (server → client)

Default allow-list (case-insensitive):

- `cache-control`
- `content-disposition`
- `content-encoding`
- `content-language`
- `content-type`
- `etag`
- `expires`
- `last-modified`
- `location`
- `pragma`
- `vary`
- `www-authenticate`
- `set-cookie` (mode-specific)

Rules:

- Hop-by-hop headers MUST NOT be forwarded.
- Implementations SHOULD omit `content-length` (the proxy body is chunk-framed).
- `set-cookie` is mode-specific:
  - Runtime mode: `set-cookie` MUST be captured into the runtime CookieJar and MUST NOT be exposed to the browser response headers.
  - Gateway mode: `set-cookie` MAY be forwarded to the browser (normal cookie semantics for the gateway origin).

#### 3.5.3 Cookie isolation (runtime mode)

In runtime mode, cookies for the proxied upstream app MUST NOT use the browser cookie store.

Rules:

- The client runtime MUST maintain an in-memory CookieJar for the proxied upstream app.
- On response: `set-cookie` headers update the CookieJar, and MUST be removed from the response visible to the browser (so the browser does not persist them).
- On request: the runtime CookieJar is the only source of the `cookie` request header.

### 3.6 Error codes (stable reason tokens)

`http_response_meta.error.code` uses the following stable tokens:

- `invalid_request_meta`
- `request_body_invalid`
- `request_body_too_large`
- `response_body_too_large`
- `upstream_dial_failed`
- `upstream_request_failed`
- `timeout`
- `canceled`

## 4. `flowersec-proxy/ws` (WebSocket over a single stream)

Each proxied WebSocket connection uses **one** Yamux stream of kind `flowersec-proxy/ws`.

### 4.1 Open handshake

Client endpoint → server endpoint: `ws_open_meta` (JSON frame)

```json
{
  "v": 1,
  "conn_id": "uuid-or-rand",
  "path": "/socket",
  "headers": [{ "name": "sec-websocket-protocol", "value": "vscode-jsonrpc" }]
}
```

Server endpoint → client endpoint: `ws_open_resp` (JSON frame)

Success:

```json
{ "v": 1, "conn_id": "uuid-or-rand", "ok": true, "protocol": "vscode-jsonrpc" }
```

Error:

```json
{
  "v": 1,
  "conn_id": "uuid-or-rand",
  "ok": false,
  "error": { "code": "upstream_ws_dial_failed", "message": "..." }
}
```

Rules:

- `path` is validated with the same rules as HTTP `path` (absolute-path; no scheme/host).
- Allowed request headers are a strict allow-list (see 4.3).

### 4.2 Frame framing (binary)

After a successful open handshake, both directions exchange frames:

- `op` (1 byte): `1` (text), `2` (binary), `8` (close), `9` (ping), `10` (pong)
- `len` (4 bytes): big-endian `uint32`
- `payload` (`len` bytes)

Rules:

- `len` MUST be bounded (`max_ws_frame_bytes`).
- On `op=8` (close), payload follows the WebSocket close frame payload convention:
  - optional 2-byte close code (big-endian `uint16`) + UTF-8 reason

### 4.3 Header and Origin policy (mandatory)

Client-provided headers default allow-list (case-insensitive):

- `sec-websocket-protocol`
- `cookie` (special: runtime mode CookieJar or gateway browser cookies)

Rules:

- The server endpoint MUST set the upstream WebSocket `Origin` header to a fixed, integration-provided value.
  - The client endpoint MUST NOT control the upstream Origin.
  - Upstream apps that enforce Origin MUST allow that configured Origin.
- In runtime mode, `cookie` MUST come from the proxy runtime CookieJar and MUST NOT be copied from the browser cookie store.
- In gateway mode, `cookie` MAY come from the inbound browser `Cookie` header of the gateway origin.
- Hop-by-hop / upgrade headers are not accepted from the client (`upgrade`, `connection`, `sec-websocket-key`, ...).

### 4.4 Error codes (stable reason tokens)

`ws_open_resp.error.code` uses the following stable tokens:

- `invalid_ws_open_meta`
- `upstream_ws_dial_failed`
- `upstream_ws_rejected`
- `canceled`
- `timeout`

## 5. SSRF and upstream target constraints (mandatory)

The client endpoint MUST NOT be able to choose an arbitrary upstream host/port.

Rules:

- The server endpoint MUST be configured with a fixed upstream target (or a fixed, explicit allow-list).
- The default configuration MUST only allow `127.0.0.1` upstream targets.
- Requests MUST be path-only (`path` cannot include scheme/authority).

## 6. Mode-specific integration requirements

This section documents the minimum requirements to make runtime mode and gateway mode work correctly.

### 6.1 Runtime mode (browser SW + runtime)

Runtime mode is meant to proxy an upstream web app (for example code-server) without introducing a plaintext L7 relay.

Requirements:

- HTTP resource requests MUST be intercepted by a Service Worker (SW). Patching `fetch` / `XMLHttpRequest` is not sufficient for browser-native resource loads (`<script src>`, `<link>`, `<img>`, navigation).
- WebSocket traffic MUST be patched in the proxied app JS context (a SW cannot intercept WebSocket).
  - This repository provides `installWebSocketPatch(...)` in `@floegence/flowersec-core/proxy`.
- Upstream apps MUST NOT register their own Service Worker within the proxied scope (conflicts with the proxy SW).
  - This repository provides `disableUpstreamServiceWorkerRegister()` in `@floegence/flowersec-core/proxy`.
- If the upstream app is rendered inside a same-origin iframe, the patch MUST be injected into upstream HTML early (before the app opens WebSockets).
  - `createProxyServiceWorkerScript({ injectHTML: { proxyModuleUrl, runtimeGlobal } })` can inject a small `<script type="module">` bootstrap into `text/html` responses (simple mode).
  - For strict upstream CSP (no inline scripts), you can inject a CSP-friendly external script instead:
    - `injectHTML: { mode: "external_script", scriptUrl }` (classic script)
    - `injectHTML: { mode: "external_module", scriptUrl }` (module script)
  - `proxyModuleUrl` / `scriptUrl` MUST be same-origin, and MUST NOT be routed back into the proxied upstream (avoid proxy recursion). Use SW passthrough rules to keep these assets on the control-plane/static origin.
  - When injecting HTML, the proxy SW SHOULD strip validator headers (`etag`, `last-modified`, etc.) and SHOULD avoid caching the modified HTML response (`Cache-Control: no-store`).
  - The generated proxy SW enforces safety caps to avoid unbounded buffering:
    - `maxRequestBodyBytes` (default: 64 MiB) limits buffered request bodies (non-GET/HEAD). Exceeding the cap returns a `413` response.
    - `maxInjectHTMLBytes` (default: 2 MiB) limits buffered HTML responses when `injectHTML` is enabled. Exceeding the cap returns a `502` response (increase the cap or disable injection).
  - The proxy SW SHOULD proxy same-origin requests only; cross-origin requests should fall through to the network to avoid losing scheme/host (the runtime proxy protocol forwards path+query only).
  - Helper: `registerServiceWorkerAndEnsureControl({ scriptUrl, ... })` (exported from `@floegence/flowersec-core/proxy`) can register the proxy SW and ensure the current page load is controlled (hard reload repair).
  - If your app needs extra fetch bridge message types (for example `redeven:proxy_fetch`), configure
    `createProxyServiceWorkerScript({ forwardFetchMessageTypes: [...] })` or use
    `createProxyIntegrationServiceWorkerScript(...)` with plugins.

### 6.2 Gateway mode (L7 reverse proxy)

Gateway mode is a deployable L7 HTTP/WS reverse proxy that forwards to a server endpoint over Flowersec streams.

Requirements and boundaries:

- The gateway is a plaintext component by design. It MUST be treated as trusted (see `docs/THREAT_MODEL.md`).
- The gateway origin MUST be on a dedicated cookie scope (for example a separate registrable domain) from any product/controlplane authentication context.
  - This prevents unrelated product cookies from being forwarded to the proxied upstream app.
  - In gateway mode, `cookie` and `set-cookie` MAY be forwarded with normal browser semantics for the gateway origin.
