# Flowersec HTTP Direct Profile v1

`flowersec-http-direct/1` explicitly supports an application served over HTTP
and direct WebSocket on one port. It reuses Flowersec v3 admission, independent
session credentials, encryption, RPC, streams, and resource limits. It does
not provide TLS protection for the page, login, or delivery of credentials.
An application must make the HTTP choice explicit to its users.

## Security and ownership

Standard `flowersec/3` APIs continue to require their existing TLS policies.
They reject this envelope. No certificate error, connection failure, or retry
selects HTTP automatically. The dedicated HTTP browser API cannot consume a
private-loopback artifact or lease, and the private-loopback API cannot consume
an HTTP artifact or lease. Private-loopback address and token constraints stay
unchanged.

The application owns password authentication, the configured listener
authority, and issuance of a distinct artifact for every connection. The HTTP
request authorization callback must validate the configured authority and
user session before upgrade. A same-origin check alone is not authentication.
Flowersec owns subsequent single-use admission, session authentication,
credential spending, cleanup, and resource limits. Closing one session does
not replace other sessions or stop the server.

## Envelope and endpoint binding

The envelope is canonical JCS JSON containing exactly:

```json
{
  "artifact_b64u": "<base64url flowersec/3 artifact>",
  "endpoint": "ws://192.168.1.20:23998/flowersec/v3/direct",
  "profile": "flowersec-http-direct/1",
  "v": 1
}
```

The nested artifact has one CA-mode WebSocket candidate with ID `http-direct`
and wire profile `flowersec-direct/3`. Its WSS URL binds the same host, numeric
port, and direct path as the outer endpoint. Default ports are canonicalized
according to each scheme: HTTP port 80 maps to explicit WSS port 80, and HTTP
port 443 maps to the default WSS port. This nested binding is neither a URL to
dial nor a claim of TLS protection. The dedicated connector dials only the
validated outer HTTP origin and preserves its port.

Endpoints use canonical `localhost` or IPv4/IPv6 literals and a port from 1
through 65535. Wildcard, multicast, link-local, IPv4-mapped IPv6, and broadcast
addresses are rejected. Credentials, queries, fragments, zones, alternate
numeric spellings, and noncanonical default ports are rejected. This profile
does not introduce DNS, reverse proxy, tunnel, or non-WebSocket carrier support.

## Server composition

`Acceptor.HTTPDirectHandler` requires a non-nil `AuthorizeRequest` callback.
It admits plain HTTP GET requests on exactly `/flowersec/v3/direct`, with one
exact same-origin HTTP Origin and valid v3 WebSocket upgrade headers. Network
client addresses are supported. The callback must explicitly approve each
request before any upgrade or admission work.

`NewHTTPDirectServer` accepts only that sealed HTTP handler.
`NewWebSocketHTTPServer` accepts only the existing TLS handler and retains its
TLS 1.3 policy. Installing the HTTP handler on an arbitrary server fails closed.
Both constructors accept an optional `ApplicationHandler` for other paths,
allowing public pages and sessions to share the same configured port. The
direct and tunnel protocol paths are reserved and never fall through to the
application. Shutdown retains ownership of ordinary and upgraded connections.

## Browser API

The Go control plane issues independent artifacts with `Issuer.IssueHTTPDirect`.
The TypeScript browser subpath exposes `parseHTTPDirectArtifactV1`,
`createHTTPDirectArtifactLeaseV1`, `connectHTTPDirectV1`, and
`createHTTPDirectConnectionControllerV1`. A connector requires the exact HTTP
origin. Each profile owns separate opaque artifact and lease handles.

The dedicated controller preserves existing bounded attempts, cancellation,
timeouts, lease cleanup, and retry semantics. It never tries TLS, another HTTP
authority, or a private bridge. Browser features that require a secure context
remain unavailable; applications must handle those features explicitly.

## Evidence

- `flowersec-go/http_direct_test.go`: separate constructors and same-port pages.
- `flowersec-go/internal/httpdirectv1/profile_test.go`: canonical endpoint and
  origin boundaries, including port 80 and 443 binding.
- `flowersec-ts/src/browser/httpDirectV1.test.ts`: parser and lease isolation,
  endpoint binding, and exact dialed URL.
- `flowersec-ts/src/interop/httpDirectV1.integration.test.ts`: two independent
  Go/TypeScript sessions, simultaneous RPC, and independent close and cleanup.

This version exposes the profile through the Go server/control-plane and
TypeScript browser APIs. It does not change the cross-language TLS deployment
capability registry or claim native client support in other SDKs.
