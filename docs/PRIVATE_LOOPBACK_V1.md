# Flowersec Private Loopback Profile v1

`flowersec-private-loopback/1` is a product-private transport profile for an
application-authenticated browser bridge on the same machine. It is not a TLS
mode, capability, deployment profile, or wire-version extension of
`flowersec/3`.

## Isolation contract

The public `flowersec/3` artifact, TLS policies (`ca` and `pin`), capability
registry, canonical bytes, hashes, and admission protocol remain unchanged.
Ordinary Go, TypeScript, Rust, Swift, Node, Provider, tunnel, and public browser
entrypoints reject a private-loopback envelope.

Only the dedicated Go server/control-plane API and TypeScript browser API
accept this profile. Rust explicitly verifies that the outer profile is
rejected; Swift and Node expose no private-loopback API.

## Envelope

The envelope is canonical JCS JSON with exactly these fields:

```json
{
  "artifact_b64u": "<base64url flowersec/3 artifact>",
  "endpoint": "ws://127.0.0.1:<port>/flowersec/v3/direct",
  "profile": "flowersec-private-loopback/1",
  "v": 1
}
```

The nested artifact is an ordinary `flowersec/3` direct artifact with exactly
one CA-mode WebSocket candidate. Its candidate ID is `private-loopback`, its
path is `/flowersec/v3/direct`, and its `wss://` authority must match the outer
`ws://` endpoint exactly. The private connector maps only that scheme; it does
not bypass artifact parsing, candidate hashing, capability checks, admission,
credential spending, session encryption, or authorization.

## Loopback admission

The server accepts a request only when all of these conditions hold:

- the method is `GET`;
- the endpoint is canonical `ws://` with an explicit unprivileged port in the inclusive range `1024..65535`;
- Host and remote address are canonical numeric loopback addresses;
- the path is exactly `/flowersec/v3/direct` with no query or fragment;
- Origin is the exact same `http://` origin as Host;
- the application authorization callback accepts the request before WebSocket
  upgrade.

The application callback is the bridge-token boundary. Flowersec does not
issue, store, log, or infer that token. The profile does not support remote
addresses, hostnames, tunnels, QUIC, WebTransport, or WebTransport fallback.

## Public API

Go issues the envelope with
`controlplane.Issuer.IssuePrivateLoopbackDirect(...)` and serves it with
`flowersec.Acceptor.PrivateLoopbackHandler(...)`. The handler is separate from
the TLS-only `flowersec.Acceptor.Handler()` boundary.

The TypeScript browser entrypoint exposes
`parsePrivateLoopbackArtifactV1(...)`,
`createPrivateLoopbackArtifactLeaseV1(...)`,
`connectPrivateLoopbackV1(...)`, and
`createPrivateLoopbackConnectionControllerV1(...)`. Each connection call
requires the exact numeric-loopback HTTP origin. The ordinary `connect(...)`
and `createConnectionController(...)` entrypoints continue to accept only
standard `flowersec/3` artifacts.

The dedicated controller keeps the existing attempt budget, cancellation,
timeout, backoff, lease-spend, replacement-session, and error projection
semantics. It changes only the one exact WebSocket URL used by the dedicated
private profile.

## Contract evidence

Shared Go and TypeScript vectors live in
`testdata/private_loopback_v1/profile_vectors.json`. They bind canonical
envelope bytes, the nested standard v3 artifact, and rejected endpoint forms.
Go produces the positive vector, TypeScript consumes it, and Rust proves that
the outer profile is rejected while the decoded nested artifact remains a
valid standard v3 artifact.

The public deployment capability registry intentionally has no
private-loopback entry. This prevents an application-private, two-language
adapter from being mistaken for a cross-language public transport capability.
