# Flowersec v2 Public API Contract

Flowersec exposes opaque artifacts, carrier-neutral connectors, sessions, RPC, and byte streams. Applications cannot inspect candidates, selected carriers, Yamux, QUIC handles, wire frames, credentials, keys, endpoint identities, logical stream IDs, or spend ledgers.

## Go

The only supported application import is `github.com/floegence/flowersec/flowersec-go/v2`, conventionally named `flowersec`.

- Artifact lifecycle: `flowersec.Artifact`, `flowersec.ArtifactLease`, `flowersec.ParseArtifact(...)`, `flowersec.NewArtifactLease(...)`, and `flowersec.ErrInvalidArtifact`.
- Connection: `flowersec.ConnectorOptions`, `flowersec.Connector`, `flowersec.NewConnector(...)`, `flowersec.Connector.Connect(...)`, `flowersec.ConnectError`, and `flowersec.ConnectErrorCode`.
- Session values: `flowersec.Session`, `flowersec.Metadata`, `flowersec.ByteStream`, `flowersec.IncomingStream`, and `flowersec.RPCPeer`.
- Streams: `flowersec.ByteStream.Read(...)`, `flowersec.ByteStream.Write(...)`, `flowersec.ByteStream.Close()`, `flowersec.ByteStream.Kind()`, `flowersec.ByteStream.TerminalError()`, `flowersec.ByteStream.CloseWrite()`, and `flowersec.ByteStream.Reset()`.
- RPC: `flowersec.RPCPeer.Call(...)`, `flowersec.RPCPeer.Notify(...)`, and sanitized application `flowersec.RPCError` values.
- Optional unreliable messages: `flowersec.Session.UnreliableMessages()` returns the carrier-neutral `flowersec.UnreliableMessageChannel`; `flowersec.UnreliableMessageChannel.MaxMessageBytes()`, `flowersec.UnreliableMessageChannel.Send(...)`, and `flowersec.UnreliableMessageChannel.Receive(...)` use `flowersec.UnreliableSendOptions` and `flowersec.UnreliableSendStatus` without exposing DATAGRAM or carrier objects.
- Session lifecycle: `flowersec.Session.RPC()`, `flowersec.Session.OpenStream(...)`, `flowersec.Session.AcceptStream(...)`, `flowersec.Session.Rekey(...)`, `flowersec.Session.ProbeLiveness(...)`, `flowersec.Session.Termination()`, `flowersec.Session.WaitClosed(...)`, and `flowersec.Session.Close()`.
- Redacted failures: `flowersec.ConnectError.Error()`, `flowersec.ConnectError.Unwrap()`, `flowersec.ConnectError.Is(...)`, `flowersec.ConnectError.Code()`, `flowersec.SessionError`, `flowersec.SessionErrorCode`, `flowersec.SessionError.Error()`, `flowersec.SessionError.Unwrap()`, `flowersec.SessionError.Code()`, and `flowersec.RPCError.Error()`.
- Opaque formatting and serialization: `flowersec.Artifact.String()`, `flowersec.Artifact.GoString()`, `flowersec.Artifact.MarshalJSON()`, `flowersec.ArtifactLease.String()`, `flowersec.ArtifactLease.GoString()`, `flowersec.ArtifactLease.MarshalJSON()`, `flowersec.Connector.String()`, and `flowersec.Connector.GoString()`.
- Connection outcomes: `flowersec.ConnectInvalid`, `flowersec.ConnectCanceled`, `flowersec.ConnectTimeout`, `flowersec.ConnectFailed`, `flowersec.ErrInvalidConnectorOptions`, and `flowersec.ErrConnectionFailed`.
- Session outcomes: `flowersec.SessionCanceled`, `flowersec.SessionTimeout`, `flowersec.SessionClosed`, `flowersec.SessionGoingAway`, `flowersec.SessionResourceExhausted`, `flowersec.SessionStreamRejected`, `flowersec.SessionStreamReset`, `flowersec.SessionRekeyFailed`, `flowersec.SessionLivenessFailed`, `flowersec.SessionUnreliableUnavailable`, `flowersec.SessionUnreliableTooLarge`, `flowersec.SessionUnreliableDropped`, and `flowersec.SessionOperationFailed`.
- Unreliable send outcomes: `flowersec.UnreliableAccepted`, `flowersec.UnreliableDroppedExpired`, `flowersec.UnreliableDroppedBudget`, and `flowersec.UnreliableDroppedCarrier`.

Opaque values have fixed redacted string and JSON behavior. Zero-value or deserialized handles cannot create a valid connector or spend lease.

### Go server-side control plane

The Go-only server import `github.com/floegence/flowersec/flowersec-go/v2/controlplane`, conventionally named `controlplane`, issues v2 artifacts and answers the `flowersec-runtime` authorization callback without exposing carrier, candidate, FSB2, PSK, or session-contract objects.

- Endpoint policy: `controlplane.EndpointSet` is created by `controlplane.NewEndpointSet(...)`; URL schemes are converted to internal carrier candidates only during issuance.
- Issuance: `controlplane.Issuer` from `controlplane.NewIssuer()` accepts carrier-neutral `controlplane.SessionOptions`, bounded `controlplane.Scope` and `controlplane.ArtifactMetadata`, plus either `controlplane.DirectIssueOptions` or `controlplane.TunnelIssueOptions`. `controlplane.Issuer.IssueDirect(...)` returns one `controlplane.IssuedArtifact`; `controlplane.Issuer.IssueTunnelPair(...)` returns one opaque `controlplane.IssuedTunnelPair`.
- Explicit delivery: `controlplane.IssuedArtifact.ArtifactJSON()` is the only client artifact serialization boundary. `controlplane.IssuedArtifact.LookupKey()` is a non-secret credential hash, and `controlplane.IssuedArtifact.AuthorizationRecord()` returns the matching opaque `controlplane.AuthorizationRecord`.
- Durable authorization: `controlplane.AuthorizationRecord.Encode()` and `controlplane.ParseAuthorizationRecord(...)` are the explicit secret-storage boundary. The caller must atomically reserve the one-time record before allowing a request; `controlplane.AuthorizationRecord.LookupKey()` never returns the bearer credential.
- Runtime callback: `controlplane.ParseRuntimeAuthorizationRequest(...)` returns a redacted `controlplane.RuntimeAuthorizationRequest`. Its `controlplane.RuntimeAuthorizationRequest.LookupKey()` locates the record; `controlplane.AuthorizeRuntime(...)` verifies the complete FSB2 and observed carrier binding and returns `controlplane.AuthorizationResponse`. `controlplane.RejectRuntime(...)` creates only validated reject or retry decisions. `controlplane.AuthorizationResponse.JSON()` is the only response serialization boundary.
- Invalid issuance, record, request, lease, expiry, or binding inputs return only `controlplane.ErrInvalidControlPlaneInput` at the public boundary. An unavailable cryptographic random source returns the stable redacted `controlplane.ErrIssuanceFailed` value.

This package owns only transport-neutral issuance and authorization mechanics. Tenant selection, endpoint placement, permissions, billing, durable lease state, and upstream routing decisions remain application control-plane responsibilities. It is not a compatibility surface for removed v1 issuer, token, channel-init, generated DTO, or HTTP helper packages.

## TypeScript

The supported package entrypoints are `@floegence/flowersec-core`, `@floegence/flowersec-core/browser`, and `@floegence/flowersec-core/node`.

The root exposes `Artifact`, `ArtifactLeaseV2`, the carrier-neutral `SessionV2`, `RPCPeerV2`, `ByteStreamV2`, reconnect orchestration, `ConnectError`, and `SessionError`. A negotiated session may expose `UnreliableMessageChannelV2`; applications construct its opaque payload with `createUnreliableMessageV2(...)` and receive redacted `UnreliableMessageError` values. Browser applications add `connectBrowserSessionV2(...)`; Node.js applications add `connectNodeSessionV2(...)` with carrier-neutral TLS options. Low-level carrier factories, capability descriptors, candidate diagnostics, wire contracts, and cryptographic state are not package exports.

## Swift

Applications `import Flowersec` from the `Flowersec` product. The public lifecycle is `parseArtifactV2(...)`, `ArtifactV2`, `ArtifactLeaseV2`, `ConnectorOptionsV2`, `ConnectorV2`, and `ConnectorV2.connect()`. The returned `SessionV2` exposes only `RPCPeerV2`, `ByteStreamV2`, `IncomingStreamV2`, and bounded stream metadata. `ConnectErrorV2`, `SessionErrorV2`, and `RPCErrorV2` are the public failure boundary. Concrete carrier sessions and runtime capability descriptors are internal.

## Rust

The `flowersec` crate exposes `Artifact`, `ArtifactError`, `ArtifactLease`, `ArtifactSpendError`, `Connector`, `ConnectorOptions`, `ConnectError`, `ConnectErrorCode`, `Session`, `SessionError`, `RpcPeer`, `ByteStream`, `IncomingStream`, `JsonObject`, `StreamTerminalError`, and the carrier-neutral optional `UnreliableMessageChannel`. Native server runtimes additionally use `AcceptorOptions`, `Acceptor`, `AcceptError`, and `AcceptErrorCode` to turn an opaque direct-session artifact into the same carrier-neutral `Session`. Quinn connections, admission frames, capability descriptors, candidate plans, session ledgers, and implementation modules remain crate-private.

## Error Boundary

Public connection and session failures contain only a stable code. They never retain raw artifacts, credential-bearing URLs, tokens, peer payloads, candidate diagnostics, path or stage selection, key material, carrier handles, or implementation objects. Sanitized remote application RPC errors may retain only their bounded semantic code and message.

## Compatibility

The maintained tree is v2-only. There is no in-process downgrade, compatibility facade, generated v1 package, or fallback credential path. Historical contracts remain available only through Git history.

Public changes follow `docs/API_CHANGE_POLICY.md`; stable failures follow `docs/ERROR_MODEL.md`, and the reviewed symbol inventory is `stability/api_contract_manifest.json`.
