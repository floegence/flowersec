# Flowersec v2 Threat Model

## Protected Assets

Flowersec protects artifact credentials, endpoint identity, session keys, RPC payloads, and byte-stream contents. Public SDK objects are opaque and errors are redacted so logging and generic serialization do not reveal those assets.

## Trust Boundaries

- Applications own artifact acquisition and the durable pending-to-spent transition.
- Endpoints terminate Flowersec session encryption.
- Tunnel relays coordinate and forward encrypted carrier streams; they do not terminate application encryption.
- WebSocket uses TLS plus hop-local Yamux. Raw QUIC and WebTransport use TLS 1.3 and native bidirectional streams without Yamux.

## Admission

All carrier candidates may prepare without credentials. Exactly one winner is selected. The application must durably commit the artifact spend before the connector writes FSB2 or any credential byte. A failed or uncertain post-commit write never makes the artifact reusable.

Admission binds the artifact, selected carrier, path, endpoint identities, capability descriptor, and session contract hash. Unknown fields, duplicate keys, invalid Unicode hosts, expired artifacts, unregistered rejection reasons, and mismatched bindings fail closed.

## Session Security

The authenticated session handshake derives independent directional and epoch keys. Control, RPC, and data streams are encrypted and integrity protected. Rekey, liveness, cancellation, deadlines, FIN, reset, and cleanup are bounded; late or duplicate stream setup cannot revive terminal ledger entries.

## Carrier Security

- WSS requires authenticated TLS outside explicit local test fixtures and accepts binary frames only.
- Raw QUIC and WebTransport require exact ALPN, explicit trust roots, TLS 1.3, and disabled early data.
- QUIC native FIN, RESET_STREAM, STOP_SENDING, flow control, and path migration remain visible to the carrier implementation but not to applications.
- Application streams remain reliable and never fall back to QUIC DATAGRAM. Raw QUIC and WebTransport may expose negotiated native DATAGRAM only through the carrier-neutral, separately encrypted unreliable-message channel.

## Out Of Scope

Flowersec does not protect a compromised endpoint process, malicious application code holding a valid artifact, traffic analysis from packet size and timing, or plaintext deliberately terminated by an application-owned L7 gateway.

## Failure Policy

There is no legacy fallback or downgrade path. Unsupported carrier tuples, missing trust roots, ambiguous admission outcomes, protocol violations, and cleanup deadline failures are terminal and return bounded public errors.
