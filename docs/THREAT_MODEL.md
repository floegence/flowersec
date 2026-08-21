# Flowersec v3 Threat Model

## Protected Assets

Flowersec protects artifact credentials, endpoint authentication policy,
session keys, RPC payloads, and byte-stream contents. Public SDK objects are
opaque and errors are redacted so logging and generic serialization do not
reveal artifacts, URLs, pins, certificates, credentials, lease identities, or
native TLS diagnostics.

## Trust Boundaries

- Applications own artifact acquisition and the durable pending-to-spent
  transition.
- Deployment systems own certificate issuance, CA installation, pin
  derivation, certificate publication, overlap windows, and rollout order.
- Flowersec control planes bind a structured endpoint URL and TLS policy into
  every candidate; SDKs do not fetch pins or implement trust on first use.
- Endpoints terminate Flowersec session encryption.
- Tunnel relays coordinate and forward opaque carrier streams. They do not
  receive the application Session contract or E2EE key, run the session engine,
  or expose application handlers.
- WSS, raw QUIC, and WebTransport use TLS 1.3. Production v3 has no plaintext
  WebSocket exception.

## Endpoint Authentication

Every candidate declares exactly one TLS mode. CA mode uses platform or
deployment-provided roots and performs chain, signature, validity, key-usage,
security-policy, revocation-policy, and DNS-ID or IP SAN verification. Pin mode
uses SHA-256 of the complete leaf X.509 DER as the sole certificate identity
decision while retaining the TLS provider's key exchange, CertificateVerify,
Finished, transcript, cipher-suite, signature-scheme, and ALPN proof.

TLS policy participates in candidate canonicalization, candidate-set hashing,
FSB3, admission binding, endpoint identity, and deduplication. A CA failure
never becomes pin, a pin failure never becomes CA, and the same endpoint cannot
be retried with a blocked pin policy. Active pins are sampled once before
transport construction; an empty set creates no socket.

Browser WebTransport passes active pins only through the production
`serverCertificateHashes` constructor option. Browser WebSocket is CA-only.
Native Go, Rust, Node.js, and Swift adapters perform pin verification within
their TLS boundary. No HTTP Upgrade, CONNECT, carrier, credential, or FSB3 is
exposed before the relevant TLS proof succeeds.

Browser JavaScript cannot inspect the peer leaf SPKI or independently prove
the native P-256-only certificate profile. Browser policy may accept another
non-RSA algorithm, so P-256-only endpoints reached through JavaScript have no
cross-runtime profile or interoperability guarantee. The SDK does not claim
that browser JavaScript verified P-256-only; deployments requiring that proof
must use a native verifier or an explicitly browser-supported profile.

## Admission and Session Security

The application durably commits a lease only after TLS establishes a candidate
winner and before the connector writes FSB3 or any credential byte. A failed or
uncertain post-commit write never makes the artifact reusable. The receiver
revalidates FSB3 canonical bytes, candidate membership and ordering, TLS
policy, hashes, role, expiry, and its authorization record before admission.

The authenticated FSH3 session handshake derives independent directional and
epoch keys using v3-only domains. Control, RPC, streams, and unreliable
messages use the FS*3 frame family and v3-only authentication domains. Rekey,
liveness, cancellation, deadlines, FIN, reset, and cleanup are bounded; late
or duplicate setup cannot revive terminal stream state.

## Refresh and Failure Policy

Runtime capability is sampled before each artifact race. Unsupported security
modes are skipped before transport construction. A connection cycle has one
scheduler, deterministic bounded backoff, a shared acquisition attempt budget,
and at most one policy-sensitive replacement lease. A pin trigger immediately
blocks its endpoint and complete declared policy digest. Replacement requires a
changed pin policy for the same endpoint and never permits pin-to-CA downgrade.

All TLS failures remain before admission and are separate from FSA3 reasons.
Public failures are closed and redacted. Browser APIs may justify only an
opaque connection failure; native runtimes classify a TLS detail only when the
verifier has evidence for it.

## Out of Scope

Flowersec does not protect a compromised endpoint process, malicious
application code holding a valid artifact, traffic analysis from packet size or
timing, or plaintext deliberately terminated outside Flowersec by an
application-owned gateway. It does not issue certificates, distribute trust
roots, decide rollout batches, or treat certificate pins as peer identity,
admission credentials, or E2EE keys.

The normative transport security and lifecycle requirements are defined in
[`TRANSPORT_V3_WIRE.md`](TRANSPORT_V3_WIRE.md) and
[`TRANSPORT_V3_ARCHITECTURE.md`](TRANSPORT_V3_ARCHITECTURE.md).
