# Authenticated invitation exchange

This Go-only enrollment profile exchanges a bounded application descriptor using
an out-of-band 128-bit invitation secret. It does not create an application
Session, extend Transport v3, grant access, consume an invitation, or own a
membership directory. The application mounts one dedicated route on its TLS
server and owns issuance, expiry, authorization, and durable consumption.

## Public API and credential

`NewInvitationCode` generates 16 random bytes. `ParseInvitationCode` accepts the
26-character Crockford Base32 representation, either case, ASCII whitespace,
and display hyphens; ambiguous letters and noncanonical padding fail closed.
`DeriveInvitationCode` can recover pseudorandom issuance from an application
secret of at least 32 bytes and a unique issuance identifier. Applications
must never reuse an issuance identifier for a different invitation.

`InvitationCode.Text` is the explicit secret-delivery boundary. Formatting and
JSON encoding redact the credential. `LookupID` is a domain-separated SHA-256
public locator, not an authorization proof. Neither locator nor secret belongs
in normal application logs. This profile requires high-entropy secrets; it is
not a password authentication protocol for user-chosen or short numeric codes.

`ExchangeInvitation(ctx, InvitationExchangeOptions)` returns authenticated
bytes. `NewInvitationExchangeHandler(InvitationExchangeHandlerOptions)` accepts
concurrency-safe, context-cooperative `Lookup` and `Describe` callbacks.
`Describe` must not consume the invitation. A product rejection created with
`RejectInvitationExchange` reaches the client only after authentication;
otherwise failures expose stable redacted reasons. Cancellation and deadlines
retain their standard context identity.

## Authentication and TLS boundary

Only WSS with TLS 1.3 or later is supported. The independent enrollment TLS
verifier requires a currently valid, hostname-matching non-CA server leaf with
server-authentication usage. It accepts a self-signed leaf because the
out-of-band invitation authenticates the peer inside this channel. This
provisional certificate is never retained, installed, or used as ordinary
connector trust. Ordinary CA and pin connectors retain their existing chain,
hostname, pin, and fail-closed policies; a failure never selects enrollment.

The subprotocol is `flowersec-invitation-exchange.v1`. The
`X-Flowersec-Invitation` header carries only the locator. Browser Origin
requests are forbidden. The route supports no application RPC, session,
Runtime management, proxying, redirect, or credential fallback.

The mature `github.com/flynn/noise` implementation supplies
`Noise_NNpsk0_25519_ChaChaPoly_SHA256`. A domain-separated SHA-256 of the code
forms the PSK; the subprotocol, operation purpose, and locator form the
prologue. Each exchange generates fresh ephemeral keys and has four binary
frames:

1. Initiator handshake with encrypted `client` proof.
2. Responder handshake with encrypted `server` proof.
3. Initiator transport-encrypted `confirm`, bound to this responder transcript.
4. Responder transport-encrypted descriptor or application rejection.

The third frame prevents replaying a recorded first message to invoke
`Describe`. A peer without the secret cannot authenticate either endpoint,
alter descriptors, or reuse a proof across purposes or exchanges. An attacker
can forward a live exchange to the legitimate peer, but cannot read or modify
its descriptor; applications still verify their descriptor signature and
perform their own explicit consent and atomic consumption.

## Resource and recovery limits

The default deadline is ten seconds; configured deadlines cannot exceed one
minute. The default concurrent exchange limit is 64, bounded to 1–1024.
Descriptors are at most 64 KiB and wire frames at most 96 KiB. Context
cancellation closes the connection. Callbacks must honor context cancellation;
the SDK cannot forcibly terminate application callback code.

A failed exchange leaves application membership and consumption unchanged.
Applications retain used or expired issuance credentials only as needed to
return authenticated product errors; unknown locators return a generic
authentication rejection. Durable single-use binding and response-loss recovery
belong entirely to the application store. The SDK persists no secrets or
trust material.

## Evidence

- `flowersec-go/invitation_code.go`: credential normalization and redaction.
- `flowersec-go/invitation_exchange.go`: independent TLS verifier and Noise exchange.
- `flowersec-go/invitation_exchange_test.go`: public delivery and error contracts.
- `flowersec-go/invitation_security_test.go`: transcript replay, tampering, limits, deadlines, and certificate profile.
- `flowersec-go/internal/transportsecurity/policy_test.go`: ordinary CA/pin policies.
