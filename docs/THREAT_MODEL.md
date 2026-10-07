# Flowersec Threat Model

Flowersec protects application payloads, endpoint identity, single-use
connection authority and bounded execution ownership. Credentials, private
keys, artifact bytes and provider details remain behind opaque SDK objects.
Public errors and progress contain only their explicitly defined bounded
fields.

## Trust boundaries

Applications configure independent namespace trust, authenticated control
routes, identity custody, durable stores and finite resource budgets. A peer
Artifact cannot install its own trust anchor. Online bootstrap and durable
restore preserve their distinct freshness and rollback requirements.

Network carriers use TLS 1.3 without early data or plaintext fallback. CA and
complete leaf-DER pin policies remain distinct signed choices. A failed pin
cannot be bypassed with a CA retry at the same endpoint. Browser APIs provide
only their actual guarantees; a browser WebSocket does not independently prove
its TLS version. Explicit `local_loopback` admission uses the same current
session protocol with strict numeric-loopback, Origin and application
authentication checks and reports outer TLS verification as not applicable.

TLS deployment operators own certificate issuance and trust distribution.
Flowersec does not infer trust from an unverified URL, silently accept a new
certificate, or turn application identity digests into certificate pins.

## Admission and encryption

Carrier preparation does not consume a connection lease. The original winner,
authenticated activation and durable once-only spend/admission transitions
precede their corresponding disclosures. An uncertain irreversible transition
cannot make a credential reusable. FSB4, FSA4, the Noise transcript and both
READY messages bind the same original identities, candidate, route, attempt,
cryptographic profile and authorization.

Authenticated encrypted control and data become usable only after all READY
requirements complete. The two supported cryptographic profiles have distinct
key and usage bounds. Streams, flow control, rekey, revocation, liveness and
cleanup retain their actual resource charges until original work exits.

Relays forward opaque encrypted application traffic. They can observe routing,
timing, lengths and public admission or hop-authorization metadata, including
identity certificates and digests. End-to-end encryption does not claim to
hide those metadata fields from a relay. Relays do not receive endpoint
session secrets or application handlers.

## Application ownership

A ConnectionController acquires fresh material for an allowed retry. Candidate
initialization precedes publication to new work. Replacement does not replay
RPCs, notifications or writes, and previously accepted work retains its
original Session. Drain stops new admission; cleanup completes only after
actual sockets, callbacks, retained results and application leases retire.

Serve authenticates the transport context before application authorization,
freezes the accepted handler plan before READY and retains the returned lease
through actual Session cleanup. Structured service contracts distinguish
execution from observation, cancellation from completion, and application
errors from transport failures. Proxy upstream authorization applies to the
final request target; controlled Cookie ownership is explicit.

## Outside the protection boundary

A compromised endpoint process or authorized malicious application can access
its own plaintext. Flowersec does not prevent traffic analysis or protect
plaintext deliberately terminated by an application gateway. Durable store,
clock, identity and native-provider guarantees require their configured host
adapters to satisfy the published contract.

Current allocations and qualification boundaries are recorded in
[TRANSPORT_V4_BINDING.md](TRANSPORT_V4_BINDING.md); public ownership is described
in [API_CONTRACT.md](API_CONTRACT.md).
