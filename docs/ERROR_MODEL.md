# Flowersec v3 Error Model

Public connection and session failures expose only stable, bounded codes. Error
values and text do not contain artifacts, credentials, candidate URLs, TLS
policies, certificate pins, selected carriers or paths, connection stages,
endpoint identities, logical stream IDs, peer payloads, key material, carrier
handles, lease identities, or native TLS diagnostics.

Cancellation and deadlines preserve their language-native semantics where the
SDK supports causal errors. Artifact, TLS, transport, admission, protocol, and
cryptographic failures are mapped to closed public outcomes before crossing an
SDK boundary. Applications do not classify error text or run a second
Flowersec retry scheduler.

## Connection Boundary

The cross-language v3 public connection codes are:

| Code | Meaning |
| --- | --- |
| `artifact_invalid` | The artifact, lease, source result, option, or adapter contract is invalid. |
| `expired_artifact` | The exclusive initiation deadline has been reached. |
| `transport_security_unsupported` | No declared candidate can be enforced by the runtime capability snapshot. |
| `transport_security_failed` | A native CA or pin security failure could not be resolved by the single policy refresh. |
| `connection_failed` | No candidate established a Session and no more specific public code is justified. |

These public codes are distinct from internal transport-security results and
from FSA3 admission reasons. TLS failures occur before durable spend and FSB3,
and therefore are never represented as FSA3 reasons. Browser pin failures may
remain opaque `connection_failed` results because browser APIs do not provide
evidence for a more specific TLS classification.

## Recovery Decisions

Every SDK implements one `ConnectionController` above its one-shot connector.
A controller failure carries exactly one validated disposition:

- `terminal` ends the current controller lifecycle.
- `retryable` permits a fresh artifact acquisition after deterministic
  monotonic backoff.
- `retry_after` additionally requires a valid absolute Unix-millisecond
  deadline before retry.

Invalid dispositions fail closed as `artifact_invalid / terminal`. Multiple
ordinary candidate failures aggregate independently of completion order:
the latest valid `retry_after` wins, then `retryable`, then `terminal`.
`retryNow` may skip only an existing backoff and cannot cross a future absolute
deadline.

`waitForSession` / `WaitForSession` / `wait_for_session` never starts a
controller. It returns immediately for an established Session and otherwise
waits for a state transition. Failed, closed, and caller-canceled outcomes use
a structured controller error. Its `ConnectionDiagnostic` contains only state,
attempt, failure phase/code, and retry disposition; it never retains a Session,
raw error, URL, carrier, candidate, credential, or peer identity.

One connection cycle may obtain at most one policy-sensitive replacement
lease. A pin trigger blocks the same endpoint and policy digest immediately.
A replacement must keep that endpoint in pin mode with a changed complete
declared policy; pin-to-CA replacement and retries of an old pin set are
terminal. Unsupported candidates may be skipped in favor of other explicitly
authorized endpoints, but no candidate changes security mode after failure.

## Lease and Session Failures

A claimed lease that fails before durable spend is retired. Once durable spend
begins, every success, failure, cancellation, or uncertain outcome consumes the
lease permanently. No disposition authorizes credential reuse.

Remote RPC application errors remain separate from connection and session
failures. They may contain only their bounded semantic code and sanitized
message. Session replacement never migrates streams or replays RPC calls,
notifications, or writes.

Negotiated unreliable-message operations use one portable error set:
`unavailable`, `invalid_message`, `too_large`, `canceled`, `closed`, and
`operation_failed`. Accepted and dropped sends are outcomes, not errors. Swift
does not expose this optional capability.

The normative ordering, retry clocks, replacement state machine, and redaction
requirements are defined in
[`TRANSPORT_V3_ARCHITECTURE.md`](TRANSPORT_V3_ARCHITECTURE.md) and frozen by
`stability/transport_v3_contract.json` plus the v3 controller vectors.
