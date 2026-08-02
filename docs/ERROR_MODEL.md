# Flowersec v2 Error Model

Public connection and session failures expose only a stable bounded code. Error values and text do not contain artifacts, credentials, candidate URLs, selected carrier or path, connection stages, endpoint identities, logical stream IDs, peer payloads, key material, carrier handles, or ledger state.

Cancellation and deadlines preserve `context.Canceled` and `context.DeadlineExceeded` semantics where the language supports causal errors. Protocol, admission, transport, and cryptographic implementation errors are mapped to closed public outcomes before crossing an SDK boundary.

Public connection input and option validation also crosses the connection boundary as a closed `ConnectError` value. Callers can pass the error directly to the language's connection classifier instead of maintaining a second recovery path for constructor or option exceptions.

Remote RPC handlers may return a bounded application code and sanitized message. SDKs preserve that application outcome separately from transport and session failures; they never attach the underlying carrier or protocol cause.

Raw public error enums and code taxonomies are SDK-local because each runtime has different cancellation, TLS, and transport integration boundaries. The portable contract is the shared recovery decision plus the separation between remote RPC application errors and connection/session failures; consumers must not compare raw codes across languages.

An error after durable artifact commitment never authorizes credential reuse. Cleanup errors may be joined internally for diagnostics, but public projections remain redacted.

## Recovery decisions

Each SDK provides public connection and session error classifiers backed by `stability/public_error_classification.json`. A classification contains an action plus `caller_canceled` and `session_closed` flags. Retryability and fresh-artifact acquisition are represented only by the action, so the public value cannot contain contradictory duplicate state. Field spelling follows each language's conventions, but the semantics are identical.

- `retry` means the failed operation may be repeated on the current usable session.
- `refresh_artifact` means the application must acquire a fresh artifact and establish a fresh session. It never authorizes reuse of a committed lease or credential.
- `stop` means no automatic retry. Caller cancellation is explicitly identified so applications can avoid presenting it as a service failure.

Connection establishment failures use `refresh_artifact` because a failed attempt may already have durably committed the one-time lease. Closed sessions also require a fresh artifact and session. Bounded operation failures such as timeouts or resource exhaustion may use `retry` only while the session remains usable. Invalid inputs and terminal operation failures use `stop`.
