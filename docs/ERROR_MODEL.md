# Flowersec v2 Error Model

Public connection and session failures expose only a stable bounded code. Error values and text do not contain artifacts, credentials, candidate URLs, selected carrier or path, connection stages, endpoint identities, logical stream IDs, peer payloads, key material, carrier handles, or ledger state.

Cancellation and deadlines preserve `context.Canceled` and `context.DeadlineExceeded` semantics where the language supports causal errors. Protocol, admission, transport, and cryptographic implementation errors are mapped to closed public outcomes before crossing an SDK boundary.

Public connection input and option validation also crosses the connection boundary as a closed `ConnectError` value. The optional `ConnectionController` owns the structured recovery decision; applications do not classify error text or maintain a second Flowersec retry path.

Remote RPC handlers may return a bounded application code and sanitized message. SDKs preserve that application outcome separately from transport and session failures; they never attach the underlying carrier or protocol cause.

Raw public error enums and code taxonomies are SDK-local because each runtime has different cancellation, TLS, and transport integration boundaries. The portable contract is the shared recovery decision plus the separation between remote RPC application errors and connection/session failures; consumers must not compare raw codes across languages.

An error after durable artifact commitment never authorizes credential reuse. Cleanup errors may be joined internally for diagnostics, but public projections remain redacted.

## Recovery decisions

Each SDK implements one `ConnectionController` above its one-shot connector. Failures crossing that controller carry one structured disposition backed by `stability/connection_controller_recovery.json`:

- `terminal` ends the controller lifecycle.
- `retryable` allows the controller to acquire a fresh artifact after deterministic backoff and establish a new session.
- `retry_after` does the same but enforces an authoritative absolute not-before deadline.

No disposition authorizes reuse of a committed lease, migration of streams, or replay of RPCs and writes. Cancellation and invalid configuration are terminal. Temporary connection failures and retryable session termination may create a new attempt only through the controller's single scheduler. Applications provide a refreshable artifact source, restore application authentication and subscriptions after a new session is published, and never parse error text or run a second Flowersec retry loop.
