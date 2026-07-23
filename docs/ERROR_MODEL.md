# Flowersec v2 Error Model

Public connection and session failures expose only a stable bounded code. Error values and text do not contain artifacts, credentials, candidate URLs, selected carrier or path, connection stages, endpoint identities, logical stream IDs, peer payloads, key material, carrier handles, or ledger state.

Cancellation and deadlines preserve `context.Canceled` and `context.DeadlineExceeded` semantics where the language supports causal errors. Protocol, admission, transport, and cryptographic implementation errors are mapped to closed public outcomes before crossing an SDK boundary.

Remote RPC handlers may return a bounded application code and sanitized message. SDKs preserve that application outcome separately from transport and session failures; they never attach the underlying carrier or protocol cause.

An error after durable artifact commitment never authorizes credential reuse. Cleanup errors may be joined internally for diagnostics, but public projections remain redacted.
