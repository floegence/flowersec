# Deploy a direct TCP client

Run `flowersec-runtime -config /etc/flowersec/client.json` beside a TCP application. The application connects to a local port; the runtime opens one encrypted Flowersec stream per TCP connection. The remote direct server chooses the upstream from its independently authorized record. Local applications cannot select another target, stream kind, or metadata.

Use the runtime binary from your distribution or build it with `go build ./cmd/flowersec-runtime` from `flowersec-go`. A direct client needs no server certificate, authorization callback, or public listener.

1. Have the control plane issue a **direct** `flowersec/5` artifact for the remote server and its upstream. The server must have the matching authorization record before you distribute `IssuedArtifact.ArtifactJSON()` to the client. Deliver the artifact privately; use a regular file readable only by the runtime account (for example, mode `0600`).
2. Provision a persistent local directory owned by the runtime account with mode `0700` for spend markers. Use the same directory across restarts and across all processes that can consume the same artifact. Use a filesystem that supports exclusive creation and directory `fsync`. Keep the artifact, state, and their parent directories under trusted administrative control.
3. Save the following configuration, substituting the actual paths and the exact HTTPS origin allowed by the remote service. Start the runtime before the invitation expires, then direct the local application to `127.0.0.1:15432`.

```json
{
  "role": "direct-client",
  "spend_directory": "/var/lib/flowersec/spends",
  "ingress": [{
    "address": "127.0.0.1:15432",
    "artifact_file": "/etc/flowersec/invitations/reports.json",
    "origin": "https://reports.example.com",
    "kind": "application.tcp",
    "metadata": {"service": "reports"},
    "slots": 8,
    "connect_timeout_ms": 10000,
    "timeout_ms": 300000
  }]
}
```

Each of the 1–64 entries must have its own credential and unique numeric loopback address with a nonzero port (IPv4 or IPv6). Loopback limits access to the local network namespace; any process that can reach the port can exercise the configured grant. Use a dedicated namespace when local users or applications do not share that trust. Use a process or supervisor readiness check: a TCP probe is a real application connection and triggers authentication.

`slots` (1–128) limits concurrent accepted connections per entry. `connect_timeout_ms` (1–90000) bounds session establishment. `timeout_ms` (1–86400000) bounds each stream from opening through the end of forwarding. `metadata` defaults to an empty object. For a private CA, set `tls_roots_file` to the absolute path of a PEM trust bundle for that entry; otherwise the SDK uses system roots for CA-mode invitations. The artifact controls endpoint selection and TLS policy. Use absolute paths for credentials, trust bundles, and the spend directory.

Startup validates all entries and binds their local ports. Until the first local connection on an entry, it does not dial, establish a session, or spend the artifact. On first use it commits a marker before sending the credential. Subsequent local connections share that authenticated session. Closing the TCP write side still allows a response to arrive. Stopping the process with SIGTERM or Ctrl+C closes listeners, cancels active relays, and waits for them to exit.

A connect failure or terminated session stops the deployment. Check the remote listener, TLS trust, origin, and control-plane authorization. If the artifact expired or reached the spend step, obtain a fresh direct artifact and replace its file before restarting. Never delete spend markers to recover access; configure the supervisor to avoid automatic restart loops with a spent credential.

## Serve registered methods on fixed TCP upstreams

Direct admission binds each invitation to the receiving listener and TLS certificate before contacting the authority. If the public URL differs from the local socket (for example, a forwarded port or a multi-name certificate), configure `listeners.direct_endpoints` with the canonical public URL keyed by `websocket`, `raw_quic`, or `webtransport` for the relevant listener.

Set `role` to `direct-server` and add `direct_services` to the server's existing TLS, listener, authorization and origin configuration. In this mode **every direct application stream must match a registration**. A server that omits both fields continues to bridge raw streams to the address in the authorized record. Tunnel listeners forward encrypted traffic and do not run these methods.

For example, add these top-level fields to serve a query, a notification and a report stream:

```json
{
  "role": "direct-server",
  "direct_services": {
    "slots": 8,
    "rpc_frame_bytes": 1048576,
    "methods": [
      {"shape":"unary", "type_id":7001, "upstream":"127.0.0.1:7101", "allowed_channels":["reports"], "timeout_ms":3000, "max_request_bytes":4096, "max_response_bytes":65536},
      {"shape":"notification", "type_id":7002, "upstream":"127.0.0.1:7102", "allowed_channels":["events"], "timeout_ms":1500, "max_request_bytes":4096},
      {"shape":"stream", "kind":"reports.rows", "metadata":{"format":"binary"}, "upstream":"127.0.0.1:7103", "allowed_channels":["reports"], "timeout_ms":30000, "max_request_bytes":4096, "max_response_bytes":65536, "max_items":1024, "max_stream_payload_bytes":8388608}
    ]
  }
}
```

Issue the direct invitation with the method's numeric IP and port as `UpstreamAddress` and an allowed `Session.ChannelID`. At each dispatch the runtime checks **both** fields from the verified authorization, plus the RPC form and type ID or the exact stream kind and canonical metadata (default `{}`). An invitation for `127.0.0.1:7101` cannot invoke the example's methods at ports 7102 or 7103, even on an allowed channel. Use a separate invitation for each distinct upstream. Administration owns the shared registrations; neither RPC input nor OPEN metadata can set the upstream. If methods share a TCP address, the application receives only their payload bytes; use separate ports for operations that require isolation at the upstream, and validate business permissions in the application.

| Client operation | Exchange with the authorized TCP application |
| --- | --- |
| `RPC().Call` | The host writes the request's JSON value, then sends TCP FIN. The application returns one UTF-8 JSON value and closes its write side. An invalid, truncated or oversized reply fails the call. |
| `RPC().Notify` | The host writes the JSON value and sends FIN. The application sends no reply bytes and closes its write side. Notifications are processed in order; the caller gets no processing acknowledgement. |
| `OpenStream` | The client writes the binary request and calls `CloseWrite`. The host validates the complete request before dialing. After receiving TCP FIN, the application returns items, each prefixed by its four-byte unsigned big-endian length, then EOF. The client reads these same application bytes on the reverse direction of the stream. A partial or oversized item resets the stream; earlier complete items may already have arrived. Empty items count toward `max_items`. |

`slots` (1–128) bounds active method exchanges across all direct sessions. Per session, it also bounds concurrent RPC requests and the sizes of the request and notification queues. Choose `rpc_frame_bytes` (256 bytes to 64 MiB) to cover the **encoded envelope**, including JSON escaping and headers; configure callers' frame limits as needed. Individual request, unary response and stream item limits are at most 32 MiB. `max_stream_payload_bytes` counts item bodies; the item count bounds framing overhead. No method reserves a TCP connection at startup. The method timeout (1–300000 ms) includes RPC queue time after frame receipt, dialing and all TCP I/O; for a stream it starts at dispatch and includes receipt of the request and delivery of its items.

An unauthorized or unregistered RPC call receives `404`; the host discards unauthorized notifications and resets unregistered streams without dialing. Oversized RPC input receives `413`, overload receives `429`, an upstream error receives `502`, and a method deadline receives `504`. A local caller timeout does not cancel completed remote effects. The host does not replay requests, keep execution history or issue completion receipts. Authorization uses the admitted grant and the deployment policy loaded at startup. A service requiring live revocation per operation must enforce it at its own effect boundary. Shutdown cancels active I/O and waits for local method and session workers before releasing the admission lease.
