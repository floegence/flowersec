# Flowersec v2 Cookbooks

Every maintained cookbook is v2-only. Examples use opaque artifacts and carrier-neutral sessions; removed v1 controlplane, endpoint, tunnel, proxy, and manual wire-stack demos are not maintained product surfaces.

| Language | Cookbook | Runnable evidence |
| --- | --- | --- |
| TypeScript | [examples/ts](ts/README.md) | Documents the published browser and Node.js connector entrypoints |
| Swift | [examples/swift](swift/README.md) | Exercises the opaque public connector and session contract |
| Rust | [examples/rust](rust/README.md) | Exercises the opaque public connector and session contract |

## Carrier Contract

WebSocket, raw QUIC, and WebTransport are equal carrier candidates.

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior. They use native bidirectional streams without Yamux; WebSocket keeps Yamux internal to its hop.

Flowersec disables application 0-RTT. Reliable streams never use QUIC DATAGRAM; runtimes with negotiated native DATAGRAM expose it only through carrier-neutral unreliable messages.

Internal runtime descriptors advertise only production tuples proven by connector and end-to-end tests. A cookbook cannot add or broaden a capability claim.

## Verify

From the repository root:

```bash
make example-check
```

The repository-wide `make check` gate includes cookbook verification.
