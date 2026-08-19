# Swift Cookbook

The Swift example prints the opaque Flowersec v3 public contract marker and
optionally establishes a macOS WSS session from an artifact lease. A connected
client exercises typed RPC, decoded notification delivery, reliable stream
write/read/FIN, liveness, subscription cancellation, and session close.

## Run

Requirements: macOS 15+ and Swift 6.1+.

```bash
swift run --package-path ./examples/swift
```

Output without an artifact is:

```text
transport=v3
session_api=opaque
```

To establish and close a session, provide a fresh artifact containing a
macOS-compatible WSS candidate and a new path for the durable spend receipt:

```bash
FSEC_ARTIFACT_V3_PATH=/secure/path/artifact-v3.json \
FSEC_SPEND_RECEIPT_V3_PATH=/durable/state/artifact.spent \
  swift run --package-path ./examples/swift
```

The example creates the receipt with no overwrite, restricts it to the current
user, synchronizes it before connection credentials are sent, and fails closed
when the path already exists. The receipt contains no artifact or key material.
After connecting, the client registers notification type `7002`, makes typed
RPC type `7001` with `{ "value": "ping" }`, exchanges
`{ "value": "notify" }`, then writes `hello` on a `parity.echo` stream,
sends FIN, and reads `world` through peer FIN. The repository server-parity
fixtures implement this application contract; a deployed service must register
equivalent handlers. Connection and session failures expose only a structured
`RetryDisposition`.
Long-lived applications give `ConnectionController` a refreshable artifact
source; this one-shot example never reuses its spend receipt.

## Runtime Boundaries

Applications receive only opaque artifacts, sessions, RPC peers, byte streams, and redacted errors. Connection selection and cryptographic state remain internal.

## Troubleshooting

- Spent or expired artifact: acquire a fresh artifact and retry.
- TLS or subprotocol rejection: verify the artifact's CA or pin policy and the exact Flowersec v3 subprotocol.
- Dependency resolution failure: run `swift package resolve --package-path ./examples/swift` and retry.
