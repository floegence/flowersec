# Swift Cookbook

The Swift example prints the opaque Flowersec v2 public contract marker and optionally establishes a macOS WSS session from an artifact lease.

## Run

Requirements: macOS 15+ and Swift 6.1+.

```bash
swift run --package-path ./examples/swift
```

Output without an artifact is:

```text
transport=v2
session_api=opaque
```

To establish and close a session, provide a fresh artifact containing a
macOS-compatible WSS candidate and a new path for the durable spend receipt:

```bash
FSEC_ARTIFACT_V2_PATH=/secure/path/artifact-v2.json \
FSEC_SPEND_RECEIPT_V2_PATH=/durable/state/artifact.spent \
  swift run --package-path ./examples/swift
```

The example creates the receipt with no overwrite, restricts it to the current
user, synchronizes it before connection credentials are sent, and fails closed
when the path already exists. The receipt contains no artifact or key material.
Connection and liveness failures expose only a structured `RetryDisposition`.
Long-lived applications give `ConnectionController` a refreshable artifact
source; this one-shot example never reuses its spend receipt.

## Runtime Boundaries

Applications receive only opaque artifacts and carrier-neutral sessions, RPC peers, byte streams, and redacted errors. Candidate, carrier, path, endpoint identity, stream identity, admission, wire, key, and Yamux state remain internal.

## Troubleshooting

- Spent or expired artifact: acquire a fresh artifact and retry.
- TLS or subprotocol rejection: verify the WSS certificate trust chain and exact Flowersec v2 subprotocol.
- Dependency resolution failure: run `swift package resolve --package-path ./examples/swift` and retry.
