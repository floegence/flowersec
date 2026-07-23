# Swift Cookbook

The Swift example reports the canonical Transport v2 Apple capability descriptor and optionally establishes a macOS WSS session from an opaque artifact lease.

## Run

Requirements: macOS 15+ and Swift 6.1+.

Print the capability descriptor:

```bash
swift run --package-path ./examples/swift
```

To establish a session, provide a fresh Transport v2 artifact containing a macOS-compatible WSS candidate:

```bash
FSEC_ARTIFACT_V2_PATH=./artifact-v2.json swift run --package-path ./examples/swift
```

Output includes these signals:

```text
descriptor={...}
tuple_count=0
digest=...
```

## Runtime Boundaries

Swift macOS supports direct and tunnel WSS dialing. `RuntimeCapabilitiesV2.apple` remains conservative because macOS evidence is not projected onto iOS. Browser Service Worker APIs remain TypeScript-owned, while shared tunnel, gateway, and helper binaries remain Go-owned.

## Troubleshooting

- Missing `FSEC_ARTIFACT_V2_PATH`: the example prints capabilities and exits without connecting.
- Spent or expired artifact: acquire a fresh artifact and retry.
- TLS or subprotocol rejection: verify the WSS certificate trust chain and exact Flowersec v2 subprotocol.
- Dependency resolution failure: run `swift package resolve --package-path ./examples/swift` and retry.
