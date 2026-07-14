# Flowersec Swift

Flowersec Swift is the native Swift implementation of the Flowersec client protocol stack.

It provides:

- direct and tunnel client session entrypoints
- WebSocket binary transport
- E2EE handshake and record encryption
- Yamux stream multiplexing
- StreamHello framing
- length-prefixed JSON RPC client support
- ConnectArtifact, DirectConnectInfo, scoped metadata, and correlation context decoding

The package is intentionally product-neutral. It does not contain downstream application models, feature type IDs, UI state, or product-specific data transformations.

## SwiftPM

The repository root exposes the Swift package:

```swift
.package(url: "https://github.com/floegence/flowersec.git", from: "0.20.2")
```

Use the `Flowersec` product:

```swift
.product(name: "Flowersec", package: "flowersec")
```

## Direct Connect

```swift
import Flowersec

let info = DirectConnectInfo(
  wsURL: wsURL,
  channelID: channelID,
  psk: psk,
  channelInitExpiresAtUnixS: expiresAt,
  defaultSuite: .x25519HKDFSHA256AES256GCM
)

let client = try await Flowersec.connectDirect(
  info,
  options: DirectConnectOptions(origin: origin)
)

let response: PingResponse = try await client.rpc.call(4001, PingRequest())
let rtt = try await client.probeLiveness(timeout: .seconds(10))
let stream = try await client.openStream(kind: "custom")
await client.close()
```

High-level connects use `.requireTLS` by default. Use `.allowPlaintextForLoopback` only for literal local development targets. The low-level WebSocket transport remains scheme-neutral; high-level callers choose the deployment policy explicitly. Automatic liveness is disabled for direct sessions by default; configure `ConnectOptions.liveness` when a direct deployment needs periodic acknowledged probes.

`ConnectOptions.connectTimeout` bounds WebSocket establishment. `ConnectOptions.handshakeTimeout` separately bounds the E2EE handshake and defaults to 8 seconds. `ConnectOptions.maxOutboundBufferedBytes` bounds pending secure-channel writes and defaults to 4 MiB; exceeding it fails the write with `resource_exhausted` without retaining the rejected `Data`.

Use `ConnectOptions.onDiagnosticEvent` for generic transport, Yamux, liveness, and resource-limit events. Events contain only low-cardinality communication metadata and optional `resource`, `current`, and `limit` values; they never include URL queries, credentials, stream kinds, RPC type IDs, or application payloads.

## Connect Artifacts

`ConnectArtifact` is the canonical wire model for direct and tunnel client setup.
Both variants carry `ConnectArtifactMetadata`:

- `scoped`: up to eight unique `ScopeMetadataEntry` values. Register product-owned validators with `ConnectOptions.scopeResolvers`. Missing critical resolvers and resolver failures fail before networking. Missing optional resolvers are ignored with a diagnostic; known optional resolver failures remain fail-closed unless `relaxedOptionalScopeValidation` is explicitly enabled.
- `correlation`: optional `CorrelationContext` with sanitized trace/session IDs and up to eight unique tags. Artifact-based connect copies trace and session IDs into emitted diagnostics.

```swift
let artifact = try JSONDecoder().decode(ConnectArtifact.self, from: data)

switch artifact {
case .direct(let info, metadata: let metadata):
  print(info.channelID, metadata.scoped.count)
case .tunnel(let grant, metadata: let metadata):
  print(grant.channelID, metadata.correlation?.tags ?? [])
}
```

Scope resolvers are asynchronous, product-neutral validators keyed by the exact scope name:

```swift
let options = ConnectOptions(
  scopeResolvers: [
    "example.capability": { entry in
      guard entry.scopeVersion == 1 else {
        throw UnsupportedScopeVersion()
      }
      try validateCapabilityPayload(entry.payload)
    }
  ]
)

let client = try await Flowersec.connect(artifact, options: options)
```

`relaxedOptionalScopeValidation` applies only when a registered resolver rejects an optional scope. It never downgrades critical scopes. Both ignored cases emit the stable low-cardinality diagnostics `scope_ignored_missing_resolver` or `scope_ignored_relaxed_validation` with `stage=scope`; resolver errors and payloads are not included.

## Boundaries

Flowersec Swift owns protocol and session mechanics only. Application-specific RPC payloads, feature availability, persistence, credentials, and UI behavior belong in downstream clients.
