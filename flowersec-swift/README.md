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
.package(url: "https://github.com/floegence/flowersec.git", from: "0.19.12")
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
let stream = try await client.openStream(kind: "custom")
await client.close()
```

## Connect Artifacts

`ConnectArtifact` is the canonical wire model for direct and tunnel client setup.
Both variants carry `ConnectArtifactMetadata`:

- `scoped`: up to eight unique `ScopeMetadataEntry` values. Flowersec Swift preserves and validates scoped metadata, but it does not interpret product-specific scope payloads.
- `correlation`: optional `CorrelationContext` with sanitized trace/session IDs and up to eight unique tags.

```swift
let artifact = try JSONDecoder().decode(ConnectArtifact.self, from: data)

switch artifact {
case .direct(let info, metadata: let metadata):
  print(info.channelID, metadata.scoped.count)
case .tunnel(let grant, metadata: let metadata):
  print(grant.channelID, metadata.correlation?.tags ?? [])
}
```

## Boundaries

Flowersec Swift owns protocol and session mechanics only. Application-specific RPC payloads, feature availability, persistence, credentials, and UI behavior belong in downstream clients.
