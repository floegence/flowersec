# Flowersec

<!-- readme-locales:start -->
<p align="center">
  <strong>English</strong> |
  <a href="README.zh-CN.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <a href="README.ja-JP.md">日本語</a> |
  <a href="README.ko-KR.md">한국어</a> |
  <a href="README.de-DE.md">Deutsch</a> |
  <a href="README.fr-FR.md">Français</a> |
  <a href="README.es-ES.md">Español</a> |
  <a href="README.pt-BR.md">Português do Brasil</a> |
  <a href="README.ru-RU.md">Русский</a>
</p>
<!-- readme-locales:end -->

<p align="center"><strong>Carrier-neutral, end-to-end encrypted sessions for Go, TypeScript, Swift, and Rust.</strong></p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Why Flowersec

- One opaque artifact and session contract across four SDKs.
- WebSocket, raw QUIC, and WebTransport are equal carrier candidates.
- RPC and byte streams share one authenticated session without exposing carrier, wire, key, or ledger objects to applications.
- Tunnel relays forward encrypted streams without terminating application encryption.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## How It Works

| Path | Connection shape | Stream transport |
| --- | --- | --- |
| Direct | Client connects to an endpoint using a compatible candidate | WebSocket uses hop-local Yamux; QUIC-family carriers use native bidirectional streams |
| Tunnel | Client and server legs join through independently selected compatible carriers | The tunnel maps encrypted streams between legs without choosing a primary carrier |

Raw QUIC and WebTransport preserve native FIN, RESET_STREAM, STOP_SENDING, flow control, and migration behavior. Flowersec disables application 0-RTT. Reliable streams never use QUIC DATAGRAM; runtimes with negotiated native DATAGRAM expose it only through carrier-neutral unreliable messages.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Try It Locally

Run the v2 unit suites:

```bash
make transport-v2-unit
```

For carrier-specific evidence, run `make transport-conformance-smoke`, `make transport-browser-smoke`, and `make transport-interop-smoke`.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDKs and Cookbooks

| Language | Package | Public entry |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.NewConnector` |
| TypeScript | `@floegence/flowersec-core` | root, `/browser`, and `/node` opaque v2 entrypoints |
| Swift | SwiftPM product `Flowersec` | `ArtifactV2`, `ConnectorV2`, `SessionV2` |
| Rust | crate `flowersec` | `Artifact`, `Connector`, `Session` |

The [cookbook index](examples/README.md) contains only v2 examples and verification commands.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Portable Contract

| Capability | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Opaque artifact, connector, session, RPC, and byte streams | Yes | Yes | Yes | Yes |
| Production WebSocket dialing | Yes | Browser and Node.js | macOS and iOS | No |
| Production raw QUIC dialing | Yes | No | No | Yes |
| Production WebTransport dialing | Yes | Browser | No | No |
| Listener support | Go library APIs | Browser runtime constraints | Not advertised | Runtime-owned raw QUIC |

Each support row is backed by production connector code and end-to-end tests. Unsupported carriers fail closed; they are never silent fallbacks. Capability descriptors and carrier selection remain internal.

<!-- readme-section:security -->
<a id="security"></a>

## Security

- Artifacts are opaque, bounded, single-use handles. Durable spend completes before the first credential byte is sent.
- QUIC-family carriers require TLS 1.3, exact ALPN, explicit trust roots, and disabled early data.
- Public errors are redacted and bounded; candidate, wire, key, and ledger details remain internal.
- Session cancellation, deadlines, FIN, reset, liveness, rekey, and cleanup have bounded behavior.

See the [Transport v2 architecture](docs/TRANSPORT_V2_ARCHITECTURE.md) and [threat model](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Deploy and Develop

The Flowersec runtime owns the production listener implementations for WebSocket, raw QUIC, and WebTransport. Application SDKs receive only opaque artifacts and sessions; no removed compatibility CLI is part of the v2 contract.

Install repository hooks and run the authoritative gate before integration:

```bash
make install-hooks
make check
```

Flowersec is available under the [MIT License](LICENSE). Release artifacts are published through [GitHub Releases](https://github.com/floegence/flowersec/releases).
