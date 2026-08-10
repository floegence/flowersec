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

<p align="center"><strong>Connect the parts of your app securely, wherever they run.</strong></p>
<p align="center">Flowersec gives Go, TypeScript, Swift, and Rust one simple API for end-to-end encrypted sessions, RPC, notifications, and byte streams.</p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Why Flowersec

Flowersec is for applications that need a private connection between clients,
services, and devices without turning transport code into application code.

- **One programming model:** use the same authenticated session API from Go, TypeScript, Swift, or Rust.
- **The features apps actually use:** make RPC calls, send notifications, and move reliable byte streams over one connection.
- **Connections that fit the network:** connect directly when possible or pass through a relay when needed, without changing your application protocol.
- **Private by default:** application data is encrypted end to end. A relay can forward traffic, but it cannot read it.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## How It Works

Flowersec keeps the application session separate from the path used to carry it:

1. Your service creates a short-lived connection invitation and gives it to the client.
2. The SDK establishes a secure session over an available direct or relayed connection.
3. Your application uses RPC, notifications, and byte streams through the same session API.

Direct and relayed connections expose the same session to your code. Transport
selection, credentials, and routing stay inside the SDK and runtime.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Start Building

Choose the SDK that matches your application:

| SDK | Best fit | Install and API guide |
| --- | --- | --- |
| Go | Services, gateways, and control-plane code | [Go SDK](flowersec-go/README.md) |
| TypeScript | Browser and Node.js applications | [TypeScript SDK](flowersec-ts/README.md) |
| Swift | macOS and iOS clients | [Swift SDK](flowersec-swift/README.md) |
| Rust | Tokio services that need native QUIC | [Rust SDK](flowersec-rust/README.md) |

The [cookbook index](examples/README.md) contains small, runnable examples for
each SDK, including direct connections, relays, accepted sessions, and RPC.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## Examples

Start with the [cookbook index](examples/README.md) for small examples that use
the same public API as production applications. It covers client connections,
control-plane invitation issuance, durable single-use handling, and session
lifecycle.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## What Your App Can Do

The shared session model is consistent across SDKs; platform support differs
where a runtime cannot provide a particular connection type.

| App capability | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| End-to-end encrypted sessions | Yes | Yes | Yes | Yes |
| Send RPC calls and notifications | Yes | Yes | Yes | Yes |
| Receive RPC notifications | No | Yes | No | No |
| Reliable byte streams | Yes | Yes | Yes | Yes |
| Long-lived connection recovery | Yes | Yes | Yes | Yes |
| Unreliable messages when available | Yes | Yes | No | Yes |
| Browser connections | No | Yes | No | No |
| Apple client connections | No | No | Yes | No |
| Native QUIC connections | Yes | No | No | Yes |
| WebSocket connections | Yes | Yes | Yes | No |
| WebTransport connections | Yes | Yes | No | No |
| Server-side session acceptance | Yes | Node.js | No | Yes |
| Control-plane invitation issuance | Go package | Application-owned | Application-owned | Application-owned |

See the SDK guides for the exact platform and connection combinations supported
by each package.

<!-- readme-section:security -->
<a id="security"></a>

## Security

- Application data is encrypted end to end for both direct and relayed sessions.
- Connection invitations are opaque, short-lived, and single-use.
- Credentials are committed before use, so a consumed invitation cannot be replayed.
- Relays forward encrypted traffic only; they do not terminate application sessions.
- Invalid or unsupported connection attempts fail closed with bounded public errors.

For protocol and threat-model details, read the [API contract](docs/API_CONTRACT.md),
[transport architecture](docs/TRANSPORT_V2_ARCHITECTURE.md), and
[threat model](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Learn More

- [API contract](docs/API_CONTRACT.md): the stable application-facing behavior shared by the SDKs.
- [Error model](docs/ERROR_MODEL.md): public connection, session, and RPC failures.
- [Transport architecture](docs/TRANSPORT_V2_ARCHITECTURE.md): direct and relayed connection design.
- [Examples](examples/README.md): runnable SDK usage.

Flowersec is available under the [MIT License](LICENSE). Published packages and
release notes are available through [GitHub Releases](https://github.com/floegence/flowersec/releases).
