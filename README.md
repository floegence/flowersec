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

Direct connections expose an application Session to the accepting service. A
tunnel relay exposes no application Session: it only pairs and forwards opaque
carrier streams while the two endpoint runtimes keep the end-to-end Session.
Transport selection, credentials, and routing stay inside the SDK and runtime.

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
client connections, durable invitation use, liveness, and session lifecycle
across the SDKs, plus the Go-owned v4 control-plane issuance flow.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## Examples

Start with the [cookbook index](examples/README.md) for small examples that use
the same public API as production applications. It covers client connections,
durable single-use handling, liveness, and session lifecycle, with v4
control-plane invitation issuance provided by Go.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## What Your App Can Do

The portable core keeps the shared session model consistent across SDKs. Each
SDK profile documents platform support, while a language convenience may adapt
syntax without changing shared behavior.

<!-- capability-table:start -->
| App capability | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Opaque, single-use connection artifacts | Yes | Yes | Yes | Yes |
| One-shot secure connection | Yes | Yes | Yes | Yes |
| End-to-end encrypted sessions | Yes | Yes | Yes | Yes |
| RPC calls and notifications | Yes | Yes | Yes | Yes |
| Validated stream metadata | Yes | Yes | Yes | Yes |
| Application stream handlers | Yes | Yes | Yes | Yes |
| Long-lived connection recovery | Yes | Yes | Yes | Yes |
| Negotiated unreliable messages | Yes | Yes | No | Yes |
| Client RPC handlers | Yes | Yes | Yes | Yes |
| Server-side session acceptance | Yes | Yes | Yes | Yes |
| Server session handlers | Yes | Yes | Yes | Yes |
| Control-plane issuance and authorization | Yes | No | No | No |
| Direct and tunneled admission | Yes | Yes | Yes | Yes |
| HTTP and WebSocket ProxyServer | Yes | Yes | No | Yes |
| Carrier-neutral stream contract | Yes | Yes | Yes | Yes |
| Transport v4 wire security | Yes | Yes | Yes | Yes |
<!-- capability-table:end -->

Deployment profiles describe the required native or browser carrier and role combinations. Current APIs and provider qualification are documented separately in each SDK guide. A source declaration does not establish verified runtime support.

The current wire uses authenticated connection materials, independent namespace trust, bounded Sessions, typed services and explicit cleanup. Direct and tunnel interoperability is qualified by the executable matrix and original providers. Release publishes packages and performs registry readback; it runs no acceptance tests.

WebTransport requires a configured native or browser provider. Browser support depends on the actual WebTransport API and certificate-policy capabilities. See each SDK guide for its current carrier, listener and relay surface.

The signed `local_loopback` access class supports an application-authenticated HTTP bridge on the same machine. It uses the current session protocol and requires a configured local provider.

<!-- readme-section:security -->
<a id="security"></a>

## Security

- Application data is encrypted end to end for both direct and relayed sessions.
- TLS trust policy is bound to every v4 transport candidate. Public or deployment-provided CA roots and explicit leaf-certificate pins are mutually exclusive and never downgrade after failure.
- The `local_loopback` access class permits `ws://` only for a signed numeric-loopback endpoint with exact Origin and application authorization before upgrade. It does not claim outer TLS verification or permit plaintext fallback.
- Connection invitations are opaque, short-lived, and single-use.
- Credentials are committed before use, so a consumed invitation cannot be replayed.
- Relays forward encrypted traffic only; they do not terminate application sessions.
- Invalid or unsupported connection attempts fail closed with bounded public errors.

For protocol and threat-model details, read the [API contract](docs/API_CONTRACT.md),
[transport architecture](docs/TRANSPORT_V4_BINDING.md), and
[threat model](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Learn More

- [API contract](docs/API_CONTRACT.md): the stable application-facing behavior shared by the SDKs.
- [Error model](docs/ERROR_MODEL.md): public connection, session, and RPC failures.
- [Transport architecture](docs/TRANSPORT_V4_BINDING.md): direct and relayed connection design.
- [Examples](examples/README.md): runnable SDK usage.

Flowersec is available under the [MIT License](LICENSE). Published packages and
release notes are available through [GitHub Releases](https://github.com/floegence/flowersec/releases).
