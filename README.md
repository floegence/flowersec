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
across the SDKs, plus the Go-owned v3 control-plane issuance flow.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## Examples

Start with the [cookbook index](examples/README.md) for small examples that use
the same public API as production applications. It covers client connections,
durable single-use handling, liveness, and session lifecycle, with v3
control-plane invitation issuance provided by Go.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## What Your App Can Do

The portable core keeps the shared session model consistent across SDKs. Each
SDK profile documents platform support, while a language convenience may adapt
syntax without changing shared behavior.

| App capability | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| End-to-end encrypted sessions | Yes | Yes | Yes | Yes |
| Send RPC calls and notifications | Yes | Yes | Yes | Yes |
| Receive RPC notifications | Yes | Yes | Yes | Yes |
| Reliable byte streams | Yes | Yes | Yes | Yes |
| Serve application streams on any Session | Yes | Yes | Yes | Yes |
| Long-lived connection recovery | Yes | Yes | Yes | Yes |
| Unreliable messages when available | Yes | Yes | No | Yes |
| Browser connections | No | Yes | No | No |
| Apple client connections | No | No | Yes | No |
| Native QUIC connections | Yes | Node.js | No | Yes |
| WebSocket connections | Yes | Yes | Yes | Yes |
| WebTransport connections | Go H4 | Browser H3 client (when available) | No | No |
| Server-side session acceptance | Yes | Node.js | No | Yes |
| Opaque tunnel runtime | Yes | Node.js | No | Yes |
| Control-plane invitation issuance | Yes | No | No | No |
| HTTP and WebSocket ProxyServer | Yes | Node.js | No | Yes |

Deployment profiles keep platform availability separate from the shared
Flowersec application protocol:

| Profile | Runtimes | Required carrier and role surface | Optional surface |
| --- | --- | --- | --- |
| `native-server-core` | Go, Rust, Node.js | WebSocket and raw QUIC endpoint client, direct server, and opaque tunnel runtime | WebTransport adapter |
| `browser-client` | TypeScript browser | WebSocket endpoint client | Browser WebTransport adapter |
| `apple-client` | Swift on Apple platforms | WSS endpoint client | None |
| `webtransport-server` | Go | WebTransport direct server and opaque tunnel runtime | None |

The machine-readable native-server-core profile contains 18 aggregate
runtime-role-carrier tuples (six per native runtime) and 24 supported
path-specific server units; Go H4 adds two WebTransport server tuples and two
path-specific units. The interoperability matrix separately declares a
coordinate universe of 18 direct cells and 18 tunnel cells. The release gate
proves all 10 direct cells and 14 pairwise tunnel cells that include Go; the
remaining 8 direct and 4 tunnel cells stay explicitly unverified. Four
additional WSS client profiles prove Swift and browser TypeScript against Go
over direct and tunneled paths. A profile never changes Artifact, handshake,
RPC, stream, close, rekey, or authorization wire semantics.

See the SDK guides for the exact platform and connection combinations supported
by each package.

WebTransport is optional rather than part of the required native-server carrier
contract. Go claims the separate complete H4 webtransport-server profile;
the Browser profile uses the H3 WebTransport API when present. Node.js and Rust
do not currently provide a production WebTransport adapter. The native-server carrier surface is
WebSocket and raw QUIC for Go, Rust, and Node.js; pairwise interoperability
support is claimed only by supported entries in the matrix.

`flowersec-private-loopback/1` is a product-private profile outside the public
deployment capability registry. Its dedicated Go server and TypeScript browser
APIs are limited to an application-authenticated numeric-loopback HTTP bridge.

<!-- readme-section:security -->
<a id="security"></a>

## Security

- Application data is encrypted end to end for both direct and relayed sessions.
- TLS trust policy is bound to every v3 transport candidate. Public or deployment-provided CA roots and explicit leaf-certificate pins are mutually exclusive and never downgrade after failure.
- `flowersec-private-loopback/1` is an isolated transport envelope, not a `flowersec/3` TLS mode or capability. Its dedicated APIs map one unchanged CA-mode v3 candidate to `ws://` only when the authority is the same numeric loopback origin and the server application authorizes the request before upgrade. Ordinary Go, TypeScript, Rust, Swift, Provider, and tunnel paths reject the envelope.
- Connection invitations are opaque, short-lived, and single-use.
- Credentials are committed before use, so a consumed invitation cannot be replayed.
- Relays forward encrypted traffic only; they do not terminate application sessions.
- Invalid or unsupported connection attempts fail closed with bounded public errors.

For protocol and threat-model details, read the [API contract](docs/API_CONTRACT.md),
[transport architecture](docs/TRANSPORT_V3_ARCHITECTURE.md), and
[threat model](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Learn More

- [API contract](docs/API_CONTRACT.md): the stable application-facing behavior shared by the SDKs.
- [Error model](docs/ERROR_MODEL.md): public connection, session, and RPC failures.
- [Transport architecture](docs/TRANSPORT_V3_ARCHITECTURE.md): direct and relayed connection design.
- [Examples](examples/README.md): runnable SDK usage.

Flowersec is available under the [MIT License](LICENSE). Published packages and
release notes are available through [GitHub Releases](https://github.com/floegence/flowersec/releases).
