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

Flowersec 2.3.6 provides the Go, TypeScript, Swift, and Rust SDKs. It supports the restricted loopback plaintext WebSocket direct profile and requires WSS for network-facing WebSocket candidates. Pin the published package versions and matching release tags.

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

Run the default acceptance suite:

```bash
make test
```

After fixing a failure, use `make test-resume` to continue from the first
incomplete test until the next failure or `ALL GREEN`. Completed IDs remain
valid when the source commit changes.

Use `make coverage-race` for the four language coverage lanes and exclusive Go
race. Use `make browser-smoke` for the three local Chromium topologies and
`make browser-compat` for explicit Firefox/WebKit capability checks. Privileged
weak-network and kernel diagnostics use `make diagnostic`; capacity and soak
use `make performance`.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDKs and Cookbooks

| Language | Package | Public entry |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.Connect`, `flowersec.NewConnectionController`, `flowersec.NewAcceptor` |
| TypeScript | `@floegence/flowersec-core` | root, `/browser`, `/node`, and `/proxy` opaque v2 entrypoints |
| Swift | SwiftPM product `Flowersec` | `Artifact`, `connect`, `Session` |
| Rust | crate `flowersec` | `Artifact`, `connect`, `Session` |

Go service control planes use the separate `github.com/floegence/flowersec/flowersec-go/v2/controlplane` package to issue opaque artifacts and answer `flowersec-runtime` authorization callbacks.

The [cookbook index](examples/README.md) contains only v2 examples and verification commands.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Portable Core and SDK Profiles

Flowersec keeps its contract layers explicit. The portable core, connection control, session/RPC/stream lifecycle, accepted-session workflows, and every published consumer workflow use same-semantic public entries in every applicable SDK. Each SDK profile declares its runtime and platform-specific carrier boundary. A platform limitation may be unsupported only with an explicit reason, alternative public boundary, and executable test ID in `stability/language_capabilities.json`. Control-plane persistence is a service boundary: clients call the authenticated service that uses `flowersec-go/v2/controlplane`; they do not embed a second issuer or datastore. A language convenience is syntax or orchestration that fits one language ecosystem without changing these contracts. The stable cross-language recovery contract is the controller's structured disposition, not byte-for-byte matching raw error codes.

| Capability | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Opaque artifact, connector, session, RPC, and byte streams | Yes | Yes | Yes | Yes |
| Single-owner connection controller | Yes | Yes | Yes | Yes |
| Negotiated unreliable message channel | Yes | Yes | No | Yes |
| RPC notification subscription | No | Yes | No | No |
| Inbound RPC request handlers | Yes | No | No | No |
| Production WebSocket dialing | Yes | Browser and Node.js | macOS and iOS | No |
| Production raw QUIC dialing | Yes | No | No | Yes |
| Production WebTransport dialing | Yes | Browser and Node.js | No | No |
| Server acceptor / accepted Session | `NewAcceptor` | `createAcceptor` / `AcceptedSession` | Unsupported on Apple listener profile | `Acceptor::bind` / `accept_with_handlers` |
| Control-plane issue / authorize | `flowersec-go/v2/controlplane` | Unsupported; application-owned service boundary | Unsupported; application-owned service boundary | Unsupported; application-owned service boundary |

Only declared carrier tuples are accepted; unsupported tuples fail closed. Each support row is backed by production connector code and an explicit test ID in `stability/language_capabilities.json`; unsupported capabilities include a reason and an alternative boundary. Capability descriptors and carrier selection remain internal.

<!-- readme-section:security -->
<a id="security"></a>

## Security

- Artifacts are opaque, bounded, single-use handles. Durable spend completes before the first credential byte is sent.
- QUIC-family carriers require TLS 1.3, exact ALPN, explicit trust roots, and disabled early data.
- Public errors are redacted and bounded; candidate, wire, key, and ledger details remain internal.
- Structured controller dispositions authorize only a fresh-artifact attempt; they never reuse credentials or replay work from a terminated session.
- Session cancellation, deadlines, FIN, reset, liveness, rekey, and cleanup have bounded behavior.

See the [Transport v2 architecture](docs/TRANSPORT_V2_ARCHITECTURE.md) and [threat model](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Deploy and Develop

The Flowersec runtime owns the production listener implementations for WebSocket, raw QUIC, and WebTransport. Application SDKs receive only opaque artifacts and sessions; runtime CLI tools compose the same connector and acceptor implementations.

Install repository hooks and run the fast feature gate before integration:

```bash
make install-hooks
make precommit
```

`scripts/push-main.sh` runs the bounded local acceptance suite before pushing
the exact main SHA. Run the complete engineering check and the explicit
nightly, diagnostic, and performance workflows for their compatibility,
privileged, and load-testing scopes; release itself runs no tests.

Flowersec is available under the [MIT License](LICENSE). Release artifacts are published through [GitHub Releases](https://github.com/floegence/flowersec/releases).
