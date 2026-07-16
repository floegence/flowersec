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

<p align="center">
  <strong>End-to-end encrypted communication, consistently implemented across Go, TypeScript, Swift, and Rust.</strong>
</p>

<p align="center">
  Build secure connections between browsers, agents, and services. Carry RPC, events, byte streams, HTTP, and WebSocket traffic over one direct or relayed session, while keeping relays blind to application plaintext.
</p>

<p align="center">
  <a href="#try-it-locally">Try it</a> |
  <a href="#sdks-and-cookbooks">Cookbooks</a> |
  <a href="#portable-contract">SDKs</a> |
  <a href="#security">Security</a> |
  <a href="#deploy-and-develop">Deploy</a>
</p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)
![Languages](https://img.shields.io/badge/SDKs-Go%20%7C%20TypeScript%20%7C%20Swift%20%7C%20Rust-2563eb)
![Security](https://img.shields.io/badge/data%20plane-E2EE-7c3aed)
![Interop](https://img.shields.io/badge/interop-Go--reference-334155)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Why Flowersec

- **One portable contract.** Go, TypeScript, Swift, and Rust implement the same wire, security, session, RPC, endpoint, controlplane, reconnect, proxy, and observability behavior.
- **Direct or relayed.** Use the shortest direct WebSocket path when an endpoint is reachable, or rendezvous through a self-hosted tunnel without giving the tunnel application plaintext.
- **One session, many flows.** Multiplex RPC calls, events, custom byte streams, HTTP requests, and WebSocket traffic over the same encrypted connection.
- **Useful building blocks included.** Flowersec ships native endpoint APIs, a TypeScript browser runtime, an open-source tunnel, a proxy gateway, and operational CLIs.

Typical uses include remote agents, private services, internal web tools, browser-based operator consoles, and real-time control planes.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## How It Works

| Path | Connection shape | Trust boundary |
| --- | --- | --- |
| Direct | Client connects to a reachable server endpoint | The client and endpoint terminate E2EE; no online controlplane is required for the data path |
| Tunnel | Client and endpoint attach with one-time grants to the same tunnel | The controlplane prepares the connection; the tunnel pairs endpoints and forwards encrypted bytes |
| Browser proxy | A browser runtime or gateway carries HTTP and WebSocket over Flowersec streams | Runtime mode keeps browser-to-endpoint E2EE; gateway mode deliberately trusts the gateway with L7 plaintext |

The controlplane is setup-only. It issues connect artifacts and grants, but it does not sit inside the end-to-end encrypted application data path.

![Flowersec secure connection patterns](docs/flowersec-connection-patterns-whiteboard.png)

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Try It Locally

From a source checkout, build the TypeScript package and start the shared demo stack:

```bash
make ts-ensure-deps ts-build
node ./examples/ts/dev-server.mjs | tee dev.json
```

The ready JSON contains browser URLs for direct, tunnel, and end-to-end proxy runtime demos, plus the controlplane URL used by the native SDK examples. Release demo bundles include the required binaries and prebuilt TypeScript package.

See the [cookbook index](examples/README.md) for exact Go, TypeScript, Swift, and Rust commands.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDKs and Cookbooks

| Language | Package and install | Cookbook |
| --- | --- | --- |
| Go | `go get github.com/floegence/flowersec/flowersec-go@latest` | [Go](examples/go/README.md) |
| TypeScript | `npm install @floegence/flowersec-core` | [TypeScript](examples/ts/README.md) |
| Swift | SwiftPM product `Flowersec` | [Swift](examples/swift/README.md) |
| Rust | `cargo add flowersec` | [Rust](examples/rust/README.md) |

New integrations follow one language-neutral path:

```text
ConnectArtifact -> connect -> RPC / stream / proxy
```

The cookbooks point to runnable source instead of duplicating large API examples in multiple documents.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Portable Contract

| Capability | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Client and endpoint sessions | Yes | Yes | Yes | Yes |
| RPC, events, and custom streams | Yes | Yes | Yes | Yes |
| Controlplane artifacts and reconnect | Yes | Yes | Yes | Yes |
| HTTP and WebSocket proxy contract | Yes | Yes | Yes | Yes |
| Shared diagnostics and resource limits | Yes | Yes | Yes | Yes |

Runtime-specific ownership stays explicit: TypeScript owns browser and Service Worker integration; Go owns the shared tunnel, proxy gateway, and CLIs; Swift and Rust provide native SDK integration without duplicating those runtime-specific components.

Interoperability is continuously checked through Go-reference client and server directions for TypeScript, Swift, and Rust, including direct and tunnel sessions, RPC, streams, liveness, rekey, reset, and proxy traffic.

<!-- readme-section:security -->
<a id="security"></a>

## Security

- High-level connections require `wss://` by default. Local `ws://` development needs the explicit loopback policy.
- Tunnel grants are single-use. Reconnect flows must fetch a fresh `ConnectArtifact` or grant.
- The tunnel cannot decrypt application payloads after the E2EE handshake, but TLS still protects pre-E2EE attach metadata and bearer tokens.
- Browser runtime mode preserves E2EE through the relay. The proxy gateway is a trusted L7 component by design.

Review the [threat model](docs/THREAT_MODEL.md), [protocol](docs/PROTOCOL.md), and [error model](docs/ERROR_MODEL.md) before production use.

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Deploy and Develop

Deployment guides:

- [Self-host the tunnel](docs/TUNNEL_DEPLOYMENT.md)
- [Deploy the proxy gateway](docs/PROXY_GATEWAY_DEPLOYMENT.md)

Repository layout:

- `flowersec-go/`, `flowersec-ts/`, `flowersec-swift/`, `flowersec-rust/`: language SDKs
- `examples/`: runnable cookbooks and shared demo stack
- `idl/`: shared protocol definitions and generated-contract inputs
- `docs/`: durable protocol, security, interoperability, and deployment contracts

Install repository-managed hooks once in every worktree, then run the complete local gate before integration:

```bash
make install-hooks
make check
```

Flowersec is available under the [MIT License](LICENSE). Published packages, binaries, images, and release notes are available from [GitHub Releases](https://github.com/floegence/flowersec/releases).
