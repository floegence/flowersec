# Flowersec

<!-- readme-locales:start -->
<p align="center">
  <a href="README.md">English</a> |
  <strong>简体中文</strong> |
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
  <strong>跨 Go、TypeScript、Swift 和 Rust 一致实现的端到端加密通信。</strong>
</p>

<p align="center">
  在浏览器、Agent 和服务之间建立安全连接。通过一个直连或中继会话承载 RPC、事件、字节流、HTTP 和 WebSocket，同时避免中继接触应用明文。
</p>

<p align="center">
  <a href="#try-it-locally">立即体验</a> |
  <a href="#sdks-and-cookbooks">Cookbook</a> |
  <a href="#portable-contract">SDK</a> |
  <a href="#security">安全</a> |
  <a href="#deploy-and-develop">部署</a>
</p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)
![Languages](https://img.shields.io/badge/SDKs-Go%20%7C%20TypeScript%20%7C%20Swift%20%7C%20Rust-2563eb)
![Security](https://img.shields.io/badge/data%20plane-E2EE-7c3aed)
![Interop](https://img.shields.io/badge/interop-Go--reference-334155)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## 为什么选择 Flowersec

- **一套可移植契约。** Go、TypeScript、Swift 和 Rust 共享相同的线协议、安全、会话、RPC、Endpoint、Controlplane、重连、代理和可观测性行为。
- **直连或中继。** Endpoint 可达时使用最短的 WebSocket 直连路径；无法直达时通过自托管 Tunnel 会合，而无需向 Tunnel 暴露应用明文。
- **一个会话，多种数据流。** 在同一加密连接上复用 RPC 调用、事件、自定义字节流、HTTP 请求和 WebSocket 流量。
- **提供完整基础组件。** Flowersec 包含原生 Endpoint API、TypeScript 浏览器 Runtime、开源 Tunnel、Proxy Gateway 和运维 CLI。

典型用途包括远程 Agent、私有服务、内部 Web 工具、浏览器运维控制台和实时控制平面。

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## 工作原理

| 路径 | 连接方式 | 信任边界 |
| --- | --- | --- |
| Direct | 客户端连接可访问的服务端 Endpoint | 客户端和 Endpoint 终止 E2EE；数据路径不需要在线 Controlplane |
| Tunnel | 客户端和 Endpoint 使用一次性 Grant 接入同一个 Tunnel | Controlplane 准备连接；Tunnel 负责配对并转发加密字节 |
| Browser proxy | 浏览器 Runtime 或 Gateway 通过 Flowersec Stream 承载 HTTP 与 WebSocket | Runtime 模式保持浏览器到 Endpoint 的 E2EE；Gateway 模式有意让 Gateway 处理 L7 明文 |

Controlplane 只参与连接准备。它签发 ConnectArtifact 和 Grant，但不进入端到端加密的应用数据路径。

![Flowersec 安全连接模式](docs/flowersec-connection-patterns-whiteboard.png)

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## 本地体验

在源码仓库中构建 TypeScript 包并启动共享 Demo Stack：

```bash
make ts-ensure-deps ts-build
node ./examples/ts/dev-server.mjs | tee dev.json
```

启动后生成的 JSON 包含 Direct、Tunnel、端到端 Proxy Runtime 的浏览器地址，以及原生 SDK 示例使用的 Controlplane 地址。Release Demo Bundle 已包含所需二进制文件和预构建的 TypeScript 包。

完整的 Go、TypeScript、Swift 和 Rust 命令请参阅 [Cookbook 索引](examples/README.md)。

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK 与 Cookbook

| 语言 | 包与安装方式 | Cookbook |
| --- | --- | --- |
| Go | `go get github.com/floegence/flowersec/flowersec-go@latest` | [Go](examples/go/README.md) |
| TypeScript | `npm install @floegence/flowersec-core` | [TypeScript](examples/ts/README.md) |
| Swift | SwiftPM 产品 `Flowersec` | [Swift](examples/swift/README.md) |
| Rust | `cargo add flowersec` | [Rust](examples/rust/README.md) |

所有新集成都遵循同一套与语言无关的路径：

```text
ConnectArtifact -> connect -> RPC / stream / proxy
```

Cookbook 直接链接可运行源码，避免在多个文档中重复维护大段 API 示例。

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## 跨语言契约

| 能力 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Client 与 Endpoint 会话 | 支持 | 支持 | 支持 | 支持 |
| RPC、事件和自定义 Stream | 支持 | 支持 | 支持 | 支持 |
| Controlplane Artifact 与重连 | 支持 | 支持 | 支持 | 支持 |
| HTTP 与 WebSocket Proxy 契约 | 支持 | 支持 | 支持 | 支持 |
| 共享诊断与资源限制 | 支持 | 支持 | 支持 | 支持 |

运行时职责保持明确：TypeScript 负责 Browser 和 Service Worker 集成；Go 负责共享 Tunnel、Proxy Gateway 和 CLI；Swift 与 Rust 提供原生 SDK 集成，不重复实现这些特定运行时组件。

互操作性通过 Go Reference Client/Server 持续验证 TypeScript、Swift 和 Rust 的双向连接，包括 Direct、Tunnel、RPC、Stream、Liveness、Rekey、Reset 和 Proxy 流量。

<!-- readme-section:security -->
<a id="security"></a>

## 安全

- 高层连接默认要求 `wss://`。本地 `ws://` 开发必须显式启用 Loopback Policy。
- Tunnel Grant 只能使用一次。重连必须获取新的 `ConnectArtifact` 或 Grant。
- E2EE 握手完成后 Tunnel 无法解密应用载荷，但仍需要 TLS 保护握手前的接入元数据和 Bearer Token。
- Browser Runtime 模式在中继链路上保持 E2EE；Proxy Gateway 按设计属于可信 L7 组件。

生产使用前请阅读[威胁模型](docs/THREAT_MODEL.md)、[协议](docs/PROTOCOL.md)和[错误模型](docs/ERROR_MODEL.md)。

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 部署与开发

部署指南：

- [自托管 Tunnel](docs/TUNNEL_DEPLOYMENT.md)
- [部署 Proxy Gateway](docs/PROXY_GATEWAY_DEPLOYMENT.md)

仓库结构：

- `flowersec-go/`、`flowersec-ts/`、`flowersec-swift/`、`flowersec-rust/`：各语言 SDK
- `examples/`：可运行 Cookbook 与共享 Demo Stack
- `idl/`：共享协议定义和生成契约输入
- `docs/`：长期维护的协议、安全、互操作性和部署契约

每个 Worktree 只需安装一次仓库 Hooks，并在集成前执行完整本地门禁：

```bash
make install-hooks
make check
```

Flowersec 使用 [MIT License](LICENSE)。已发布的包、二进制文件、镜像和 Release Notes 可从 [GitHub Releases](https://github.com/floegence/flowersec/releases) 获取。
