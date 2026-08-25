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

<p align="center"><strong>无论应用运行在哪里，都能安全连接彼此。</strong></p>
<p align="center">Flowersec 为 Go、TypeScript、Swift 和 Rust 提供一套简单 API，用于端到端加密会话、RPC、通知和字节流。</p>

[![最新版本](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![许可证](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## 为什么选择 Flowersec

Flowersec 适合需要在客户端、服务和设备之间建立私密连接，又不希望业务代码被网络传输细节绑住的应用。

- **一套编程模型：** Go、TypeScript、Swift 和 Rust 使用相同的认证会话 API。
- **直接提供应用所需能力：** 在同一连接中发起 RPC、发送通知并传输可靠字节流。
- **适应不同网络：** 能直连时直接连接，需要时经过中继，无需改写应用协议。
- **默认保护隐私：** 应用数据始终端到端加密；中继只能转发，无法读取内容。

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## 工作原理

Flowersec 将应用会话与承载它的网络路径分离：

1. 服务创建一份短期连接邀请并交给客户端。
2. SDK 通过可用的直连或中继路径建立安全会话。
3. 应用通过同一套会话 API 使用 RPC、通知和字节流。

无论直连还是中继，业务代码拿到的都是同一种会话。连接选择、凭据和路由由 SDK 与运行时在内部处理。

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## 开始构建

选择与应用场景匹配的 SDK：

| SDK | 适用场景 | 安装与 API 指南 |
| --- | --- | --- |
| Go | 服务、网关和控制面代码 | [Go SDK](flowersec-go/README.md) |
| TypeScript | 浏览器和 Node.js 应用 | [TypeScript SDK](flowersec-ts/README.md) |
| Swift | macOS 和 iOS 客户端 | [Swift SDK](flowersec-swift/README.md) |
| Rust | 需要原生 QUIC 的 Tokio 服务 | [Rust SDK](flowersec-rust/README.md) |

[Cookbook 索引](examples/README.md)提供每种 SDK 的小型可运行示例，覆盖客户端连接、持久化单次使用、控制面签发、活性探测和会话生命周期。

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## 示例

从 [Cookbook 索引](examples/README.md)开始，里面的示例使用与生产应用相同的公共 API，涵盖客户端连接、由 Go 控制面签发 v3 连接邀请、持久化单次使用处理、活性探测和会话生命周期。

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## 应用可以做什么

四种 SDK 共享一致的会话模型；当某个平台无法提供特定连接方式时，支持范围会有所不同。

| 应用能力 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| 端到端加密会话 | 是 | 是 | 是 | 是 |
| 发送 RPC 调用和通知 | 是 | 是 | 是 | 是 |
| 接收 RPC 通知 | 是 | 是 | 是 | 是 |
| 可靠字节流 | 是 | 是 | 是 | 是 |
| 在任意会话上处理应用流 | 是 | 是 | 是 | 是 |
| 长连接自动恢复 | 是 | 是 | 是 | 是 |
| 条件允许时发送不可靠消息 | 是 | 是 | 否 | 是 |
| 浏览器连接 | 否 | 是 | 否 | 否 |
| Apple 客户端连接 | 否 | 否 | 是 | 否 |
| 原生 QUIC 连接 | 是 | Node.js | 否 | 是 |
| WebSocket 连接 | 是 | 是 | 是 | 是 |
| WebTransport 连接 | Go H4 | Browser H3 client（浏览器 API 可用时） | 否 | 否 |
| 服务端接收会话 | 是 | Node.js | 否 | 是 |
| 不透明中继运行时 | 是 | Node.js | 否 | 是 |
| 控制面签发连接邀请 | 是 | 否 | 否 | 否 |
| HTTP 和 WebSocket ProxyServer | 是 | Node.js | 否 | 是 |

部署 profile 将平台可用性与共享的 Flowersec 应用协议分离：

| Profile | 运行时 | 必需的 carrier 与角色范围 | 可选范围 |
| --- | --- | --- | --- |
| `native-server-core` | Go、Rust、Node.js | WebSocket 和 raw QUIC endpoint client、direct server 与 opaque tunnel runtime | WebTransport adapter |
| `browser-client` | TypeScript browser | WebSocket endpoint client | Browser WebTransport adapter |
| `apple-client` | Apple 平台上的 Swift | WSS endpoint client | 无 |
| `webtransport-server` | Go | WebTransport direct server 与 opaque tunnel runtime | 无 |

机器可读的 native-server-core profile 包含 18 个聚合的运行时-角色-carrier tuple（每个原生运行时 6 个）和 24 个已支持的特定路径服务端单元；Go H4 另增加 2 个 WebTransport 服务端 tuple 和 2 个特定路径单元。互操作矩阵另行声明 18 个 direct cell 和 18 个 tunnel cell。发布门禁已验证所有包含 Go 的 10 个 direct cell 和 14 个两两 tunnel cell；其余 8 个 direct cell 和 4 个 tunnel cell 仍明确标记为未验证。另有 4 个 WSS 客户端 profile 验证 Swift 和浏览器 TypeScript 通过 direct 与 tunnel 路径连接 Go。profile 绝不会改变 Artifact、handshake、RPC、stream、close、rekey 或 authorization wire 语义。

请查看各 SDK 指南，了解每个包支持的平台和连接组合。

WebTransport 是可选能力，不属于必需的 native-server carrier 合同。Go 声明独立且完整的 H4 webtransport-server profile；Browser profile 在浏览器 WebTransport API 可用时使用 H3；Node.js 和 Rust 当前没有 production WebTransport adapter。Go、Rust 和 Node.js 的 native-server carrier 范围是 WebSocket 与 raw QUIC；两两互操作支持只由矩阵中标记 supported 的条目声明。

<!-- readme-section:security -->
<a id="security"></a>

## 安全

- 直连和中继会话中的应用数据都采用端到端加密。
- TLS 信任策略会绑定到每个 v3 传输候选项。公共或部署提供的 CA 根与显式叶证书 pin 互斥，失败后绝不降级。
- 连接邀请不透明、有效期短且只能使用一次。
- 凭据会在使用前完成核销，已消费的邀请无法重放。
- 中继只转发加密流量，不会终止应用会话。
- 无效或不受支持的连接尝试会安全失败，并只返回有限的公共错误信息。

协议与威胁模型详情请阅读 [API 契约](docs/API_CONTRACT.md)、[传输架构](docs/TRANSPORT_V3_ARCHITECTURE.md)和[威胁模型](docs/THREAT_MODEL.md)。

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 深入了解

- [API 契约](docs/API_CONTRACT.md)：各 SDK 共享的稳定应用行为。
- [错误模型](docs/ERROR_MODEL.md)：公共连接、会话和 RPC 错误。
- [传输架构](docs/TRANSPORT_V3_ARCHITECTURE.md)：直连与中继连接的设计。
- [示例](examples/README.md)：可运行的 SDK 用法。

Flowersec 采用 [MIT License](LICENSE)。已发布的软件包和版本说明可在 [GitHub Releases](https://github.com/floegence/flowersec/releases)中查看。
