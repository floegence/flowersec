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

[Cookbook 索引](examples/README.md)提供每种 SDK 的小型可运行示例，覆盖直连、中继、服务端接收会话和 RPC。

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## 示例

从 [Cookbook 索引](examples/README.md)开始，里面的示例使用与生产应用相同的公共 API，涵盖客户端连接、控制面签发连接邀请、持久化单次使用处理和会话生命周期。

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## 应用可以做什么

四种 SDK 共享一致的会话模型；当某个平台无法提供特定连接方式时，支持范围会有所不同。

| 应用能力 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| 端到端加密会话 | 是 | 是 | 是 | 是 |
| 发送 RPC 调用和通知 | 是 | 是 | 是 | 是 |
| 接收 RPC 通知 | 否 | 是 | 否 | 否 |
| 可靠字节流 | 是 | 是 | 是 | 是 |
| 长连接自动恢复 | 是 | 是 | 是 | 是 |
| 条件允许时发送不可靠消息 | 是 | 是 | 否 | 是 |
| 浏览器连接 | 否 | 是 | 否 | 否 |
| Apple 客户端连接 | 否 | 否 | 是 | 否 |
| 原生 QUIC 连接 | 是 | 否 | 否 | 是 |
| WebSocket 连接 | 是 | 是 | 是 | 否 |
| WebTransport 连接 | 是 | 是 | 否 | 否 |
| 服务端接收会话 | 是 | Node.js | 否 | 是 |
| 控制面签发连接邀请 | Go 包 | 由应用服务负责 | 由应用服务负责 | 由应用服务负责 |

请查看各 SDK 指南，了解每个包支持的平台和连接组合。

<!-- readme-section:security -->
<a id="security"></a>

## 安全

- 直连和中继会话中的应用数据都采用端到端加密。
- 连接邀请不透明、有效期短且只能使用一次。
- 凭据会在使用前完成核销，已消费的邀请无法重放。
- 中继只转发加密流量，不会终止应用会话。
- 无效或不受支持的连接尝试会安全失败，并只返回有限的公共错误信息。

协议与威胁模型详情请阅读 [API 契约](docs/API_CONTRACT.md)、[传输架构](docs/TRANSPORT_V2_ARCHITECTURE.md)和[威胁模型](docs/THREAT_MODEL.md)。

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 深入了解

- [API 契约](docs/API_CONTRACT.md)：各 SDK 共享的稳定应用行为。
- [错误模型](docs/ERROR_MODEL.md)：公共连接、会话和 RPC 错误。
- [传输架构](docs/TRANSPORT_V2_ARCHITECTURE.md)：直连与中继连接的设计。
- [示例](examples/README.md)：可运行的 SDK 用法。

Flowersec 采用 [MIT License](LICENSE)。已发布的软件包和版本说明可在 [GitHub Releases](https://github.com/floegence/flowersec/releases)中查看。
