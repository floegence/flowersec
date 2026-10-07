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

从 [Cookbook 索引](examples/README.md)开始，里面的示例使用与生产应用相同的公共 API，涵盖客户端连接、由 Go 控制面签发 v4 连接邀请、持久化单次使用处理、活性探测和会话生命周期。

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## 应用可以做什么

四种 SDK 共享一致的会话模型；当某个平台无法提供特定连接方式时，支持范围会有所不同。

<!-- capability-table:start -->
| 应用能力 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| 不透明、单次使用的连接邀请 | 是 | 是 | 是 | 是 |
| 一次性安全连接 | 是 | 是 | 是 | 是 |
| 端到端加密会话 | 是 | 是 | 是 | 是 |
| RPC 调用与通知 | 是 | 是 | 是 | 是 |
| 经过验证的流元数据 | 是 | 是 | 是 | 是 |
| 应用流处理器 | 是 | 是 | 是 | 是 |
| 长连接自动恢复 | 是 | 是 | 是 | 是 |
| 协商后的不可靠消息 | 是 | 是 | 否 | 是 |
| 客户端 RPC 处理器 | 是 | 是 | 是 | 是 |
| 服务端会话接收 | 是 | 是 | 是 | 是 |
| 服务端会话处理器 | 是 | 是 | 是 | 是 |
| 控制面签发与授权 | 是 | 否 | 否 | 否 |
| 直连与隧道准入 | 是 | 是 | 是 | 是 |
| HTTP 和 WebSocket ProxyServer | 是 | 是 | 否 | 是 |
| 与载体无关的流合同 | 是 | 是 | 是 | 是 |
| Transport v4 线协议安全 | 是 | 是 | 是 | 是 |
<!-- capability-table:end -->

部署 profile 描述所需的原生或浏览器载体与角色组合。各 SDK 指南分别说明当前 API 和 provider 资格；源码声明不等于运行验证通过。

当前协议使用经过认证的连接材料、独立命名空间信任、有界会话、类型化服务和显式清理。直连及隧道互操作由可执行矩阵和原 provider 验证。发布只进行包发布与仓库回读，不运行验收测试。

WebTransport 需要配置原生或浏览器 provider。浏览器支持取决于实际 WebTransport API 和证书策略能力。当前载体、监听和中继范围请参阅各 SDK 指南。

签名的 `local_loopback` 接入类支持同一机器上经过应用鉴权的 HTTP 桥。它使用当前会话协议，并要求配置本地 provider。

<!-- readme-section:security -->
<a id="security"></a>

## 安全

- 直连和中继会话中的应用数据都采用端到端加密。
- TLS 信任策略会绑定到每个 v4 传输候选项。公共或部署提供的 CA 根与显式叶证书 pin 互斥，失败后绝不降级。
- `local_loopback` 接入类仅允许签名数字回环端点使用 `ws://`，并要求精确 Origin 和 upgrade 前的应用鉴权。它不声明外层 TLS 验证能力，也不允许明文回退。
- 连接邀请不透明、有效期短且只能使用一次。
- 凭据会在使用前完成核销，已消费的邀请无法重放。
- 中继只转发加密流量，不会终止应用会话。
- 无效或不受支持的连接尝试会安全失败，并只返回有限的公共错误信息。

协议与威胁模型详情请阅读 [API 契约](docs/API_CONTRACT.md)、[传输架构](docs/TRANSPORT_V4_BINDING.md)和[威胁模型](docs/THREAT_MODEL.md)。

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 深入了解

- [API 契约](docs/API_CONTRACT.md)：各 SDK 共享的稳定应用行为。
- [错误模型](docs/ERROR_MODEL.md)：公共连接、会话和 RPC 错误。
- [传输架构](docs/TRANSPORT_V4_BINDING.md)：直连与中继连接的设计。
- [示例](examples/README.md)：可运行的 SDK 用法。

Flowersec 采用 [MIT License](LICENSE)。已发布的软件包和版本说明可在 [GitHub Releases](https://github.com/floegence/flowersec/releases)中查看。
