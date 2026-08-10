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

<p align="center"><strong>构建安全的应用间连接，无需管理底层传输方式。</strong></p>
<p align="center">Flowersec 为 Go、TypeScript、Swift 和 Rust 提供统一的端到端加密会话模型，并内置 RPC、通知和字节流。</p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## 为什么选择 Flowersec

- 四种 SDK 共用同一套安全会话模型，应用可以复用相同的 RPC 和数据流工作流。
- 在支持的网络连接方式之间切换，无需为每种方式重写业务代码。
- RPC、通知和字节流统一运行在一条经过认证的端到端加密连接上。
- 即使经过中继，业务数据仍保持加密；中继只能转发密文。

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## 工作原理

| 路径 | 连接形态 | 数据流传输 |
| --- | --- | --- |
| Direct | 客户端通过兼容候选项连接端点 | WebSocket 使用单跳本地 Yamux；QUIC 系列 Carrier 使用原生双向数据流 |
| Tunnel | 客户端与服务端链路分别通过兼容 Carrier 接入 | Tunnel 在两条链路之间映射加密数据流，不选择主 Carrier |

raw QUIC 与 WebTransport 保留原生 FIN、RESET_STREAM、STOP_SENDING、流控和迁移语义。Flowersec 禁用应用层 0-RTT。可靠流绝不使用 QUIC DATAGRAM；运行时仅在协商出原生 DATAGRAM 支持后，才通过 Carrier 中立的不可靠消息公开该能力。

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## 本地试用

运行默认验收测试：

```bash
make test
```

修复失败后，使用 `make test-resume` 从首个未完成测试继续运行，直到下一次失败或显示 `ALL GREEN`。即使源代码提交发生变化，已完成的测试 ID 仍然有效。

使用 `make coverage-race` 运行四种语言的覆盖率任务以及独占的 Go race 测试。使用 `make browser-smoke` 验证三种本地 Chromium 拓扑，使用 `make browser-compat` 显式检查 Firefox/WebKit 能力。需要特权的弱网和内核诊断使用 `make diagnostic`；容量与 soak 测试使用 `make performance`。

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK 与 Cookbook

| 语言 | 软件包 | 公共入口 |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.Connect`, `flowersec.NewConnectionController`, `flowersec.NewAcceptor` |
| TypeScript | `@floegence/flowersec-core` | 根入口、`/browser`、`/node` 和 `/proxy` 不透明 v2 入口 |
| Swift | SwiftPM 产品 `Flowersec` | `Artifact`、`connect`、`Session` |
| Rust | crate `flowersec` | `Artifact`、`connect`、`Session` |

Go 服务控制面使用独立的 `github.com/floegence/flowersec/flowersec-go/v2/controlplane` 包签发 opaque artifact，并响应 `flowersec-runtime` 的授权回调。

[Cookbook 索引](examples/README.md)仅包含 v2 示例和验证命令。

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## SDK 能力

下表按应用开发者可以直接使用的功能划分，而不是按内部协议对象划分。每个 SDK 配置都会声明其运行时和平台特有的 Carrier 边界。平台限制只有在 `stability/language_capabilities.json` 中记录明确原因、替代公共边界和可执行测试 ID 后，才能标记为不支持。控制面持久化属于服务边界：客户端调用使用 `flowersec-go/v2/controlplane` 的认证服务，而不是嵌入第二套签发器或数据存储。语言便利能力可以适配某一语言生态的语法或编排方式，但不会改变这些共享工作流。连接恢复行为通过控制器的结构化处置结果报告。

| 能力 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| 端到端加密会话、RPC 与字节流 | 是 | 是 | 是 | 是 |
| 长连接自动恢复 | 是 | 是 | 是 | 是 |
| 不可靠消息 | 是 | 是 | 否 | 是 |
| 接收 RPC 通知 | 否 | 是 | 否 | 否 |
| 处理入站 RPC 请求 | 是 | 否 | 否 | 否 |
| WebSocket 客户端连接 | 是 | 浏览器与 Node.js | macOS 与 iOS | 否 |
| raw QUIC 客户端连接 | 是 | 否 | 否 | 是 |
| WebTransport 客户端连接 | 是 | 浏览器与 Node.js | 否 | 否 |
| 服务端接收会话 | `NewAcceptor` | `createAcceptor` / `AcceptedSession` | Apple Listener 配置不支持 | `Acceptor::bind` / `accept_with_handlers` |
| 控制面签发 Artifact 与授权 | `flowersec-go/v2/controlplane` | 不支持；由应用服务负责 | 不支持；由应用服务负责 | 不支持；由应用服务负责 |

只接受已声明的 Carrier 组合；不支持的组合会失败关闭。每一行支持状态都有生产级 Connector 代码和 `stability/language_capabilities.json` 中的显式测试 ID 作为依据；不支持的能力会给出原因和替代边界。能力描述符和 Carrier 选择逻辑始终属于内部实现。

<!-- readme-section:security -->
<a id="security"></a>

## 安全

- Artifact 是不透明、有界且单次使用的句柄。持久化核销必须在发送第一个凭据字节前完成。
- QUIC 系列 Carrier 要求 TLS 1.3、精确 ALPN、显式信任根，并禁用提前数据。
- 公共错误经过脱敏且有界；Candidate、Wire、Key 与 Ledger 细节保持内部可见。
- 结构化控制器处置结果只允许使用全新 Artifact 再次尝试；它绝不会复用凭据，也不会重放已终止 Session 中的工作。
- Session 的取消、截止时间、FIN、重置、活性检测、密钥轮换和资源清理均有明确边界。

请参阅 [Transport v2 架构](docs/TRANSPORT_V2_ARCHITECTURE.md)和[威胁模型](docs/THREAT_MODEL.md)。

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 部署与开发

Flowersec 运行时负责 WebSocket、raw QUIC 和 WebTransport 的生产级监听器实现。应用 SDK 只接收不透明的 Artifact 和 Session；运行时 CLI 使用相同的 Connector 与 Acceptor 实现。

安装仓库 Hook，并在集成前运行权威门禁：

```bash
make install-hooks
make precommit
```

`scripts/push-main.sh` 会先运行有界的本地验收测试，再推送准确的 main SHA。完整工程检查以及显式的 nightly、diagnostic 和 performance 工作流分别覆盖兼容性、特权诊断和负载测试；发布流程本身不运行测试。

Flowersec 采用 [MIT License](LICENSE)。发布制品通过 [GitHub Releases](https://github.com/floegence/flowersec/releases) 提供。
