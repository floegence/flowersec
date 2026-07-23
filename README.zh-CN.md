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

<p align="center"><strong>面向 Go、TypeScript、Swift 和 Rust 的 Carrier 中立端到端加密会话。</strong></p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## 为什么选择 Flowersec

- 四种 SDK 共用一套不透明 Artifact 与 Session 契约。
- WebSocket、raw QUIC 和 WebTransport 是同等的 Carrier 候选。
- RPC 与字节流共享一个经过认证的 Session，应用无需接触 Carrier、Wire、Key 或 Ledger 对象。
- Tunnel 中继只转发加密数据流，不终止应用层加密。

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## 工作原理

| 路径 | 连接形态 | 数据流传输 |
| --- | --- | --- |
| Direct | 客户端通过兼容候选项连接端点 | WebSocket 使用单跳本地 Yamux；QUIC 系列 Carrier 使用原生双向数据流 |
| Tunnel | 客户端与服务端链路分别通过兼容 Carrier 接入 | Tunnel 在两条链路之间映射加密数据流，不选择主 Carrier |

raw QUIC 与 WebTransport 保留原生 FIN、RESET_STREAM、STOP_SENDING、流控和迁移语义。Flowersec 禁用应用层 0-RTT，且不使用 QUIC DATAGRAM。

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## 本地试用

运行 v2 单元测试：

```bash
make transport-v2-unit
```

如需验证特定 Carrier，请运行 `make transport-conformance-smoke`、`make transport-browser-smoke` 和 `make transport-interop-smoke`。

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK 与 Cookbook

| 语言 | 软件包 | 公共入口 |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.NewConnector` |
| TypeScript | `@floegence/flowersec-core` | 根入口、`/browser` 和 `/node` 不透明 v2 入口 |
| Swift | SwiftPM 产品 `Flowersec` | `ArtifactV2`、`ConnectorV2`、`SessionV2` |
| Rust | crate `flowersec` | `Artifact`、`Connector`、`Session` |

[Cookbook 索引](examples/README.md)仅包含 v2 示例和验证命令。

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## 可移植契约

| 能力 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| 不透明 Artifact、Connector、Session、RPC 与字节流 | 支持 | 支持 | 支持 | 支持 |
| 生产级 WebSocket 拨号 | 支持 | 浏览器与 Node.js | macOS | 不支持 |
| 生产级 raw QUIC 拨号 | 支持 | 不支持 | 不支持 | 支持 |
| 生产级 WebTransport 拨号 | 支持 | 浏览器 | 不支持 | 不支持 |
| 监听器支持 | Go 库 API | 受浏览器运行时限制 | 不对外声明 | 不对外声明 |

表中每项支持均由生产级 Connector 代码和端到端测试提供证据。不支持的 Carrier 会失败关闭，绝不会成为静默回退；能力描述符和 Carrier 选择逻辑均为内部实现细节。

<!-- readme-section:security -->
<a id="security"></a>

## 安全

- Artifact 是不透明、有界且单次使用的句柄。持久化核销必须在发送第一个凭据字节前完成。
- QUIC 系列 Carrier 要求 TLS 1.3、精确 ALPN、显式信任根，并禁用提前数据。
- 公共错误经过脱敏且有界；Candidate、Wire、Key 与 Ledger 细节保持内部可见。
- Session 的取消、截止时间、FIN、重置、活性检测、密钥轮换和资源清理均有明确边界。

请参阅 [Transport v2 架构](docs/TRANSPORT_V2_ARCHITECTURE.md)和[威胁模型](docs/THREAT_MODEL.md)。

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 部署与开发

Flowersec 运行时负责 WebSocket、raw QUIC 和 WebTransport 的生产级监听器实现。应用 SDK 只接收不透明的 Artifact 和 Session；任何已移除的兼容 CLI 都不属于 v2 契约。

安装仓库 Hook，并在集成前运行权威门禁：

```bash
make install-hooks
make check
```

Flowersec 采用 [MIT License](LICENSE)。发布制品通过 [GitHub Releases](https://github.com/floegence/flowersec/releases) 提供。
