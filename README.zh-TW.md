# Flowersec

<!-- readme-locales:start -->
<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh-CN.md">简体中文</a> |
  <strong>繁體中文</strong> |
  <a href="README.ja-JP.md">日本語</a> |
  <a href="README.ko-KR.md">한국어</a> |
  <a href="README.de-DE.md">Deutsch</a> |
  <a href="README.fr-FR.md">Français</a> |
  <a href="README.es-ES.md">Español</a> |
  <a href="README.pt-BR.md">Português do Brasil</a> |
  <a href="README.ru-RU.md">Русский</a>
</p>
<!-- readme-locales:end -->

<p align="center"><strong>適用於 Go、TypeScript、Swift 與 Rust 的 Carrier 中立端對端加密工作階段。</strong></p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## 為什麼選擇 Flowersec

- 四種 SDK 共用一套不透明的 Artifact 與 Session 契約。
- WebSocket、raw QUIC 與 WebTransport 是同等的 Carrier 候選。
- RPC 與位元組 Stream 共用一個已驗證的 Session，且不向應用程式暴露 Carrier、Wire、Key 或 Ledger 物件。
- Tunnel Relay 會轉送加密 Stream，但不會終止應用層加密。

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## 運作方式

| 路徑 | 連線形態 | Stream 傳輸 |
| --- | --- | --- |
| Direct | Client 使用相容的候選項目連線至 Endpoint | WebSocket 使用 Hop-local Yamux；QUIC 系 Carrier 使用原生雙向 Stream |
| Tunnel | Client 與 Server 兩端各自選擇相容的 Carrier 接入 | Tunnel 在兩端之間對應加密 Stream，不指定主要 Carrier |

raw QUIC 與 WebTransport 保留原生 FIN、RESET_STREAM、STOP_SENDING、流量控制及遷移行為。Flowersec 會停用應用層 0-RTT，且不使用 QUIC DATAGRAM。

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## 本機試用

執行 v2 單元測試套件：

```bash
make transport-v2-unit
```

如需 Carrier 專項證據，請執行 `make transport-conformance-smoke`、`make transport-browser-smoke` 與 `make transport-interop-smoke`。

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK 與 Cookbook

| 語言 | Package | 公開入口 |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.NewConnector` |
| TypeScript | `@floegence/flowersec-core` | Root、`/browser` 與 `/node` 的不透明 v2 入口 |
| Swift | SwiftPM Product `Flowersec` | `ArtifactV2`、`ConnectorV2`、`SessionV2` |
| Rust | Crate `flowersec` | `Artifact`、`Connector`、`Session` |

[Cookbook 索引](examples/README.md)僅收錄 v2 範例與驗證命令。

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## 可攜式契約

| 能力 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| 不透明 Artifact、Connector、Session、RPC 與位元組串流 | 支援 | 支援 | 支援 | 支援 |
| 生產級 WebSocket 撥號 | 支援 | Browser 與 Node.js | macOS | 不支援 |
| 生產級 raw QUIC 撥號 | 支援 | 不支援 | 不支援 | 支援 |
| 生產級 WebTransport 撥號 | 支援 | Browser | 不支援 | 不支援 |
| Listener 支援 | Go Library API | 受 Browser Runtime 限制 | 不宣告支援 | 不宣告支援 |

每一列支援項目都有生產級 Connector 程式碼與端對端測試作為佐證。不支援的 Carrier 會 Fail Closed，絕不會成為靜默回退。Capability Descriptor 與 Carrier 選擇機制均維持內部可見。

<!-- readme-section:security -->
<a id="security"></a>

## 安全

- Artifact 是不透明、有界且僅供單次使用的 Handle。Durable Spend 必須在傳送第一個 Credential Byte 前完成。
- QUIC 系 Carrier 要求 TLS 1.3、精確的 ALPN、明確的 Trust Root，並停用 Early Data。
- 公開錯誤會遮蔽敏感資訊且內容有界；Candidate、Wire、Key 與 Ledger 細節維持內部可見。
- Session 的取消、Deadline、FIN、Reset、Liveness、Rekey 與 Cleanup 行為均有明確邊界。

請參閱 [Transport v2 架構](docs/TRANSPORT_V2_ARCHITECTURE.md)與[威脅模型](docs/THREAT_MODEL.md)。

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 部署與開發

Flowersec Runtime 擁有 WebSocket、raw QUIC 與 WebTransport 的生產級 Listener 實作。應用程式 SDK 只會接收不透明的 Artifact 與 Session；任何已移除的相容性 CLI 都不屬於 v2 契約。

安裝 Repository Hook，並在整合前執行正式 Gate：

```bash
make install-hooks
make check
```

Flowersec 採用 [MIT License](LICENSE)。Release Artifact 透過 [GitHub Releases](https://github.com/floegence/flowersec/releases) 發布。
