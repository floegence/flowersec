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

raw QUIC 與 WebTransport 保留原生 FIN、RESET_STREAM、STOP_SENDING、流量控制及遷移行為。Flowersec 會停用應用層 0-RTT。可靠 Stream 絕不使用 QUIC DATAGRAM；Runtime 僅在協商出原生 DATAGRAM 支援後，才透過 Carrier 中立的不可靠訊息公開此能力。

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## 本機試用

執行 v2 單元測試套件：

```bash
make test
```

修正失敗後，使用 `make test-resume` 從第一個未完成的測試繼續執行，直到下一次失敗或顯示 `ALL GREEN`。即使原始碼 Commit 改變，已完成的測試 ID 仍然有效。

使用 `make coverage-race` 執行四種語言的覆蓋率工作以及獨占的 Go race 測試。使用 `make browser-smoke` 驗證三種本機 Chromium 拓撲，使用 `make browser-compat` 明確檢查 Firefox/WebKit 能力。需要特殊權限的弱網與 Kernel 診斷使用 `make diagnostic`；容量與 soak 測試使用 `make performance`。

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK 與 Cookbook

| 語言 | Package | 公開入口 |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.Connect`, `flowersec.NewConnectionController`, `flowersec.NewAcceptor` |
| TypeScript | `@floegence/flowersec-core` | Root、`/browser`、`/node` 與 `/proxy` 的不透明 v2 入口 |
| Swift | SwiftPM Product `Flowersec` | `Artifact`、`connect`、`Session` |
| Rust | Crate `flowersec` | `Artifact`、`connect`、`Session` |

Go 服務控制面使用獨立的 `github.com/floegence/flowersec/flowersec-go/v2/controlplane` 套件簽發 opaque artifact，並回應 `flowersec-runtime` 的授權 callback。

[Cookbook 索引](examples/README.md)僅收錄 v2 範例與驗證命令。

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## SDK 功能支援

下表按照應用程式開發者可以直接使用的功能劃分，而不是按照內部協定物件劃分。每個 SDK Profile 都會宣告其 Runtime 與平台特有的 Carrier 邊界。平台限制只有在 `stability/language_capabilities.json` 中記錄明確原因、替代公開邊界與可執行測試 ID 後，才能標示為不支援。Control Plane 持久化屬於服務邊界：Client 呼叫使用 `flowersec-go/v2/controlplane` 的已驗證服務，而不是內嵌第二套簽發器或資料儲存。語言便利能力可以配合特定語言生態的語法或編排方式，但不會改變這些共用工作流程。連線復原行為透過 Controller 的結構化處置結果回報。

| 能力 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| 端對端加密工作階段、RPC 與位元組串流 | 是 | 是 | 是 | 是 |
| 長連線自動復原 | 是 | 是 | 是 | 是 |
| 不可靠訊息 | 是 | 是 | 否 | 是 |
| 接收 RPC 通知 | 否 | 是 | 否 | 否 |
| 處理 Inbound RPC Request | 是 | 否 | 否 | 否 |
| WebSocket Client 連線 | 是 | Browser 與 Node.js | macOS 與 iOS | 否 |
| raw QUIC Client 連線 | 是 | 否 | 否 | 是 |
| WebTransport Client 連線 | 是 | Browser 與 Node.js | 否 | 否 |
| Server 端接收工作階段 | `NewAcceptor` | `createAcceptor` / `AcceptedSession` | Apple Listener Profile 不支援 | `Acceptor::bind` / `accept_with_handlers` |
| Control Plane 簽發 Artifact 與授權 | `flowersec-go/v2/controlplane` | 不支援；由應用服務負責 | 不支援；由應用服務負責 | 不支援；由應用服務負責 |

僅接受已宣告的 Carrier 組合；不支援的組合會 Fail Closed。每一列支援狀態都有生產級 Connector 程式碼和 `stability/language_capabilities.json` 中的明確測試 ID 作為依據；不支援的能力會提供原因與替代邊界。Capability Descriptor 與 Carrier 選擇機制均維持內部可見。

<!-- readme-section:security -->
<a id="security"></a>

## 安全

- Artifact 是不透明、有界且僅供單次使用的 Handle。Durable Spend 必須在傳送第一個 Credential Byte 前完成。
- QUIC 系 Carrier 要求 TLS 1.3、精確的 ALPN、明確的 Trust Root，並停用 Early Data。
- 公開錯誤會遮蔽敏感資訊且內容有界；Candidate、Wire、Key 與 Ledger 細節維持內部可見。
- 結構化 Controller 處置結果只允許使用全新 Artifact 再次嘗試；它絕不會重複使用 Credential，也不會重播已終止 Session 中的工作。
- Session 的取消、Deadline、FIN、Reset、Liveness、Rekey 與 Cleanup 行為均有明確邊界。

請參閱 [Transport v2 架構](docs/TRANSPORT_V2_ARCHITECTURE.md)與[威脅模型](docs/THREAT_MODEL.md)。

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 部署與開發

Flowersec Runtime 擁有 WebSocket、raw QUIC 與 WebTransport 的生產級 Listener 實作。應用程式 SDK 只會接收不透明的 Artifact 與 Session；Runtime CLI 使用相同的 Connector 與 Acceptor 實作。

安裝 Repository Hook，並在整合前執行正式 Gate：

```bash
make install-hooks
make precommit
```

`scripts/push-main.sh` 會先執行有界的本機驗收測試，再推送正確的 main SHA。完整工程檢查及明確的 nightly、diagnostic 與 performance 工作流程分別涵蓋相容性、特權診斷與負載測試；Release 本身不執行測試。

Flowersec 採用 [MIT License](LICENSE)。Release Artifact 透過 [GitHub Releases](https://github.com/floegence/flowersec/releases) 發布。
