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

<p align="center"><strong>無論應用程式在哪裡執行，都能安全地彼此連線。</strong></p>
<p align="center">Flowersec 為 Go、TypeScript、Swift 與 Rust 提供一套簡單 API，用於端對端加密工作階段、RPC、通知與位元組串流。</p>

[![最新版本](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![授權條款](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## 為什麼選擇 Flowersec

Flowersec 適合需要在用戶端、服務與裝置之間建立私密連線，又不希望業務程式碼受網路傳輸細節限制的應用程式。

- **一套程式設計模型：** Go、TypeScript、Swift 與 Rust 使用相同的驗證工作階段 API。
- **直接提供應用所需能力：** 在同一條連線中進行 RPC、傳送通知並傳輸可靠位元組串流。
- **適應不同網路：** 可直連時直接連線，需要時經由中繼，無須改寫應用協定。
- **預設保護隱私：** 應用資料始終端對端加密；中繼只能轉送，無法讀取內容。

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## 運作方式

Flowersec 將應用工作階段與承載它的網路路徑分離：

1. 服務建立一份短期連線邀請並交給用戶端。
2. SDK 透過可用的直連或中繼路徑建立安全工作階段。
3. 應用程式透過同一套工作階段 API 使用 RPC、通知與位元組串流。

無論直連或中繼，業務程式碼取得的都是同一種工作階段。連線選擇、憑證與路由由 SDK 和執行環境在內部處理。

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## 開始建置

選擇符合應用場景的 SDK：

| SDK | 適用場景 | 安裝與 API 指南 |
| --- | --- | --- |
| Go | 服務、閘道與控制面程式碼 | [Go SDK](flowersec-go/README.md) |
| TypeScript | 瀏覽器與 Node.js 應用程式 | [TypeScript SDK](flowersec-ts/README.md) |
| Swift | macOS 與 iOS 用戶端 | [Swift SDK](flowersec-swift/README.md) |
| Rust | 需要原生 QUIC 的 Tokio 服務 | [Rust SDK](flowersec-rust/README.md) |

[Cookbook 索引](examples/README.md)提供每種 SDK 的小型可執行範例，涵蓋用戶端連線、持久化單次使用、控制面簽發、活性探測與工作階段生命週期。

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## 範例

從 [Cookbook 索引](examples/README.md)開始，其中的範例使用與正式應用相同的公開 API，涵蓋用戶端連線、控制面簽發連線邀請、持久化單次使用處理、活性探測與工作階段生命週期。

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## 應用程式可以做什麼

四種 SDK 共用一致的工作階段模型；當平台無法提供特定連線方式時，支援範圍會有所不同。

| 應用能力 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| 端對端加密工作階段 | 是 | 是 | 是 | 是 |
| 傳送 RPC 呼叫與通知 | 是 | 是 | 是 | 是 |
| 接收 RPC 通知 | 是 | 是 | 是 | 是 |
| 可靠位元組串流 | 是 | 是 | 是 | 是 |
| 在任意工作階段上處理應用程式串流 | 是 | 是 | 是 | 是 |
| 長連線自動恢復 | 是 | 是 | 是 | 是 |
| 條件允許時傳送不可靠訊息 | 是 | 是 | 否 | 是 |
| 瀏覽器連線 | 否 | 是 | 否 | 否 |
| Apple 用戶端連線 | 否 | 否 | 是 | 否 |
| 原生 QUIC 連線 | 是 | Node.js | 否 | 是 |
| WebSocket 連線 | 是 | 是 | 是 | 是 |
| WebTransport 連線 | Go H4 | Browser H3 client（瀏覽器 API 可用時） | 否 | 否 |
| 伺服器端接收工作階段 | 是 | Node.js | 否 | 是 |
| 不透明中繼執行時 | 是 | Node.js | 否 | 是 |
| 控制面簽發連線邀請 | 是 | 否 | 否 | 否 |
| HTTP 與 WebSocket ProxyServer | 是 | Node.js | 否 | 是 |

部署 profile 將平台可用性與共享的 Flowersec 應用協定分離：

| Profile | 執行環境 | 必要的 carrier 與角色範圍 | 選用範圍 |
| --- | --- | --- | --- |
| `native-server-core` | Go、Rust、Node.js | WebSocket 和 raw QUIC endpoint client、direct server 與 opaque tunnel runtime | WebTransport adapter |
| `browser-client` | TypeScript browser | WebSocket endpoint client | Browser WebTransport adapter |
| `apple-client` | Apple 平台上的 Swift | WSS endpoint client | 無 |
| `webtransport-server` | Go | WebTransport direct server 與 opaque tunnel runtime | 無 |

機器可讀的 native-server-core profile 包含 18 個彙總的執行環境-角色-carrier tuple（每個原生執行環境 6 個）和 24 個已支援的特定路徑伺服器單元；Go H4 另增加 2 個 WebTransport 伺服器 tuple 和 2 個特定路徑單元。互通矩陣另行宣告 18 個 direct cell 和 18 個 tunnel cell。發佈門檻已驗證所有包含 Go 的 10 個 direct cell 和 14 個兩兩 tunnel cell；其餘 8 個 direct cell 和 4 個 tunnel cell 仍明確標記為未驗證。另有 4 個 WSS 用戶端 profile 驗證 Swift 和瀏覽器 TypeScript 經由 direct 與 tunnel 路徑連接 Go。profile 絕不會改變 Artifact、handshake、RPC、stream、close、rekey 或 authorization wire 語意。

請參閱各 SDK 指南，了解每個套件支援的平台與連線組合。

WebTransport 是選用能力，不屬於必要的 native-server carrier 合約。Go 宣告獨立且完整的 H4 webtransport-server profile；Browser profile 會在瀏覽器 WebTransport API 可用時使用 H3；Node.js 與 Rust 目前沒有 production WebTransport adapter。Go、Rust 與 Node.js 的 native-server carrier 範圍是 WebSocket 與 raw QUIC；兩兩互通支援只由矩陣中標記 supported 的項目宣告。

<!-- readme-section:security -->
<a id="security"></a>

## 安全性

- 直連與中繼工作階段中的應用資料都採用端對端加密。
- TLS 信任原則會綁定至每個 v3 傳輸候選項。公開或部署提供的 CA 根與明確的葉憑證 pin 互斥，失敗後絕不降級。
- 連線邀請不透明、有效期短且只能使用一次。
- 憑證會在使用前完成核銷，已使用的邀請無法重播。
- 中繼只轉送加密流量，不會終止應用工作階段。
- 無效或不支援的連線嘗試會安全失敗，且只回傳有限的公開錯誤資訊。

協定與威脅模型詳情請閱讀 [API 契約](docs/API_CONTRACT.md)、[傳輸架構](docs/TRANSPORT_V3_ARCHITECTURE.md)與[威脅模型](docs/THREAT_MODEL.md)。

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 深入了解

- [API 契約](docs/API_CONTRACT.md)：各 SDK 共用的穩定應用行為。
- [錯誤模型](docs/ERROR_MODEL.md)：公開的連線、工作階段與 RPC 錯誤。
- [傳輸架構](docs/TRANSPORT_V3_ARCHITECTURE.md)：直連與中繼連線設計。
- [範例](examples/README.md)：可執行的 SDK 用法。

Flowersec 採用 [MIT License](LICENSE)。已發布的套件與版本說明可在 [GitHub Releases](https://github.com/floegence/flowersec/releases)查看。
