# Flowersec

<!-- readme-locales:start -->
<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh-CN.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <strong>日本語</strong> |
  <a href="README.ko-KR.md">한국어</a> |
  <a href="README.de-DE.md">Deutsch</a> |
  <a href="README.fr-FR.md">Français</a> |
  <a href="README.es-ES.md">Español</a> |
  <a href="README.pt-BR.md">Português do Brasil</a> |
  <a href="README.ru-RU.md">Русский</a>
</p>
<!-- readme-locales:end -->

<p align="center"><strong>アプリがどこで動いていても、安全につなげます。</strong></p>
<p align="center">Flowersec は Go、TypeScript、Swift、Rust に、エンドツーエンド暗号化セッション、RPC、通知、Byte Stream のためのシンプルな共通 API を提供します。</p>

[![最新リリース](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![ライセンス](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Flowersec を選ぶ理由

Flowersec は、ネットワーク処理をアプリケーションコードに持ち込まず、クライアント、サービス、デバイス間を安全につなぎたいアプリケーション向けです。

- **1 つのプログラミングモデル：** Go、TypeScript、Swift、Rust で同じ認証済みセッション API を利用できます。
- **アプリに必要な機能：** 1 つの接続で RPC、通知、信頼性のある Byte Stream を扱えます。
- **ネットワークに合う接続：** 可能なら直接接続し、必要ならリレーを経由します。アプリケーションプロトコルの書き換えは不要です。
- **プライバシーを標準装備：** アプリケーションデータは常にエンドツーエンドで暗号化され、リレーは内容を読めません。

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## 仕組み

Flowersec はアプリケーションセッションを、それを運ぶネットワーク経路から分離します。

1. サービスが短期間だけ有効な接続招待を作り、クライアントへ渡します。
2. SDK が利用可能な直接接続またはリレー接続で安全なセッションを確立します。
3. アプリケーションは同じセッション API から RPC、通知、Byte Stream を利用します。

直接接続でもリレー接続でも、コードが扱うセッションは同じです。接続方式の選択、認証情報、ルーティングは SDK と Runtime の内部に保たれます。

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## 開発を始める

アプリケーションに合う SDK を選んでください。

| SDK | 主な用途 | インストールと API ガイド |
| --- | --- | --- |
| Go | サービス、ゲートウェイ、コントロールプレーン | [Go SDK](flowersec-go/README.md) |
| TypeScript | ブラウザおよび Node.js アプリケーション | [TypeScript SDK](flowersec-ts/README.md) |
| Swift | macOS および iOS クライアント | [Swift SDK](flowersec-swift/README.md) |
| Rust | ネイティブ QUIC が必要な Tokio サービス | [Rust SDK](flowersec-rust/README.md) |

[Cookbook 一覧](examples/README.md)には、各 SDK のクライアント接続、永続的な一回限りの使用、コントロールプレーンによる発行、liveness、セッションのライフサイクルを扱う小さな実行可能サンプルがあります。

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## サンプル

まず [Cookbook 一覧](examples/README.md)をご覧ください。本番アプリケーションと同じ公開 API を使い、クライアント接続、接続招待の発行、永続的な一回限りの処理、liveness、セッションのライフサイクルを示します。

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## アプリでできること

4 つの SDK は同じセッションモデルを共有します。特定の接続方式を提供できないプラットフォームでは、対応範囲が異なります。

| アプリケーション機能 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| エンドツーエンド暗号化セッション | 対応 | 対応 | 対応 | 対応 |
| RPC 呼び出しと通知の送信 | 対応 | 対応 | 対応 | 対応 |
| RPC 通知の受信 | 対応 | 対応 | 対応 | 対応 |
| 信頼性のある Byte Stream | 対応 | 対応 | 対応 | 対応 |
| 任意のセッションでアプリケーションストリームを処理 | 対応 | 対応 | 対応 | 対応 |
| 長時間接続の自動復旧 | 対応 | 対応 | 対応 | 対応 |
| 利用可能な場合の非信頼メッセージ | 対応 | 対応 | 非対応 | 対応 |
| ブラウザ接続 | 非対応 | 対応 | 非対応 | 非対応 |
| Apple クライアント接続 | 非対応 | 非対応 | 対応 | 非対応 |
| ネイティブ QUIC 接続 | 対応 | Node.js | 非対応 | 対応 |
| WebSocket 接続 | 対応 | 対応 | 対応 | 対応 |
| WebTransport 接続 | Go H4 | Browser H3 client（ブラウザー API が利用可能な場合） | 非対応 | 非対応 |
| サーバー側のセッション受け入れ | 対応 | Node.js | 非対応 | 対応 |
| 不透明リレーランタイム | 対応 | Node.js | 非対応 | 対応 |
| コントロールプレーンでの接続招待発行 | 対応 | 非対応 | 非対応 | 非対応 |
| HTTP と WebSocket ProxyServer | 対応 | Node.js | 非対応 | 対応 |

デプロイ profile は、プラットフォームでの利用可否と共通の Flowersec アプリケーションプロトコルを分離します。

| Profile | ランタイム | 必須の carrier と role | オプション |
| --- | --- | --- | --- |
| `native-server-core` | Go、Rust、Node.js | WebSocket と raw QUIC の endpoint client、direct server、opaque tunnel runtime | WebTransport adapter |
| `browser-client` | TypeScript browser | WebSocket endpoint client | Browser WebTransport adapter |
| `apple-client` | Apple プラットフォームの Swift | WSS endpoint client | なし |
| `webtransport-server` | Go | WebTransport direct server と opaque tunnel runtime | なし |

機械可読な native-server-core profile には、native runtime ごとに 6 個、合計 18 個の集約 runtime-role-carrier tuple と、対応済みの path 固有 server unit 24 個があります。Go H4 は、WebTransport server tuple 2 個と path 固有 unit 2 個を追加します。interoperability matrix は direct cell 18 個と tunnel cell 18 個を別に宣言します。release gate は Go を含む direct cell 10 個と pairwise tunnel cell 14 個をすべて検証し、残る direct cell 8 個と tunnel cell 4 個は明示的に未検証です。さらに 4 個の WSS client profile が、Swift と browser TypeScript から Go への direct および tunnel path を検証します。profile が Artifact、handshake、RPC、stream、close、rekey、authorization の wire semantics を変更することはありません。

各パッケージが対応するプラットフォームと接続方式の組み合わせは、SDK ガイドで確認してください。

WebTransport は必須の native-server carrier contract に含まれないオプションの adapter です。Go は独立した完全な H4 webtransport-server profile を宣言し、Browser profile はブラウザーの WebTransport API が利用可能な場合に H3 を使用します。Node.js と Rust は現在 production WebTransport adapter を提供しません。Go、Rust、Node.js の native-server carrier surface は WebSocket と raw QUIC であり、pairwise interoperability は matrix の supported entry だけが宣言します。

<!-- readme-section:security -->
<a id="security"></a>

## セキュリティ

- 直接接続とリレー接続のどちらでも、アプリケーションデータはエンドツーエンドで暗号化されます。
- TLS 信頼ポリシーは各 v3 トランスポート候補に結び付けられます。公開またはデプロイ提供の CA ルートと明示的なリーフ証明書 pin は排他的で、失敗後に降格しません。
- 接続招待は不透明で、有効期間が短く、1 回だけ使用できます。
- 認証情報は使用前に消費済みとして確定されるため、使用済み招待は再利用できません。
- リレーは暗号化トラフィックだけを転送し、アプリケーションセッションを終端しません。
- 無効または未対応の接続は安全に失敗し、公開エラーの情報量は制限されます。

プロトコルと脅威モデルの詳細は、[API コントラクト](docs/API_CONTRACT.md)、[トランスポートアーキテクチャ](docs/TRANSPORT_V3_ARCHITECTURE.md)、[脅威モデル](docs/THREAT_MODEL.md)を参照してください。

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 詳細情報

- [API コントラクト](docs/API_CONTRACT.md)：SDK 間で共有される安定したアプリケーション動作。
- [エラーモデル](docs/ERROR_MODEL.md)：公開される接続、セッション、RPC エラー。
- [トランスポートアーキテクチャ](docs/TRANSPORT_V3_ARCHITECTURE.md)：直接接続とリレー接続の設計。
- [サンプル](examples/README.md)：実行可能な SDK の使用例。

Flowersec は [MIT License](LICENSE) で提供されます。公開済みパッケージとリリースノートは [GitHub Releases](https://github.com/floegence/flowersec/releases)で確認できます。
