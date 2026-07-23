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

<p align="center"><strong>Go、TypeScript、Swift、Rust に対応する、Carrier に依存しないエンドツーエンド暗号化セッション。</strong></p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Flowersec を選ぶ理由

- 4 つの SDK で、単一の不透明な Artifact と Session の契約を共有します。
- WebSocket、raw QUIC、WebTransport は同等の Carrier 候補です。
- RPC とバイトストリームは 1 つの認証済み Session を共有し、Carrier、Wire、Key、Ledger オブジェクトをアプリケーションへ公開しません。
- Tunnel Relay はアプリケーションの暗号化を終端せず、暗号化された Stream を転送します。

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## 仕組み

| 経路 | 接続形態 | Stream トランスポート |
| --- | --- | --- |
| Direct | Client が互換性のある候補を使用して Endpoint に接続 | WebSocket は Hop-local Yamux、QUIC 系 Carrier はネイティブの双方向 Stream を使用 |
| Tunnel | Client Leg と Server Leg がそれぞれ独立に選択した互換性のある Carrier を介して接続 | Tunnel は主 Carrier を選ばず、Leg 間で暗号化 Stream を対応付け |

raw QUIC と WebTransport は、ネイティブの FIN、RESET_STREAM、STOP_SENDING、フロー制御、マイグレーション動作を維持します。Flowersec はアプリケーション 0-RTT を無効化し、QUIC DATAGRAM を使用しません。

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## ローカルで試す

v2 ユニットスイートを実行します。

```bash
make transport-v2-unit
```

Carrier ごとの検証には、`make transport-conformance-smoke`、`make transport-browser-smoke`、`make transport-interop-smoke` を実行してください。

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK と Cookbook

| 言語 | パッケージ | 公開エントリ |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.NewConnector` |
| TypeScript | `@floegence/flowersec-core` | ルート、`/browser`、`/node` の不透明な v2 エントリポイント |
| Swift | SwiftPM プロダクト `Flowersec` | `ArtifactV2`、`ConnectorV2`、`SessionV2` |
| Rust | crate `flowersec` | `Artifact`、`Connector`、`Session` |

[Cookbook インデックス](examples/README.md)には、v2 の例と検証コマンドだけが含まれます。

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## ポータブル契約

| 機能 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| 不透明な Artifact、Connector、Session、RPC、バイトストリーム | 対応 | 対応 | 対応 | 対応 |
| 本番 WebSocket Dial | 対応 | Browser と Node.js | macOS | 非対応 |
| 本番 raw QUIC Dial | 対応 | 非対応 | 非対応 | 対応 |
| 本番 WebTransport Dial | 対応 | Browser | 非対応 | 非対応 |
| Listener 対応 | Go ライブラリ API | Browser Runtime の制約あり | 非公開 | 非公開 |

各対応項目は、本番用 Connector コードとエンドツーエンドテストによって裏付けられています。非対応の Carrier は Fail Closed となり、暗黙のフォールバックにはなりません。Capability Descriptor と Carrier の選択は内部に留まります。

<!-- readme-section:security -->
<a id="security"></a>

## セキュリティ

- Artifact は不透明でサイズ制限があり、1 回だけ使える Handle です。認証情報の最初のバイトを送信する前に Durable Spend を完了します。
- QUIC 系 Carrier は TLS 1.3、完全一致する ALPN、明示的な Trust Root、Early Data の無効化を必須とします。
- 公開エラーは秘匿化され、サイズも制限されます。Candidate、Wire、Key、Ledger の詳細は内部に留まります。
- Session のキャンセル、Deadline、FIN、Reset、Liveness、Rekey、Cleanup はすべて境界が定義されています。

[Transport v2 アーキテクチャ](docs/TRANSPORT_V2_ARCHITECTURE.md)と[脅威モデル](docs/THREAT_MODEL.md)を参照してください。

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## デプロイと開発

Flowersec Runtime が、WebSocket、raw QUIC、WebTransport の本番用 Listener 実装を担います。アプリケーション SDK に渡されるのは不透明な Artifact と Session だけであり、削除済みの互換 CLI は v2 契約に含まれません。

リポジトリの Hook をインストールし、統合前に正式な品質ゲートを実行します。

```bash
make install-hooks
make check
```

Flowersec は [MIT License](LICENSE) で提供されます。リリース成果物は [GitHub Releases](https://github.com/floegence/flowersec/releases) で公開されます。
