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

<p align="center"><strong>トランスポートを管理せず、安全なアプリ間接続を構築できます。</strong></p>
<p align="center">Flowersec は Go、TypeScript、Swift、Rust に共通のエンドツーエンド暗号化セッションモデルを提供し、RPC、通知、Byte Stream を組み込みます。</p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Flowersec を選ぶ理由

- 4 つの SDK が同じ安全なセッションモデルを共有するため、RPC とデータストリームのワークフローを共通化できます。
- 対応するネットワーク接続方式を利用でき、方式ごとにアプリケーションコードを書き直す必要がありません。
- RPC、通知、Byte Stream を 1 つの認証済みエンドツーエンド暗号化接続にまとめます。
- Relay を経由してもアプリケーションデータは暗号化されたままです。Relay は暗号文を転送するだけです。

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## 仕組み

| 経路 | 接続形態 | Stream トランスポート |
| --- | --- | --- |
| Direct | Client が互換性のある候補を使用して Endpoint に接続 | WebSocket は Hop-local Yamux、QUIC 系 Carrier はネイティブの双方向 Stream を使用 |
| Tunnel | Client Leg と Server Leg がそれぞれ独立に選択した互換性のある Carrier を介して接続 | Tunnel は主 Carrier を選ばず、Leg 間で暗号化 Stream を対応付け |

raw QUIC と WebTransport は、ネイティブの FIN、RESET_STREAM、STOP_SENDING、フロー制御、マイグレーション動作を維持します。Flowersec はアプリケーション 0-RTT を無効化します。Reliable Stream は QUIC DATAGRAM を使用しません。ネイティブ DATAGRAM がネゴシエートされた Runtime のみが、Carrier に依存しない Unreliable Message として公開します。

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## ローカルで試す

デフォルトの Acceptance Suite を実行します。

```bash
make test
```

失敗を修正した後は、`make test-resume` を使用して最初の未完了テストから次の失敗または `ALL GREEN` まで再開します。ソース Commit が変わっても、完了済み ID は有効です。

4 言語の Coverage Lane と排他的な Go race には `make coverage-race` を使用します。3 つのローカル Chromium Topology には `make browser-smoke`、明示的な Firefox/WebKit Capability Check には `make browser-compat` を使用します。特権が必要な弱いネットワークおよび Kernel 診断には `make diagnostic`、Capacity と Soak には `make performance` を使用します。

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK と Cookbook

| 言語 | パッケージ | 公開エントリ |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.Connect`, `flowersec.NewConnectionController`, `flowersec.NewAcceptor` |
| TypeScript | `@floegence/flowersec-core` | ルート、`/browser`、`/node`、`/proxy` の不透明な v2 エントリポイント |
| Swift | SwiftPM プロダクト `Flowersec` | `Artifact`、`connect`、`Session` |
| Rust | crate `flowersec` | `Artifact`、`connect`、`Session` |

Go サービスのコントロールプレーンは、opaque artifact の発行と `flowersec-runtime` の認可コールバックへの応答に、独立した `github.com/floegence/flowersec/flowersec-go/v2/controlplane` パッケージを使用します。

[Cookbook インデックス](examples/README.md)には、v2 の例と検証コマンドだけが含まれます。

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## SDK の機能

以下の機能は、内部のプロトコルオブジェクトではなく、アプリケーション開発者が直接利用するワークフローとして分類しています。各 SDK プロファイルは、Runtime と Platform 固有の Carrier 境界を宣言します。Platform の制約を未対応とできるのは、明確な理由、代替の Public Boundary、実行可能な Test ID が `stability/language_capabilities.json` に記録されている場合だけです。Control Plane の永続化はサービス境界です。Client は `flowersec-go/v2/controlplane` を使用する認証済み Service を呼び出し、第 2 の Issuer や Datastore を組み込みません。言語固有の Convenience は、共有ワークフローを変えずに各言語エコシステムへ構文や Orchestration を適合させるものです。接続の復旧動作は Controller の構造化 Disposition で報告されます。

| 機能 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| エンドツーエンド暗号化セッション、RPC、Byte Stream | 対応 | 対応 | 対応 | 対応 |
| 長期接続の自動復旧 | 対応 | 対応 | 対応 | 対応 |
| Unreliable Message | 対応 | 対応 | 非対応 | 対応 |
| RPC 通知の受信 | 非対応 | 対応 | 非対応 | 非対応 |
| Inbound RPC Request の処理 | 対応 | 非対応 | 非対応 | 非対応 |
| WebSocket Client 接続 | 対応 | Browser と Node.js | macOS と iOS | 非対応 |
| raw QUIC Client 接続 | 対応 | 非対応 | 非対応 | 対応 |
| WebTransport Client 接続 | 対応 | Browser と Node.js | 非対応 | 非対応 |
| Server 側の Session 受け入れ | `NewAcceptor` | `createAcceptor` / `AcceptedSession` | Apple Listener プロファイルでは非対応 | `Acceptor::bind` / `accept_with_handlers` |
| Control Plane による Artifact 発行と認可 | `flowersec-go/v2/controlplane` | 非対応。Application 所有の Service Boundary | 非対応。Application 所有の Service Boundary | 非対応。Application 所有の Service Boundary |

宣言済みの Carrier Tuple だけを受け入れ、未対応の Tuple は Fail Closed になります。各対応行は、本番用 Connector コードと `stability/language_capabilities.json` の明示的な Test ID によって裏付けられています。未対応 Capability には理由と代替 Boundary が記載されています。Capability Descriptor と Carrier の選択は内部に留まります。

<!-- readme-section:security -->
<a id="security"></a>

## セキュリティ

- Artifact は不透明でサイズ制限があり、1 回だけ使える Handle です。認証情報の最初のバイトを送信する前に Durable Spend を完了します。
- QUIC 系 Carrier は TLS 1.3、完全一致する ALPN、明示的な Trust Root、Early Data の無効化を必須とします。
- 公開エラーは秘匿化され、サイズも制限されます。Candidate、Wire、Key、Ledger の詳細は内部に留まります。
- 構造化された Controller Disposition が許可するのは、新しい Artifact を使った再試行だけです。Credential の再利用や、終了した Session の処理の Replay は行いません。
- Session のキャンセル、Deadline、FIN、Reset、Liveness、Rekey、Cleanup はすべて境界が定義されています。

[Transport v2 アーキテクチャ](docs/TRANSPORT_V2_ARCHITECTURE.md)と[脅威モデル](docs/THREAT_MODEL.md)を参照してください。

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## デプロイと開発

Flowersec Runtime が、WebSocket、raw QUIC、WebTransport の本番用 Listener 実装を担います。アプリケーション SDK に渡されるのは不透明な Artifact と Session だけであり、Runtime CLI は同じ Connector と Acceptor 実装を構成します。

リポジトリの Hook をインストールし、統合前に正式な品質ゲートを実行します。

```bash
make install-hooks
make precommit
```

`scripts/push-main.sh` は、境界が定められたローカル Acceptance Suite を実行してから、正確な main SHA を Push します。完全な Engineering Check と明示的な nightly、diagnostic、performance Workflow は、それぞれ Compatibility、特権診断、Load Test を対象とします。Release 自体は Test を実行しません。

Flowersec は [MIT License](LICENSE) で提供されます。リリース成果物は [GitHub Releases](https://github.com/floegence/flowersec/releases) で公開されます。
