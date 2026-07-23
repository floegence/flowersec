# Flowersec

<!-- readme-locales:start -->
<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh-CN.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <a href="README.ja-JP.md">日本語</a> |
  <strong>한국어</strong> |
  <a href="README.de-DE.md">Deutsch</a> |
  <a href="README.fr-FR.md">Français</a> |
  <a href="README.es-ES.md">Español</a> |
  <a href="README.pt-BR.md">Português do Brasil</a> |
  <a href="README.ru-RU.md">Русский</a>
</p>
<!-- readme-locales:end -->

<p align="center"><strong>Go, TypeScript, Swift, Rust를 위한 캐리어 중립적 종단 간 암호화 세션.</strong></p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Flowersec을 선택하는 이유

- 네 가지 SDK에서 하나의 불투명 Artifact 및 세션 계약을 사용합니다.
- WebSocket, raw QUIC, WebTransport를 동등한 캐리어 후보로 취급합니다.
- 애플리케이션에 캐리어, wire, key 또는 ledger 객체를 노출하지 않으면서 RPC와 바이트 스트림이 하나의 인증된 세션을 공유합니다.
- Tunnel relay는 애플리케이션 암호화를 종료하지 않고 암호화된 스트림을 전달합니다.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## 동작 방식

| 경로 | 연결 형태 | 스트림 전송 |
| --- | --- | --- |
| Direct | 클라이언트가 호환되는 후보를 사용해 Endpoint에 연결 | WebSocket은 hop-local Yamux를 사용하고, QUIC 계열 캐리어는 네이티브 양방향 스트림을 사용 |
| Tunnel | 클라이언트와 서버 leg가 각각 독립적으로 선택한 호환 캐리어를 통해 합류 | Tunnel은 주 캐리어를 선택하지 않고 leg 간 암호화된 스트림을 매핑 |

raw QUIC와 WebTransport는 네이티브 FIN, RESET_STREAM, STOP_SENDING, 흐름 제어 및 마이그레이션 동작을 유지합니다. Flowersec은 애플리케이션 0-RTT를 비활성화하며 QUIC DATAGRAM을 사용하지 않습니다.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## 로컬에서 실행

v2 단위 테스트 모음을 실행합니다.

```bash
make transport-v2-unit
```

캐리어별 증거는 `make transport-conformance-smoke`, `make transport-browser-smoke`, `make transport-interop-smoke`를 실행해 확인합니다.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK와 Cookbook

| 언어 | 패키지 | 공개 진입점 |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.NewConnector` |
| TypeScript | `@floegence/flowersec-core` | root, `/browser`, `/node`의 불투명 v2 진입점 |
| Swift | SwiftPM 제품 `Flowersec` | `ArtifactV2`, `ConnectorV2`, `SessionV2` |
| Rust | crate `flowersec` | `Artifact`, `Connector`, `Session` |

[Cookbook 색인](examples/README.md)에는 v2 예제와 검증 명령만 포함됩니다.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## 이식 가능한 계약

| 기능 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| 불투명 Artifact, Connector, Session, RPC 및 바이트 스트림 | 지원 | 지원 | 지원 | 지원 |
| 프로덕션 WebSocket dial | 지원 | Browser 및 Node.js | macOS | 미지원 |
| 프로덕션 raw QUIC dial | 지원 | 미지원 | 미지원 | 지원 |
| 프로덕션 WebTransport dial | 지원 | Browser | 미지원 | 미지원 |
| Listener 지원 | Go 라이브러리 API | Browser runtime 제약 | 공개하지 않음 | 공개하지 않음 |

각 지원 항목은 프로덕션 Connector 코드와 종단 간 테스트로 검증됩니다. 지원하지 않는 캐리어는 fail closed하며, 암묵적인 fallback으로 사용되지 않습니다. Capability descriptor와 캐리어 선택은 내부에만 유지됩니다.

<!-- readme-section:security -->
<a id="security"></a>

## 보안

- Artifact는 불투명하고 크기가 제한된 일회용 handle입니다. 첫 credential byte를 보내기 전에 durable spend가 완료됩니다.
- QUIC 계열 캐리어는 TLS 1.3, 정확한 ALPN, 명시적 trust root 및 비활성화된 early data를 요구합니다.
- 공개 오류는 정보가 제거되고 크기가 제한됩니다. candidate, wire, key 및 ledger 세부 정보는 내부에만 유지됩니다.
- 세션 취소, deadline, FIN, reset, liveness, rekey 및 cleanup은 제한된 동작을 보장합니다.

[Transport v2 아키텍처](docs/TRANSPORT_V2_ARCHITECTURE.md)와 [위협 모델](docs/THREAT_MODEL.md)을 참조하세요.

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 배포 및 개발

Flowersec runtime은 WebSocket, raw QUIC 및 WebTransport의 프로덕션 Listener 구현을 담당합니다. 애플리케이션 SDK에는 불투명 Artifact와 Session만 제공되며, 제거된 호환성 CLI는 v2 계약에 포함되지 않습니다.

통합 전에 저장소 hook을 설치하고 authoritative gate를 실행합니다.

```bash
make install-hooks
make check
```

Flowersec은 [MIT License](LICENSE)로 제공됩니다. Release artifact는 [GitHub Releases](https://github.com/floegence/flowersec/releases)를 통해 게시됩니다.
