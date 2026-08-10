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

raw QUIC와 WebTransport는 네이티브 FIN, RESET_STREAM, STOP_SENDING, 흐름 제어 및 마이그레이션 동작을 유지합니다. Flowersec은 애플리케이션 0-RTT를 비활성화합니다. Reliable Stream은 QUIC DATAGRAM을 사용하지 않으며, 네이티브 DATAGRAM을 협상한 Runtime만 Carrier 중립적인 Unreliable Message를 통해 이를 제공합니다.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## 로컬에서 실행

기본 Acceptance Suite를 실행합니다.

```bash
make test
```

실패를 수정한 뒤 `make test-resume`으로 첫 번째 미완료 테스트부터 다음 실패 또는 `ALL GREEN`까지 재개합니다. 소스 Commit이 변경되어도 완료된 ID는 유효합니다.

네 언어의 Coverage Lane과 단독 Go race에는 `make coverage-race`를 사용합니다. 세 가지 로컬 Chromium Topology에는 `make browser-smoke`를, 명시적인 Firefox/WebKit Capability Check에는 `make browser-compat`를 사용합니다. 권한이 필요한 약한 네트워크 및 Kernel 진단에는 `make diagnostic`을, Capacity와 Soak에는 `make performance`를 사용합니다.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK와 Cookbook

| 언어 | 패키지 | 공개 진입점 |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.Connect`, `flowersec.NewConnectionController`, `flowersec.NewAcceptor` |
| TypeScript | `@floegence/flowersec-core` | root, `/browser`, `/node`, `/proxy`의 불투명 v2 진입점 |
| Swift | SwiftPM 제품 `Flowersec` | `Artifact`, `connect`, `Session` |
| Rust | crate `flowersec` | `Artifact`, `connect`, `Session` |

Go 서비스 control plane은 별도의 `github.com/floegence/flowersec/flowersec-go/v2/controlplane` 패키지를 사용해 opaque artifact를 발급하고 `flowersec-runtime` authorization callback에 응답합니다.

[Cookbook 색인](examples/README.md)에는 v2 예제와 검증 명령만 포함됩니다.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## SDK 기능

아래 기능은 내부 프로토콜 객체가 아니라 애플리케이션 개발자가 직접 사용하는 워크플로를 기준으로 분류했습니다. 각 SDK Profile은 Runtime 및 Platform 고유 Carrier 경계를 선언합니다. Platform 제한은 명시적 이유, 대체 Public Boundary, 실행 가능한 Test ID가 `stability/language_capabilities.json`에 기록된 경우에만 미지원으로 선언할 수 있습니다. Control Plane 영속성은 서비스 경계입니다. Client는 `flowersec-go/v2/controlplane`을 사용하는 인증된 Service를 호출하며 별도의 Issuer나 Datastore를 내장하지 않습니다. 언어별 Convenience는 공유 워크플로를 바꾸지 않고 해당 언어 생태계에 맞는 구문이나 Orchestration만 제공합니다. 연결 복구 동작은 Controller의 구조화된 Disposition으로 보고됩니다.

| 기능 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| 종단 간 암호화 Session, RPC 및 Byte Stream | 지원 | 지원 | 지원 | 지원 |
| 장기 연결 자동 복구 | 지원 | 지원 | 지원 | 지원 |
| Unreliable Message | 지원 | 지원 | 미지원 | 지원 |
| RPC Notification 수신 | 미지원 | 지원 | 미지원 | 미지원 |
| Inbound RPC Request 처리 | 지원 | 미지원 | 미지원 | 미지원 |
| WebSocket Client 연결 | 지원 | Browser 및 Node.js | macOS 및 iOS | 미지원 |
| raw QUIC Client 연결 | 지원 | 미지원 | 미지원 | 지원 |
| WebTransport Client 연결 | 지원 | Browser 및 Node.js | 미지원 | 미지원 |
| Server 측 Session 수락 | `NewAcceptor` | `createAcceptor` / `AcceptedSession` | Apple Listener Profile에서 미지원 | `Acceptor::bind` / `accept_with_handlers` |
| Control Plane Artifact 발급 및 권한 부여 | `flowersec-go/v2/controlplane` | 미지원, Application 소유 Service Boundary | 미지원, Application 소유 Service Boundary | 미지원, Application 소유 Service Boundary |

선언된 Carrier Tuple만 허용되며 미지원 Tuple은 Fail Closed됩니다. 각 지원 행은 프로덕션 Connector 코드와 `stability/language_capabilities.json`의 명시적인 Test ID로 검증됩니다. 미지원 Capability에는 이유와 대체 Boundary가 포함됩니다. Capability Descriptor와 Carrier 선택은 내부에만 유지됩니다.

<!-- readme-section:security -->
<a id="security"></a>

## 보안

- Artifact는 불투명하고 크기가 제한된 일회용 handle입니다. 첫 credential byte를 보내기 전에 durable spend가 완료됩니다.
- QUIC 계열 캐리어는 TLS 1.3, 정확한 ALPN, 명시적 trust root 및 비활성화된 early data를 요구합니다.
- 공개 오류는 정보가 제거되고 크기가 제한됩니다. candidate, wire, key 및 ledger 세부 정보는 내부에만 유지됩니다.
- 구조화된 Controller Disposition은 새 Artifact를 사용한 재시도만 허용하며 Credential을 재사용하거나 종료된 Session의 작업을 Replay하지 않습니다.
- 세션 취소, deadline, FIN, reset, liveness, rekey 및 cleanup은 제한된 동작을 보장합니다.

[Transport v2 아키텍처](docs/TRANSPORT_V2_ARCHITECTURE.md)와 [위협 모델](docs/THREAT_MODEL.md)을 참조하세요.

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 배포 및 개발

Flowersec runtime은 WebSocket, raw QUIC 및 WebTransport의 프로덕션 Listener 구현을 담당합니다. 애플리케이션 SDK에는 불투명 Artifact와 Session만 제공되며, runtime CLI는 동일한 Connector와 Acceptor 구현을 구성합니다.

통합 전에 저장소 hook을 설치하고 authoritative gate를 실행합니다.

```bash
make install-hooks
make precommit
```

`scripts/push-main.sh`는 범위가 제한된 로컬 Acceptance Suite를 실행한 후 정확한 main SHA를 Push합니다. 전체 Engineering Check와 명시적인 nightly, diagnostic, performance Workflow는 각각 Compatibility, 권한 진단, Load Test 범위를 담당하며 Release 자체는 Test를 실행하지 않습니다.

Flowersec은 [MIT License](LICENSE)로 제공됩니다. Release artifact는 [GitHub Releases](https://github.com/floegence/flowersec/releases)를 통해 게시됩니다.
