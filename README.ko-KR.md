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

<p align="center"><strong>앱이 어디에서 실행되든 서로 안전하게 연결하세요.</strong></p>
<p align="center">Flowersec은 Go, TypeScript, Swift, Rust에 종단 간 암호화 세션, RPC, 알림, Byte Stream을 위한 하나의 간단한 API를 제공합니다.</p>

[![최신 릴리스](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![라이선스](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Flowersec을 선택하는 이유

Flowersec은 전송 코드를 애플리케이션 코드에 끌어들이지 않고 클라이언트, 서비스, 기기를 비공개로 연결해야 하는 앱을 위한 도구입니다.

- **하나의 프로그래밍 모델:** Go, TypeScript, Swift, Rust에서 같은 인증 세션 API를 사용합니다.
- **앱에 필요한 기능:** 하나의 연결에서 RPC 호출, 알림, 신뢰성 있는 Byte Stream을 처리합니다.
- **네트워크에 맞는 연결:** 가능하면 직접 연결하고 필요하면 릴레이를 사용하며, 애플리케이션 프로토콜은 바꾸지 않습니다.
- **기본으로 보호되는 개인정보:** 애플리케이션 데이터는 종단 간 암호화되며 릴레이는 내용을 읽을 수 없습니다.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## 작동 방식

Flowersec은 애플리케이션 세션과 이를 전달하는 네트워크 경로를 분리합니다.

1. 서비스가 수명이 짧은 연결 초대를 만들어 클라이언트에 전달합니다.
2. SDK가 사용 가능한 직접 또는 릴레이 연결로 보안 세션을 설정합니다.
3. 애플리케이션은 동일한 세션 API로 RPC, 알림, Byte Stream을 사용합니다.

직접 연결과 릴레이 연결 모두 코드에는 같은 세션을 제공합니다. 연결 선택, 자격 증명, 라우팅은 SDK와 런타임 내부에서 처리됩니다.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## 시작하기

애플리케이션에 맞는 SDK를 선택하세요.

| SDK | 적합한 용도 | 설치 및 API 가이드 |
| --- | --- | --- |
| Go | 서비스, 게이트웨이, 제어 영역 코드 | [Go SDK](flowersec-go/README.md) |
| TypeScript | 브라우저 및 Node.js 애플리케이션 | [TypeScript SDK](flowersec-ts/README.md) |
| Swift | macOS 및 iOS 클라이언트 | [Swift SDK](flowersec-swift/README.md) |
| Rust | 네이티브 QUIC가 필요한 Tokio 서비스 | [Rust SDK](flowersec-rust/README.md) |

[Cookbook 인덱스](examples/README.md)에는 각 SDK의 클라이언트 연결, 영구 단일 사용 처리, 제어 영역 발급, liveness, 세션 수명 주기를 다루는 작고 실행 가능한 예제가 있습니다.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## 예제

[Cookbook 인덱스](examples/README.md)부터 살펴보세요. 프로덕션 앱과 같은 공개 API를 사용해 클라이언트 연결, 제어 영역의 연결 초대 발급, 영구 단일 사용 처리, liveness, 세션 수명 주기를 보여 줍니다.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## 앱에서 할 수 있는 일

네 가지 SDK는 동일한 세션 모델을 공유합니다. 특정 연결 방식을 제공할 수 없는 플랫폼에서는 지원 범위가 달라집니다.

<!-- capability-table:start -->
| 애플리케이션 기능 | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| 불투명한 일회용 연결 초대 | 지원 | 지원 | 지원 | 지원 |
| 일회성 보안 연결 | 지원 | 지원 | 지원 | 지원 |
| 종단간 암호화 세션 | 지원 | 지원 | 지원 | 지원 |
| RPC 호출 및 알림 | 지원 | 지원 | 지원 | 지원 |
| 검증된 스트림 메타데이터 | 지원 | 지원 | 지원 | 지원 |
| 애플리케이션 스트림 핸들러 | 지원 | 지원 | 지원 | 지원 |
| 장기 연결 자동 복구 | 지원 | 지원 | 지원 | 지원 |
| 협상된 비신뢰 메시지 | 지원 | 지원 | 미지원 | 지원 |
| 클라이언트 RPC 핸들러 | 지원 | 지원 | 지원 | 지원 |
| 서버 측 세션 수락 | 지원 | 지원 | 지원 | 지원 |
| 서버 세션 핸들러 | 지원 | 지원 | 지원 | 지원 |
| 제어 영역 발급 및 권한 부여 | 지원 | 미지원 | 미지원 | 미지원 |
| 직접 및 터널 승인 | 지원 | 지원 | 지원 | 지원 |
| HTTP 및 WebSocket ProxyServer | 지원 | 지원 | 미지원 | 지원 |
| 캐리어 중립 스트림 계약 | 지원 | 지원 | 지원 | 지원 |
| Transport v4 와이어 보안 | 지원 | 지원 | 지원 | 지원 |
<!-- capability-table:end -->

배포 profile은 필요한 네이티브 또는 브라우저 carrier와 역할 조합을 설명합니다. 각 SDK 가이드는 현재 API와 provider 자격을 구분합니다. 소스 선언만으로 실행 검증을 입증하지 않습니다.

현재 프로토콜은 인증된 연결 자료, 독립적인 namespace 신뢰, 제한된 세션, 타입 서비스와 명시적 cleanup을 사용합니다. 직접 연결과 터널 상호 운용성은 실행 가능한 매트릭스와 원래 provider로 검증합니다. 릴리스는 패키지 게시와 registry readback만 수행하고 승인 테스트는 실행하지 않습니다.

WebTransport에는 설정된 네이티브 또는 브라우저 provider가 필요합니다. 브라우저 지원은 실제 WebTransport API와 인증서 정책 기능에 따라 달라집니다. 현재 carrier, listener, relay 범위는 각 SDK 가이드를 참조하세요.

서명된 `local_loopback` 접근 클래스는 같은 시스템에서 애플리케이션이 인증하는 HTTP 브리지를 지원합니다. 현재 세션 프로토콜을 사용하며 로컬 provider 설정이 필요합니다.

<!-- readme-section:security -->
<a id="security"></a>

## 보안

- 직접 및 릴레이 세션 모두 애플리케이션 데이터를 종단 간 암호화합니다.
- TLS 신뢰 정책은 각 v4 전송 후보에 바인딩됩니다. 공개 또는 배포 제공 CA 루트와 명시적 리프 인증서 pin은 상호 배타적이며 실패 후 강등되지 않습니다.
- `local_loopback`은 서명된 숫자 루프백 endpoint에만 `ws://`를 허용하며 정확한 Origin과 upgrade 전 애플리케이션 인증을 요구합니다. 외부 TLS 검증을 보장하거나 평문 fallback을 허용하지 않습니다.
- 연결 초대는 불투명하고 수명이 짧으며 한 번만 사용할 수 있습니다.
- 자격 증명은 사용 전에 소비 처리되어 이미 사용한 초대를 재사용할 수 없습니다.
- 릴레이는 암호화된 트래픽만 전달하며 애플리케이션 세션을 종료하지 않습니다.
- 유효하지 않거나 지원하지 않는 연결은 안전하게 실패하고 제한된 공개 오류만 반환합니다.

프로토콜과 위협 모델의 자세한 내용은 [API 계약](docs/API_CONTRACT.md), [전송 아키텍처](docs/TRANSPORT_V4_BINDING.md), [위협 모델](docs/THREAT_MODEL.md)을 참고하세요.

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## 더 알아보기

- [API 계약](docs/API_CONTRACT.md): SDK가 공유하는 안정적인 애플리케이션 동작입니다.
- [오류 모델](docs/ERROR_MODEL.md): 공개 연결, 세션, RPC 오류입니다.
- [전송 아키텍처](docs/TRANSPORT_V4_BINDING.md): 직접 및 릴레이 연결 설계입니다.
- [예제](examples/README.md): 실행 가능한 SDK 사용법입니다.

Flowersec은 [MIT License](LICENSE)로 제공됩니다. 배포된 패키지와 릴리스 노트는 [GitHub Releases](https://github.com/floegence/flowersec/releases)에서 확인할 수 있습니다.
