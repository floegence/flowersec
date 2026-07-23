# Flowersec

<!-- readme-locales:start -->
<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh-CN.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <a href="README.ja-JP.md">日本語</a> |
  <a href="README.ko-KR.md">한국어</a> |
  <a href="README.de-DE.md">Deutsch</a> |
  <a href="README.fr-FR.md">Français</a> |
  <a href="README.es-ES.md">Español</a> |
  <a href="README.pt-BR.md">Português do Brasil</a> |
  <strong>Русский</strong>
</p>
<!-- readme-locales:end -->

<p align="center"><strong>Независимые от транспортного канала сеансы со сквозным шифрованием для Go, TypeScript, Swift и Rust.</strong></p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Зачем нужен Flowersec

- Единый контракт непрозрачных артефактов и сеансов во всех четырёх SDK.
- WebSocket, raw QUIC и WebTransport являются равноправными вариантами транспортного канала.
- RPC и байтовые потоки используют один аутентифицированный сеанс, не раскрывая приложениям объекты транспортного канала, сетевого формата, ключей или журнала состояния.
- Туннельные ретрансляторы передают зашифрованные потоки, не завершая шифрование приложения.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## Как это работает

| Маршрут | Схема соединения | Транспорт потоков |
| --- | --- | --- |
| Direct | Клиент подключается к конечной точке через совместимый вариант транспорта | WebSocket использует Yamux в пределах одного перехода; транспорты семейства QUIC используют нативные двунаправленные потоки |
| Tunnel | Клиентское и серверное плечи соединяются через независимо выбранные совместимые транспорты | Туннель сопоставляет зашифрованные потоки между плечами, не назначая основной транспорт |

Raw QUIC и WebTransport сохраняют нативное поведение FIN, RESET_STREAM, STOP_SENDING, управления потоком и миграции. Flowersec отключает 0-RTT приложения и не использует QUIC DATAGRAM.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Локальный запуск

Запустите наборы модульных тестов v2:

```bash
make transport-v2-unit
```

Для проверки отдельных транспортов выполните `make transport-conformance-smoke`, `make transport-browser-smoke` и `make transport-interop-smoke`.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK и практические примеры

| Язык | Пакет | Публичная точка входа |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.NewConnector` |
| TypeScript | `@floegence/flowersec-core` | непрозрачные точки входа v2 в корне пакета, `/browser` и `/node` |
| Swift | Продукт SwiftPM `Flowersec` | `ArtifactV2`, `ConnectorV2`, `SessionV2` |
| Rust | crate `flowersec` | `Artifact`, `Connector`, `Session` |

[Указатель практических примеров](examples/README.md) содержит только примеры v2 и команды проверки.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Переносимый контракт

| Возможность | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Непрозрачные объекты: артефакт, коннектор, сеанс, RPC и байтовые потоки | Да | Да | Да | Да |
| Подключение WebSocket в промышленной эксплуатации | Да | Browser и Node.js | macOS | Нет |
| Подключение raw QUIC в промышленной эксплуатации | Да | Нет | Нет | Да |
| Подключение WebTransport в промышленной эксплуатации | Да | Browser | Нет | Нет |
| Поддержка входящих соединений | API библиотеки Go | Ограничения среды Browser | Не заявлена | Не заявлена |

Каждая строка поддержки подтверждена промышленным кодом коннекторов и сквозными тестами. Попытка использовать неподдерживаемый транспорт завершается безопасным отказом; неявного перехода на резервный вариант не происходит. Данные о возможностях и выбор транспорта остаются внутренними деталями.

<!-- readme-section:security -->
<a id="security"></a>

## Безопасность

- Артефакты являются непрозрачными дескрипторами ограниченного размера и однократного использования. Расходование фиксируется в постоянном хранилище до отправки первого байта учётных данных.
- Транспорты семейства QUIC требуют TLS 1.3, точного совпадения ALPN, явно заданных корней доверия и отключенной ранней передачи данных.
- Публичные ошибки не содержат чувствительных данных и ограничены по размеру; сведения о кандидатах, сетевом формате, ключах и журнале состояния остаются внутренними.
- Отмена сеанса, сроки выполнения, FIN, сброс, проверка активности, смена ключей и очистка имеют чёткие временные и ресурсные границы.

См. [архитектуру Transport v2](docs/TRANSPORT_V2_ARCHITECTURE.md) и [модель угроз](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Развёртывание и разработка

Среда выполнения Flowersec предоставляет готовые к промышленной эксплуатации реализации входящих соединений WebSocket, raw QUIC и WebTransport. SDK приложений получают только непрозрачные артефакты и сеансы; удалённый CLI обратной совместимости не входит в контракт v2.

Установите хуки репозитория и запустите основную проверку перед интеграцией:

```bash
make install-hooks
make check
```

Flowersec распространяется по [лицензии MIT](LICENSE). Артефакты релизов публикуются через [GitHub Releases](https://github.com/floegence/flowersec/releases).
