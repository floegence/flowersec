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

<p align="center"><strong>Безопасно соединяйте части приложения, где бы они ни работали.</strong></p>
<p align="center">Flowersec предоставляет Go, TypeScript, Swift и Rust простой API для сеансов со сквозным шифрованием, RPC, уведомлений и потоков байтов.</p>

[![Последний выпуск](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![Лицензия](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Зачем нужен Flowersec

Flowersec предназначен для приложений, которым нужно приватно соединять клиентов, сервисы и устройства, не смешивая транспортную логику с прикладным кодом.

- **Единая модель программирования:** один API аутентифицированного сеанса для Go, TypeScript, Swift и Rust.
- **Нужные приложению возможности:** RPC, уведомления и надёжные потоки байтов в одном соединении.
- **Подключение под условия сети:** прямое соединение или relay без изменения протокола приложения.
- **Приватность по умолчанию:** данные зашифрованы от конца до конца. Relay может пересылать их, но не читать.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## Как это работает

Flowersec отделяет сеанс приложения от сетевого пути, по которому он передаётся:

1. Сервис создаёт краткосрочное приглашение на подключение и передаёт его клиенту.
2. SDK устанавливает защищённый сеанс через доступное прямое соединение или relay.
3. Приложение использует RPC, уведомления и потоки байтов через единый API сеанса.

Прямые соединения и relay предоставляют коду один и тот же сеанс. Выбор соединения, учётные данные и маршрутизация остаются внутри SDK и среды выполнения.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Начало работы

Выберите SDK для своего приложения:

| SDK | Лучше всего подходит для | Установка и руководство по API |
| --- | --- | --- |
| Go | Сервисы, шлюзы и код управляющей плоскости | [Go SDK](flowersec-go/README.md) |
| TypeScript | Браузерные приложения и Node.js | [TypeScript SDK](flowersec-ts/README.md) |
| Swift | Клиенты macOS и iOS | [Swift SDK](flowersec-swift/README.md) |
| Rust | Сервисы Tokio, которым нужен нативный QUIC | [Rust SDK](flowersec-rust/README.md) |

В [каталоге примеров](examples/README.md) для каждого SDK есть небольшие запускаемые примеры клиентских соединений, надёжного однократного использования, выпуска управляющей плоскостью, проверки liveness и жизненного цикла сеанса.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## Примеры

Начните с [каталога примеров](examples/README.md). В них используется тот же публичный API, что и в рабочих приложениях, и показаны клиентские соединения, выпуск приглашений, надёжная однократная обработка, liveness и жизненный цикл сеанса.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Что умеет приложение

Четыре SDK используют единую модель сеанса. Поддержка различается, если платформа не может предоставить определённый тип соединения.

| Возможность приложения | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Сеансы со сквозным шифрованием | Да | Да | Да | Да |
| Отправка вызовов RPC и уведомлений | Да | Да | Да | Да |
| Получение уведомлений RPC | Да | Да | Да | Да |
| Надёжные потоки байтов | Да | Да | Да | Да |
| Обработка прикладных потоков в любом сеансе | Да | Да | Да | Да |
| Восстановление долговременных соединений | Да | Да | Да | Да |
| Ненадёжные сообщения, когда доступны | Да | Да | Нет | Да |
| Браузерные соединения | Нет | Да | Нет | Нет |
| Соединения клиентов Apple | Нет | Нет | Да | Нет |
| Нативные соединения QUIC | Да | Node.js | Нет | Да |
| Соединения WebSocket | Да | Да | Да | Да |
| Соединения WebTransport | Go H4 | Browser H3 client (при наличии API WebTransport в браузере) | Нет | Нет |
| Приём сеансов на сервере | Да | Node.js | Нет | Да |
| Непрозрачный relay runtime | Да | Node.js | Нет | Да |
| Выпуск приглашений управляющей плоскостью | Да | Нет | Нет | Нет |
| HTTP и WebSocket ProxyServer | Да | Node.js | Нет | Да |

Профили развертывания отделяют доступность платформы от общего прикладного протокола Flowersec:

| Профиль | Среды выполнения | Обязательные carrier и role | Необязательные возможности |
| --- | --- | --- | --- |
| `native-server-core` | Go, Rust, Node.js | WebSocket и raw QUIC endpoint client, direct server и opaque tunnel runtime | WebTransport adapter |
| `browser-client` | TypeScript browser | WebSocket endpoint client | Browser WebTransport adapter |
| `apple-client` | Swift на платформах Apple | WSS endpoint client | Нет |
| `webtransport-server` | Go | WebTransport direct server и opaque tunnel runtime | Нет |

Машиночитаемый профиль native-server-core содержит 18 агрегированных runtime-role-carrier tuple, по шесть для каждой нативной среды, и 24 поддерживаемые серверные единицы, специфичные для пути. Go H4 добавляет два серверных WebTransport tuple и две специфичные для пути единицы. Матрица interoperability отдельно объявляет 18 direct cells и 18 tunnel cells. Release gate проверяет все 10 direct cells и 14 попарных tunnel cells с участием Go; оставшиеся 8 direct cells и 4 tunnel cells явно отмечены как непроверенные. Еще четыре клиентских WSS profile проверяют Swift и браузерный TypeScript с Go по direct и tunnel путям. Профиль никогда не меняет wire-семантику Artifact, handshake, RPC, stream, close, rekey или authorization.

Точные сочетания платформ и типов соединений перечислены в руководствах SDK.

WebTransport является необязательным адаптером и не входит в обязательный контракт carrier native-server. Go заявляет отдельный полный профиль H4 webtransport-server; профиль Browser использует H3, если доступен API WebTransport браузера. Node.js и Rust в настоящее время не предоставляют production-адаптер WebTransport. Поверхность carrier native-server для Go, Rust и Node.js включает WebSocket и raw QUIC; попарная interoperability заявляется только поддерживаемыми записями матрицы.

`flowersec-private-loopback/1` — приватный профиль продукта вне публичного deployment capability registry. Его специализированные API для Go server и TypeScript browser ограничены аутентифицированным приложением numeric-loopback HTTP bridge.

<!-- readme-section:security -->
<a id="security"></a>

## Безопасность

- Данные приложения зашифрованы от конца до конца и в прямых сеансах, и при работе через relay.
- Политика доверия TLS привязана к каждому транспортному кандидату v3. Публичные или предоставленные развёртыванием корни CA и явные pin-значения конечного сертификата взаимоисключающи; после сбоя понижение режима запрещено.
- `flowersec-private-loopback/1` — изолированный transport envelope, а не TLS mode или capability профиля `flowersec/3`. Его специализированные API сопоставляют один неизменённый CA-mode v3 candidate с `ws://` только когда authority совпадает с тем же numeric-loopback origin, а server application авторизует request до upgrade. Обычные пути Go, TypeScript, Rust, Swift, Provider и tunnel отклоняют этот envelope.
- Приглашения на подключение непрозрачны, краткосрочны и одноразовы.
- Учётные данные фиксируются до использования, поэтому потраченное приглашение нельзя воспроизвести.
- Relay только пересылает зашифрованный трафик и не завершает сеанс приложения.
- Недопустимые и неподдерживаемые подключения безопасно завершаются с ограниченной публичной ошибкой.

Подробности протокола и модели угроз приведены в [контракте API](docs/API_CONTRACT.md), [архитектуре транспорта](docs/TRANSPORT_V3_ARCHITECTURE.md) и [модели угроз](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Подробнее

- [Контракт API](docs/API_CONTRACT.md): стабильное поведение приложения, общее для SDK.
- [Модель ошибок](docs/ERROR_MODEL.md): публичные ошибки соединений, сеансов и RPC.
- [Архитектура транспорта](docs/TRANSPORT_V3_ARCHITECTURE.md): устройство прямых соединений и relay.
- [Примеры](examples/README.md): запускаемые примеры использования SDK.

Flowersec распространяется по [лицензии MIT](LICENSE). Опубликованные пакеты и заметки о выпусках доступны в [GitHub Releases](https://github.com/floegence/flowersec/releases).
