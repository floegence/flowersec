# Flowersec

<!-- readme-locales:start -->
<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh-CN.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <a href="README.ja-JP.md">日本語</a> |
  <a href="README.ko-KR.md">한국어</a> |
  <strong>Deutsch</strong> |
  <a href="README.fr-FR.md">Français</a> |
  <a href="README.es-ES.md">Español</a> |
  <a href="README.pt-BR.md">Português do Brasil</a> |
  <a href="README.ru-RU.md">Русский</a>
</p>
<!-- readme-locales:end -->

<p align="center"><strong>Carrier-neutrale, Ende-zu-Ende-verschlüsselte Sitzungen für Go, TypeScript, Swift und Rust.</strong></p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Warum Flowersec

- Ein einheitlicher Vertrag für opake Artifacts und Sitzungen in vier SDKs.
- WebSocket, raw QUIC und WebTransport sind gleichwertige Carrier-Kandidaten.
- RPC und Byte-Streams teilen sich eine authentifizierte Sitzung, ohne Carrier-, Wire-, Key- oder Ledger-Objekte für Anwendungen offenzulegen.
- Tunnel-Relays leiten verschlüsselte Streams weiter, ohne die Anwendungsverschlüsselung zu terminieren.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## Funktionsweise

| Pfad | Verbindungsform | Stream-Transport |
| --- | --- | --- |
| Direct | Der Client verbindet sich über einen kompatiblen Kandidaten mit einem Endpoint | WebSocket verwendet hop-lokales Yamux; Carrier der QUIC-Familie verwenden native bidirektionale Streams |
| Tunnel | Client- und Server-Leg treten über unabhängig ausgewählte kompatible Carrier bei | Der Tunnel ordnet verschlüsselte Streams zwischen den Legs zu, ohne einen primären Carrier festzulegen |

raw QUIC und WebTransport bewahren das native Verhalten von FIN, RESET_STREAM, STOP_SENDING, Flusskontrolle und Migration. Flowersec deaktiviert 0-RTT auf Anwendungsebene. Zuverlässige Streams verwenden niemals QUIC DATAGRAM; Runtimes mit ausgehandeltem nativem DATAGRAM stellen es ausschließlich über Carrier-neutrale unzuverlässige Nachrichten bereit.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Lokal ausprobieren

Führe die standardmäßige Abnahmetestsuite aus:

```bash
make test
```

Verwende nach der Behebung eines Fehlers `make test-resume`, um beim ersten unvollständigen Test fortzufahren, bis der nächste Fehler oder `ALL GREEN` erreicht ist. Abgeschlossene IDs bleiben auch bei einer Änderung des Quell-Commits gültig.

Verwende `make coverage-race` für die Coverage-Lanes aller vier Sprachen und den exklusiven Go-Race-Test. `make browser-smoke` prüft die drei lokalen Chromium-Topologien, `make browser-compat` die expliziten Firefox-/WebKit-Fähigkeiten. Privilegierte Schwachnetz- und Kernel-Diagnosen laufen mit `make diagnostic`; Kapazitäts- und Soak-Tests mit `make performance`.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDKs und Cookbooks

| Sprache | Paket | Öffentlicher Einstieg |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.Connect`, `flowersec.NewConnectionController`, `flowersec.NewAcceptor` |
| TypeScript | `@floegence/flowersec-core` | opake v2-Einstiege im Root sowie unter `/browser`, `/node` und `/proxy` |
| Swift | SwiftPM-Produkt `Flowersec` | `Artifact`, `connect`, `Session` |
| Rust | Crate `flowersec` | `Artifact`, `connect`, `Session` |

Go-Service-Control-Planes verwenden das separate Paket `github.com/floegence/flowersec/flowersec-go/v2/controlplane`, um opake Artefakte auszustellen und Autorisierungs-Callbacks von `flowersec-runtime` zu beantworten.

Der [Cookbook-Index](examples/README.md) enthält ausschließlich v2-Beispiele und Verifikationsbefehle.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## SDK-Funktionen

Die folgenden Fähigkeiten sind nach direkt nutzbaren Anwendungs-Workflows und nicht nach internen Protokollobjekten gruppiert. Jedes SDK-Profil deklariert seine Runtime- und plattformspezifische Carrier-Grenze. Eine Plattformbeschränkung darf nur dann als nicht unterstützt gelten, wenn `stability/language_capabilities.json` einen eindeutigen Grund, eine alternative öffentliche Grenze und eine ausführbare Test-ID enthält. Die Persistenz der Control Plane ist eine Servicegrenze: Clients rufen den authentifizierten Service auf, der `flowersec-go/v2/controlplane` verwendet, statt einen zweiten Issuer oder Datastore einzubetten. Sprachspezifischer Komfort darf Syntax oder Orchestrierung an ein Ökosystem anpassen, ohne die gemeinsamen Workflows zu ändern. Das Verhalten bei der Verbindungswiederherstellung wird durch die strukturierte Disposition des Controllers beschrieben.

| Fähigkeit | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Ende-zu-Ende-verschlüsselte Sitzungen, RPC und Byte-Streams | Ja | Ja | Ja | Ja |
| Automatische Wiederherstellung langlebiger Verbindungen | Ja | Ja | Ja | Ja |
| Unzuverlässige Nachrichten | Ja | Ja | Nein | Ja |
| Empfang von RPC-Benachrichtigungen | Nein | Ja | Nein | Nein |
| Verarbeitung eingehender RPC-Anfragen | Ja | Nein | Nein | Nein |
| WebSocket-Clientverbindungen | Ja | Browser und Node.js | macOS und iOS | Nein |
| Raw-QUIC-Clientverbindungen | Ja | Nein | Nein | Ja |
| WebTransport-Clientverbindungen | Ja | Browser und Node.js | Nein | Nein |
| Serverseitige Sitzungsannahme | `NewAcceptor` | `createAcceptor` / `AcceptedSession` | Im Apple-Listener-Profil nicht unterstützt | `Acceptor::bind` / `accept_with_handlers` |
| Ausstellung und Autorisierung von Control-Plane-Artifacts | `flowersec-go/v2/controlplane` | Nicht unterstützt; Servicegrenze der Anwendung | Nicht unterstützt; Servicegrenze der Anwendung | Nicht unterstützt; Servicegrenze der Anwendung |

Nur deklarierte Carrier-Tupel werden akzeptiert; nicht unterstützte Tupel werden sicher abgelehnt. Jede Unterstützungszeile ist durch produktiven Connector-Code und eine explizite Test-ID in `stability/language_capabilities.json` belegt. Nicht unterstützte Fähigkeiten nennen einen Grund und eine alternative Grenze. Capability-Deskriptoren und die Carrier-Auswahl bleiben intern.

<!-- readme-section:security -->
<a id="security"></a>

## Sicherheit

- Artifacts sind opake, begrenzte Einweg-Handles. Der dauerhafte Verbrauch ist abgeschlossen, bevor das erste Credential-Byte gesendet wird.
- Carrier der QUIC-Familie erfordern TLS 1.3, exaktes ALPN, explizite Trust Roots und deaktivierte Early Data.
- Öffentliche Fehler sind redigiert und begrenzt; Details zu Kandidaten, Wire, Keys und Ledger bleiben intern.
- Strukturierte Controller-Dispositionen erlauben nur einen Versuch mit einem neuen Artifact; sie verwenden keine Zugangsdaten erneut und spielen keine Arbeit aus einer beendeten Sitzung ab.
- Sitzungsabbruch, Deadlines, FIN, Reset, Liveness, Rekey und Bereinigung verhalten sich innerhalb definierter Grenzen.

Siehe die [Transport-v2-Architektur](docs/TRANSPORT_V2_ARCHITECTURE.md) und das [Bedrohungsmodell](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Bereitstellung und Entwicklung

Die Flowersec-Runtime stellt die produktiven Listener-Implementierungen für WebSocket, raw QUIC und WebTransport bereit. Anwendungs-SDKs erhalten ausschließlich opake Artifacts und Sitzungen; die Runtime-CLIs kombinieren dieselben Connector- und Acceptor-Implementierungen.

Installiere die Repository-Hooks und führe vor der Integration das maßgebliche Gate aus:

```bash
make install-hooks
make precommit
```

`scripts/push-main.sh` führt die begrenzte lokale Abnahmetestsuite aus, bevor der exakte main-SHA gepusht wird. Der vollständige Engineering-Check und die expliziten Workflows für nightly, diagnostic und performance decken Kompatibilität, privilegierte Diagnosen und Lasttests ab; der Release selbst führt keine Tests aus.

Flowersec ist unter der [MIT License](LICENSE) verfügbar. Release-Artefakte werden über [GitHub Releases](https://github.com/floegence/flowersec/releases) veröffentlicht.
