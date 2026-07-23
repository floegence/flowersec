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

raw QUIC und WebTransport bewahren das native Verhalten von FIN, RESET_STREAM, STOP_SENDING, Flusskontrolle und Migration. Flowersec deaktiviert 0-RTT auf Anwendungsebene und verwendet QUIC DATAGRAM nicht.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Lokal ausprobieren

Führe die v2-Unit-Suites aus:

```bash
make transport-v2-unit
```

Carrier-spezifische Nachweise liefern `make transport-conformance-smoke`, `make transport-browser-smoke` und `make transport-interop-smoke`.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDKs und Cookbooks

| Sprache | Paket | Öffentlicher Einstieg |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.NewConnector` |
| TypeScript | `@floegence/flowersec-core` | opake v2-Einstiege im Root sowie unter `/browser` und `/node` |
| Swift | SwiftPM-Produkt `Flowersec` | `ArtifactV2`, `ConnectorV2`, `SessionV2` |
| Rust | Crate `flowersec` | `Artifact`, `Connector`, `Session` |

Der [Cookbook-Index](examples/README.md) enthält ausschließlich v2-Beispiele und Verifikationsbefehle.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Portabler Vertrag

| Fähigkeit | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Opakes Artifact, Connector, Sitzung, RPC und Byte-Streams | Ja | Ja | Ja | Ja |
| WebSocket-Dialing für den Produktionseinsatz | Ja | Browser und Node.js | macOS | Nein |
| raw-QUIC-Dialing für den Produktionseinsatz | Ja | Nein | Nein | Ja |
| WebTransport-Dialing für den Produktionseinsatz | Ja | Browser | Nein | Nein |
| Listener-Unterstützung | Go-Bibliotheks-APIs | Einschränkungen der Browser-Runtime | Nicht ausgewiesen | Nicht ausgewiesen |

Jede Zeile zur Unterstützung ist durch produktiven Connector-Code und Ende-zu-Ende-Tests belegt. Nicht unterstützte Carrier werden sicher abgelehnt und dienen niemals als stiller Fallback. Capability-Deskriptoren und die Carrier-Auswahl bleiben intern.

<!-- readme-section:security -->
<a id="security"></a>

## Sicherheit

- Artifacts sind opake, begrenzte Einweg-Handles. Der dauerhafte Verbrauch ist abgeschlossen, bevor das erste Credential-Byte gesendet wird.
- Carrier der QUIC-Familie erfordern TLS 1.3, exaktes ALPN, explizite Trust Roots und deaktivierte Early Data.
- Öffentliche Fehler sind redigiert und begrenzt; Details zu Kandidaten, Wire, Keys und Ledger bleiben intern.
- Sitzungsabbruch, Deadlines, FIN, Reset, Liveness, Rekey und Bereinigung verhalten sich innerhalb definierter Grenzen.

Siehe die [Transport-v2-Architektur](docs/TRANSPORT_V2_ARCHITECTURE.md) und das [Bedrohungsmodell](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Bereitstellung und Entwicklung

Die Flowersec-Runtime stellt die produktiven Listener-Implementierungen für WebSocket, raw QUIC und WebTransport bereit. Anwendungs-SDKs erhalten ausschließlich opake Artifacts und Sitzungen; ausgemusterte Kompatibilitäts-CLIs gehören nicht zum v2-Vertrag.

Installiere die Repository-Hooks und führe vor der Integration das maßgebliche Gate aus:

```bash
make install-hooks
make check
```

Flowersec ist unter der [MIT License](LICENSE) verfügbar. Release-Artefakte werden über [GitHub Releases](https://github.com/floegence/flowersec/releases) veröffentlicht.
