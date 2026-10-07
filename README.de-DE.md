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

<p align="center"><strong>Verbinde die Teile deiner Anwendung sicher, ganz gleich, wo sie laufen.</strong></p>
<p align="center">Flowersec bietet Go, TypeScript, Swift und Rust eine einfache API für Ende-zu-Ende-verschlüsselte Sitzungen, RPC, Benachrichtigungen und Byte-Streams.</p>

[![Neueste Version](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![Lizenz](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Warum Flowersec

Flowersec richtet sich an Anwendungen, die Clients, Dienste und Geräte privat verbinden müssen, ohne Transportlogik in den Anwendungscode zu ziehen.

- **Ein Programmiermodell:** Nutze dieselbe authentifizierte Sitzungs-API in Go, TypeScript, Swift und Rust.
- **Funktionen für echte Anwendungen:** RPC-Aufrufe, Benachrichtigungen und zuverlässige Byte-Streams laufen über eine Verbindung.
- **Passend zum Netzwerk:** Stelle direkte Verbindungen her oder nutze bei Bedarf ein Relay, ohne das Anwendungsprotokoll zu ändern.
- **Datenschutz als Standard:** Anwendungsdaten sind Ende zu Ende verschlüsselt. Ein Relay kann sie weiterleiten, aber nicht lesen.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## Funktionsweise

Flowersec trennt die Anwendungssitzung von dem Netzwerkpfad, der sie transportiert:

1. Dein Dienst erstellt eine kurzlebige Verbindungseinladung und übergibt sie an den Client.
2. Das SDK baut über eine verfügbare direkte oder weitergeleitete Verbindung eine sichere Sitzung auf.
3. Die Anwendung nutzt RPC, Benachrichtigungen und Byte-Streams über dieselbe Sitzungs-API.

Direkte und weitergeleitete Verbindungen liefern deinem Code dieselbe Sitzung. Auswahl, Zugangsdaten und Routing bleiben im SDK und in der Runtime.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Loslegen

Wähle das SDK für deine Anwendung:

| SDK | Geeignet für | Installations- und API-Anleitung |
| --- | --- | --- |
| Go | Dienste, Gateways und Control-Plane-Code | [Go SDK](flowersec-go/README.md) |
| TypeScript | Browser- und Node.js-Anwendungen | [TypeScript SDK](flowersec-ts/README.md) |
| Swift | macOS- und iOS-Clients | [Swift SDK](flowersec-swift/README.md) |
| Rust | Tokio-Dienste mit nativem QUIC | [Rust SDK](flowersec-rust/README.md) |

Der [Cookbook-Index](examples/README.md) enthält kleine ausführbare Beispiele für Client-Verbindungen, dauerhafte Einmalverwendung, Control-Plane-Ausstellung, Liveness und den Sitzungslebenszyklus in jedem SDK.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## Beispiele

Beginne mit dem [Cookbook-Index](examples/README.md). Die Beispiele verwenden dieselbe öffentliche API wie Produktionsanwendungen und zeigen Client-Verbindungen, das Ausstellen von Verbindungseinladungen, dauerhafte Einmalverwendung, Liveness und den Sitzungslebenszyklus.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Was deine Anwendung kann

Alle vier SDKs verwenden dasselbe Sitzungsmodell. Der Plattformumfang unterscheidet sich, wenn eine Runtime eine Verbindungsart nicht bereitstellen kann.

<!-- capability-table:start -->
| Anwendungsfunktion | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Opake, einmal verwendbare Verbindungseinladungen | Ja | Ja | Ja | Ja |
| Einmalige sichere Verbindung | Ja | Ja | Ja | Ja |
| Ende-zu-Ende-verschlüsselte Sitzungen | Ja | Ja | Ja | Ja |
| RPC-Aufrufe und Benachrichtigungen | Ja | Ja | Ja | Ja |
| Validierte Stream-Metadaten | Ja | Ja | Ja | Ja |
| Handler für Anwendungsstreams | Ja | Ja | Ja | Ja |
| Wiederherstellung langlebiger Verbindungen | Ja | Ja | Ja | Ja |
| Ausgehandelte unzuverlässige Nachrichten | Ja | Ja | Nein | Ja |
| Clientseitige RPC-Handler | Ja | Ja | Ja | Ja |
| Serverseitige Sitzungsannahme | Ja | Ja | Ja | Ja |
| Serverseitige Sitzungs-Handler | Ja | Ja | Ja | Ja |
| Ausgabe und Autorisierung der Control Plane | Ja | Nein | Nein | Nein |
| Zulassung direkter und getunnelter Verbindungen | Ja | Ja | Ja | Ja |
| HTTP- und WebSocket-ProxyServer | Ja | Ja | Nein | Ja |
| Carrier-neutraler Stream-Vertrag | Ja | Ja | Ja | Ja |
| Transport-v4-Wire-Sicherheit | Ja | Ja | Ja | Ja |
<!-- capability-table:end -->

Deployment-Profile beschreiben erforderliche native oder Browser-Carrier und Rollen. Jeder SDK-Leitfaden trennt aktuelle APIs von der Provider-Qualifikation. Eine Quellcodedeklaration belegt keine geprüfte Laufzeitunterstützung.

Das aktuelle Protokoll verwendet authentifizierte Verbindungsmaterialien, unabhängiges Namespace-Vertrauen, begrenzte Sitzungen, typisierte Dienste und explizite Bereinigung. Direkte und getunnelte Interoperabilität wird anhand der ausführbaren Matrix und der ursprünglichen Provider qualifiziert. Releases veröffentlichen Pakete und lesen Registries zurück; sie führen keine Akzeptanztests aus.

WebTransport benötigt einen konfigurierten nativen oder Browser-Provider. Browser-Unterstützung hängt von der tatsächlichen WebTransport-API und den Zertifikatsrichtlinien ab. Die aktuellen Carrier-, Listener- und Relay-Funktionen stehen im jeweiligen SDK-Leitfaden.

Die signierte Zugriffsklasse `local_loopback` unterstützt eine von der Anwendung authentifizierte HTTP-Bridge auf demselben Rechner. Sie verwendet das aktuelle Sitzungsprotokoll und benötigt einen konfigurierten lokalen Provider.

<!-- readme-section:security -->
<a id="security"></a>

## Sicherheit

- Anwendungsdaten sind bei direkten und weitergeleiteten Sitzungen Ende zu Ende verschlüsselt.
- Die TLS-Vertrauensrichtlinie ist an jeden v4-Transportkandidaten gebunden. Öffentliche oder bereitgestellte CA-Wurzeln und explizite Leaf-Zertifikat-Pins schließen sich gegenseitig aus; nach einem Fehler gibt es keine Herabstufung.
- `local_loopback` erlaubt `ws://` nur für einen signierten numerischen Loopback-Endpunkt mit exaktem Origin und Anwendungsautorisierung vor dem Upgrade. Es behauptet keine äußere TLS-Verifikation und erlaubt keinen Klartext-Fallback.
- Verbindungseinladungen sind undurchsichtig, kurzlebig und nur einmal verwendbar.
- Zugangsdaten werden vor der Nutzung fest verbucht, damit eine verbrauchte Einladung nicht wiederholt werden kann.
- Relays leiten nur verschlüsselten Datenverkehr weiter und beenden keine Anwendungssitzungen.
- Ungültige oder nicht unterstützte Verbindungen schlagen sicher mit begrenzten öffentlichen Fehlern fehl.

Details zu Protokoll und Bedrohungsmodell stehen im [API-Vertrag](docs/API_CONTRACT.md), in der [Transportarchitektur](docs/TRANSPORT_V4_BINDING.md) und im [Bedrohungsmodell](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Mehr erfahren

- [API-Vertrag](docs/API_CONTRACT.md): stabiles Anwendungsverhalten aller SDKs.
- [Fehlermodell](docs/ERROR_MODEL.md): öffentliche Verbindungs-, Sitzungs- und RPC-Fehler.
- [Transportarchitektur](docs/TRANSPORT_V4_BINDING.md): Design direkter und weitergeleiteter Verbindungen.
- [Beispiele](examples/README.md): ausführbare SDK-Nutzung.

Flowersec ist unter der [MIT License](LICENSE) verfügbar. Veröffentlichte Pakete und Versionshinweise findest du in den [GitHub Releases](https://github.com/floegence/flowersec/releases).
