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

Der [Cookbook-Index](examples/README.md) enthält kleine ausführbare Beispiele für direkte Verbindungen, Relays, serverseitige Sitzungen und RPC.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## Beispiele

Beginne mit dem [Cookbook-Index](examples/README.md). Die Beispiele verwenden dieselbe öffentliche API wie Produktionsanwendungen und zeigen Client-Verbindungen, das Ausstellen von Verbindungseinladungen, dauerhafte Einmalverwendung und den Sitzungslebenszyklus.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Was deine Anwendung kann

Alle vier SDKs verwenden dasselbe Sitzungsmodell. Der Plattformumfang unterscheidet sich, wenn eine Runtime eine Verbindungsart nicht bereitstellen kann.

| Anwendungsfunktion | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Ende-zu-Ende-verschlüsselte Sitzungen | Ja | Ja | Ja | Ja |
| RPC-Aufrufe und Benachrichtigungen senden | Ja | Ja | Ja | Ja |
| RPC-Benachrichtigungen empfangen | Ja | Ja | Ja | Ja |
| Zuverlässige Byte-Streams | Ja | Ja | Ja | Ja |
| Wiederherstellung langlebiger Verbindungen | Ja | Ja | Ja | Ja |
| Unzuverlässige Nachrichten, wenn verfügbar | Ja | Ja | Nein | Ja |
| Browserverbindungen | Nein | Ja | Nein | Nein |
| Apple-Clientverbindungen | Nein | Nein | Ja | Nein |
| Native QUIC-Verbindungen | Ja | Node.js | Nein | Ja |
| WebSocket-Verbindungen | Ja | Ja | Ja | Ja |
| WebTransport-Verbindungen | Go direct | Browser | Nein | Nein |
| Serverseitige Sitzungsannahme | Ja | Node.js | Nein | Ja |
| Undurchsichtige Relay-Laufzeit | Ja | Node.js | Nein | Ja |
| Verbindungseinladungen der Control Plane | Ja | Node.js | Nein | Ja |
| HTTP- und WebSocket-ProxyServer | Ja | Node.js | Nein | Ja |

Bereitstellungsprofile trennen die Plattformverfuegbarkeit vom gemeinsamen Flowersec-Anwendungsprotokoll:

| Profil | Laufzeiten | Erforderliche Carrier- und Rollenoberflaeche | Optionale Oberflaeche |
| --- | --- | --- | --- |
| `native-server-core` | Go, Rust, Node.js | WebSocket- und Raw-QUIC-Endpunktclient, direkter Server und opake Tunnellaufzeit | WebTransport-Adapter |
| `browser-client` | TypeScript-Browser | WebSocket-Endpunktclient | Browser-WebTransport-Adapter |
| `apple-client` | Swift auf Apple-Plattformen | WSS-Endpunktclient | Keine |
| `webtransport-server` | Derzeit von keiner Laufzeit beansprucht | Vor einer Beanspruchung muessen direkter Server und opake Tunnellaufzeit konform sein | Keine |

Go, Rust und Node.js implementieren dieselben 18 erforderlichen Runtime-Rollen-Carrier-Tupel von `native-server-core`. Durch die Aufschluesselung direkter und getunnelter Pfade entstehen 24 pfadspezifische Servereinheiten. Die Konformitaet wird separat als 18 direkte Client-Server-Zellen und 18 paarweise Tunneltopologien gezaehlt. Ein Profil aendert niemals die Wire-Semantik fuer Artifact, Handshake, RPC, Stream, Close, Rekey oder Autorisierung.

Die SDK-Anleitungen nennen die genauen unterstützten Kombinationen aus Plattform und Verbindung.

<!-- readme-section:security -->
<a id="security"></a>

## Sicherheit

- Anwendungsdaten sind bei direkten und weitergeleiteten Sitzungen Ende zu Ende verschlüsselt.
- Verbindungseinladungen sind undurchsichtig, kurzlebig und nur einmal verwendbar.
- Zugangsdaten werden vor der Nutzung fest verbucht, damit eine verbrauchte Einladung nicht wiederholt werden kann.
- Relays leiten nur verschlüsselten Datenverkehr weiter und beenden keine Anwendungssitzungen.
- Ungültige oder nicht unterstützte Verbindungen schlagen sicher mit begrenzten öffentlichen Fehlern fehl.

Details zu Protokoll und Bedrohungsmodell stehen im [API-Vertrag](docs/API_CONTRACT.md), in der [Transportarchitektur](docs/TRANSPORT_V2_ARCHITECTURE.md) und im [Bedrohungsmodell](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Mehr erfahren

- [API-Vertrag](docs/API_CONTRACT.md): stabiles Anwendungsverhalten aller SDKs.
- [Fehlermodell](docs/ERROR_MODEL.md): öffentliche Verbindungs-, Sitzungs- und RPC-Fehler.
- [Transportarchitektur](docs/TRANSPORT_V2_ARCHITECTURE.md): Design direkter und weitergeleiteter Verbindungen.
- [Beispiele](examples/README.md): ausführbare SDK-Nutzung.

Flowersec ist unter der [MIT License](LICENSE) verfügbar. Veröffentlichte Pakete und Versionshinweise findest du in den [GitHub Releases](https://github.com/floegence/flowersec/releases).
