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

| Anwendungsfunktion | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Ende-zu-Ende-verschlüsselte Sitzungen | Ja | Ja | Ja | Ja |
| RPC-Aufrufe und Benachrichtigungen senden | Ja | Ja | Ja | Ja |
| RPC-Benachrichtigungen empfangen | Ja | Ja | Ja | Ja |
| Zuverlässige Byte-Streams | Ja | Ja | Ja | Ja |
| Anwendungs-Streams in jeder Sitzung bedienen | Ja | Ja | Ja | Ja |
| Wiederherstellung langlebiger Verbindungen | Ja | Ja | Ja | Ja |
| Unzuverlässige Nachrichten, wenn verfügbar | Ja | Ja | Nein | Ja |
| Browserverbindungen | Nein | Ja | Nein | Nein |
| Apple-Clientverbindungen | Nein | Nein | Ja | Nein |
| Native QUIC-Verbindungen | Ja | Node.js | Nein | Ja |
| WebSocket-Verbindungen | Ja | Ja | Ja | Ja |
| WebTransport-Verbindungen | Go H4 | Browser H3 client (wenn die WebTransport-API verfügbar ist) | Nein | Nein |
| Serverseitige Sitzungsannahme | Ja | Node.js | Nein | Ja |
| Undurchsichtige Relay-Laufzeit | Ja | Node.js | Nein | Ja |
| Verbindungseinladungen der Control Plane | Ja | Nein | Nein | Nein |
| HTTP- und WebSocket-ProxyServer | Ja | Node.js | Nein | Ja |

Bereitstellungsprofile trennen die Plattformverfuegbarkeit vom gemeinsamen Flowersec-Anwendungsprotokoll:

| Profil | Laufzeiten | Erforderliche Carrier- und Rollenoberflaeche | Optionale Oberflaeche |
| --- | --- | --- | --- |
| `native-server-core` | Go, Rust, Node.js | WebSocket- und Raw-QUIC-Endpunktclient, direkter Server und opake Tunnellaufzeit | WebTransport-Adapter |
| `browser-client` | TypeScript-Browser | WebSocket-Endpunktclient | Browser-WebTransport-Adapter |
| `apple-client` | Swift auf Apple-Plattformen | WSS-Endpunktclient | Keine |
| `webtransport-server` | Go | WebTransport-Direktserver und opake Tunnellaufzeit | Keine |

Das maschinenlesbare native-server-core-Profil enthaelt 18 aggregierte Runtime-Rollen-Carrier-Tupel, sechs pro nativer Laufzeit, und 24 unterstuetzte pfadspezifische Servereinheiten. Go H4 fuegt zwei WebTransport-Server-Tupel und zwei pfadspezifische Einheiten hinzu. Die Interoperabilitaetsmatrix deklariert separat 18 direkte Zellen und 18 Tunnelzellen. Das Release-Gate prueft alle 10 direkten Zellen und 14 paarweisen Tunnelzellen mit Go; die verbleibenden 8 direkten und 4 Tunnelzellen bleiben explizit ungeprueft. Vier zusaetzliche WSS-Clientprofile pruefen Swift und Browser-TypeScript gegen Go ueber direkte und getunnelte Pfade. Ein Profil aendert niemals die Wire-Semantik fuer Artifact, Handshake, RPC, Stream, Close, Rekey oder Autorisierung.

Die SDK-Anleitungen nennen die genauen unterstützten Kombinationen aus Plattform und Verbindung.

WebTransport ist optional und nicht Teil des erforderlichen native-server-carrier-Vertrags. Go beansprucht das separate vollstaendige H4-webtransport-server-Profil; das Browser-Profil verwendet H3, wenn die Browser-WebTransport-API verfügbar ist. Node.js und Rust bieten derzeit keinen produktiven WebTransport-Adapter. Die native-server-carrier-Oberflaeche ist WebSocket und raw QUIC fuer Go, Rust und Node.js; paarweise Interoperabilitaet wird nur durch unterstuetzte Matrixeintraege beansprucht.

`flowersec-private-loopback/1` ist ein produktprivates Profil außerhalb des öffentlichen deployment capability registry. Seine dedizierten APIs für Go-Server und TypeScript-Browser sind auf eine von der Anwendung authentifizierte numerische Loopback-HTTP-Bridge beschränkt.

<!-- readme-section:security -->
<a id="security"></a>

## Sicherheit

- Anwendungsdaten sind bei direkten und weitergeleiteten Sitzungen Ende zu Ende verschlüsselt.
- Die TLS-Vertrauensrichtlinie ist an jeden v3-Transportkandidaten gebunden. Öffentliche oder bereitgestellte CA-Wurzeln und explizite Leaf-Zertifikat-Pins schließen sich gegenseitig aus; nach einem Fehler gibt es keine Herabstufung.
- `flowersec-private-loopback/1` ist ein isolierter Transport-Envelope und kein TLS-Modus oder Capability von `flowersec/3`. Seine dedizierten APIs bilden genau einen unveränderten CA-Modus-v3-Kandidaten nur dann auf `ws://` ab, wenn die Authority demselben numerischen Loopback-Origin entspricht und die Serveranwendung die Anfrage vor dem Upgrade autorisiert. Gewöhnliche Go-, TypeScript-, Rust-, Swift-, Provider- und Tunnelpfade lehnen den Envelope ab.
- Verbindungseinladungen sind undurchsichtig, kurzlebig und nur einmal verwendbar.
- Zugangsdaten werden vor der Nutzung fest verbucht, damit eine verbrauchte Einladung nicht wiederholt werden kann.
- Relays leiten nur verschlüsselten Datenverkehr weiter und beenden keine Anwendungssitzungen.
- Ungültige oder nicht unterstützte Verbindungen schlagen sicher mit begrenzten öffentlichen Fehlern fehl.

Details zu Protokoll und Bedrohungsmodell stehen im [API-Vertrag](docs/API_CONTRACT.md), in der [Transportarchitektur](docs/TRANSPORT_V3_ARCHITECTURE.md) und im [Bedrohungsmodell](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Mehr erfahren

- [API-Vertrag](docs/API_CONTRACT.md): stabiles Anwendungsverhalten aller SDKs.
- [Fehlermodell](docs/ERROR_MODEL.md): öffentliche Verbindungs-, Sitzungs- und RPC-Fehler.
- [Transportarchitektur](docs/TRANSPORT_V3_ARCHITECTURE.md): Design direkter und weitergeleiteter Verbindungen.
- [Beispiele](examples/README.md): ausführbare SDK-Nutzung.

Flowersec ist unter der [MIT License](LICENSE) verfügbar. Veröffentlichte Pakete und Versionshinweise findest du in den [GitHub Releases](https://github.com/floegence/flowersec/releases).
