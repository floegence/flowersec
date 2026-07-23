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
  <strong>Español</strong> |
  <a href="README.pt-BR.md">Português do Brasil</a> |
  <a href="README.ru-RU.md">Русский</a>
</p>
<!-- readme-locales:end -->

<p align="center"><strong>Sesiones independientes del carrier y cifradas de extremo a extremo para Go, TypeScript, Swift y Rust.</strong></p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Por qué Flowersec

- Un único artefacto opaco y un contrato de sesión común para los cuatro SDK.
- WebSocket, raw QUIC y WebTransport son candidatos de carrier equivalentes.
- RPC y los flujos de bytes comparten una sesión autenticada sin exponer a las aplicaciones objetos del carrier, del protocolo de red, de claves ni del registro.
- Los relays de Tunnel reenvían flujos cifrados sin descifrar los datos de la aplicación.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## Cómo funciona

| Ruta | Forma de conexión | Transporte de flujos |
| --- | --- | --- |
| Direct | El cliente se conecta a un endpoint mediante un candidato compatible | WebSocket usa Yamux local al salto; los carriers de la familia QUIC usan flujos bidireccionales nativos |
| Tunnel | Los extremos de cliente y servidor se unen mediante carriers compatibles seleccionados de forma independiente | El Tunnel asocia los flujos cifrados de ambos extremos sin elegir un carrier principal |

Raw QUIC y WebTransport conservan el comportamiento nativo de FIN, RESET_STREAM, STOP_SENDING, control de flujo y migración. Flowersec desactiva el 0-RTT de aplicación y no usa QUIC DATAGRAM.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Prueba local

Ejecuta las pruebas unitarias de v2:

```bash
make transport-v2-unit
```

Para obtener evidencia específica de cada carrier, ejecuta `make transport-conformance-smoke`, `make transport-browser-smoke` y `make transport-interop-smoke`.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK y guías prácticas

| Lenguaje | Paquete | Entrada pública |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.NewConnector` |
| TypeScript | `@floegence/flowersec-core` | puntos de entrada opacos v2 en la raíz, `/browser` y `/node` |
| Swift | Producto SwiftPM `Flowersec` | `ArtifactV2`, `ConnectorV2`, `SessionV2` |
| Rust | crate `flowersec` | `Artifact`, `Connector`, `Session` |

El [índice de guías prácticas](examples/README.md) contiene únicamente ejemplos v2 y comandos de verificación.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Contrato común

| Capacidad | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Artefacto opaco, conector, sesión, RPC y flujos de bytes | Sí | Sí | Sí | Sí |
| Conexión WebSocket en producción | Sí | Navegador y Node.js | macOS | No |
| Conexión raw QUIC en producción | Sí | No | No | Sí |
| Conexión WebTransport en producción | Sí | Navegador | No | No |
| Compatibilidad con listeners | API de biblioteca de Go | Restricciones del navegador | No se anuncia | No se anuncia |

Cada fila de compatibilidad está respaldada por conectores de producción y pruebas de extremo a extremo. Los carriers no compatibles se rechazan de forma segura; nunca activan alternativas silenciosas. Los descriptores de capacidades y la selección del carrier permanecen internos.

<!-- readme-section:security -->
<a id="security"></a>

## Seguridad

- Los artefactos son handles opacos, acotados y de un solo uso. Su consumo queda registrado de forma duradera antes de enviar el primer byte de credenciales.
- Los carriers de la familia QUIC exigen TLS 1.3, un ALPN exacto, raíces de confianza explícitas y early data desactivado.
- Los errores públicos están redactados y acotados; los detalles sobre candidatos, protocolo de red, claves y registros permanecen internos.
- La cancelación de sesiones, los plazos, FIN, reset, la detección de actividad, la renovación de claves y la limpieza tienen un comportamiento acotado.

Consulta la [arquitectura de Transport v2](docs/TRANSPORT_V2_ARCHITECTURE.md) y el [modelo de amenazas](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Desplegar y desarrollar

El runtime de Flowersec proporciona implementaciones de listeners de producción para WebSocket, raw QUIC y WebTransport. Los SDK de aplicación reciben únicamente artefactos y sesiones opacos; ninguna CLI de compatibilidad eliminada forma parte del contrato v2.

Instala los hooks del repositorio y ejecuta la validación obligatoria antes de integrar:

```bash
make install-hooks
make check
```

Flowersec está disponible bajo la [licencia MIT](LICENSE). Los artefactos de cada versión se publican mediante [GitHub Releases](https://github.com/floegence/flowersec/releases).
