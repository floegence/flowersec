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

<p align="center"><strong>Conecta de forma segura las partes de tu aplicación, estén donde estén.</strong></p>
<p align="center">Flowersec ofrece a Go, TypeScript, Swift y Rust una API sencilla para sesiones cifradas de extremo a extremo, RPC, notificaciones y flujos de bytes.</p>

[![Última versión](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![Licencia](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Por qué Flowersec

Flowersec está pensado para aplicaciones que necesitan conexiones privadas entre clientes, servicios y dispositivos sin mezclar la lógica de transporte con el código de negocio.

- **Un solo modelo de programación:** usa la misma API de sesión autenticada en Go, TypeScript, Swift y Rust.
- **Funciones que las aplicaciones necesitan:** RPC, notificaciones y flujos de bytes fiables en una única conexión.
- **Conexiones adaptadas a la red:** conecta directamente o mediante un relay sin cambiar el protocolo de la aplicación.
- **Privacidad por defecto:** los datos se cifran de extremo a extremo. El relay puede reenviarlos, pero no leerlos.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## Cómo funciona

Flowersec separa la sesión de la aplicación de la ruta de red que la transporta:

1. Tu servicio crea una invitación de conexión de corta duración y se la entrega al cliente.
2. El SDK establece una sesión segura mediante una conexión directa o con relay disponible.
3. La aplicación usa RPC, notificaciones y flujos de bytes desde la misma API de sesión.

Las conexiones directas y con relay presentan la misma sesión al código. La selección, las credenciales y el enrutamiento permanecen dentro del SDK y del runtime.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Empieza a desarrollar

Elige el SDK que mejor encaje con tu aplicación:

| SDK | Uso recomendado | Guía de instalación y API |
| --- | --- | --- |
| Go | Servicios, gateways y código de plano de control | [Go SDK](flowersec-go/README.md) |
| TypeScript | Aplicaciones web y Node.js | [TypeScript SDK](flowersec-ts/README.md) |
| Swift | Clientes macOS e iOS | [Swift SDK](flowersec-swift/README.md) |
| Rust | Servicios Tokio que necesitan QUIC nativo | [Rust SDK](flowersec-rust/README.md) |

El [índice de ejemplos](examples/README.md) contiene ejemplos pequeños y ejecutables de conexiones directas, relays, aceptación de sesiones en servidor y RPC.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## Ejemplos

Empieza por el [índice de ejemplos](examples/README.md). Usa la misma API pública que una aplicación de producción y cubre conexiones cliente, emisión de invitaciones, uso único duradero y ciclo de vida de sesiones.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Lo que puede hacer tu aplicación

Los cuatro SDK comparten el mismo modelo de sesión. El soporte varía cuando una plataforma no puede ofrecer un tipo de conexión.

| Capacidad de la aplicación | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Sesiones cifradas de extremo a extremo | Sí | Sí | Sí | Sí |
| Enviar llamadas RPC y notificaciones | Sí | Sí | Sí | Sí |
| Recibir notificaciones RPC | No | Sí | No | No |
| Flujos de bytes fiables | Sí | Sí | Sí | Sí |
| Recuperación de conexiones duraderas | Sí | Sí | Sí | Sí |
| Mensajes no fiables cuando estén disponibles | Sí | Sí | No | Sí |
| Conexiones desde navegador | No | Sí | No | No |
| Conexiones de clientes Apple | No | No | Sí | No |
| Conexiones QUIC nativas | Sí | No | No | Sí |
| Conexiones WebSocket | Sí | Sí | Sí | No |
| Conexiones WebTransport | Sí | Sí | No | No |
| Aceptación de sesiones en servidor | Sí | Node.js | No | Sí |
| Emisión de invitaciones desde el plano de control | Paquete Go | Servicio de la aplicación | Servicio de la aplicación | Servicio de la aplicación |

Consulta las guías de cada SDK para ver las combinaciones exactas de plataforma y conexión compatibles.

<!-- readme-section:security -->
<a id="security"></a>

## Seguridad

- Los datos de la aplicación se cifran de extremo a extremo tanto en sesiones directas como con relay.
- Las invitaciones de conexión son opacas, de corta duración y de un solo uso.
- Las credenciales se consumen antes de usarse, por lo que una invitación gastada no puede reproducirse.
- Los relays solo reenvían tráfico cifrado; no terminan las sesiones de la aplicación.
- Los intentos inválidos o incompatibles fallan de forma segura con errores públicos limitados.

Para conocer el protocolo y el modelo de amenazas, consulta el [contrato de API](docs/API_CONTRACT.md), la [arquitectura de transporte](docs/TRANSPORT_V2_ARCHITECTURE.md) y el [modelo de amenazas](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Más información

- [Contrato de API](docs/API_CONTRACT.md): comportamiento estable compartido por los SDK.
- [Modelo de errores](docs/ERROR_MODEL.md): errores públicos de conexión, sesión y RPC.
- [Arquitectura de transporte](docs/TRANSPORT_V2_ARCHITECTURE.md): diseño de conexiones directas y con relay.
- [Ejemplos](examples/README.md): uso ejecutable de los SDK.

Flowersec está disponible bajo la [licencia MIT](LICENSE). Los paquetes publicados y las notas de versión están en [GitHub Releases](https://github.com/floegence/flowersec/releases).
