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

El [índice de ejemplos](examples/README.md) contiene ejemplos pequeños y ejecutables de conexiones cliente, uso único duradero, emisión desde el plano de control, liveness y ciclo de vida de sesiones en cada SDK.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## Ejemplos

Empieza por el [índice de ejemplos](examples/README.md). Usa la misma API pública que una aplicación de producción y cubre conexiones cliente, emisión de invitaciones, uso único duradero, liveness y ciclo de vida de sesiones.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Lo que puede hacer tu aplicación

Los cuatro SDK comparten el mismo modelo de sesión. El soporte varía cuando una plataforma no puede ofrecer un tipo de conexión.

<!-- capability-table:start -->
| Capacidad de la aplicación | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Invitaciones de conexión opacas de un solo uso | Sí | Sí | Sí | Sí |
| Conexión segura de un solo intento | Sí | Sí | Sí | Sí |
| Sesiones cifradas de extremo a extremo | Sí | Sí | Sí | Sí |
| Llamadas RPC y notificaciones | Sí | Sí | Sí | Sí |
| Metadatos de flujo validados | Sí | Sí | Sí | Sí |
| Manejadores de flujos de aplicación | Sí | Sí | Sí | Sí |
| Recuperación de conexiones persistentes | Sí | Sí | Sí | Sí |
| Mensajes no fiables negociados | Sí | Sí | No | Sí |
| Manejadores RPC del cliente | Sí | Sí | No | Sí |
| Aceptación de sesiones en el servidor | Sí | Sí | No | Sí |
| Manejadores de sesiones del servidor | Sí | Sí | No | Sí |
| Emisión y autorización del plano de control | Sí | No | No | No |
| Admisión directa y por túnel | Sí | Sí | No | Sí |
| ProxyServer HTTP y WebSocket | Sí | Sí | No | Sí |
| Contrato de flujo independiente del transporte | Sí | Sí | Sí | Sí |
| Seguridad wire de Transport v3 | Sí | Sí | Sí | Sí |
<!-- capability-table:end -->
Los perfiles de despliegue separan la disponibilidad de plataforma del protocolo de aplicacion Flowersec compartido:

| Perfil | Runtimes | Superficie obligatoria de carrier y rol | Superficie opcional |
| --- | --- | --- | --- |
| `native-server-core` | Go, Rust, Node.js | Cliente endpoint, servidor directo y runtime de tunel opaco para WebSocket y raw QUIC | Adaptador WebTransport |
| `browser-client` | Navegador TypeScript | Cliente endpoint WebSocket | Adaptador WebTransport del navegador |
| `apple-client` | Swift en plataformas Apple | Cliente endpoint WSS | Ninguna |
| `webtransport-server` | Go | Servidor WebTransport directo y runtime de tunel opaco | Ninguna |

El perfil native-server-core legible por máquina contiene 18 tuplas agregadas de runtime, rol y carrier, seis por runtime nativo, y 24 unidades de servidor específicas de ruta compatibles. Go H4 añade dos tuplas de servidor WebTransport y dos unidades específicas de ruta. La matriz de interoperabilidad declara por separado 18 celdas directas y 18 celdas de túnel. La puerta de release verifica las 10 celdas directas y las 14 celdas de túnel por pares que incluyen Go; las 8 celdas directas y 4 celdas de túnel restantes siguen marcadas explícitamente como no verificadas. Cuatro perfiles cliente WSS adicionales verifican Swift y TypeScript de navegador con Go por rutas directas y de túnel. Un perfil nunca cambia la semántica wire de Artifact, handshake, RPC, stream, close, rekey o authorization.

Consulta las guías de cada SDK para ver las combinaciones exactas de plataforma y conexión compatibles.

WebTransport es un adaptador opcional y no forma parte del contrato de carrier native-server obligatorio. Go declara el perfil H4 webtransport-server independiente y completo; el perfil Browser usa H3 cuando la API WebTransport del navegador está disponible. Node.js y Rust no ofrecen actualmente un adaptador WebTransport de producción. La superficie carrier native-server es WebSocket y raw QUIC para Go, Rust y Node.js; la interoperabilidad por pares solo se declara mediante entradas compatibles de la matriz.

`flowersec-private-loopback/1` es un perfil privado del producto, fuera del deployment capability registry público. Sus API dedicadas de servidor Go y navegador TypeScript se limitan a un bridge HTTP de loopback numérico autenticado por la aplicación.

<!-- readme-section:security -->
<a id="security"></a>

## Seguridad

- Los datos de la aplicación se cifran de extremo a extremo tanto en sesiones directas como con relay.
- La política de confianza TLS está vinculada a cada candidato de transporte v3. Las raíces de CA públicas o proporcionadas por el despliegue y los pins explícitos del certificado hoja son mutuamente excluyentes, sin degradación tras un fallo.
- `flowersec-private-loopback/1` es un envelope de transporte aislado, no un modo TLS ni una capability de `flowersec/3`. Sus API dedicadas solo asignan un candidato v3 sin cambios en modo CA a `ws://` cuando la autoridad coincide con el mismo origen de loopback numérico y la aplicación del servidor autoriza la solicitud antes del upgrade. Las rutas ordinarias de Go, TypeScript, Rust, Swift, Provider y tunnel rechazan el envelope.
- Las invitaciones de conexión son opacas, de corta duración y de un solo uso.
- Las credenciales se consumen antes de usarse, por lo que una invitación gastada no puede reproducirse.
- Los relays solo reenvían tráfico cifrado; no terminan las sesiones de la aplicación.
- Los intentos inválidos o incompatibles fallan de forma segura con errores públicos limitados.

Para conocer el protocolo y el modelo de amenazas, consulta el [contrato de API](docs/API_CONTRACT.md), la [arquitectura de transporte](docs/TRANSPORT_V3_ARCHITECTURE.md) y el [modelo de amenazas](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Más información

- [Contrato de API](docs/API_CONTRACT.md): comportamiento estable compartido por los SDK.
- [Modelo de errores](docs/ERROR_MODEL.md): errores públicos de conexión, sesión y RPC.
- [Arquitectura de transporte](docs/TRANSPORT_V3_ARCHITECTURE.md): diseño de conexiones directas y con relay.
- [Ejemplos](examples/README.md): uso ejecutable de los SDK.

Flowersec está disponible bajo la [licencia MIT](LICENSE). Los paquetes publicados y las notas de versión están en [GitHub Releases](https://github.com/floegence/flowersec/releases).
