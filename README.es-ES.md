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

Raw QUIC y WebTransport conservan el comportamiento nativo de FIN, RESET_STREAM, STOP_SENDING, control de flujo y migración. Flowersec desactiva el 0-RTT de aplicación. Los flujos fiables nunca usan QUIC DATAGRAM; los runtimes que negocian DATAGRAM nativo solo lo exponen mediante mensajes no fiables independientes del carrier.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Prueba local

Ejecuta la suite de aceptación predeterminada:

```bash
make test
```

Después de corregir un fallo, usa `make test-resume` para continuar desde la primera prueba incompleta hasta el siguiente fallo o hasta `ALL GREEN`. Los ID completados siguen siendo válidos aunque cambie el commit de origen.

Usa `make coverage-race` para los lanes de cobertura de los cuatro lenguajes y la prueba race exclusiva de Go. Usa `make browser-smoke` para las tres topologías locales de Chromium y `make browser-compat` para comprobar explícitamente las capacidades de Firefox/WebKit. Los diagnósticos privilegiados de red débil y kernel usan `make diagnostic`; las pruebas de capacidad y soak usan `make performance`.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK y guías prácticas

| Lenguaje | Paquete | Entrada pública |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.Connect`, `flowersec.NewConnectionController`, `flowersec.NewAcceptor` |
| TypeScript | `@floegence/flowersec-core` | puntos de entrada opacos v2 en la raíz, `/browser`, `/node` y `/proxy` |
| Swift | Producto SwiftPM `Flowersec` | `Artifact`, `connect`, `Session` |
| Rust | crate `flowersec` | `Artifact`, `connect`, `Session` |

Los planos de control de servicios en Go usan el paquete separado `github.com/floegence/flowersec/flowersec-go/v2/controlplane` para emitir artifacts opacos y responder a los callbacks de autorización de `flowersec-runtime`.

El [índice de guías prácticas](examples/README.md) contiene únicamente ejemplos v2 y comandos de verificación.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Capacidades de los SDK

Las capacidades siguientes se agrupan por workflows que los desarrolladores de aplicaciones pueden usar directamente, no por objetos internos del protocolo. Cada perfil de SDK declara su frontera específica de runtime y plataforma. Una limitación de plataforma solo puede figurar como no compatible si `stability/language_capabilities.json` incluye un motivo explícito, una frontera pública alternativa y un ID de prueba ejecutable. La persistencia del control plane es una frontera de servicio: los clientes llaman al servicio autenticado que usa `flowersec-go/v2/controlplane`; no incorporan un segundo emisor ni datastore. Una comodidad específica de un lenguaje adapta la sintaxis o la orquestación a su ecosistema sin cambiar los workflows compartidos. El comportamiento de recuperación de conexiones se describe mediante la disposición estructurada del controlador.

| Capacidad | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Sesiones cifradas de extremo a extremo, RPC y flujos de bytes | Sí | Sí | Sí | Sí |
| Recuperación automática de conexiones persistentes | Sí | Sí | Sí | Sí |
| Mensajería no fiable | Sí | Sí | No | Sí |
| Recepción de notificaciones RPC | No | Sí | No | No |
| Gestión de solicitudes RPC entrantes | Sí | No | No | No |
| Conexiones cliente WebSocket | Sí | Navegador y Node.js | macOS e iOS | No |
| Conexiones cliente raw QUIC | Sí | No | No | Sí |
| Conexiones cliente WebTransport | Sí | Navegador y Node.js | No | No |
| Aceptación de sesiones en el servidor | `NewAcceptor` | `createAcceptor` / `AcceptedSession` | No compatible con el perfil listener de Apple | `Acceptor::bind` / `accept_with_handlers` |
| Emisión y autorización de artifacts del control plane | `flowersec-go/v2/controlplane` | No compatible; frontera del servicio de la aplicación | No compatible; frontera del servicio de la aplicación | No compatible; frontera del servicio de la aplicación |

Solo se aceptan las tuplas de carrier declaradas; las no compatibles se rechazan de forma segura. Cada fila está respaldada por código de connector de producción y un ID de prueba explícito en `stability/language_capabilities.json`. Las capacidades no compatibles incluyen un motivo y una frontera alternativa. Los descriptores de capacidades y la selección del carrier permanecen internos.

<!-- readme-section:security -->
<a id="security"></a>

## Seguridad

- Los artefactos son handles opacos, acotados y de un solo uso. Su consumo queda registrado de forma duradera antes de enviar el primer byte de credenciales.
- Los carriers de la familia QUIC exigen TLS 1.3, un ALPN exacto, raíces de confianza explícitas y early data desactivado.
- Los errores públicos están redactados y acotados; los detalles sobre candidatos, protocolo de red, claves y registros permanecen internos.
- Las disposiciones estructuradas del controlador solo autorizan un nuevo intento con un artefacto nuevo; nunca reutilizan credenciales ni repiten trabajo de una sesión terminada.
- La cancelación de sesiones, los plazos, FIN, reset, la detección de actividad, la renovación de claves y la limpieza tienen un comportamiento acotado.

Consulta la [arquitectura de Transport v2](docs/TRANSPORT_V2_ARCHITECTURE.md) y el [modelo de amenazas](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Desplegar y desarrollar

El runtime de Flowersec proporciona implementaciones de listeners de producción para WebSocket, raw QUIC y WebTransport. Los SDK de aplicación reciben únicamente artefactos y sesiones opacos; las CLI del runtime componen las mismas implementaciones de connector y acceptor.

Instala los hooks del repositorio y ejecuta la validación obligatoria antes de integrar:

```bash
make install-hooks
make precommit
```

`scripts/push-main.sh` ejecuta la suite de aceptación local acotada antes de enviar el SHA exacto de main. La comprobación de ingeniería completa y los workflows explícitos nightly, diagnostic y performance cubren la compatibilidad, los diagnósticos privilegiados y las pruebas de carga; la publicación no ejecuta pruebas.

Flowersec está disponible bajo la [licencia MIT](LICENSE). Los artefactos de cada versión se publican mediante [GitHub Releases](https://github.com/floegence/flowersec/releases).
