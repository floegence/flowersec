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
  <strong>Português do Brasil</strong> |
  <a href="README.ru-RU.md">Русский</a>
</p>
<!-- readme-locales:end -->

<p align="center"><strong>Sessões independentes de carrier, com criptografia de ponta a ponta, para Go, TypeScript, Swift e Rust.</strong></p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Por que usar Flowersec

- Um único contrato para artifacts e sessões opacos nos quatro SDKs.
- WebSocket, raw QUIC e WebTransport são opções de carrier equivalentes.
- RPC e fluxos de bytes compartilham uma sessão autenticada sem expor às aplicações objetos de carrier, wire, chave ou ledger.
- Relays em modo Tunnel encaminham fluxos criptografados sem encerrar a criptografia da aplicação.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## Como funciona

| Caminho | Formato da conexão | Transporte dos fluxos |
| --- | --- | --- |
| Direct | O cliente se conecta a um endpoint por meio de um candidato compatível | WebSocket usa Yamux local em cada salto; carriers da família QUIC usam fluxos bidirecionais nativos |
| Tunnel | As pontas do cliente e do servidor são unidas por carriers compatíveis selecionados de forma independente | O Tunnel mapeia fluxos criptografados entre as pontas sem escolher um carrier principal |

Raw QUIC e WebTransport preservam o comportamento nativo de FIN, RESET_STREAM, STOP_SENDING, controle de fluxo e migração. O Flowersec desativa o 0-RTT da aplicação e não usa QUIC DATAGRAM.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Teste localmente

Execute as suítes de testes unitários v2:

```bash
make transport-v2-unit
```

Para obter evidências específicas de cada carrier, execute `make transport-conformance-smoke`, `make transport-browser-smoke` e `make transport-interop-smoke`.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDKs e Cookbooks

| Linguagem | Pacote | Entrada pública |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.NewConnector` |
| TypeScript | `@floegence/flowersec-core` | entradas opacas v2 na raiz, em `/browser` e em `/node` |
| Swift | Produto SwiftPM `Flowersec` | `ArtifactV2`, `ConnectorV2`, `SessionV2` |
| Rust | crate `flowersec` | `Artifact`, `Connector`, `Session` |

O [índice de Cookbooks](examples/README.md) contém somente exemplos v2 e comandos de verificação.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Contrato portável

| Capacidade | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Artifact opaco, connector, sessão, RPC e fluxos de bytes | Sim | Sim | Sim | Sim |
| Discagem WebSocket em produção | Sim | Browser e Node.js | macOS | Não |
| Discagem raw QUIC em produção | Sim | Não | Não | Sim |
| Discagem WebTransport em produção | Sim | Browser | Não | Não |
| Suporte a listener | APIs da biblioteca Go | Restrições do ambiente de execução do navegador | Não anunciado | Não anunciado |

Cada linha de suporte é respaldada por código de connector de produção e testes de ponta a ponta. Carriers sem suporte falham de forma fechada; nunca funcionam como fallbacks silenciosos. Os descritores de capacidade e a seleção de carrier permanecem internos.

<!-- readme-section:security -->
<a id="security"></a>

## Segurança

- Artifacts são handles opacos, limitados e de uso único. O registro persistente do consumo é concluído antes do envio do primeiro byte de credencial.
- Carriers da família QUIC exigem TLS 1.3, ALPN exato, raízes de confiança explícitas e early data desativado.
- Erros públicos são sanitizados e limitados; detalhes de candidate, wire, chave e ledger permanecem internos.
- Cancelamento de sessão, deadlines, FIN, reset, liveness, rekey e limpeza obedecem a limites definidos.

Consulte a [arquitetura do Transport v2](docs/TRANSPORT_V2_ARCHITECTURE.md) e o [modelo de ameaças](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Implantação e desenvolvimento

O runtime do Flowersec fornece as implementações dos listeners de produção para WebSocket, raw QUIC e WebTransport. Os SDKs de aplicação recebem apenas artifacts e sessões opacos; nenhuma CLI de compatibilidade removida faz parte do contrato v2.

Instale os hooks do repositório e execute a verificação oficial antes da integração:

```bash
make install-hooks
make check
```

Flowersec está disponível sob a [licença MIT](LICENSE). Os artefatos de release são publicados por meio do [GitHub Releases](https://github.com/floegence/flowersec/releases).
