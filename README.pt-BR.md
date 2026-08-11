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

<p align="center"><strong>Conecte com segurança as partes do seu aplicativo, onde quer que estejam.</strong></p>
<p align="center">Flowersec oferece a Go, TypeScript, Swift e Rust uma API simples para sessões criptografadas de ponta a ponta, RPC, notificações e fluxos de bytes.</p>

[![Versão mais recente](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![Licença](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Por que usar Flowersec

Flowersec é para aplicativos que precisam conectar clientes, serviços e dispositivos com privacidade, sem misturar lógica de transporte ao código da aplicação.

- **Um modelo de programação:** use a mesma API de sessão autenticada em Go, TypeScript, Swift e Rust.
- **Recursos que os aplicativos usam:** RPC, notificações e fluxos de bytes confiáveis em uma única conexão.
- **Conexões adequadas à rede:** conecte diretamente ou use um relay quando necessário, sem alterar o protocolo do aplicativo.
- **Privacidade por padrão:** os dados são criptografados de ponta a ponta. O relay pode encaminhá-los, mas não lê-los.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## Como funciona

Flowersec separa a sessão do aplicativo do caminho de rede que a transporta:

1. Seu serviço cria um convite de conexão de curta duração e o entrega ao cliente.
2. O SDK estabelece uma sessão segura por uma conexão direta ou via relay disponível.
3. O aplicativo usa RPC, notificações e fluxos de bytes pela mesma API de sessão.

Conexões diretas e via relay apresentam a mesma sessão ao código. A seleção, as credenciais e o roteamento ficam dentro do SDK e do runtime.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Comece a desenvolver

Escolha o SDK adequado ao seu aplicativo:

| SDK | Melhor uso | Guia de instalação e API |
| --- | --- | --- |
| Go | Serviços, gateways e código de plano de controle | [Go SDK](flowersec-go/README.md) |
| TypeScript | Aplicativos de navegador e Node.js | [TypeScript SDK](flowersec-ts/README.md) |
| Swift | Clientes macOS e iOS | [Swift SDK](flowersec-swift/README.md) |
| Rust | Serviços Tokio que precisam de QUIC nativo | [Rust SDK](flowersec-rust/README.md) |

O [índice de exemplos](examples/README.md) contém exemplos pequenos e executáveis de conexões diretas, relays, aceitação de sessões no servidor e RPC.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## Exemplos

Comece pelo [índice de exemplos](examples/README.md). Eles usam a mesma API pública de aplicativos em produção e cobrem conexões de cliente, emissão de convites, uso único durável e ciclo de vida da sessão.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## O que seu aplicativo pode fazer

Os quatro SDKs compartilham o mesmo modelo de sessão. O suporte varia quando uma plataforma não oferece um tipo de conexão.

| Recurso do aplicativo | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Sessões criptografadas de ponta a ponta | Sim | Sim | Sim | Sim |
| Enviar chamadas RPC e notificações | Sim | Sim | Sim | Sim |
| Receber notificações RPC | Sim | Sim | Sim | Sim |
| Fluxos de bytes confiáveis | Sim | Sim | Sim | Sim |
| Recuperação de conexões duradouras | Sim | Sim | Sim | Sim |
| Mensagens não confiáveis quando disponíveis | Sim | Sim | Não | Sim |
| Conexões de navegador | Não | Sim | Não | Não |
| Conexões de clientes Apple | Não | Não | Sim | Não |
| Conexões QUIC nativas | Sim | Não | Não | Sim |
| Conexões WebSocket | Sim | Sim | Sim | Sim |
| Conexões WebTransport | Sim | Sim | Não | Não |
| Aceitação de sessões no servidor | Sim | Node.js | Não | Sim |
| Runtime de relay opaco | Sim | Node.js | Não | Sim |
| Emissão de convites no plano de controle | Sim | Node.js | Não | Sim |
| ProxyServer HTTP e WebSocket | Sim | Node.js | Não | Sim |

Consulte os guias dos SDKs para ver as combinações exatas de plataforma e conexão disponíveis.

<!-- readme-section:security -->
<a id="security"></a>

## Segurança

- Os dados do aplicativo são criptografados de ponta a ponta em sessões diretas e via relay.
- Os convites de conexão são opacos, de curta duração e de uso único.
- As credenciais são consumidas antes do uso, impedindo a repetição de um convite já usado.
- Relays apenas encaminham tráfego criptografado; eles não encerram sessões do aplicativo.
- Tentativas inválidas ou não compatíveis falham com segurança e retornam erros públicos limitados.

Para detalhes do protocolo e do modelo de ameaças, leia o [contrato da API](docs/API_CONTRACT.md), a [arquitetura de transporte](docs/TRANSPORT_V2_ARCHITECTURE.md) e o [modelo de ameaças](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Saiba mais

- [Contrato da API](docs/API_CONTRACT.md): comportamento estável compartilhado pelos SDKs.
- [Modelo de erros](docs/ERROR_MODEL.md): erros públicos de conexão, sessão e RPC.
- [Arquitetura de transporte](docs/TRANSPORT_V2_ARCHITECTURE.md): projeto das conexões diretas e via relay.
- [Exemplos](examples/README.md): uso executável dos SDKs.

Flowersec está disponível sob a [licença MIT](LICENSE). Os pacotes publicados e as notas de versão estão em [GitHub Releases](https://github.com/floegence/flowersec/releases).
