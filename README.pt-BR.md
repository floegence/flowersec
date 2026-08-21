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

O [índice de exemplos](examples/README.md) contém exemplos pequenos e executáveis de conexões de cliente, uso único durável, emissão pelo plano de controle, liveness e ciclo de vida da sessão em cada SDK.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## Exemplos

Comece pelo [índice de exemplos](examples/README.md). Eles usam a mesma API pública de aplicativos em produção e cobrem conexões de cliente, emissão de convites, uso único durável, liveness e ciclo de vida da sessão.

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
| Atender fluxos de aplicativo em qualquer sessão | Sim | Sim | Sim | Sim |
| Recuperação de conexões duradouras | Sim | Sim | Sim | Sim |
| Mensagens não confiáveis quando disponíveis | Sim | Sim | Não | Sim |
| Conexões de navegador | Não | Sim | Não | Não |
| Conexões de clientes Apple | Não | Não | Sim | Não |
| Conexões QUIC nativas | Sim | Node.js | Não | Sim |
| Conexões WebSocket | Sim | Sim | Sim | Sim |
| Conexões WebTransport | Go H4 | Cliente Browser H3 (quando a API WebTransport do navegador está disponível) | Não | Não |
| Aceitação de sessões no servidor | Sim | Node.js | Não | Sim |
| Runtime de relay opaco | Sim | Node.js | Não | Sim |
| Emissão de convites no plano de controle | Sim | Não | Não | Não |
| ProxyServer HTTP e WebSocket | Sim | Node.js | Não | Sim |

Os perfis de implantacao separam a disponibilidade da plataforma do protocolo de aplicacao Flowersec compartilhado:

| Perfil | Runtimes | Superficie obrigatoria de carrier e funcao | Superficie opcional |
| --- | --- | --- | --- |
| `native-server-core` | Go, Rust, Node.js | Cliente endpoint, servidor direto e runtime de tunel opaco para WebSocket e raw QUIC | Adaptador WebTransport |
| `browser-client` | Navegador TypeScript | Cliente endpoint WebSocket | Adaptador WebTransport do navegador |
| `apple-client` | Swift em plataformas Apple | Cliente endpoint WSS | Nenhuma |
| `webtransport-server` | Go | Servidor WebTransport direto e runtime de tunel opaco | Nenhuma |

O perfil native-server-core legível por máquina contém 18 tuplas agregadas de runtime, função e carrier, seis por runtime nativo, e 24 unidades de servidor específicas de caminho compatíveis. O Go H4 adiciona duas tuplas de servidor WebTransport e duas unidades específicas de caminho. A matriz de interoperabilidade declara separadamente 18 células diretas e 18 células de túnel. As 36 células em pares são atualmente declarações `unsupported` explícitas porque nenhum teste v3 de release executa o conjunto completo de casos de uma célula. Um perfil nunca altera a semântica wire de Artifact, handshake, RPC, stream, close, rekey ou authorization.

Consulte os guias dos SDKs para ver as combinações exatas de plataforma e conexão disponíveis.

WebTransport é um adaptador opcional e não faz parte do contrato obrigatório de carrier native-server. O Go declara o perfil H4 webtransport-server separado e completo; o perfil Browser usa H3 quando a API WebTransport do navegador está disponível. Node.js e Rust atualmente não fornecem um adaptador WebTransport de produção. A superfície carrier native-server é WebSocket e raw QUIC para Go, Rust e Node.js; a interoperabilidade em pares só é declarada por entradas compatíveis da matriz.

<!-- readme-section:security -->
<a id="security"></a>

## Segurança

- Os dados do aplicativo são criptografados de ponta a ponta em sessões diretas e via relay.
- A política de confiança TLS é vinculada a cada candidato de transporte v3. Raízes de CA públicas ou fornecidas pela implantação e pins explícitos do certificado folha são mutuamente exclusivos, sem rebaixamento após falha.
- Os convites de conexão são opacos, de curta duração e de uso único.
- As credenciais são consumidas antes do uso, impedindo a repetição de um convite já usado.
- Relays apenas encaminham tráfego criptografado; eles não encerram sessões do aplicativo.
- Tentativas inválidas ou não compatíveis falham com segurança e retornam erros públicos limitados.

Para detalhes do protocolo e do modelo de ameaças, leia o [contrato da API](docs/API_CONTRACT.md), a [arquitetura de transporte](docs/TRANSPORT_V3_ARCHITECTURE.md) e o [modelo de ameaças](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Saiba mais

- [Contrato da API](docs/API_CONTRACT.md): comportamento estável compartilhado pelos SDKs.
- [Modelo de erros](docs/ERROR_MODEL.md): erros públicos de conexão, sessão e RPC.
- [Arquitetura de transporte](docs/TRANSPORT_V3_ARCHITECTURE.md): projeto das conexões diretas e via relay.
- [Exemplos](examples/README.md): uso executável dos SDKs.

Flowersec está disponível sob a [licença MIT](LICENSE). Os pacotes publicados e as notas de versão estão em [GitHub Releases](https://github.com/floegence/flowersec/releases).
