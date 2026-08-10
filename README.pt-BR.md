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

Raw QUIC e WebTransport preservam o comportamento nativo de FIN, RESET_STREAM, STOP_SENDING, controle de fluxo e migração. O Flowersec desativa o 0-RTT da aplicação. Fluxos confiáveis nunca usam QUIC DATAGRAM; runtimes que negociam DATAGRAM nativo o expõem somente por mensagens não confiáveis independentes de carrier.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Teste localmente

Execute a suíte de aceitação padrão:

```bash
make test
```

Após corrigir uma falha, use `make test-resume` para continuar a partir do primeiro teste incompleto até a próxima falha ou até `ALL GREEN`. IDs concluídos continuam válidos quando o commit de origem muda.

Use `make coverage-race` para as quatro lanes de cobertura e o teste race exclusivo de Go. Use `make browser-smoke` para as três topologias locais do Chromium e `make browser-compat` para verificações explícitas de capacidade no Firefox/WebKit. Diagnósticos privilegiados de rede fraca e kernel usam `make diagnostic`; testes de capacidade e soak usam `make performance`.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDKs e Cookbooks

| Linguagem | Pacote | Entrada pública |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.Connect`, `flowersec.NewConnectionController`, `flowersec.NewAcceptor` |
| TypeScript | `@floegence/flowersec-core` | entradas opacas v2 na raiz, em `/browser`, em `/node` e em `/proxy` |
| Swift | Produto SwiftPM `Flowersec` | `Artifact`, `connect`, `Session` |
| Rust | crate `flowersec` | `Artifact`, `connect`, `Session` |

Os control planes de serviços Go usam o pacote separado `github.com/floegence/flowersec/flowersec-go/v2/controlplane` para emitir artifacts opacos e responder aos callbacks de autorização do `flowersec-runtime`.

O [índice de Cookbooks](examples/README.md) contém somente exemplos v2 e comandos de verificação.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Recursos dos SDKs

As capacidades abaixo são agrupadas por workflows que desenvolvedores de aplicações podem usar diretamente, e não por objetos internos do protocolo. Cada perfil de SDK declara sua fronteira específica de runtime e plataforma. Uma limitação de plataforma só pode constar como não suportada quando `stability/language_capabilities.json` apresenta um motivo explícito, uma fronteira pública alternativa e um ID de teste executável. A persistência do control plane é uma fronteira de serviço: os clientes chamam o serviço autenticado que usa `flowersec-go/v2/controlplane`; eles não incorporam um segundo emissor nem datastore. Uma conveniência de linguagem adapta sintaxe ou orquestração ao ecossistema sem alterar os workflows compartilhados. O comportamento de recuperação das conexões é descrito pela disposition estruturada do controller.

| Capacidade | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Sessões criptografadas de ponta a ponta, RPC e fluxos de bytes | Sim | Sim | Sim | Sim |
| Recuperação automática de conexões persistentes | Sim | Sim | Sim | Sim |
| Mensagens não confiáveis | Sim | Sim | Não | Sim |
| Recebimento de notificações RPC | Não | Sim | Não | Não |
| Tratamento de solicitações RPC recebidas | Sim | Não | Não | Não |
| Conexões cliente WebSocket | Sim | Browser e Node.js | macOS e iOS | Não |
| Conexões cliente raw QUIC | Sim | Não | Não | Sim |
| Conexões cliente WebTransport | Sim | Browser e Node.js | Não | Não |
| Aceitação de sessões no servidor | `NewAcceptor` | `createAcceptor` / `AcceptedSession` | Não suportado no perfil listener da Apple | `Acceptor::bind` / `accept_with_handlers` |
| Emissão e autorização de artifacts do control plane | `flowersec-go/v2/controlplane` | Não suportado; fronteira do serviço da aplicação | Não suportado; fronteira do serviço da aplicação | Não suportado; fronteira do serviço da aplicação |

Somente tuplas de carrier declaradas são aceitas; tuplas sem suporte falham de forma fechada. Cada linha é respaldada por código de connector de produção e um ID de teste explícito em `stability/language_capabilities.json`. Capacidades sem suporte incluem um motivo e uma fronteira alternativa. Os descritores de capacidade e a seleção de carrier permanecem internos.

<!-- readme-section:security -->
<a id="security"></a>

## Segurança

- Artifacts são handles opacos, limitados e de uso único. O registro persistente do consumo é concluído antes do envio do primeiro byte de credencial.
- Carriers da família QUIC exigem TLS 1.3, ALPN exato, raízes de confiança explícitas e early data desativado.
- Erros públicos são sanitizados e limitados; detalhes de candidate, wire, chave e ledger permanecem internos.
- Dispositions estruturadas do controller autorizam apenas uma nova tentativa com um artifact novo; nunca reutilizam credenciais nem repetem trabalho de uma sessão encerrada.
- Cancelamento de sessão, deadlines, FIN, reset, liveness, rekey e limpeza obedecem a limites definidos.

Consulte a [arquitetura do Transport v2](docs/TRANSPORT_V2_ARCHITECTURE.md) e o [modelo de ameaças](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Implantação e desenvolvimento

O runtime do Flowersec fornece as implementações dos listeners de produção para WebSocket, raw QUIC e WebTransport. Os SDKs de aplicação recebem apenas artifacts e sessões opacos; as CLIs do runtime compõem as mesmas implementações de connector e acceptor.

Instale os hooks do repositório e execute a verificação oficial antes da integração:

```bash
make install-hooks
make precommit
```

`scripts/push-main.sh` executa a suíte de aceitação local limitada antes de enviar o SHA exato de main. A verificação completa de engenharia e os workflows explícitos nightly, diagnostic e performance cobrem compatibilidade, diagnósticos privilegiados e testes de carga; o release não executa testes.

Flowersec está disponível sob a [licença MIT](LICENSE). Os artefatos de release são publicados por meio do [GitHub Releases](https://github.com/floegence/flowersec/releases).
