# Flowersec

<!-- readme-locales:start -->
<p align="center">
  <a href="README.md">English</a> |
  <a href="README.zh-CN.md">简体中文</a> |
  <a href="README.zh-TW.md">繁體中文</a> |
  <a href="README.ja-JP.md">日本語</a> |
  <a href="README.ko-KR.md">한국어</a> |
  <a href="README.de-DE.md">Deutsch</a> |
  <strong>Français</strong> |
  <a href="README.es-ES.md">Español</a> |
  <a href="README.pt-BR.md">Português do Brasil</a> |
  <a href="README.ru-RU.md">Русский</a>
</p>
<!-- readme-locales:end -->

<p align="center"><strong>Connectez les composants de votre application en toute sécurité, où qu'ils s'exécutent.</strong></p>
<p align="center">Flowersec offre à Go, TypeScript, Swift et Rust une API simple pour les sessions chiffrées de bout en bout, les RPC, les notifications et les flux d'octets.</p>

[![Dernière version](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![Licence](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Pourquoi Flowersec

Flowersec s'adresse aux applications qui doivent relier clients, services et appareils de façon privée, sans mêler la gestion du transport au code métier.

- **Un modèle de programmation unique :** utilisez la même API de session authentifiée en Go, TypeScript, Swift et Rust.
- **Les fonctions utiles aux applications :** RPC, notifications et flux d'octets fiables partagent une seule connexion.
- **Une connexion adaptée au réseau :** connectez-vous directement ou passez par un relais sans modifier le protocole de l'application.
- **Confidentialité par défaut :** les données sont chiffrées de bout en bout. Un relais peut les transmettre, pas les lire.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## Fonctionnement

Flowersec sépare la session applicative du chemin réseau qui la transporte :

1. Votre service crée une invitation de connexion à courte durée de vie et la remet au client.
2. Le SDK établit une session sécurisée par une connexion directe ou relayée disponible.
3. L'application utilise RPC, notifications et flux d'octets avec la même API de session.

Les connexions directes et relayées présentent la même session à votre code. Le choix de la connexion, les identifiants et le routage restent internes au SDK et au runtime.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Commencer

Choisissez le SDK adapté à votre application :

| SDK | Usage recommandé | Guide d'installation et d'API |
| --- | --- | --- |
| Go | Services, passerelles et code de plan de contrôle | [Go SDK](flowersec-go/README.md) |
| TypeScript | Applications navigateur et Node.js | [TypeScript SDK](flowersec-ts/README.md) |
| Swift | Clients macOS et iOS | [Swift SDK](flowersec-swift/README.md) |
| Rust | Services Tokio nécessitant QUIC natif | [Rust SDK](flowersec-rust/README.md) |

L'[index des exemples](examples/README.md) propose, pour chaque SDK, de petits exemples exécutables de connexions clientes, d'utilisation unique durable, d'émission par le plan de contrôle, de liveness et de cycle de vie des sessions.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## Exemples

Commencez par l'[index des exemples](examples/README.md). Ils utilisent la même API publique qu'une application de production et couvrent les connexions clientes, l'émission d'invitations, leur utilisation unique durable, la liveness et le cycle de vie des sessions.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Ce que votre application peut faire

Les quatre SDK partagent le même modèle de session. La prise en charge varie lorsqu'une plateforme ne peut pas proposer un type de connexion.

<!-- capability-table:start -->
| Capacité applicative | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Invitations de connexion opaques à usage unique | Oui | Oui | Oui | Oui |
| Connexion sécurisée ponctuelle | Oui | Oui | Oui | Oui |
| Sessions chiffrées de bout en bout | Oui | Oui | Oui | Oui |
| Appels RPC et notifications | Oui | Oui | Oui | Oui |
| Métadonnées de flux validées | Oui | Oui | Oui | Oui |
| Gestionnaires de flux applicatifs | Oui | Oui | Oui | Oui |
| Rétablissement des connexions persistantes | Oui | Oui | Oui | Oui |
| Messages non fiables négociés | Oui | Oui | Non | Oui |
| Gestionnaires RPC côté client | Oui | Oui | Oui | Oui |
| Acceptation de sessions côté serveur | Oui | Oui | Oui | Oui |
| Gestionnaires de sessions serveur | Oui | Oui | Oui | Oui |
| Émission et autorisation par le plan de contrôle | Oui | Non | Non | Non |
| Admission directe et par tunnel | Oui | Oui | Oui | Oui |
| ProxyServer HTTP et WebSocket | Oui | Oui | Non | Oui |
| Contrat de flux indépendant du transport | Oui | Oui | Oui | Oui |
| Sécurité wire Transport v4 | Oui | Oui | Oui | Oui |
<!-- capability-table:end -->

Les profils de déploiement décrivent les combinaisons de transports natifs ou de navigateur et de rôles requises. Chaque guide SDK distingue les API actuelles de la qualification des fournisseurs. Une déclaration de code source ne prouve pas la prise en charge à l'exécution.

Le protocole actuel utilise des matériaux de connexion authentifiés, une confiance de namespace indépendante, des sessions bornées, des services typés et un nettoyage explicite. L'interopérabilité directe et par tunnel est qualifiée par la matrice exécutable et les fournisseurs d'origine. La publication distribue les paquets et relit les registres, sans exécuter de tests d'acceptation.

WebTransport nécessite un fournisseur natif ou de navigateur configuré. La prise en charge du navigateur dépend de l'API WebTransport réelle et des capacités de politique de certificat. Consultez chaque guide SDK pour les transports, listeners et relais actuels.

La classe d'accès signée `local_loopback` prend en charge un pont HTTP authentifié par l'application sur la même machine. Elle utilise le protocole de session actuel et nécessite un fournisseur local configuré.

<!-- readme-section:security -->
<a id="security"></a>

## Sécurité

- Les données applicatives sont chiffrées de bout en bout pour les sessions directes et relayées.
- La politique de confiance TLS est liée à chaque candidat de transport v4. Les racines d'AC publiques ou fournies par le déploiement et les pins explicites de certificat feuille sont mutuellement exclusifs, sans dégradation après un échec.
- `local_loopback` autorise `ws://` uniquement pour un endpoint numérique de loopback signé, avec une Origin exacte et une autorisation applicative avant l'upgrade. Elle ne garantit pas la vérification TLS externe et n'autorise aucun repli en clair.
- Les invitations de connexion sont opaques, éphémères et à usage unique.
- Les identifiants sont validés avant utilisation afin qu'une invitation consommée ne puisse pas être rejouée.
- Les relais transmettent uniquement du trafic chiffré et ne terminent pas les sessions applicatives.
- Les connexions invalides ou non prises en charge échouent de façon sûre avec des erreurs publiques limitées.

Pour les détails du protocole et du modèle de menace, consultez le [contrat d'API](docs/API_CONTRACT.md), l'[architecture de transport](docs/TRANSPORT_V4_BINDING.md) et le [modèle de menace](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## En savoir plus

- [Contrat d'API](docs/API_CONTRACT.md) : comportement applicatif stable partagé par les SDK.
- [Modèle d'erreur](docs/ERROR_MODEL.md) : erreurs publiques de connexion, de session et de RPC.
- [Architecture de transport](docs/TRANSPORT_V4_BINDING.md) : conception des connexions directes et relayées.
- [Exemples](examples/README.md) : utilisation exécutable des SDK.

Flowersec est disponible sous [licence MIT](LICENSE). Les paquets publiés et les notes de version sont disponibles dans les [versions GitHub](https://github.com/floegence/flowersec/releases).
