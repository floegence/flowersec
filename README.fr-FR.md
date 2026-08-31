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
| Gestionnaires RPC côté client | Oui | Oui | Non | Oui |
| Acceptation de sessions côté serveur | Oui | Oui | Non | Oui |
| Gestionnaires de sessions serveur | Oui | Oui | Non | Oui |
| Émission et autorisation par le plan de contrôle | Oui | Non | Non | Non |
| Admission directe et par tunnel | Oui | Oui | Non | Oui |
| ProxyServer HTTP et WebSocket | Oui | Oui | Non | Oui |
| Contrat de flux indépendant du transport | Oui | Oui | Oui | Oui |
| Sécurité wire Transport v3 | Oui | Oui | Oui | Oui |
<!-- capability-table:end -->
Les profils de deploiement separent la disponibilite de la plateforme du protocole applicatif Flowersec partage :

| Profil | Runtimes | Surface carrier et role requise | Surface facultative |
| --- | --- | --- | --- |
| `native-server-core` | Go, Rust, Node.js | Client endpoint, serveur direct et runtime de tunnel opaque WebSocket et raw QUIC | Adaptateur WebTransport |
| `browser-client` | Navigateur TypeScript | Client endpoint WebSocket | Adaptateur WebTransport du navigateur |
| `apple-client` | Swift sur les plateformes Apple | Client endpoint WSS | Aucune |
| `webtransport-server` | Go | Serveur WebTransport direct et runtime de tunnel opaque | Aucune |

Le profil native-server-core lisible par machine contient 18 tuples agrégés runtime-rôle-carrier, six par runtime natif, et 24 unités serveur propres à un chemin prises en charge. Go H4 ajoute deux tuples serveur WebTransport et deux unités propres à un chemin. La matrice d'interopérabilité déclare séparément 18 cellules directes et 18 cellules tunnel. Le portail de release vérifie les 10 cellules directes et les 14 cellules tunnel par paires qui incluent Go ; les 8 cellules directes et 4 cellules tunnel restantes demeurent explicitement non vérifiées. Quatre profils client WSS supplémentaires vérifient Swift et TypeScript navigateur avec Go sur les chemins directs et tunnel. Un profil ne modifie jamais la sémantique wire de Artifact, handshake, RPC, stream, close, rekey ou authorization.

Consultez les guides des SDK pour connaître les combinaisons exactes de plateformes et de connexions prises en charge.

WebTransport est un adaptateur facultatif et ne fait pas partie du contrat de carrier native-server requis. Go revendique le profil H4 webtransport-server séparé et complet ; le profil Browser utilise H3 lorsque l'API WebTransport du navigateur est disponible. Node.js et Rust ne fournissent actuellement aucun adaptateur WebTransport de production. La surface carrier native-server est WebSocket et raw QUIC pour Go, Rust et Node.js ; l'interopérabilité par paires n'est revendiquée que par les entrées prises en charge de la matrice.

`flowersec-private-loopback/1` est un profil privé au produit, hors du deployment capability registry public. Ses API dédiées de serveur Go et de navigateur TypeScript sont limitées à un bridge HTTP de loopback numérique authentifié par l'application.

<!-- readme-section:security -->
<a id="security"></a>

## Sécurité

- Les données applicatives sont chiffrées de bout en bout pour les sessions directes et relayées.
- La politique de confiance TLS est liée à chaque candidat de transport v3. Les racines d'AC publiques ou fournies par le déploiement et les pins explicites de certificat feuille sont mutuellement exclusifs, sans dégradation après un échec.
- `flowersec-private-loopback/1` est une enveloppe de transport isolée, et non un mode TLS ni une capability de `flowersec/3`. Ses API dédiées ne mappent un candidat v3 en mode CA inchangé vers `ws://` que si l'autorité correspond à la même origine de loopback numérique et si l'application serveur autorise la requête avant l'upgrade. Les chemins Go, TypeScript, Rust, Swift, Provider et tunnel ordinaires rejettent cette enveloppe.
- Les invitations de connexion sont opaques, éphémères et à usage unique.
- Les identifiants sont validés avant utilisation afin qu'une invitation consommée ne puisse pas être rejouée.
- Les relais transmettent uniquement du trafic chiffré et ne terminent pas les sessions applicatives.
- Les connexions invalides ou non prises en charge échouent de façon sûre avec des erreurs publiques limitées.

Pour les détails du protocole et du modèle de menace, consultez le [contrat d'API](docs/API_CONTRACT.md), l'[architecture de transport](docs/TRANSPORT_V3_ARCHITECTURE.md) et le [modèle de menace](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## En savoir plus

- [Contrat d'API](docs/API_CONTRACT.md) : comportement applicatif stable partagé par les SDK.
- [Modèle d'erreur](docs/ERROR_MODEL.md) : erreurs publiques de connexion, de session et de RPC.
- [Architecture de transport](docs/TRANSPORT_V3_ARCHITECTURE.md) : conception des connexions directes et relayées.
- [Exemples](examples/README.md) : utilisation exécutable des SDK.

Flowersec est disponible sous [licence MIT](LICENSE). Les paquets publiés et les notes de version sont disponibles dans les [versions GitHub](https://github.com/floegence/flowersec/releases).
