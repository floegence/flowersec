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

<p align="center"><strong>Des sessions indépendantes du transport et chiffrées de bout en bout pour Go, TypeScript, Swift et Rust.</strong></p>

[![Latest Release](https://img.shields.io/github/v/release/floegence/flowersec?display_name=tag&sort=semver)](https://github.com/floegence/flowersec/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-0f766e)](LICENSE)

<!-- readme-section:why-flowersec -->
<a id="why-flowersec"></a>

## Pourquoi Flowersec

- Un contrat unique d'artefact opaque et de session pour les quatre SDK.
- WebSocket, raw QUIC et WebTransport sont des options de transport de même rang.
- RPC et les flux d'octets partagent une même session authentifiée sans exposer aux applications les objets de transport, de protocole filaire, de clé ou de journal de consommation.
- Les relais de tunnel transmettent les flux chiffrés sans mettre fin au chiffrement applicatif.

<!-- readme-section:how-it-works -->
<a id="how-it-works"></a>

## Fonctionnement

| Chemin | Forme de la connexion | Transport des flux |
| --- | --- | --- |
| Direct | Le client se connecte à un point de terminaison à l'aide d'une option compatible | WebSocket utilise Yamux localement sur chaque tronçon ; les transports de la famille QUIC utilisent des flux bidirectionnels natifs |
| Tunnel | Les branches cliente et serveur se rejoignent par l'intermédiaire de transports compatibles choisis indépendamment | Le tunnel fait correspondre les flux chiffrés entre les deux branches sans désigner de transport principal |

Raw QUIC et WebTransport préservent le comportement natif de FIN, RESET_STREAM, STOP_SENDING, du contrôle de flux et de la migration. Flowersec désactive le 0-RTT applicatif. Les flux fiables n'utilisent jamais QUIC DATAGRAM ; les runtimes ayant négocié DATAGRAM natif ne l'exposent que par des messages non fiables indépendants du transport.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Essai local

Exécutez la suite d'acceptation par défaut :

```bash
make test
```

Après avoir corrigé un échec, utilisez `make test-resume` pour reprendre au premier test incomplet jusqu'au prochain échec ou jusqu'à `ALL GREEN`. Les ID terminés restent valides lorsque le commit source change.

Utilisez `make coverage-race` pour les quatre lanes de couverture et le test race Go exclusif. `make browser-smoke` couvre les trois topologies Chromium locales et `make browser-compat` vérifie explicitement les capacités Firefox/WebKit. Les diagnostics privilégiés de réseau dégradé et du kernel utilisent `make diagnostic` ; les tests de capacité et de soak utilisent `make performance`.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK et guides pratiques

| Langage | Paquet | Point d'entrée public |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.Connect`, `flowersec.NewConnectionController`, `flowersec.NewAcceptor` |
| TypeScript | `@floegence/flowersec-core` | points d'entrée v2 opaques à la racine, sous `/browser`, sous `/node` et sous `/proxy` |
| Swift | Produit SwiftPM `Flowersec` | `Artifact`, `connect`, `Session` |
| Rust | crate `flowersec` | `Artifact`, `connect`, `Session` |

Les plans de contrôle de services Go utilisent le package séparé `github.com/floegence/flowersec/flowersec-go/v2/controlplane` pour émettre des artifacts opaques et répondre aux callbacks d'autorisation de `flowersec-runtime`.

L'[index des guides pratiques](examples/README.md) contient uniquement des exemples v2 et des commandes de vérification.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Capacités des SDK

Les capacités ci-dessous sont regroupées par workflows directement utilisables par les développeurs d'applications, et non par objets internes du protocole. Chaque profil SDK déclare sa frontière propre au runtime et à la plateforme. Une limitation de plateforme ne peut être déclarée non prise en charge que si `stability/language_capabilities.json` en indique la raison, une frontière publique alternative et un ID de test exécutable. La persistance du control plane est une frontière de service : les clients appellent le service authentifié qui utilise `flowersec-go/v2/controlplane` ; ils n'intègrent ni second émetteur ni datastore. Une commodité propre à un langage adapte la syntaxe ou l'orchestration à son écosystème sans modifier les workflows partagés. Le comportement de reprise des connexions est décrit par la disposition structurée du contrôleur.

| Capacité | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Sessions chiffrées de bout en bout, RPC et flux d'octets | Oui | Oui | Oui | Oui |
| Reprise automatique des connexions persistantes | Oui | Oui | Oui | Oui |
| Messages non fiables | Oui | Oui | Non | Oui |
| Réception des notifications RPC | Non | Oui | Non | Non |
| Traitement des requêtes RPC entrantes | Oui | Non | Non | Non |
| Connexions clientes WebSocket | Oui | Navigateur et Node.js | macOS et iOS | Non |
| Connexions clientes raw QUIC | Oui | Non | Non | Oui |
| Connexions clientes WebTransport | Oui | Navigateur et Node.js | Non | Non |
| Acceptation de sessions côté serveur | `NewAcceptor` | `createAcceptor` / `AcceptedSession` | Non pris en charge par le profil listener Apple | `Acceptor::bind` / `accept_with_handlers` |
| Émission et autorisation d'artifacts par le control plane | `flowersec-go/v2/controlplane` | Non pris en charge ; frontière du service applicatif | Non pris en charge ; frontière du service applicatif | Non pris en charge ; frontière du service applicatif |

Seuls les tuples de transport déclarés sont acceptés ; les tuples non pris en charge échouent en mode fermé. Chaque ligne repose sur du code de connexion destiné à la production et sur un ID de test explicite dans `stability/language_capabilities.json`. Les capacités non prises en charge indiquent une raison et une frontière alternative. Les descripteurs de capacité et la sélection du transport restent internes.

<!-- readme-section:security -->
<a id="security"></a>

## Sécurité

- Les artefacts sont des références opaques, de taille limitée et à usage unique. Leur consommation est enregistrée durablement avant l'envoi du premier octet de données d'authentification.
- Les transports de la famille QUIC exigent TLS 1.3, un ALPN exact, des racines de confiance explicites et la désactivation des données anticipées.
- Les erreurs publiques sont expurgées et de taille limitée ; les détails relatifs aux options candidates, au protocole filaire, aux clés et au journal de consommation restent internes.
- Les dispositions structurées du contrôleur n'autorisent qu'une nouvelle tentative avec un artefact neuf ; elles ne réutilisent jamais les identifiants et ne rejouent aucun travail d'une session terminée.
- L'annulation des sessions, les délais d'expiration, FIN, les réinitialisations, la vérification d'activité, le renouvellement des clés et le nettoyage sont encadrés par des limites explicites.

Consultez l'[architecture Transport v2](docs/TRANSPORT_V2_ARCHITECTURE.md) et le [modèle de menace](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Déploiement et développement

L'environnement d'exécution Flowersec fournit les implémentations de production des points d'écoute WebSocket, raw QUIC et WebTransport. Les SDK applicatifs reçoivent uniquement des artefacts et des sessions opaques ; les CLI d'exécution composent les mêmes implémentations de connecteur et d'accepteur.

Installez les hooks du dépôt et exécutez la vérification de référence avant l'intégration :

```bash
make install-hooks
make precommit
```

`scripts/push-main.sh` exécute la suite d'acceptation locale bornée avant de pousser le SHA main exact. La vérification d'ingénierie complète et les workflows explicites nightly, diagnostic et performance couvrent respectivement la compatibilité, les diagnostics privilégiés et les tests de charge ; la publication elle-même n'exécute aucun test.

Flowersec est disponible sous [licence MIT](LICENSE). Les artefacts de publication sont distribués par l'intermédiaire des [versions GitHub](https://github.com/floegence/flowersec/releases).
