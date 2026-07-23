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

Raw QUIC et WebTransport préservent le comportement natif de FIN, RESET_STREAM, STOP_SENDING, du contrôle de flux et de la migration. Flowersec désactive le 0-RTT applicatif et n'utilise pas QUIC DATAGRAM.

<!-- readme-section:try-it-locally -->
<a id="try-it-locally"></a>

## Essai local

Exécutez les suites de tests unitaires v2 :

```bash
make transport-v2-unit
```

Pour obtenir des preuves propres à chaque transport, exécutez `make transport-conformance-smoke`, `make transport-browser-smoke` et `make transport-interop-smoke`.

<!-- readme-section:sdks-and-cookbooks -->
<a id="sdks-and-cookbooks"></a>

## SDK et guides pratiques

| Langage | Paquet | Point d'entrée public |
| --- | --- | --- |
| Go | `github.com/floegence/flowersec/flowersec-go/v2` | `flowersec.ParseArtifact`, `flowersec.NewConnector` |
| TypeScript | `@floegence/flowersec-core` | points d'entrée v2 opaques à la racine, sous `/browser` et sous `/node` |
| Swift | Produit SwiftPM `Flowersec` | `ArtifactV2`, `ConnectorV2`, `SessionV2` |
| Rust | crate `flowersec` | `Artifact`, `Connector`, `Session` |

L'[index des guides pratiques](examples/README.md) contient uniquement des exemples v2 et des commandes de vérification.

<!-- readme-section:portable-contract -->
<a id="portable-contract"></a>

## Contrat portable

| Capacité | Go | TypeScript | Swift | Rust |
| --- | :---: | :---: | :---: | :---: |
| Artefact, connecteur, session, RPC et flux d'octets opaques | Oui | Oui | Oui | Oui |
| Connexion WebSocket en production | Oui | Navigateur et Node.js | macOS | Non |
| Connexion raw QUIC en production | Oui | Non | Non | Oui |
| Connexion WebTransport en production | Oui | Navigateur | Non | Non |
| Prise en charge de l'écoute | API de bibliothèque Go | Contraintes de l'environnement d'exécution du navigateur | Non annoncée | Non annoncée |

Chaque ligne de prise en charge repose sur du code de connexion destiné à la production et sur des tests de bout en bout. Les transports non pris en charge échouent en mode fermé ; ils ne servent jamais de solution de repli silencieuse. Les descripteurs de capacité et la sélection du transport restent internes.

<!-- readme-section:security -->
<a id="security"></a>

## Sécurité

- Les artefacts sont des références opaques, de taille limitée et à usage unique. Leur consommation est enregistrée durablement avant l'envoi du premier octet de données d'authentification.
- Les transports de la famille QUIC exigent TLS 1.3, un ALPN exact, des racines de confiance explicites et la désactivation des données anticipées.
- Les erreurs publiques sont expurgées et de taille limitée ; les détails relatifs aux options candidates, au protocole filaire, aux clés et au journal de consommation restent internes.
- L'annulation des sessions, les délais d'expiration, FIN, les réinitialisations, la vérification d'activité, le renouvellement des clés et le nettoyage sont encadrés par des limites explicites.

Consultez l'[architecture Transport v2](docs/TRANSPORT_V2_ARCHITECTURE.md) et le [modèle de menace](docs/THREAT_MODEL.md).

<!-- readme-section:deploy-and-develop -->
<a id="deploy-and-develop"></a>

## Déploiement et développement

L'environnement d'exécution Flowersec fournit les implémentations de production des points d'écoute WebSocket, raw QUIC et WebTransport. Les SDK applicatifs reçoivent uniquement des artefacts et des sessions opaques ; aucune CLI de compatibilité supprimée ne fait partie du contrat v2.

Installez les hooks du dépôt et exécutez la vérification de référence avant l'intégration :

```bash
make install-hooks
make check
```

Flowersec est disponible sous [licence MIT](LICENSE). Les artefacts de publication sont distribués par l'intermédiaire des [versions GitHub](https://github.com/floegence/flowersec/releases).
