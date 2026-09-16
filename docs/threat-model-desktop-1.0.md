# Threat model — Desktop / Multi-device 1.0

## Actifs

Contenu des messages/pièces jointes, clés privées Signal et sessions, clé maître locale, secrets d'appairage, clés de pièces jointes, tokens device-bound, intégrité du registre de devices et historique transféré.

## Adversaires considérés

- opérateur de relay curieux ;
- stockage objet compromis ;
- attaquant réseau ;
- serveur tentant de substituer une identité publique ou d'ajouter un device ;
- replay, réordonnancement et duplication ;
- device précédemment autorisé puis révoqué ;
- entrées réseau malformées/surdimensionnées.

## Garanties visées

Le relay ne possède aucune clé permettant de lire le contenu E2EE. Les pièces jointes quittent un endpoint déjà chiffrées. Chaque device possède une identité Signal distincte. Les changements d'identité sont visibles. Le registre de devices est appuyé par une preuve cryptographique d'autorisation d'un device existant.

P2P/TURN/relay est une décision de transport distincte du chiffrement.

## Non-garanties 1.0

Pas d'anonymat réseau ni de dissimulation complète d'IP/timing/volume/taille. Une compromission complète d'un endpoint déverrouillé reste hors protection. Une révocation n'efface pas rétroactivement un plaintext déjà reçu. Aucun historique ancien n'est récupérable sans device autorisé ou sauvegarde E2EE externe.

## Stockage local

La Storage Master Key est aléatoire et distincte du mot de passe. Windows doit la protéger via DPAPI/mécanisme Windows approprié ; Linux via Secret Service/keyring. Un fallback mot de passe, s'il est réellement nécessaire, utilise Argon2id avec paramètres documentés.

Les secrets ne sont jamais retournés à l'UI. Les types secrets ont un Debug redacted et une durée de vie minimisée. L'effacement mémoire Rust simple reste best-effort jusqu'à l'intégration/audit de mémoire sécurisée libsodium.

## Release security tests

La RC est bloquée si le canari `ENIGMA_PLAINTEXT_CANARY_7CE2...` apparaît dans la DB relay, l'object storage, les logs, les fichiers temporaires hors endpoint ou des payloads réseau intermédiaires.

Couvrir au minimum : envelope malformée/tronquée/surdimensionnée, signature invalide, replay, MessageId dupliqué, device inconnu/révoqué, pairing/relay expiré, tag d'attachement invalide, DB locale corrompue, mauvaise vault key, downgrade/unknown protocol version, UTF-8 invalide, payload nul, metadata excessive, livraison désordonnée, reconnect concurrent, double/lost ACK et retry relay.

Aucun cas ne doit causer un panic exploitable ni révéler un secret dans une erreur.
