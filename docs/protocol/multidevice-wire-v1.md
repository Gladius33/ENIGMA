# Multi-device wire contract — ENIGMA 1.0

## Message logique

Un message possède un `MessageId` global stable, indépendant du transport. Il produit toutefois une enveloppe E2EE distincte pour chaque device destinataire. Le serveur ne fait jamais le fanout à partir d'un plaintext.

Exemple : Alice A1/A2, Bob B1/B2. Un envoi depuis A1 produit des enveloppes pour B1, B2 et A2. A2 reçoit une copie E2EE de sender-sync.

## Header

Toute nouvelle enveloppe multi-device transporte `protocol_version`, `min_supported_version` et les capabilities. Une incompatibilité est rejetée explicitement : aucun downgrade ou fallback cryptographique silencieux.

## Fanout

Le core cible :
- tous les devices actifs du destinataire ;
- tous les autres devices actifs du compte émetteur ;
- jamais le device source ;
- jamais un device révoqué ;
- jamais deux fois le même device id.

Chaque destination a sa propre session Signal.

## Déduplication

Le `MessageId` est la clé logique d'idempotence. P2P puis relay, retry, ACK perdu, livraison désordonnée ou reconnexion concurrente ne doivent jamais créer deux messages UI.

## Transport

La crypto ne dépend pas de la route :
1. P2P direct ;
2. TURN/transit sans stockage disque lorsque les deux pairs sont présents ;
3. relay store-and-forward temporaire si la livraison live ne réussit pas ou si le device est offline.

Le changement de route conserve le même `MessageId`.

## Relay

Le relay ne reçoit qu'un identifiant de mailbox aléatoire/non sémantique, le ciphertext opaque, un TTL obligatoire et un état minimal de livraison.

ACK final => suppression. Expiration => suppression. Le garbage collector rend cette propriété testable.

La garantie 1.0 est la confidentialité du contenu et l'absence de clés de déchiffrement côté relay, pas l'absence totale de métadonnées. IP, timing, taille/volume et identifiants techniques de routage peuvent rester observables.

## Pièces jointes

Une pièce jointe utilise une clé aléatoire dédiée et un chiffrement par chunks avec une primitive AEAD établie. La clé voyage uniquement dans le message E2EE.

P2P est prioritaire. Le fallback object storage contient uniquement le ciphertext, possède un TTL et est supprimé après ACK/expiration conformément au lifecycle.

## Historique initial

Le nouveau desktop n'a pas les sessions historiques. L'historique est donc transféré depuis un device autorisé existant par un flux E2EE spécifique à l'appairage, single-use, TTL et anti-replay.

Sans ancien device ni sauvegarde E2EE externe, l'historique ancien est volontairement irrécupérable en 1.0.
