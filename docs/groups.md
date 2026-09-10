# Groupes V1

Le serveur implemente un modele minimal :

- creation de groupe;
- roles `owner`, `admin`, `member`;
- ajout/retrait de membres par owner/admin;
- messages de groupe opaques;
- pending par device membre;
- ACK `delivered` ou `read`.

Statut : V1 testable. Les retries de messages sont idempotents : un retry identique retourne l'ancien id sans renotifier, un retry divergent avec le meme `client_message_id` retourne `409 CONFLICT`.

## Chiffrement

Le serveur ne gere pas les secrets de groupe et ne voit que des messages opaques. La strategie V1 Android chiffre par destinataire/device dans une enveloppe opaque; elle n'implemente pas encore Sender Keys Signal.

Roadmap apres V1 : Sender Keys ou equivalent audite, rotation a ajout/suppression, politique claire sur l'historique accessible aux nouveaux membres et tests appareil reels a grande echelle.
