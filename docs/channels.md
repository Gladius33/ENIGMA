# Canaux publics V1

Le serveur implemente :

- creation de canal public;
- titre, description et avatar optionnel;
- owner;
- abonnement/desabonnement;
- publication opaque par owner/admin;
- lecture pending par abonne.

Le contenu des posts reste opaque pour le serveur.

Statut : V1 testable. Les retries de posts sont idempotents : un retry identique retourne l'ancien id sans renotifier, un retry divergent avec le meme `client_post_id` retourne `409 CONFLICT`.

## Limites

Pas de moteur de recherche ni d'indexation publique avancee en V1. En bulle privee/isolated, l'indexation doit rester interdite par defaut.

La strategie V1 Android chiffre par destinataire/device dans une enveloppe opaque pour les abonnes/devices. Sender-key canal, rotation avancee, revocation d'admin et garanties d'historique pour nouveaux abonnes restent des sujets apres V1.
