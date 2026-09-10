# Architecture V1

## Vue d'ensemble

Enigma V1 separe strictement le client Android, le transport serveur et le stockage d'objets.

- Android chiffre les messages et pieces jointes avant tout envoi reseau.
- Le serveur Rust ne stocke que des enveloppes opaques, des cles publiques/prekeys, des identifiants techniques et des timestamps.
- PostgreSQL stocke les comptes, appareils, prekeys, files de messages, recus et metadonnees d'attachements.
- Redis sert au rate limiting HTTP.
- MinIO/S3 stocke uniquement les blobs deja chiffres par le client.
- WebSocket notifie l'arrivee d'un message sans transporter de clair.
- Le push Android transporte seulement des notifications generiques; aucun contenu sensible n'est mis dans la notification.

## Backend Rust

Modules principaux :

- `config` : configuration par variables d'environnement.
- `auth` : inscription, login, sessions JWT bootstrap puis device-bound, Argon2.
- `devices` : enregistrement appareil et token FCM.
- `keys` : publication de bundles, discovery non consommatrice, claim explicite de one-time prekey et statut de replenishment.
- `relays` : descriptor du relais officiel et enregistrement minimal de relais personnalises.
- `bubbles` : Main Bubble par utilisateur, memberships, relais attaches et politiques locales.
- `messages` : relais d'enveloppes chiffrees, pending, ACK idempotent, suppression apres ACK.
- `contacts` : carnet serveur minimal par identifiant utilisateur.
- `groups` : groupes, membres, roles et messages opaques.
- `channels` : canaux publics, abonnements et posts opaques.
- `calls` : signaling WebRTC opaque uniquement.
- `turn` : credentials coturn temporaires.
- `attachments` : URL S3 pre-signees, verification `complete` post-upload et secret de telechargement.
- `ws` : hub WebSocket par appareil.
- `push` : interface `PushSender`, implementation `NoopPushSender` dev/test et implementation Firebase HTTP v1 activable par configuration.
- `security` : validation, headers HTTP, rate limiting.

Les migrations SQLx versionnees vivent dans `server/migrations/` et sont executees au demarrage du serveur.

## Client Android

Couches principales :

- `ui` : Jetpack Compose, navigation et etats utilisateur.
- `domain` : modeles metier et resultats d'erreur affichables.
- `data` : repositories, mapping DTO/Room/domaine.
- `network` : Retrofit, OkHttp, WebSocket, FCM.
- `storage` : Room, DataStore, Android Keystore, fichiers chiffrés.
- `crypto` : abstraction `CryptoEngine`.
- `signal`, `media`, `calls`, `groups`, `channels`, `sync` : couches a isoler pour la V1 produit; `SignalCryptoEngine` est actif pour le texte 1-to-1, groupes et canaux via enveloppes par device. Les sender keys groupe/canal restent a planifier apres V1 et WebRTC media Android est integre pour les appels 1-to-1.
- `di` : assemblage manuel des dependances.

`SignalCryptoEngine` est cable derriere `CryptoEngine` pour les messages texte 1-to-1. Le moteur crypto provisoire n'est plus present dans le code Android principal et ne doit pas revenir dans le chemin release.

Le client conserve un modele local de bulles et relais. Le relais officiel a l'UUID stable `00000000-0000-0000-0000-000000000001`, partage avec le serveur, Android et les QR. Les relais personnalises sont stockes separement et attaches aux bulles; ils ne remplacent pas globalement toutes les conversations.

## Flux

1. Inscription/login : Android appelle `/v1/auth/register` ou `/v1/auth/login`, puis stocke un token bootstrap localement.
2. Appareil : Android cree ou recupere son identite locale, appelle `/v1/devices/register`, remplace le token bootstrap par le token lie au device, puis publie les prekeys via `/v1/keys/upload`. Pour un relais prive actif, Android se connecte au relais cible, appelle le meme endpoint avec le `device_id` local explicite, stocke le token device-bound pour cette base URL, puis republie les prekeys sur ce relais.
3. Contact : Android resout `public_id` avec `/v1/users/resolve/{public_id}`, stocke le contact localement, puis fait une discovery non consommatrice avec `/v1/keys/{user_id}/devices`.
4. Premiere session : avant le premier message vers un device sans session libsignal locale, Android appelle `/v1/keys/{user_id}/devices/{device_id}/claim-prekey`, cree la session, puis chiffre. Les messages suivants utilisent `hasSession` et ne claim plus de prekey.
5. Message : Android chiffre le texte, poste l'enveloppe opaque sur `/v1/messages` avec `bubble_id`, `client_message_id`, `message_type = text`, `sender_device_id` et `recipient_device_id`, puis le serveur notifie le destinataire via WebSocket avec le contexte de bulle.
6. Reception : Android lit `/v1/messages/pending`, utilise le `bubble_id` renvoye par le serveur pour trouver ou creer la conversation locale, dechiffre localement, stocke le corps rechiffre localement et ACK avec `/v1/messages/{id}/receipt`.
7. Piece jointe : Android chiffre le fichier via le relais actif, demande `/v1/attachments/presign-upload` avec `bubble_id`, upload vers S3 avec un client HTTP sans header `Authorization`, appelle `/v1/attachments/{blob_id}/complete`, puis envoie dans le message E2EE le `blob_id`, le `bubble_id`, le `download_secret`, la cle et le nonce d'attachement.
8. Telechargement : Android lit le descripteur E2EE, demande `/v1/attachments/presign-download` avec `blob_id`, `bubble_id` et `download_secret`, telecharge le blob chiffre et dechiffre localement. Le serveur refuse le download si l'objet n'est pas `verified`.
9. FCM : Android envoie son token via `/v1/devices/fcm-token`; le serveur stocke le token sur l'appareil lie au JWT. En dev/test, l'envoi reste Noop; en production, `PUSH_PROVIDER=fcm` active Firebase HTTP v1.
10. Groupe/canal : Android synchronise et cree les groupes/canaux avec l'UUID de bulle du relais actif; le serveur stocke `bubble_id` sur groupes, canaux, messages, posts et receipts, filtre les listes par `bubble_id`, puis relaie des ciphertexts opaques. La crypto de groupe/canal reste a finaliser cote Signal.
11. Appel : Android cree l'appel avec l'UUID de bulle du relais actif; le serveur stocke `bubble_id` sur `calls` et `call_signaling_events`, relaie SDP/ICE opaques et notifie WebSocket avec le contexte de bulle. Les medias doivent passer par WebRTC entre clients.
12. Bulle/relais : Android charge les bulles Room, synchronise les endpoints `/v1/bubbles` et `/v1/relays`, active un `ActiveBubbleContext`, pousse ce contexte dans `RelayScopedApiProvider`, puis construit Retrofit/WebSocket sur le relais primaire de la bulle. Main Bubble reste sur le relais officiel; Private Connected peut retomber sur l'officiel si configure; Private Isolated exige un relais prive et masque les conversations/contacts globaux. Les messages, contacts contextuels, pieces jointes, groupes, canaux, appels et statut serveur passent par ce provider scoped; auth/registration officiels, update APK et descriptor officiel restent sur l'API officielle. Un relais non officiel exige une session dediee stockee par base URL; l'ecran Bulles peut creer cette session en appelant login, `/v1/devices/register` avec le `device_id` local, puis `/v1/keys/upload` sur le relais prive. Le token officiel global n'est pas ajoute aux requetes HTTP ou WebSocket de relais prive. Pour les appels reseau avec `bubble_id`, Android utilise une bulle synchronisee avec le relais; une bulle locale non synchronisee produit `BUBBLE_SYNC_REQUIRED`.

## Limites V1 connues

- Les tokens de login/register restent des tokens bootstrap jusqu'a l'enregistrement d'appareil; les routes device-specifiques attendent ensuite un token lie au device.
- Aucun moteur crypto provisoire ne doit etre recable dans le chemin release; `ReleaseCryptoGuard` impose `SignalCryptoEngine` hors debug.
- Firebase HTTP v1 est code, mais la validation production exige un vrai projet Firebase et un appareil reel. Sans cela, le push reste non signe production-ready.
- Les endpoints groupes/canaux/calls existent cote serveur; groupes, canaux et appels sont scopes par `bubble_id` cote serveur/Android. Groupes/canaux utilisent une enveloppe V1 par destinataire/device sans sender-key; WebRTC media Android est integre mais demande validation deux appareils.
- Pas de P2P ni de cache distribue en V1 actuelle.
