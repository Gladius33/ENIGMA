# Limites V1 actuelles

## Production bloquee

Enigma ne doit pas encore etre declare production-ready. `SignalCryptoEngine` est maintenant le moteur applicatif Android pour les messages texte 1-to-1, `assembleRelease` passe, les smoke tests instrumentes FR/EN passent sur un telephone reel S35 et le flux debug deux telephones A vers B / B vers A a ete valide sur LAN avec fermeture/reouverture. Un audit automatise logs/secrets bloque les regressions evidentes via `./scripts/audit-secret-logs.sh`. Il manque encore la validation release signee sur appareils reels, la validation FCM production et l'audit securite manuel final.

`org.signal:libsignal-android:0.76.1` est centralise dans le catalogue Gradle `android/gradle/libs.versions.toml`, telecharge, compile, package des `.so` Android et passe les tests unitaires lors des validations Gradle disponibles. Le contrat serveur transporte les champs de bundle libsignal, `SignalKeyCodec` sait convertir ces bundles, `SignalPreKeyBundleFactory` sait generer/stocker les prekeys, `PersistentSignalProtocolStore` fournit un store libsignal persistant et `SignalCryptoEngine` chiffre/dechiffre le texte 1-to-1 via libsignal.

Android affiche maintenant une empreinte locale dans `Parametres` et un code de securite par conversation quand la cle d'identite distante est connue ou recuperable via la discovery non consommatrice `/v1/keys/{user_id}/devices`. L'utilisateur peut marquer ce code comme verifie; l'etat local par appareil est `UNVERIFIED`, `VERIFIED`, `CHANGED` ou `BLOCKED`, et un changement de cle cree un historique local. Ce n'est pas encore une ceremonie complete : le QR code safety number et les tests instrumentes produit restent a finaliser.

Room a des migrations explicites jusqu'au schema 11; le fallback destructif n'est plus active. Les migrations couvrent l'etat de verification locale, l'etat de confiance d'identite, l'historique de changement de cle, les relais/bulles et le scoping `bubble_id` des conversations, groupes, canaux, appels et attachments. La validation production exige encore `connectedDebugAndroidTest` sur appareil/emulateur et un test d'upgrade depuis une APK ancienne reellement installee.

## Beta testable

Fonctionnel pour test LAN/debug :

- serveur Docker racine;
- health/version;
- identite avec handle;
- check disponibilite;
- secret de recuperation affiche et confirme;
- recuperation par nouvel appareil;
- suppression avec tombstone;
- contacts;
- messages texte 1-to-1;
- WebSocket lifecycle-aware avec reconnexion backoff et polling fallback;
- APK debug.
- verification manuelle du code de securite par conversation.

## Experimental ou reporte

- Groupes/canaux : endpoints, DTO, Room et UI presents; `bubble_id` est porte par serveur et Android pour la creation, les listes, les pending et les notifications. V1 chiffre par destinataire/device dans une enveloppe opaque; sender-key Signal non implemente.
- Appels : signaling/TURN scopes par `bubble_id` et media WebRTC Android integre avec audio, video, offer/answer/ICE automatiques et rendu video local/distant. Validation deux appareils Android, release signee, qualite reseau et monitoring TURN restent a faire.
- Bulles/relais : socle Android/backend fonctionnel mais encore experimental. La Main Bubble reste sur le relais officiel `00000000-0000-0000-0000-000000000001`; les relais personnalises peuvent etre crees/synchronises, attaches a une bulle, puis influencer l'URL Retrofit/WebSocket active. `ConversationEntity`, `GroupEntity`, `GroupMessageEntity`, `ChannelEntity` et `ChannelPostEntity` portent `bubble_id`; le serveur porte maintenant `bubble_id` sur messages directs/groupes/canaux, pending/receipts et evenements WebSocket. Android refuse un appel reseau de contenu si la bulle locale n'a pas d'UUID synchronise avec le relais (`BUBBLE_SYNC_REQUIRED`). Private Isolated masque les contacts/conversations globaux et n'autorise pas le fallback officiel. Messages, contacts contextuels, attachments, groupes, canaux, calls et statut serveur utilisent le provider scoped. Federation complete, signatures de descriptors, invitations serveur, pinning produit final et sessions vraiment separees par relais restent a auditer.
- Auth multi-relais : `SecureSessionStore` a maintenant un stockage par base URL pour les sessions de relais prives, et Android bloque les appels HTTP/WebSocket non officiels avec `RELAY_SESSION_REQUIRED` si aucune session dediee n'existe; le token officiel global n'est plus envoye aux relais prives. L'ecran Bulles permet de connecter/deconnecter le relais prive actif : Android login sur ce relais, enregistre le meme `device_id` local via `/v1/devices/register`, stocke le token device-bound pour cette base URL et republie les prekeys. Les URLs objet presignees des attachments utilisent aussi un client sans header `Authorization`. Federation complete, rotation de session, UX de recuperation d'erreur et validation deux appareils/deux relais restent a auditer avant V1 prod-ready.
- Medias/fichiers : serveur attachments et repositories Android generiques presents; upload/download portent `bubble_id` et passent par le relais actif, l'upload S3 doit passer par `complete` avant download. UX stable fichier/image/video/vocal non exposee en production V1.
- FCM : provider HTTP v1 code avec payload `sync_hint` uniquement; Android demande `POST_NOTIFICATIONS` depuis les parametres sur Android 13+; validation production exige un vrai projet Firebase et appareil reel.
- Update APK : manifeste et check manuel presents; le bandeau normal reste silencieux si aucune mise a jour n'est disponible et s'affiche seulement pour une release disponible ou un APK verifie. Validation `https`/SHA-256 hex/signature manifeste, affichage Play Store/sideload, telechargement explicite en cache, verification SHA-256 des bytes telecharges, verification Ed25519 des bytes telecharges quand `ENIGMA_UPDATE_ED25519_PUBLIC_KEY` est configuree, ouverture sources inconnues et installateur Android presents; cle officielle de release et validation appareil reel du flux installateur non finalisees.
- i18n : le parcours stable onboarding/auth/contacts/conversation/verrouillage/parametres est FR/EN et suit la langue choisie dans l'app; les statuts serveur/crypto/update/suppression des parametres sont localises via ressources. Les surfaces experimentales groupes/canaux/appels ne sont pas encore completement couvertes.
- Receipts lecture : le protocole direct accepte `delivered|read`, conserve `read` sans downgrade et Android envoie `read` quand la conversation est ouverte. La conversation affiche les statuts avec libelles FR/EN et propose un retry manuel des messages sortants en echec. L'UX avancee des confirmations de lecture et la validation release deux appareils restent a finaliser.

## Verification requise avant public

- test deux telephones complet en release signee;
- tests instrumentes Android critiques;
- test reel libsignal release sur deux appareils avec fermeture/reouverture;
- test reel WebSocket/reconnexion/polling fallback;
- audit securite manuel final logs/secrets apres le gate automatise `./scripts/audit-secret-logs.sh`;
- backup/restore production;
- cle officielle et signature APK release via secrets externes;
- monitoring minimal.
