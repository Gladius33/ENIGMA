# Modele de securite V1

## Objectif

La V1 fournit un relais serveur aveugle au contenu et un client Android qui garde les cles privees et les messages en clair sur l'appareil uniquement.

## Ce que le serveur ne doit jamais voir

- Texte de message en clair.
- Fichier ou blob d'attachement en clair.
- Cles privees Android.
- Cles d'attachement et nonces d'attachement.
- Tokens JWT complets dans les logs.
- Payload chiffre complet dans les logs.

## Ce que le serveur stocke

- `public_id`, hash Argon2 du mot de passe, sessions JWT persistantes.
- Identifiants utilisateur/appareil, plateforme et token FCM.
- Cles publiques d'identite, signed prekeys publiques, one-time prekeys publiques.
- `sessions` : `id`, `user_id`, `device_id` optionnel apres enregistrement d'appareil, timestamps d'expiration/revocation.
- `message_queue` : `id`, `sender_device_id`, `recipient_device_id`, `client_message_id`, `message_type`, `ciphertext` opaque, timestamps, statut minimal.
- `message_receipts` : message, appareil destinataire, statut `delivered`, timestamp.
- `attachments` : `blob_id`, proprietaire, cle objet S3, taille declaree, hash declare, content type declare, statut `pending|verified|expired|deleted`, metadata verifiees, expiration, hash du `download_secret`.
- `groups`, `channels`, `calls` : membres/abonnes/participants, roles, ciphertexts opaques, SDP/ICE opaques et timestamps.

Ces donnees restent des metadonnees sensibles et doivent etre traitees comme telles.

## Controles backend

- Secrets exclusivement par variables d'environnement.
- JWT signes avec secret configurable, algorithme fixe, issuer/audience/type de token et compatibilite legacy seulement pendant migration.
- JWT bootstrap limites au flux d'enregistrement d'appareil; les routes device-specifiques exigent un JWT dont le `device_id` correspond au device cible.
- Mots de passe haches avec Argon2.
- Validation stricte des champs utilisateur, appareil, bundles de cles base64, tailles, MIME et SHA-256.
- Rate limiting Redis par IP socket reelle par defaut. Les headers `x-forwarded-for`/`x-real-ip` ne sont acceptes que si l'IP socket appartient a `TRUSTED_PROXIES`.
- CORS configurable.
- Headers HTTP de securite via middleware.
- Logs JSON via tracing, sans payloads sensibles.
- ACK idempotent et suppression de la file apres livraison.
- Envoi de message idempotent par couple `sender_device_id` + `client_message_id` si le payload est identique. Le meme modele s'applique aux groupes et canaux; un retry divergent retourne `409 CONFLICT`.
- Groupes/canaux/calls verifient les permissions serveur, mais le contenu applicatif reste opaque.
- TURN genere des credentials temporaires HMAC-SHA1 compatibles coturn avec secret env.
- URL S3 pre-signees avec TTL configurable.
- Telechargement d'attachement protege par `download_secret` hashe cote serveur et refuse tant que l'objet S3 n'est pas passe par `complete`/verification.

## Controles Android

- Les cles privees restent dans le stockage local chiffre.
- Le secret de recuperation est genere cote client, affiche une seule fois et seul un verifier est envoye au serveur a la creation.
- Les messages en clair ne sont pas stockes dans Room; le corps local est rechiffre avec AES-256-GCM via Android Keystore.
- Les attachements sont chiffres avant upload et les fichiers persistants doivent rester sous forme chiffree.
- OkHttp ajoute le JWT en header sans le logger.
- TLS est obligatoire par manifeste Android (`usesCleartextTraffic=false`).
- Certificate pinning activable par build fields et desactivable en debug.
- Le push Android affiche une notification generique sans contenu de message. En dev/test, le serveur utilise `NoopPushSender`; en production, `PUSH_PROVIDER=fcm` active Firebase HTTP v1.

## Limite crypto Android

`SignalCryptoEngine` utilise l'AAR Android `org.signal:libsignal-android:0.76.1` pour les messages texte 1-to-1 via `SignalProtocolStore`, prekeys, signed prekeys et Kyber prekeys persistants localement.

Le moteur crypto provisoire a ete retire du code Android principal. `ReleaseCryptoGuard` impose `SignalCryptoEngine` hors debug; tout retour d'un moteur non libsignal dans le chemin release doit faire echouer les tests.

La discovery de cles (`GET /v1/keys/{user_id}/devices`) ne consomme jamais de one-time prekey. La consommation est limitee a `POST /v1/keys/{user_id}/devices/{device_id}/claim-prekey`, appele uniquement quand Android doit creer une nouvelle session libsignal. Android verifie `hasSession` avant de claim et publie de nouvelles prekeys quand `/v1/keys/status` signale un stock bas.

L'app expose une empreinte locale dans les parametres et un code de securite par conversation calcule depuis les cles d'identite locale/distante. L'etat local par appareil est `UNVERIFIED`, `VERIFIED`, `CHANGED` ou `BLOCKED`. Un changement de cle distante efface la verification, passe l'appareil en `CHANGED` et cree un historique local. Le mode haute securite bloque l'envoi vers `UNVERIFIED` ou `CHANGED`. Il manque encore une ceremonie produit complete avec scan QR finalise et validation instrumentee exhaustive.

Le depot ne doit pas etre declare production-ready cryptographiquement tant que le chemin libsignal release n'a pas ete valide sur deux appareils reels avec fermeture/reouverture, que la politique de confiance/fingerprint n'a pas ete auditee, et que groupes/canaux restent sans sender-key Signal.

Le relais officiel est un bootstrap applicatif, pas un secret de securite. En release, Android affiche le libelle produit du relais officiel et son etat, sans exposer l'URL brute. Les relais personnalises sont stockes separement et attaches a des bulles; ils ne remplacent pas globalement toutes les conversations.

## Menaces hors perimetre V1

- Groupes et multi-device robuste.
- WebRTC Android media reel et appels de groupe robustes.
- P2P.
- Protection avancee contre l'analyse de trafic.
- Compromission complete de l'appareil Android.
- Backend malveillant qui sert de mauvaises prekeys sans mecanisme Signal complet de verification d'identite.
