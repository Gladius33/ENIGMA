# Contrat API V1 produit

Source de verite commune serveur Rust et Android. Base URL : `/v1`.

Auth HTTP : `Authorization: Bearer <jwt>` sauf `GET /health`, `GET /version`, `GET /v1/health`, `POST /v1/auth/register`, `POST /v1/auth/login`, `GET /v1/identities/check`, `POST /v1/identities`, `POST /v1/identities/recover/start` et `POST /v1/identities/recover/complete`.

Les tokens `register/login` sont bootstrap. `POST /v1/devices/register` retourne un token lie au `device_id`; les endpoints par appareil exigent ce token. Les nouveaux JWT portent `iss`, `aud`, `typ` (`bootstrap` ou `device`) et `jti`; les tokens legacy sans ces claims peuvent etre acceptes uniquement pendant la fenetre de migration configuree cote serveur.

Erreur JSON :

```json
{
  "error_code":"FORBIDDEN",
  "message":"access denied",
  "request_id":"uuid"
}
```

Codes stables minimaux : `VALIDATION_ERROR`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `RATE_LIMITED`, `INTERNAL_ERROR`, `HANDLE_ALREADY_TAKEN`, `HANDLE_RESERVED`, `INVALID_RECOVERY_SECRET`, `RECOVERY_NOT_CONFIGURED`, `RELEASE_NOT_CONFIGURED`, `RELAY_SESSION_REQUIRED`, `BUBBLE_SYNC_REQUIRED`, `DEVICE_ID_ALREADY_REGISTERED`.

Android parse ce format via un mapper d'erreurs et ne doit pas parser `message` pour prendre une decision. Les clients alternatifs doivent utiliser `error_code` pour la logique et conserver `request_id` pour le diagnostic.

## Health

- `GET /health` sans auth.
- `GET /version` sans auth.
- `GET /v1/health` sans auth.
- `200`: `{"status":"ok"}`.

Version response :

```json
{"name":"enigma-e2ee-server","version":"0.1.0"}
```

## Android release manifest

- `GET /v1/releases/android?channel=stable` sans auth.

Si le relais ne distribue pas d'APK sideload :

```json
{
  "error_code":"RELEASE_NOT_CONFIGURED",
  "message":"RELEASE_NOT_CONFIGURED",
  "request_id":"uuid"
}
```

Si configure :

```json
{
  "platform":"android",
  "channel":"stable",
  "latest_version_name":"1.0.0",
  "latest_version_code":1,
  "apk_url":"https://example.org/enigma.apk",
  "sha256":"hex-sha256",
  "signature":"base64-ed25519-signature-or-null",
  "mandatory":false,
  "release_notes":{"fr":"Notes FR","en":"English notes"}
}
```

Le champ `signature` est une signature Ed25519 base64 calculee sur les bytes exacts de l'APK. Android verifie cette signature seulement si l'APK a ete construit avec `ENIGMA_UPDATE_ED25519_PUBLIC_KEY`, une cle publique Ed25519 X.509 DER encodee en base64.

Le client Android ne doit jamais installer silencieusement une mise a jour. Etat actuel : il valide le manifeste (`https`, SHA-256 hex, signature si presente), affiche l'origine d'installation et le hash attendu, telecharge explicitement l'APK en cache pour les installations non Play Store, verifie le SHA-256 des bytes telecharges, verifie la signature Ed25519 des bytes telecharges quand la cle publique est configuree, refuse un manifeste signe si aucune cle publique n'est embarquee, supprime le fichier si le hash ou la signature divergent, ouvre les parametres sources inconnues si necessaire, puis lance l'installateur Android via `FileProvider`. La validation appareil reel du flux installateur reste a finaliser.

## Identities

V1 conserve `users.public_id` comme alias de compatibilite, mais la source V1 est :

- `display_name` : saisie affichable ASCII V1.
- `canonical_handle` : minuscule, unique PostgreSQL, sans `@`.
- `public_handle` : forme publique `@handle`.

Regles handle V1 : 3 a 32 caracteres, ASCII lettres/chiffres/`_`/`-`, pas d'espace, pas d'accent, casse ignoree.

- `GET /v1/identities/check?handle=Seb63`
- `POST /v1/identities`
- `DELETE /v1/identities/me`
- `POST /v1/identities/recover/start`
- `POST /v1/identities/recover/complete`

Check disponible :

```json
{"handle":"Seb63","canonical_handle":"seb63","available":true,"reason":null}
```

Check indisponible :

```json
{"handle":"Seb63","canonical_handle":"seb63","available":false,"reason":"HANDLE_ALREADY_TAKEN"}
```

Create request :

```json
{
  "display_name":"Seb63",
  "password":"correct horse battery staple",
  "identity_public_key":"base64-public-key",
  "signed_prekey":"base64-public-key",
  "signed_prekey_signature":"base64-signature",
  "one_time_prekeys":["base64-public-key"],
  "device_name":"Seb Android",
  "platform":"android",
  "device_public_key":"base64-public-key",
  "recovery_key_verifier":"pbkdf2-sha256$120000$salt-base64url$hash-base64url"
}
```

Create response :

```json
{
  "identity_id":"uuid",
  "display_name":"Seb63",
  "canonical_handle":"seb63",
  "public_handle":"@seb63",
  "device_id":"uuid",
  "access_token":"jwt-device-bound",
  "token_type":"Bearer",
  "expires_in":3600,
  "created_at":"timestamp"
}
```

Suppression :

```json
{"status":"deleted","canonical_handle":"seb63","reserved_forever":true}
```

La suppression marque l'identite supprimee, revoque appareils/sessions/prekeys et cree un tombstone. Elle ne supprime pas a distance les messages deja livres sur les appareils.

Recovery start response :

```json
{"canonical_handle":"seb63","recovery_configured":true}
```

`recovery_key_verifier` est un verifier client-side. Le client Android actuel genere un secret aleatoire, calcule un verifier `pbkdf2-sha256$iterations$salt$hash`, puis affiche le secret une seule fois. Le serveur accepte aussi les anciens verifiers Argon2 utilises par les tests. Recovery complete cree un nouvel appareil et de nouvelles cles. Le serveur ne recupere jamais les anciennes cles privees et ne promet pas la recuperation des anciens messages.

## Auth

- `POST /v1/auth/register`
- `POST /v1/auth/login`

Request :

```json
{"public_id":"alice","password":"correct horse battery staple"}
```

Response :

```json
{
  "access_token": "jwt-bootstrap",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id":"uuid",
    "public_id":"alice",
    "display_name":"Alice",
    "canonical_handle":"alice",
    "public_handle":"@alice"
  }
}
```

## Devices

- `POST /v1/devices/register`
- `POST /v1/devices/fcm-token`
- `GET /v1/devices`
- `DELETE /v1/devices/{device_id}`

Register request :

```json
{"display_name":"Alice Pixel","platform":"android","device_id":"uuid-optional"}
```

`device_id` est optionnel pour les clients existants. Si fourni, le serveur reutilise cet UUID pour le meme utilisateur, met a jour `display_name`/`platform`, lie la session courante a cet appareil et retourne un nouveau token device-bound. Si l'UUID existe pour une autre identite ou pour un appareil revoque, le serveur repond `409` avec `DEVICE_ID_ALREADY_REGISTERED`. Android utilise ce champ lors de la connexion a un relais prive actif : il se connecte localement au relais, enregistre le meme `device_id` que sur le relais officiel, stocke le token device-bound pour cette base URL, puis republie les prekeys sur ce relais sans envoyer le token officiel global.

Register response :

```json
{
  "device":{"id":"uuid","display_name":"Alice Pixel","platform":"android","created_at":"timestamp"},
  "access_token":"jwt-device-bound",
  "token_type":"Bearer",
  "expires_in":3600
}
```

FCM request :

```json
{"fcm_token":"opaque-fcm-token","platform":"android"}
```

`GET /v1/devices` response :

```json
{"devices":[{"id":"uuid","display_name":"Alice Pixel","platform":"android","created_at":"timestamp"}]}
```

Security : le token FCM complet ne doit jamais etre logge.

## Keys

- `POST /v1/keys/upload`
- `GET /v1/keys/{user_id}` alias legacy non consommateur
- `GET /v1/keys/{user_id}/devices`
- `POST /v1/keys/{user_id}/devices/{device_id}/claim-prekey`
- `GET /v1/keys/status`

Upload request :

```json
{
  "device_id":"uuid",
  "identity_key":"base64-public-key",
  "registration_id":12345,
  "protocol_device_id":1,
  "signed_prekey":{"key_id":1,"public_key":"base64","signature":"base64"},
  "kyber_prekey":{"key_id":2,"public_key":"base64","signature":"base64"},
  "one_time_prekeys":[{"key_id":2,"public_key":"base64"}]
}
```

Pour le moteur Android actuel base sur `org.signal:libsignal-android:0.76.1`, `registration_id` et `protocol_device_id` doivent etre fournis ensemble, `kyber_prekey` est requis, les champs de cles doivent etre du base64 valide et les `one_time_prekeys` ne doivent pas contenir de doublons de `key_id`.

Discovery response, sans consommation de one-time prekey :

```json
{
  "user_id":"uuid",
  "devices":[{
    "device_id":"uuid",
    "identity_key":"base64-public-key",
    "registration_id":12345,
    "protocol_device_id":1,
    "signed_prekey":{"key_id":1,"public_key":"base64","signature":"base64"},
    "kyber_prekey":{"key_id":2,"public_key":"base64","signature":"base64"},
    "one_time_prekey_count":42,
    "prekey_low":false
  }]
}
```

Claim response, seul endpoint autorise a consommer une one-time prekey :

```json
{
  "user_id":"uuid",
  "device":{
    "device_id":"uuid",
    "identity_key":"base64-public-key",
    "registration_id":12345,
    "protocol_device_id":1,
    "signed_prekey":{"key_id":1,"public_key":"base64","signature":"base64"},
    "kyber_prekey":{"key_id":2,"public_key":"base64","signature":"base64"},
    "one_time_prekey":{"key_id":3,"public_key":"base64"},
    "one_time_prekey_count_after_claim":41,
    "prekey_low":false
  }
}
```

Si le stock est epuise, `one_time_prekey` vaut `null`; le client doit declencher un replenishment du device proprietaire via `GET /v1/keys/status` et `POST /v1/keys/upload`.

Status response :

```json
{
  "device_id":"uuid",
  "one_time_prekey_count":8,
  "prekey_low":true,
  "recommended_upload_count":50,
  "max_upload_count":100
}
```

## Users / Contacts

- `GET /v1/users/resolve/{public_id}`
- `POST /v1/contacts`
- `GET /v1/contacts`
- `DELETE /v1/contacts/{contact_user_id}`

Add contact request :

```json
{"contact_user_id":"uuid"}
```

Contacts response :

```json
{"contacts":[{"user_id":"uuid","public_id":"bob","created_at":"timestamp"}]}
```

## Relays

- `GET /v1/relays`
- `POST /v1/relays/custom`
- `GET /v1/relays/official-descriptor`

Relay response :

```json
{
  "id":"00000000-0000-0000-0000-000000000001",
  "name":"Relais officiel Enigma",
  "url":"https://relay.example.invalid/",
  "public_key":null,
  "type":"OFFICIAL",
  "trust_level":"VERIFIED",
  "is_official":true,
  "created_at":"timestamp",
  "last_seen_at":"timestamp",
  "region":"automatic"
}
```

L'identifiant public stable du relais officiel est `00000000-0000-0000-0000-000000000001`. Le serveur, Android, le seed local, les QR et les tests doivent utiliser cet UUID et ne doivent pas introduire d'alias local divergent. Android ne doit pas afficher l'URL brute du relais officiel en release. Les relais personnalises peuvent etre affiches et attaches a une bulle sans remplacer globalement les conversations existantes.

Create custom relay request :

```json
{"name":"Relais prive","url":"wss://relay.example","relay_type":"PRIVATE","public_key":null}
```

## Bubbles

- `GET /v1/bubbles`
- `POST /v1/bubbles`
- `GET /v1/bubbles/{bubble_id}`
- `GET /v1/bubbles/{bubble_id}/members`
- `GET /v1/bubbles/{bubble_id}/relays`
- `POST /v1/bubbles/{bubble_id}/relays`

Pour la V1, `GET /v1/bubbles` cree et retourne une Main Bubble par utilisateur authentifie si elle n'existe pas encore.

Bubble response :

```json
{
  "id":"uuid",
  "slug":"main-user",
  "name":"Main Bubble",
  "description":"Conversations Enigma globales",
  "mode":"MAIN_GLOBAL",
  "visibility":"PRIVATE",
  "join_policy":"CLOSED",
  "index_policy":"INDEX_FORBIDDEN",
  "owner_identity_id":"uuid",
  "public_key":null,
  "created_at":"timestamp",
  "updated_at":"timestamp"
}
```

Attach relay request :

```json
{"relay_id":"uuid","role":"primary","priority":0,"required":false,"fallback_allowed":true}
```

Politique client attendue :

- Main Bubble : relais officiel `00000000-0000-0000-0000-000000000001`.
- Private Connected : relais prive attache a la bulle; fallback officiel autorise seulement si `fallback_allowed=true`.
- Private Isolated : relais prive attache a la bulle uniquement; aucun fallback officiel et pas de melange contacts/conversations globales.

Android stocke `bubble_id` sur les conversations locales. Les listes messages/contacts/groupes/canaux doivent etre filtrees par le contexte de bulle actif. Les payloads reseau `bubble_id` utilisent l'UUID de bulle connu du relais; si une bulle locale n'est pas encore synchronisee avec le relais, Android doit afficher `BUBBLE_SYNC_REQUIRED` au lieu d'envoyer un identifiant local non canonique.
Les appels reseau dependants d'une bulle passent par `RelayScopedApiProvider` : messages, contacts contextuels, attachments, groupes, canaux, calls et statut serveur. Les exceptions qui restent volontairement sur le relais officiel sont l'auth/registration du compte global, l'identite globale, le descriptor officiel et le check update APK. Un relais non officiel exige une session dediee par base URL; sans cette session, Android doit afficher `RELAY_SESSION_REQUIRED` et ne doit pas envoyer le token officiel au relais prive. La creation de cette session dediee se fait sur le relais prive cible via login, `/v1/devices/register` avec `device_id` local explicite, puis `/v1/keys/upload`.

## QR publics

Les QR Enigma ne doivent contenir aucun token, mot de passe, cle privee, `download_secret` ou secret serveur. Les QR actuellement autorises transportent uniquement :

- identite/contact : identifiant public, handle public, nom affiche, cle publique et signature optionnelle;
- relais : nom, URL publique, cle publique optionnelle et signature optionnelle;
- invitation bulle locale : `bubble_id`, nom, mode et `relay_hint` public optionnel.

Le parser Android rejette les payloads contenant les cles `token`, `password`, `private_key`, `identity_private`, `download_secret`, `access_token` ou `refresh_token`. Les URLs de relais QR doivent utiliser `https://` ou `wss://`, avoir un host, ne pas contenir de userinfo et ne pas porter ces secrets en query string.

## Messages directs

- `POST /v1/messages`
- `GET /v1/messages/pending?device_id={uuid}`
- `GET /v1/messages/receipts?device_id={uuid}`
- `POST /v1/messages/{id}/receipt`

Send request :

```json
{
  "bubble_id":"uuid",
  "sender_device_id":"uuid",
  "recipient_device_id":"uuid",
  "client_message_id":"uuid",
  "message_type":"text|opaque|image|video|audio_message|video_message|file",
  "ciphertext":"base64"
}
```

Response :

```json
{"id":"uuid","bubble_id":"uuid","client_message_id":"uuid","created_at":"timestamp","expires_at":"timestamp"}
```

Pending response :

```json
{
  "messages":[{
    "id":"uuid",
    "bubble_id":"uuid",
    "sender_device_id":"uuid",
    "sender_user_id":"uuid",
    "sender_public_id":"alice",
    "recipient_device_id":"uuid",
    "client_message_id":"uuid",
    "message_type":"text",
    "ciphertext":"base64",
    "created_at":"timestamp",
    "expires_at":"timestamp"
  }]
}
```

Receipt request :

```json
{"device_id":"uuid","status":"delivered|read"}
```

`status` est optionnel pour compatibilite et vaut `delivered` par defaut. `read` est monotone : une receipt deja `read` ne redescend pas en `delivered`.

Sent receipts response :

```json
{
  "receipts":[{
    "message_id":"uuid",
    "bubble_id":"uuid",
    "client_message_id":"uuid",
    "recipient_device_id":"uuid",
    "status":"delivered|read",
    "delivered_at":"timestamp"
  }]
}
```

Security : le serveur ne parse jamais `ciphertext`; pending et receipts sont limites au device destinataire authentifie. `bubble_id` est obligatoire dans `POST /v1/messages`, stocke avec le message et renvoye dans pending/receipts afin qu'Android rattache les conversations a la bulle portee par le serveur, jamais a la bulle active au moment de la synchronisation. `GET /v1/messages/receipts` est limite au device expediteur authentifie et permet au client de marquer les messages sortants comme `DELIVERED` ou `READ` apres relance.

## Attachments

- `POST /v1/attachments/presign-upload`
- `POST /v1/attachments/{blob_id}/complete`
- `POST /v1/attachments/presign-download`

Upload request :

```json
{"bubble_id":"uuid","size_bytes":12345,"sha256":"64-hex-chars","content_type":"application/octet-stream"}
```

Upload response :

```json
{
  "blob_id":"uuid",
  "bubble_id":"uuid",
  "download_secret":"opaque-secret",
  "url":"https://s3/presigned-put",
  "method":"PUT",
  "headers":{},
  "expires_at":"timestamp"
}
```

Download request :

```json
{"blob_id":"uuid","bubble_id":"uuid","download_secret":"opaque-secret"}
```

Complete request :

```json
{"download_secret":"opaque-secret","size_bytes":12345,"sha256":"64-hex-chars"}
```

Security : le client chiffre avant upload et envoie l'UUID de bulle du relais actif. Le serveur stocke `bubble_id` sur l'attachment, ne recoit jamais cle/nonce d'attachement et ne logge jamais l'URL pre-signee complete. Le download exige `blob_id`, `bubble_id` et `download_secret`; il est refuse tant que l'attachement n'est pas `verified`. `complete` verifie l'objet S3 par `HEAD Object`, taille et hash SHA-256 streaming.

## Groups

- `POST /v1/groups`
- `GET /v1/groups?bubble_id=uuid`
- `GET /v1/groups/{group_id}`
- `POST /v1/groups/{group_id}/members`
- `DELETE /v1/groups/{group_id}/members/{user_id}`
- `POST /v1/groups/{group_id}/messages`
- `GET /v1/groups/{group_id}/messages/pending`
- `POST /v1/groups/{group_id}/messages/{message_id}/receipt`

Create request :

```json
{"bubble_id":"uuid","title":"Projet"}
```

Add member request :

```json
{"user_id":"uuid","role":"admin|member"}
```

Group message request :

```json
{
  "bubble_id":"uuid",
  "sender_device_id":"uuid",
  "client_message_id":"uuid",
  "message_type":"opaque",
  "ciphertext":"base64"
}
```

Receipt request :

```json
{"device_id":"uuid","status":"delivered|read"}
```

Responses groupe, message pending et WebSocket portent `bubble_id`. Security : roles `owner/admin/member`; contenu opaque; pending par device membre authentifie. `bubble_id` est stocke sur `groups`, `group_message_queue` et `group_receipts`, puis filtre par la bulle active. La rotation de secrets de groupe libsignal n'est pas finalisee cote Android.

## Channels

- `POST /v1/channels`
- `GET /v1/channels?bubble_id=uuid`
- `GET /v1/channels/{channel_id}`
- `GET /v1/channels/{channel_id}/subscribers`
- `POST /v1/channels/{channel_id}/subscribe`
- `DELETE /v1/channels/{channel_id}/subscribe`
- `POST /v1/channels/{channel_id}/posts`
- `GET /v1/channels/{channel_id}/posts/pending`

Create request :

```json
{"bubble_id":"uuid","title":"Annonces","description":"Posts opaques","avatar_blob_id":null}
```

Subscribers response :

```json
{"subscribers":[{"user_id":"uuid","public_id":"alice","role":"owner|admin|subscriber"}]}
```

Post request :

```json
{
  "bubble_id":"uuid",
  "sender_device_id":"uuid",
  "client_post_id":"uuid",
  "post_type":"opaque",
  "ciphertext":"base64"
}
```

Responses canal, audience, post pending et WebSocket portent le contexte de bulle ou de canal necessaire. Security : seuls owner/admin publient. Les posts restent opaques cote serveur; Android V1 publie une enveloppe base64 contenant des ciphertexts libsignal par device abonne, puis stocke localement uniquement un corps dechiffre rechiffre par le keystore local. `bubble_id` est stocke sur `channels`, `channel_posts_queue` et `channel_post_receipts`, puis filtre par la bulle active. La recherche/indexation serveur publique reste future; une bulle `INDEX_FORBIDDEN` ou `PRIVATE_ONLY` ne doit pas exposer de contenu indexable.

## Calls signaling

- `POST /v1/calls`
- `POST /v1/calls/{call_id}/accept`
- `POST /v1/calls/{call_id}/reject`
- `POST /v1/calls/{call_id}/hangup`
- `POST /v1/calls/{call_id}/offer`
- `POST /v1/calls/{call_id}/answer`
- `POST /v1/calls/{call_id}/ice-candidates`
- `GET /v1/calls/{call_id}/ice-candidates`
- `GET /v1/calls/{call_id}/signaling`

Create request :

```json
{"bubble_id":"uuid","callee_user_id":"uuid","call_kind":"audio|video"}
```

Offer/answer request :

```json
{"bubble_id":"uuid","sdp":"opaque-sdp"}
```

ICE request :

```json
{"bubble_id":"uuid","candidates":["opaque-ice-candidate"]}
```

Signaling response :

```json
{
  "events":[
    {
      "id":"uuid",
      "bubble_id":"uuid",
      "sender_user_id":"uuid",
      "event_kind":"offer|answer|ice|hangup|reject|accept",
      "payload":"opaque-sdp-or-ice-or-null",
      "created_at":"timestamp"
    }
  ]
}
```

`GET /signaling` retourne uniquement les evenements envoyes par les autres participants. Response appel et evenements signaling portent `bubble_id`. Security : signaling opaque uniquement. `bubble_id` est stocke sur `calls` et `call_signaling_events`; le serveur ne transporte pas les flux media.

## TURN

- `POST /v1/turn/credentials`

Response :

```json
{
  "username":"unix_expiry:user_uuid",
  "credential":"base64-hmac-sha1",
  "ttl_seconds":600,
  "expires_at":"timestamp",
  "uris":["turn:example:3478?transport=udp"],
  "realm":"enigma.example"
}
```

Compatible coturn REST auth avec `TURN_SHARED_SECRET`.

## WebSocket

- `GET /v1/ws?device_id=<uuid>`
- Header requis : `Authorization: Bearer <jwt>` avec un token lie au `device_id`.

Evenements :

```json
{"type":"new_message","conversation_kind":"direct","bubble_id":"uuid","message_id":"uuid"}
{"type":"receipt_updated","conversation_kind":"direct","bubble_id":"uuid","message_id":"uuid","client_message_id":"uuid","status":"delivered|read"}
{"type":"new_group_message","bubble_id":"uuid","group_id":"uuid","message_id":"uuid"}
{"type":"new_channel_post","bubble_id":"uuid","channel_id":"uuid","post_id":"uuid"}
{"type":"incoming_call","bubble_id":"uuid","call_id":"uuid"}
{"type":"call_signaling","bubble_id":"uuid","call_id":"uuid","event_kind":"offer|answer|ice|hangup|reject|accept"}
```

Security : aucun payload clair en WebSocket. Le JWT ne doit jamais etre passe en query string. Les logs serveur ne journalisent que la methode HTTP et le path sans query ni header `Authorization`.

## FCM / Push

Le serveur stocke les tokens FCM via `POST /v1/devices/fcm-token` et expose une interface interne `PushSender`.

Etat V1 actuel :

- `NoopPushSender` est l'implementation active en dev/test.
- Les hooks existent pour message direct, message de groupe, post de canal et appel entrant.
- Le payload Firebase HTTP v1 ne contient que `{"type":"sync_hint"}`.
- Aucun contenu clair, ciphertext complet, cle, JWT, token FCM, identifiant de message, groupe, canal, appel, expediteur ou conversation ne doit etre journalise ou envoye dans le payload visible.
- L'envoi Firebase HTTP v1 est disponible via `PUSH_PROVIDER=fcm`, service account et payload opaque. Validation production restante : tester avec un vrai projet Firebase et un appareil reel.

## Business relay endpoints

- `GET /v1/me/plan`, `GET /v1/me/usage` (authentifiés)
- `GET /v1/support/config` (public)
- `GET /v1/official/account`, `GET /v1/official/announcements/pending`, `POST .../{id}/read|dismiss`
- Admin (token `X-Enigma-Admin-Token` ou Bearer): `GET|POST /v1/admin/official/announcements`, `POST .../{id}/publish|broadcast|send-test`.

Les routes official répondent 404 lorsque `OFFICIAL_RELAY_MODE=false`. Les erreurs quota utilisent un `error_code` stable. Aucun endpoint support ne distribue le secret admin ou une URL S3.
