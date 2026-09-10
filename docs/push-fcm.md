# Push FCM V1

## Etat actuel

Le backend accepte et stocke les tokens FCM par appareil via `POST /v1/devices/fcm-token`.

Le module serveur `push` fournit :

- `PushSender` : interface d'envoi.
- `NoopPushSender` : implementation active par defaut en dev/test.
- `FcmPushSender` : implementation Firebase HTTP v1 active avec `PUSH_PROVIDER=fcm`.
- `PushNotification` : signal interne converti en payload Firebase opaque.
- hooks pour message direct, message de groupe, post de canal et appel entrant.

## Confidentialite

Les notifications push ne doivent jamais contenir :

- texte clair;
- ciphertext complet;
- cle, nonce ou secret de telechargement;
- JWT;
- token FCM dans les logs.

Le payload Firebase HTTP v1 reste volontairement minimal :

```json
{"type":"sync_hint"}
```

Il ne transporte pas d'identifiant de message, groupe, canal, appel, expediteur ou conversation. Le client resynchronise ensuite via HTTPS authentifie.

## Configuration

Dev/test :

```env
APP_ENV=development
PUSH_PROVIDER=noop
```

Production :

```env
APP_ENV=production
PUSH_PROVIDER=fcm
FCM_PROJECT_ID=your-firebase-project
FCM_SERVICE_ACCOUNT_JSON_PATH=/run/secrets/firebase-service-account.json
```

`FCM_SERVICE_ACCOUNT_JSON` peut aussi contenir le JSON complet si le deploiement ne permet pas de monter un fichier secret.

## Implementation HTTP v1

L'implementation Firebase HTTP v1 :

1. charge un service account depuis la configuration serveur;
2. obtient un access token OAuth2 scope `https://www.googleapis.com/auth/firebase.messaging`;
3. poste vers `https://fcm.googleapis.com/v1/projects/{project_id}/messages:send`;
4. encode uniquement `type=sync_hint`;
5. traite les tokens invalides en desactivant `push_enabled` sans journaliser le token complet.

Android accepte `sync_hint` et `wake`, lance une sync pending/receipts/retry/contacts, puis affiche une notification locale generique si les notifications sont autorisees. Sur Android 13+, l'ecran `Parametres` expose l'etat de permission `POST_NOTIFICATIONS` et permet de demander l'autorisation runtime; le refus ne bloque pas la reception, car WebSocket et polling restent les chemins de sync.

Tests automatises actuels :

- tous les types de notification serveur serialisent uniquement `type=sync_hint`;
- le sender FCM HTTP v1 est teste contre un endpoint HTTP mock local;
- les reponses Firebase `400` et `404` sont traitees comme tokens invalides, ce qui desactive ensuite le push du device cote base;
- aucun test automatise ne contacte Google.

Validation production restante : tester l'envoi avec un vrai projet Firebase, des credentials de service account reels et un appareil Android reel. Sans credentials et appareil, le code est compilable et mocke, mais le push ne peut pas etre signe production-ready.
