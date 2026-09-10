# API serveur V1

La source de verite du contrat HTTP/WebSocket est `../docs/api-contract.md`.

Routes exposees par le serveur :

- `GET /v1/health`
- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `POST /v1/devices/register`
- `POST /v1/devices/fcm-token`
- `GET /v1/devices`
- `DELETE /v1/devices/{device_id}`
- `POST /v1/keys/upload`
- `GET /v1/keys/{user_id}`
- `GET /v1/users/resolve/{public_id}`
- `POST /v1/contacts`
- `GET /v1/contacts`
- `DELETE /v1/contacts/{contact_user_id}`
- `POST /v1/messages`
- `GET /v1/messages/pending?device_id={uuid}`
- `GET /v1/messages/receipts?device_id={uuid}`
- `POST /v1/messages/{id}/receipt`
- `POST /v1/attachments/presign-upload`
- `POST /v1/attachments/presign-download`
- `POST /v1/groups`
- `GET /v1/groups`
- `GET /v1/groups/{group_id}`
- `POST /v1/groups/{group_id}/members`
- `DELETE /v1/groups/{group_id}/members/{user_id}`
- `POST /v1/groups/{group_id}/messages`
- `GET /v1/groups/{group_id}/messages/pending`
- `POST /v1/groups/{group_id}/messages/{message_id}/receipt`
- `POST /v1/channels`
- `GET /v1/channels`
- `GET /v1/channels/{channel_id}`
- `POST /v1/channels/{channel_id}/subscribe`
- `DELETE /v1/channels/{channel_id}/subscribe`
- `POST /v1/channels/{channel_id}/posts`
- `GET /v1/channels/{channel_id}/posts/pending`
- `POST /v1/calls`
- `POST /v1/calls/{call_id}/accept`
- `POST /v1/calls/{call_id}/reject`
- `POST /v1/calls/{call_id}/hangup`
- `POST /v1/calls/{call_id}/offer`
- `POST /v1/calls/{call_id}/answer`
- `POST /v1/calls/{call_id}/ice-candidates`
- `GET /v1/calls/{call_id}/ice-candidates`
- `POST /v1/turn/credentials`
- `GET /v1/releases/android?channel=stable`
- `GET /v1/ws?device_id=<uuid>` avec `Authorization: Bearer <jwt>`

Notes serveur :

- `POST /v1/devices/register` retourne le token lie au device; le client doit remplacer le token bootstrap recu a l'authentification.
- Les routes liees a un appareil refusent un JWT dont le `device_id` ne correspond pas au device cible.
- WebSocket refuse les JWT en query string; utiliser le header `Authorization`.
- Le serveur ne doit jamais logger mots de passe, JWT complets, tokens FCM complets, cles, ciphertexts complets ni URLs S3 pre-signees completes.
- Les erreurs publiques utilisent `error_code`, `message` et `request_id`.
