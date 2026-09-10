# API Enigma V1

Le contrat détaillé vit dans [api-contract.md](api-contract.md). Ce fichier sert d'entrée courte pour clients alternatifs.

Base locale Docker :

```text
http://IP_THINKSTATION:8080
```

Routes sans auth :

- `GET /health`
- `GET /version`
- `GET /v1/health`
- `GET /v1/identities/check?handle=alice`
- `GET /v1/releases/android?channel=stable`
- `POST /v1/identities`
- `POST /v1/auth/register`
- `POST /v1/auth/login`

Routes principales avec `Authorization: Bearer <jwt>` :

- devices : `/v1/devices`
- keys : `/v1/keys`
- contacts : `/v1/contacts`
- messages : `/v1/messages`, incluant `/pending`, `/receipts` et `/{id}/receipt`
- attachments : `/v1/attachments`
- groups : `/v1/groups`
- channels : `/v1/channels`
- calls : `/v1/calls`
- turn : `/v1/turn/credentials`
- websocket : `/v1/ws?device_id=<uuid>` avec header `Authorization`

Erreur standard :

```json
{"error_code":"FORBIDDEN","message":"access denied","request_id":"uuid"}
```

Exemple création identité :

```bash
curl -s http://localhost:8080/v1/identities \
  -H 'content-type: application/json' \
  -d '{
    "display_name":"alice_test",
    "password":"correct horse battery staple",
    "identity_public_key":"opaque-public-identity-key",
    "signed_prekey":"opaque-signed-prekey",
    "signed_prekey_signature":"opaque-signed-prekey-signature",
    "one_time_prekeys":[],
    "device_name":"Alice Android",
    "platform":"android"
  }'
```

Exemple upload de cles compatible libsignal :

```bash
curl -s http://localhost:8080/v1/keys/upload \
  -H 'authorization: Bearer TOKEN_DEVICE' \
  -H 'content-type: application/json' \
  -d '{
    "device_id":"DEVICE_UUID",
    "identity_key":"base64-identity-key",
    "registration_id":12345,
    "protocol_device_id":1,
    "signed_prekey":{"key_id":1,"public_key":"base64-signed-prekey","signature":"base64-signature"},
    "kyber_prekey":{"key_id":2,"public_key":"base64-kyber-prekey","signature":"base64-signature"},
    "one_time_prekeys":[{"key_id":3,"public_key":"base64-one-time-prekey"}]
  }'
```

Discovery sans consommation de one-time prekey :

```bash
curl -s http://localhost:8080/v1/keys/USER_UUID/devices \
  -H 'authorization: Bearer TOKEN_DEVICE'
```

Claim explicite, uniquement si le client doit creer une nouvelle session libsignal :

```bash
curl -s -X POST http://localhost:8080/v1/keys/USER_UUID/devices/DEVICE_UUID/claim-prekey \
  -H 'authorization: Bearer TOKEN_DEVICE'
```

Exemple health :

```bash
curl http://localhost:8080/health
curl http://localhost:8080/version
```
