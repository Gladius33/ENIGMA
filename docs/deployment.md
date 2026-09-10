# Deploiement

## Developpement Docker

```bash
./scripts/dev-up.sh
./scripts/dev-down.sh
```

`infra/docker-compose.dev.yml` inclut le compose serveur avec PostgreSQL, Redis, MinIO, backend et coturn.

## Production Docker

`infra/docker-compose.prod.yml` ne lance que le backend et suppose PostgreSQL, Redis, S3/MinIO et coturn externes.

En production, definir `APP_ENV=production`. Le serveur refuse `CORS_ALLOWED_ORIGINS=*` et refuse `PUSH_PROVIDER=noop`; ces garde-fous sont couverts par les tests unitaires `config::tests`.

## Binaire natif systemd

Compiler le serveur puis installer le binaire avec `infra/systemd/enigma-server.service`. Les variables doivent vivre dans `/etc/enigma/server.env`.

## Variables externes

- `DATABASE_URL`
- `REDIS_URL`
- `S3_ENDPOINT`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_BUCKET`
- `TURN_SHARED_SECRET`, `TURN_REALM`, `TURN_URIS`
- `JWT_SECRET`, `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_ACCEPT_LEGACY_TOKENS`
- `TRUSTED_PROXIES`, `PUBLIC_CLIENT_IP_HEADER`
- `CORS_ALLOWED_ORIGINS`
- `APP_ENV`
- `PUSH_PROVIDER`
- `FCM_PROJECT_ID`, `FCM_SERVICE_ACCOUNT_JSON_PATH` ou `FCM_SERVICE_ACCOUNT_JSON` si `PUSH_PROVIDER=fcm`
- `ANDROID_APK_URL`, `ANDROID_LATEST_VERSION_NAME`, `ANDROID_LATEST_VERSION_CODE`, `ANDROID_APK_SHA256` si le relais publie un manifeste sideload

## Reverse proxy/TLS

Des exemples nginx et Caddy sont dans `infra/nginx/` et `infra/caddy/`. Android attend HTTPS.

Par defaut, le backend ignore `x-forwarded-for` et `x-real-ip` et rate-limit sur l'IP socket reelle. Pour utiliser l'IP publique derriere un reverse proxy, definir explicitement :

```text
TRUSTED_PROXIES=127.0.0.1/32,10.0.0.0/8
PUBLIC_CLIENT_IP_HEADER=x-forwarded-for
```

Le proxy doit reecrire strictement le header choisi et le backend ne doit pas etre expose directement avec des headers forwarding acceptes. Si l'IP socket n'appartient pas a `TRUSTED_PROXIES`, tout header forwarding est ignore.

## Manifeste APK sideload

Le backend expose `GET /v1/releases/android?channel=stable` seulement si les variables `ANDROID_APK_URL`, `ANDROID_LATEST_VERSION_NAME`, `ANDROID_LATEST_VERSION_CODE` et `ANDROID_APK_SHA256` sont configurees. Le client Android valide le manifeste, distingue Play Store/sideload quand Android expose l'information, affiche le SHA-256 attendu et ne doit jamais installer silencieusement une APK.
