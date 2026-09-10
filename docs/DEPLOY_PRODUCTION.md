# Deploiement production

Ce runbook decrit l'etat attendu pour un self-host production. Il ne transforme pas le depot en production-ready tant que les hard gates crypto/Android ne sont pas verts.

## Prerequis

- Domaine DNS pointe vers le serveur.
- Reverse proxy HTTPS Caddy ou nginx.
- PostgreSQL gere hors conteneur backend ou service Docker dedie.
- Redis gere.
- S3 compatible ou MinIO production.
- Secrets stockes hors Git.
- Backup/restore testes.

## Variables minimales

```env
APP_ENV=production
BIND_ADDR=0.0.0.0:8080
DATABASE_URL=postgres://...
REDIS_URL=redis://...
S3_ENDPOINT=https://...
S3_ACCESS_KEY_ID=...
S3_SECRET_ACCESS_KEY=...
S3_BUCKET=enigma-attachments
JWT_SECRET=long-secret
JWT_ISSUER=enigma-v1
JWT_AUDIENCE=enigma-api
JWT_ACCEPT_LEGACY_TOKENS=false
TRUSTED_PROXIES=10.0.0.0/8
PUBLIC_CLIENT_IP_HEADER=x-forwarded-for
CORS_ALLOWED_ORIGINS=https://app.example.com
PUSH_PROVIDER=fcm
FCM_PROJECT_ID=...
FCM_SERVICE_ACCOUNT_JSON_PATH=/run/secrets/firebase-service-account.json
```

Le serveur refuse `CORS_ALLOWED_ORIGINS=*` et `PUSH_PROVIDER=noop` en `APP_ENV=production`.

## Lancement

```bash
docker compose -f infra/docker-compose.prod.yml up -d --build
curl https://example.com/health
curl https://example.com/version
```

## Reverse proxy

Exemples :

- `infra/caddy/Caddyfile.example`
- `infra/nginx/enigma.conf.example`

Le proxy doit transmettre WebSocket `/v1/ws` et ne pas journaliser les query strings ni headers `Authorization`. Il doit reecrire strictement le header client configure (`x-forwarded-for` ou `x-real-ip`). Le backend ignore ces headers si l'IP socket n'appartient pas a `TRUSTED_PROXIES`.

## Sauvegardes

A sauvegarder :

- PostgreSQL;
- bucket S3/MinIO des blobs chiffres;
- configuration et secrets hors Git.

Redis ne contient pas de source de verite durable en V1.

## Rollback

1. conserver l'image backend precedente taggee;
2. conserver le schema PostgreSQL sauvegarde avant migration;
3. restaurer image + base + env;
4. verifier `/health`, `/version`, login, pending messages et presign attachments.

## Gates avant exposition publique

```bash
./scripts/check-server.sh
./scripts/check-android.sh
cd android && ./gradlew :app:lintDebug :app:assembleRelease
```

Pour signer la release Android, fournir un keystore hors depot via l'environnement :

```bash
cd android
ENIGMA_BASE_URL=https://ton-domaine.example/ \
ENIGMA_RELEASE_STORE_FILE=/chemin/absolu/enigma-release.jks \
ENIGMA_RELEASE_STORE_PASSWORD='secret-keystore' \
ENIGMA_RELEASE_KEY_ALIAS=enigma \
ENIGMA_RELEASE_KEY_PASSWORD='secret-cle' \
ENIGMA_UPDATE_ED25519_PUBLIC_KEY='base64-public-key-x509-der' \
./gradlew :app:assembleRelease
```

Sans les variables de signature APK, `assembleRelease` reste utile comme gate de compilation/R8 mais produit une APK unsigned non publiable. Sans `ENIGMA_UPDATE_ED25519_PUBLIC_KEY`, le client refuse de telecharger un manifeste d'update signe parce qu'il ne peut pas verifier la signature Ed25519.

Ne pas exposer publiquement comme V1 production tant que libsignal release, safety ceremony, replenishment prekeys, FCM reel, tests Android critiques, signature APK officielle et audit logs/secrets ne sont pas valides. Groupes et canaux utilisent l'enveloppe V1 par destinataire/device sans Sender Keys; les appels WebRTC Android sont integres mais doivent etre valides sur deux appareils reels avant une release publique.
