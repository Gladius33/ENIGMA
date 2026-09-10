# Enigma E2EE Server V1

Serveur Rust V1 pour Enigma. Le backend relaie des enveloppes chiffrées opaques, gère comptes, appareils, contacts, prekeys, messages directs, groupes, canaux publics, signaling d'appels, TURN, WebSocket et pièces jointes S3 compatibles MinIO.

## Propriétés V1

- Le serveur ne reçoit jamais de message en clair.
- Les `ciphertext`, clés, secrets et tokens ne sont pas journalisés.
- Les messages livrés sont supprimés de `message_queue` après ACK.
- Les pièces jointes doivent être chiffrées côté client avant upload.
- Groupes/canaux/calls ne transportent que des payloads opaques.
- Pas de P2P, pas de lecture serveur. Les tokens FCM sont acceptes comme metadonnees appareil V1.

## Installation

```bash
rustup toolchain install stable
rustup default stable
cargo --version
```

## Lancement local complet

```bash
cp .env.example .env
docker compose up -d --build
```

Le backend écoute sur `http://localhost:8080`. MinIO est disponible sur `http://localhost:9001`.

## Migrations

Les migrations SQLx sont embarquées dans le binaire et exécutées au démarrage.

Pour lancer seulement les dépendances et le serveur hors Docker :

```bash
docker compose up -d postgres redis minio minio-init
set -a
. ./.env
set +a
cargo run
```

## Tests

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Le script racine demarre PostgreSQL, Redis et MinIO via Docker si `TEST_DATABASE_URL` et `TEST_REDIS_URL` ne sont pas definis :

```bash
../scripts/check-server.sh
```

Pour pointer vers des dependances deja lancees :

```bash
export TEST_DATABASE_URL=postgres://enigma:enigma_dev_password@localhost:5432/enigma
export TEST_REDIS_URL=redis://localhost:6379
cargo test --test api_integration
```

## Exemple curl

```bash
curl -s http://localhost:8080/v1/health
```

```bash
TOKEN=$(
  curl -s -X POST http://localhost:8080/v1/auth/register \
    -H 'content-type: application/json' \
    -d '{"public_id":"alice","password":"correct horse battery staple"}' \
  | jq -r .access_token
)
```

```bash
curl -s -X POST http://localhost:8080/v1/devices/register \
  -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"display_name":"Alice Pixel","platform":"android"}'
```

La reponse contient un nouveau `access_token` lie au device; utilise-le pour `keys`, `messages`, `attachments`, `fcm-token` et WebSocket.

Voir [api.md](api.md) et [../docs/api-contract.md](../docs/api-contract.md) pour les payloads des endpoints.

TURN utilise `TURN_SHARED_SECRET`, `TURN_REALM` et `TURN_URIS`. Le compose dev inclut un coturn local.

## Notes sécurité

La V1 limite les métadonnées stockées au strict nécessaire pour relayer les messages : identifiants d’appareils, enveloppe chiffrée opaque, timestamps et état de livraison. Toute logique cryptographique E2EE, y compris chiffrement des messages et pièces jointes, reste côté client.
