# Déploiement ThinkStation

Objectif : lancer le relais Enigma sur le LAN pour tester deux téléphones Android réels.

## Préparer

Depuis la racine du dépôt :

```bash
cp .env.example .env
```

Édite `.env` avant exposition hors LAN :

- change `JWT_SECRET`;
- garde `BIND_ADDR=0.0.0.0:8080` pour écouter sur le LAN;
- garde `SERVER_PORT=8080` sauf conflit local.

## Lancer

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f backend
```

Le serveur exécute les migrations automatiquement au démarrage.

## Vérifier

Depuis la ThinkStation :

```bash
curl http://localhost:8080/health
curl http://localhost:8080/version
```

Depuis un autre appareil du LAN :

```bash
curl http://IP_THINKSTATION:8080/health
curl http://IP_THINKSTATION:8080/version
```

Trouver l'IP LAN :

```bash
hostname -I
```

## Ports

- `8080` : API HTTP/WebSocket backend.
- `15432` : PostgreSQL dev sur l'hote (`5432` dans le reseau Docker).
- `16379` : Redis dev sur l'hote (`6379` dans le reseau Docker).
- `19000` : MinIO API sur l'hote (`9000` dans le reseau Docker).
- `19001` : console MinIO sur l'hote (`9001` dans le reseau Docker).
- `3478` : coturn.

Si un port est déjà pris, change la variable correspondante dans `.env`, par exemple `SERVER_PORT=18080`.

Si `./scripts/check-server.sh` a lancé les dépendances de test avant le compose racine, libère ces conteneurs avant le test LAN :

```bash
docker compose -f server/docker-compose.yml down
docker compose up -d --build
```

## Pare-feu LAN

Sur Ubuntu, autoriser le port API :

```bash
sudo ufw allow 8080/tcp
```

N'expose pas PostgreSQL, Redis, MinIO ou TURN à Internet pour ce test.

## Arrêter

```bash
docker compose down
```

Les volumes Docker conservent les données. Pour un reset complet de test :

```bash
docker compose down -v
```

## Binaire natif

Docker n'est pas obligatoire. Le binaire Rust reste lançable avec les variables de `.env` adaptées à des services PostgreSQL/Redis/S3 externes :

```bash
cd server
cargo run --release
```
