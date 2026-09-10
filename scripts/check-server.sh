#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/server"

wait_for_compose_health() {
  local service="$1"
  local container
  container="$(docker compose -f "$ROOT_DIR/server/docker-compose.yml" ps -q "$service")"
  if [[ -z "$container" ]]; then
    echo "Docker service '$service' is not running." >&2
    return 1
  fi

  for _ in {1..60}; do
    local status
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container")"
    if [[ "$status" == "healthy" || "$status" == "none" ]]; then
      return 0
    fi
    sleep 2
  done

  echo "Docker service '$service' did not become healthy in time." >&2
  return 1
}

port_open() {
  local host="$1"
  local port="$2"
  timeout 1 bash -c "cat < /dev/null > /dev/tcp/${host}/${port}" >/dev/null 2>&1
}

if [[ "${SKIP_INTEGRATION:-0}" == "1" ]]; then
  echo "SKIP_INTEGRATION=1 set: server integration tests are intentionally skipped."
elif [[ -z "${TEST_DATABASE_URL:-}" || -z "${TEST_REDIS_URL:-}" ]]; then
  export POSTGRES_PORT="${POSTGRES_PORT:-15432}"
  export REDIS_PORT="${REDIS_PORT:-16379}"
  export MINIO_PORT="${MINIO_PORT:-19000}"
  export MINIO_CONSOLE_PORT="${MINIO_CONSOLE_PORT:-19001}"
  if port_open localhost "$POSTGRES_PORT" && port_open localhost "$REDIS_PORT" && port_open localhost "$MINIO_PORT"; then
    echo "Using existing PostgreSQL, Redis and MinIO on localhost ports ${POSTGRES_PORT}, ${REDIS_PORT}, ${MINIO_PORT}."
    export TEST_DATABASE_URL="${TEST_DATABASE_URL:-postgres://enigma:enigma_dev_password@localhost:${POSTGRES_PORT}/enigma}"
    export TEST_REDIS_URL="${TEST_REDIS_URL:-redis://localhost:${REDIS_PORT}}"
    export TEST_S3_ENDPOINT="${TEST_S3_ENDPOINT:-http://localhost:${MINIO_PORT}}"
    export TEST_S3_ACCESS_KEY_ID="${TEST_S3_ACCESS_KEY_ID:-minioadmin}"
    export TEST_S3_SECRET_ACCESS_KEY="${TEST_S3_SECRET_ACCESS_KEY:-minioadmin123}"
    export TEST_S3_BUCKET="${TEST_S3_BUCKET:-enigma-attachments}"
  elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "TEST_DATABASE_URL/TEST_REDIS_URL are not set and local ports are unavailable; starting PostgreSQL, Redis and MinIO via Docker Compose."
    docker compose -f "$ROOT_DIR/server/docker-compose.yml" up -d --force-recreate postgres redis minio minio-init
    wait_for_compose_health postgres
    wait_for_compose_health redis
    wait_for_compose_health minio
    export TEST_DATABASE_URL="${TEST_DATABASE_URL:-postgres://enigma:enigma_dev_password@localhost:${POSTGRES_PORT}/enigma}"
    export TEST_REDIS_URL="${TEST_REDIS_URL:-redis://localhost:${REDIS_PORT}}"
    export TEST_S3_ENDPOINT="${TEST_S3_ENDPOINT:-http://localhost:${MINIO_PORT}}"
    export TEST_S3_ACCESS_KEY_ID="${TEST_S3_ACCESS_KEY_ID:-minioadmin}"
    export TEST_S3_SECRET_ACCESS_KEY="${TEST_S3_SECRET_ACCESS_KEY:-minioadmin123}"
    export TEST_S3_BUCKET="${TEST_S3_BUCKET:-enigma-attachments}"
  else
    cat >&2 <<'EOF'
Server integration tests require TEST_DATABASE_URL and TEST_REDIS_URL.
Set those variables, start PostgreSQL/Redis/MinIO on the documented local ports,
install Docker Compose so scripts/check-server.sh can start dependencies,
or run SKIP_INTEGRATION=1 ./scripts/check-server.sh to skip integration tests intentionally.
EOF
    exit 2
  fi
fi

if [[ -z "${CARGO_BIN:-}" ]]; then
  if [[ -x /tmp/cargo/bin/cargo ]]; then
    CARGO_BIN=/tmp/cargo/bin/cargo
    export RUSTUP_HOME="${RUSTUP_HOME:-/tmp/rustup}"
    export CARGO_HOME="${CARGO_HOME:-/tmp/cargo}"
  else
    CARGO_BIN=cargo
  fi
fi

"$CARGO_BIN" fmt --check
"$CARGO_BIN" clippy --locked --all-targets --all-features -- -D warnings
"$CARGO_BIN" test --locked --all-targets --all-features
