#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.test.yml"

wait_for_service() {
  local service="$1"
  local container_id
  local status

  container_id="$(docker compose -f "$COMPOSE_FILE" ps -q "$service")"
  if [[ -z "$container_id" ]]; then
    printf 'failed to resolve container for %s\n' "$service" >&2
    exit 1
  fi

  for _ in $(seq 1 60); do
    status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id")"
    if [[ "$status" == "healthy" || "$status" == "running" ]]; then
      return 0
    fi
    sleep 1
  done

  printf '%s did not become ready\n' "$service" >&2
  docker compose -f "$COMPOSE_FILE" logs "$service" >&2 || true
  exit 1
}

docker compose -f "$COMPOSE_FILE" up -d postgres redis mailpit

wait_for_service postgres
wait_for_service redis

printf 'DATABASE_URL=%s\n' "${DATABASE_URL:-postgres://aegis:aegis@localhost:5433/aegis_test}"
printf 'REDIS_URL=%s\n' "${REDIS_URL:-redis://localhost:6380}"
printf 'MAILPIT_SMTP_URL=smtp://%s:%s\n' "${SMTP_HOST:-localhost}" "${SMTP_PORT:-1026}"
printf 'MAILPIT_WEB_URL=%s\n' "${MAILPIT_WEB_URL:-http://localhost:8026}"
