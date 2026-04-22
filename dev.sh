#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="$(dirname "$0")/.env"
COMPOSE="docker compose --env-file $ENV_FILE -f infra/dev/compose.yml"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[aegis]${NC} $*"; }
ok()    { echo -e "${GREEN}[aegis]${NC} $*"; }
warn()  { echo -e "${YELLOW}[aegis]${NC} $*"; }
err()   { echo -e "${RED}[aegis]${NC} $*" >&2; }

if [[ ! -f "$ENV_FILE" ]]; then
    err "missing .env — copy from infra/dev/.env.example"
    exit 1
fi

wait_for_postgres() {
    info "waiting for postgres..."
    for i in $(seq 1 30); do
        if docker exec aegis-postgres pg_isready -U aegis &>/dev/null; then
            return
        fi
        sleep 1
    done
    err "postgres never became ready"
    exit 1
}

wait_for_redis() {
    info "waiting for redis..."
    for i in $(seq 1 30); do
        if docker exec aegis-redis redis-cli ping &>/dev/null; then
            return
        fi
        sleep 1
    done
    err "redis never became ready"
    exit 1
}

cmd_up() {
    info "starting services..."
    $COMPOSE up -d
    wait_for_postgres
    wait_for_redis
    ok "services ready"

    info "running migrations..."
    cargo run --bin aegis -- migrate up
    ok "migrations applied"

    cmd_status
}

cmd_down() {
    info "stopping services..."
    $COMPOSE down
    ok "stopped"
}

cmd_reset() {
    warn "wiping all data..."
    $COMPOSE down -v
    $COMPOSE up -d
    wait_for_postgres
    wait_for_redis
    ok "services ready"

    info "running migrations on fresh database..."
    cargo run --bin aegis -- migrate up
    ok "migrations applied"

    cmd_status
}

cmd_status() {
    $COMPOSE ps
}

cmd_logs() {
    $COMPOSE logs -f "${1:-}"
}

cmd_psql() {
    docker exec -it aegis-postgres psql -U aegis aegis_dev
}

cmd_redis() {
    docker exec -it aegis-redis redis-cli
}

cmd_migrate() {
    cargo run --bin aegis -- migrate up
}

cmd_new_migration() {
    local name="${1:?usage: ./dev.sh new-migration <name>}"
    cargo run --bin aegis -- migrate create "$name"
}

cmd_schema() {
    cargo run --bin aegis -- schema --out schema.json
}

cmd_init_config() {
    cargo run --bin aegis -- config init
}

cmd_check_config() {
    cargo run --bin aegis -- config validate
}

cmd_lint() {
    cargo clippy --workspace -- -D warnings
}

cmd_test() {
    cargo test --workspace
}

cmd_check() {
    cmd_lint
    cmd_test
}

cmd_help() {
    cat <<EOF
aegis dev environment

usage: ./dev.sh <command> [args]

services:
  up                start services, wait for healthy, run migrations
  down              stop all services
  reset             wipe volumes, restart, run migrations on fresh db
  status            show service status
  logs [service]    tail logs (optional: postgres, redis, mailpit)

database:
  psql              open psql shell
  migrate           run pending migrations
  new-migration     create new migration file (arg: name)

redis:
  redis             open redis-cli shell

config:
  init-config       generate default aegis.toml
  check-config      validate aegis.toml
  schema            dump JSON schema to schema.json

build:
  lint              clippy whole workspace
  test              run all tests
  check             lint + test

EOF
}

main() {
    local cmd="${1:-help}"
    shift || true

    case "$cmd" in
        up)              cmd_up ;;
        down)            cmd_down ;;
        reset)           cmd_reset ;;
        status)          cmd_status ;;
        logs)            cmd_logs "$@" ;;
        psql)            cmd_psql ;;
        redis)           cmd_redis ;;
        migrate)         cmd_migrate ;;
        new-migration)   cmd_new_migration "$@" ;;
        schema)          cmd_schema ;;
        init-config)     cmd_init_config ;;
        check-config)    cmd_check_config ;;
        lint)            cmd_lint ;;
        test)            cmd_test ;;
        check)           cmd_check ;;
        help|--help|-h)  cmd_help ;;
        *)               err "unknown command: $cmd"; cmd_help; exit 1 ;;
    esac
}

main "$@"
