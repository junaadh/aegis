#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="$ROOT_DIR/target/test-artifacts"
TEST_CONFIG="$ARTIFACT_DIR/aegis.test.toml"
SERVER_LOG="$ARTIFACT_DIR/aegisd.log"
SERVER_PID=""

export DATABASE_URL="${DATABASE_URL:-postgres://aegis:aegis@localhost:5433/aegis_test}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6380}"
export SMTP_HOST="${SMTP_HOST:-localhost}"
export SMTP_PORT="${SMTP_PORT:-1026}"
export AEGIS_ENV="${AEGIS_ENV:-test}"
export AEGIS_HTTP_ADDR="${AEGIS_HTTP_ADDR:-127.0.0.1:4001}"
export AEGIS_BASE_URL="${AEGIS_BASE_URL:-http://${AEGIS_HTTP_ADDR}}"
export AEGIS_INTERNAL_TOKEN="${AEGIS_INTERNAL_TOKEN:-test-internal-token}"
export AEGIS_COOKIE_NAME="${AEGIS_COOKIE_NAME:-aegis_session}"
export AEGIS_COOKIE_SECURE="${AEGIS_COOKIE_SECURE:-false}"

export AEGIS_DATABASE_URL="$DATABASE_URL"
export AEGIS_REDIS_URL="$REDIS_URL"
export AEGIS_EMAIL_SMTP_HOST="$SMTP_HOST"
export AEGIS_EMAIL_SMTP_PORT="$SMTP_PORT"
export AEGIS_EMAIL_SMTP_USERNAME="${AEGIS_EMAIL_SMTP_USERNAME:-}"
export AEGIS_EMAIL_SMTP_PASSWORD="${AEGIS_EMAIL_SMTP_PASSWORD:-}"
export AEGIS_EMAIL_FROM_ADDRESS="${AEGIS_EMAIL_FROM_ADDRESS:-noreply@aegis.test}"
export AEGIS_SESSION_SECRET="${AEGIS_SESSION_SECRET:-test-session-secret-test-session-secret}"
export AEGIS_CRYPTO_MASTER_KEY="${AEGIS_CRYPTO_MASTER_KEY:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"

mkdir -p "$ARTIFACT_DIR"

write_test_config() {
  cat > "$TEST_CONFIG" <<EOF
[server]
host = "127.0.0.1"
port = 4001
log_level = "debug"

[database]
url = "${DATABASE_URL}"

[redis]
enabled = true
url = "${REDIS_URL}"

[session]
secret = "${AEGIS_SESSION_SECRET}"

[session.cookie]
name = "${AEGIS_COOKIE_NAME}"
path = "/"
secure = ${AEGIS_COOKIE_SECURE}
http_only = true
same_site = "lax"

[credentials.passkeys]
rp_id = "localhost"
rp_name = "Aegis Test"
origins = ["http://localhost:4001"]

[email]
enabled = true
from_address = "${AEGIS_EMAIL_FROM_ADDRESS}"
from_name = "Aegis Test"

[email.smtp]
host = "${SMTP_HOST}"
port = ${SMTP_PORT}
username = "${AEGIS_EMAIL_SMTP_USERNAME}"
password = "${AEGIS_EMAIL_SMTP_PASSWORD}"
starttls = false

[api.internal]
api_token = "${AEGIS_INTERNAL_TOKEN}"
allowed_cidrs = []

[crypto]
master_key = "${AEGIS_CRYPTO_MASTER_KEY}"

[crypto.jwt]
enabled = false
EOF
}

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  "$ROOT_DIR/scripts/test-env-down.sh"
}

trap cleanup EXIT

write_test_config

"$ROOT_DIR/scripts/test-env-up.sh"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

cargo build -p aegisd --bin aegisd
cargo run -p aegis -- --config "$TEST_CONFIG" migrate up

"$ROOT_DIR/target/debug/aegisd" "$TEST_CONFIG" > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
  if curl -fsS \
    -H "Authorization: Bearer ${AEGIS_INTERNAL_TOKEN}" \
    "http://${AEGIS_HTTP_ADDR}/v1/internal/health" >/dev/null 2>/dev/null; then
    break
  fi
  sleep 1
done

curl -fsS \
  -H "Authorization: Bearer ${AEGIS_INTERNAL_TOKEN}" \
  "http://${AEGIS_HTTP_ADDR}/v1/internal/health" >/dev/null

if [[ ! -d "$ROOT_DIR/node_modules" ]]; then
  bun install --frozen-lockfile
fi

bun run typecheck
bun run build
bun test
