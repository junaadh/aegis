<div align="center">

# aegis

A self-hosted authentication and identity platform.

</div>

---

Aegis is the authoritative identity layer for distributed applications. It owns authentication, sessions, credentials, and identity data — nothing more.

## Features

- **Password auth** — Argon2id with configurable policy
- **Passkeys** — WebAuthn Level 2 passwordless login
- **MFA** — TOTP with recovery codes
- **Sessions** — HTTP-only secure cookies and opaque bearer tokens
- **Guest identity** — Ephemeral sessions convertible to registered users
- **Audit trail** — Immutable log of all identity events
- **Outbox pattern** — Reliable async delivery with LISTEN/NOTIFY and exponential backoff
- **UUIDv7 keys** — Time-ordered, globally unique, index-friendly

## Getting Started

```bash
cp .env.example .env
cp aegis.toml.example aegis.toml
cargo run -p aegis -- migrate up
cargo run -p aegisd
```

## Architecture

```
aegisd/         HTTP server — auth, sessions, internal API
aegis/          CLI — migrations, admin ops, compliance
aegis-core/     Domain types — IDs, identity, permissions
aegis-app/      Application layer — use cases, ports, policies
aegis-db/       PostgreSQL — repositories, outbox worker
aegis-http/     HTTP layer — handlers, middleware, routing
aegis-infra/    Adapters — Argon2, SMTP, Redis, WebAuthn
aegis-config/   TOML configuration with env var overrides
aegis-migrate/  Migration runner
aegis-cache/    Cache abstraction — in-memory and Redis
```

## Stack

| Layer | Choice |
|---|---|
| Language | Rust (2024 edition) |
| Runtime | Tokio |
| HTTP | Axum |
| Database | PostgreSQL 15+ with pgcrypto |
| Caching | Redis 7+ (optional) |
| Configuration | TOML + environment variables |

## Scaling

| Phase | Capabilities |
|---|---|
| 1 | Single instance, opaque tokens |
| 2 | Redis cache, webhooks, rate limiting |
| 3 | Signed JWT, OAuth/OIDC federation |
| 4 | Multi-tenancy, fine-grained RBAC |

## Documentation

Full specification in [`docs/rfc/0001.md`](docs/rfc/0001.md).

## License

[MIT](LICENSE)
