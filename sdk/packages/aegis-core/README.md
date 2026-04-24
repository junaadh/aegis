# @junaadh/aegis

TypeScript SDK for talking to the Aegis HTTP API.

`@junaadh/aegis` is the base package in the SDK stack. It is responsible for:

- making HTTP requests to the Aegis API
- handling the API response envelope
- exposing DTOs and domain types
- mapping DTOs into nicer domain objects where useful
- surfacing typed API and response errors

It does not depend on React or server framework helpers.

## Install

```bash
bun add @junaadh/aegis
```

## Create a client

```ts
import { AegisClient } from "@junaadh/aegis";

const client = new AegisClient({
  baseUrl: "https://auth.example.com",
});
```

## Internal routes

Use `internalToken` for `/internal/*` endpoints.

```ts
import { AegisClient } from "@junaadh/aegis";

const client = new AegisClient({
  baseUrl: "http://localhost:8080",
  internalToken: process.env.AEGIS_API_INTERNAL_TOKEN,
});

const overview = await client.internal.overview();

console.log(overview.totalUsers);
console.log(overview.activeUsers);
console.log(overview.totalGuests);
console.log(overview.activeGuests);
console.log(overview.activeSessions);
console.log(overview.emailEnabled);
```

Available internal helpers include:

```ts
await client.internal.health();
await client.internal.overview();
await client.internal.validateSession({ token: "session-token" });

await client.users.lookup({ userId: "uuid" });
await client.users.lookupByEmail({ email: "user@example.com" });
await client.users.list({ page: 1, perPage: 20 });
await client.users.getById("uuid");

await client.sessions.list({ activeOnly: true });
await client.sessions.getById("uuid");
await client.sessions.revokeById("uuid");
```

## Session and browser-auth routes

Session-auth routes live under `client.auth` and `client.sessions`.

If your app authenticates with cookies, the client uses `credentials: "include"` by default so browser cookies are sent automatically.

```ts
const client = new AegisClient({
  baseUrl: "https://auth.example.com",
});

await client.auth.login({
  email: "user@example.com",
  password: "secret",
});

const me = await client.auth.me();
await client.auth.logout();
```

If you use bearer-token based session auth, pass `token` in the config:

```ts
const client = new AegisClient({
  baseUrl: "https://auth.example.com",
  token: "session-or-access-token",
});
```

## Logging

Pass a logger to get request lifecycle logs. Any object with `debug`, `info`, `warn`, or `error` methods works, including `console`.

```ts
const client = new AegisClient({
  baseUrl: "https://auth.example.com",
  internalToken: process.env.AEGIS_API_INTERNAL_TOKEN,
  logger: console,
});
```

The client logs:

- request start
- request success with status, duration, and request ID
- API failures with code and message
- invalid JSON or invalid response envelopes

## Errors

```ts
import { AegisApiError } from "@junaadh/aegis";

try {
  await client.internal.overview();
} catch (error) {
  if (error instanceof AegisApiError) {
    console.error(error.status);
    console.error(error.code);
    console.error(error.meta.requestId);
  }
}
```
