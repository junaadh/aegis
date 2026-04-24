# @junaadh/aegis-server

Server-side helpers for integrating applications with the Aegis auth server.

`@junaadh/aegis-server` builds on top of `@junaadh/aegis` and adds:

- server-side session validation helpers
- cookie extraction helpers
- bearer-token extraction helpers
- Next.js-oriented session and middleware utilities

## Install

```bash
bun add @junaadh/aegis-server @junaadh/aegis
```

## Create a server client

```ts
import { createAegisServerClient } from "@junaadh/aegis-server";

const aegis = createAegisServerClient({
  baseUrl: "https://auth.example.com",
  internalToken: process.env.AEGIS_INTERNAL_TOKEN,
});
```

## Validate a session token

```ts
const session = await aegis.validateSessionToken("session-token");

if (session?.valid) {
  console.log(session.userId);
}
```

## Read a session from cookies

```ts
const session = await aegis.getSessionFromCookies();

if (!session) {
  return new Response("Unauthorized", { status: 401 });
}
```

## Require an authenticated user

```ts
const user = await aegis.requireUser();
console.log(user.email);
```

## Request helpers

The package also exports low-level helpers for working with incoming requests.

```ts
import {
  getBearerToken,
  getCookieHeader,
  getCookieValue,
} from "@junaadh/aegis-server";

const bearer = getBearerToken(request);
const cookieHeader = getCookieHeader(request);
const sessionToken = getCookieValue(cookieHeader, "aegis_session");
```

## Next.js helpers

```ts
import {
  DEFAULT_AEGIS_SESSION_COOKIE_NAME,
  createAegisServerClient,
  getSessionCookie,
} from "@junaadh/aegis-server";
```

These exports are intended for Next.js middleware, route handlers, and server components.
