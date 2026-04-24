# @junaadh/aegis-react

React bindings for applications that use the Aegis auth server.

`@junaadh/aegis-react` wraps `@junaadh/aegis` with:

- a provider for auth state
- hooks for common auth actions
- a simple auth gate component

## Install

```bash
bun add @junaadh/aegis-react @junaadh/aegis
```

## Wrap your app

```tsx
import { AegisProvider } from "@junaadh/aegis-react";

export function App() {
  return (
    <AegisProvider baseUrl="https://auth.example.com">
      <Routes />
    </AegisProvider>
  );
}
```

## Use hooks

```tsx
import { useLogin, useLogout, useUser } from "@junaadh/aegis-react";

export function AccountMenu() {
  const user = useUser();
  const login = useLogin();
  const logout = useLogout();

  if (!user) {
    return (
      <button
        onClick={() =>
          login({
            email: "user@example.com",
            password: "secret",
          })
        }
      >
        Sign in
      </button>
    );
  }

  return <button onClick={() => logout()}>Sign out {user.email}</button>;
}
```

## Read session state

```tsx
import { useSession } from "@junaadh/aegis-react";

export function SessionDebug() {
  const session = useSession();
  return <pre>{JSON.stringify(session, null, 2)}</pre>;
}
```

## Auth gate

```tsx
import { AuthGate } from "@junaadh/aegis-react";

export function ProtectedPage() {
  return (
    <AuthGate fallback={<div>Please sign in</div>}>
      <Dashboard />
    </AuthGate>
  );
}
```

## Notes

- This package is client-side React code.
- It expects a reachable Aegis server `baseUrl`.
- Cookie-based auth works naturally in browser environments because the underlying client uses `credentials: "include"` by default.
