import { randomUUID } from "node:crypto";

import type { AegisApiErrorBody } from "../packages/aegis-core/src/errors";

export const BASE_URL = process.env.AEGIS_BASE_URL ?? "http://127.0.0.1:4001";
export const INTERNAL_TOKEN = process.env.AEGIS_INTERNAL_TOKEN ?? "test-internal-token";

export function testEmail(prefix: string): string {
  return `${prefix}-${randomUUID()}@example.test`;
}

export function createCookieFetch(baseFetch: typeof fetch = fetch): {
  fetch: typeof fetch;
  getCookie: () => string | null;
} {
  let cookieHeader: string | null = null;

  return {
    fetch: async (input, init) => {
      const headers = new Headers(init?.headers);
      if (cookieHeader) {
        headers.set("cookie", cookieHeader);
      }

      const response = await baseFetch(input, {
        ...init,
        headers,
        credentials: "include",
      });

      const setCookie = response.headers.get("set-cookie");
      if (setCookie) {
        cookieHeader = setCookie.split(",")[0]?.split(";")[0] ?? null;
      }

      return response;
    },
    getCookie: () => cookieHeader,
  };
}

export async function waitForMailpitToken(
  email: string,
  marker: string,
): Promise<string> {
  const deadline = Date.now() + 30_000;

  while (Date.now() < deadline) {
    const response = await fetch(`${process.env.MAILPIT_WEB_URL ?? "http://localhost:8026"}/api/v1/messages`);
    const json = await response.json();
    const snippet = findSnippetForEmail(json, email);
    if (snippet) {
      const token = snippet.split(marker)[1]?.split(/\r?\n/)[0]?.trim();
      if (token) {
        return token;
      }
    }
    await Bun.sleep(500);
  }

  throw new Error(`Timed out waiting for Mailpit message for ${email}`);
}

function objectContainsEmail(value: unknown, email: string): boolean {
  if (typeof value === "string") {
    return value.includes(email);
  }

  if (Array.isArray(value)) {
    return value.some((item) => objectContainsEmail(item, email));
  }

  if (value && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).some((nested) =>
      objectContainsEmail(nested, email),
    );
  }

  return false;
}

function findSnippetForEmail(value: unknown, email: string): string | null {
  if (Array.isArray(value)) {
    for (const item of value) {
      const snippet = findSnippetForEmail(item, email);
      if (snippet) {
        return snippet;
      }
    }
    return null;
  }

  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (objectContainsEmail(record, email)) {
      const snippet = record.Snippet ?? record.snippet;
      if (typeof snippet === "string") {
        return snippet;
      }
    }

    for (const nested of Object.values(record)) {
      const snippet = findSnippetForEmail(nested, email);
      if (snippet) {
        return snippet;
      }
    }
  }

  return null;
}

export async function verifyEmail(token: string): Promise<void> {
  const response = await fetch(`${BASE_URL}/v1/auth/email/verify`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify({ token }),
  });

  if (!response.ok) {
    throw new Error(`Email verification failed with status ${response.status}`);
  }
}

export function assertApiErrorShape(error: unknown): asserts error is Error & {
  status: number;
  code: string;
  message: string;
  requestId: string;
  meta?: AegisApiErrorBody["details"];
} {
  if (!(error instanceof Error)) {
    throw new Error(`Expected Error, received ${String(error)}`);
  }
  for (const key of ["status", "code", "requestId"] as const) {
    if (!(key in error)) {
      throw new Error(`Expected error to include ${key}`);
    }
  }
}
