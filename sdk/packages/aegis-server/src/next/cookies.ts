import { cookies } from "next/headers";
import type { NextResponse } from "next/server";

export const DEFAULT_AEGIS_SESSION_COOKIE_NAME = "aegis_session";

export type AegisCookieStore = {
  get(name: string): { value: string } | undefined;
};

export type AegisSessionCookieOptions = {
  name?: string;
  path?: string;
  domain?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: "lax" | "strict" | "none";
  maxAge?: number;
};

export async function getCookieStore(): Promise<AegisCookieStore> {
  return cookies();
}

export function getSessionCookie(
  store: AegisCookieStore,
  name: string = DEFAULT_AEGIS_SESSION_COOKIE_NAME,
): string | undefined {
  return store.get(name)?.value;
}

export function setSessionCookie(
  response: NextResponse,
  value: string,
  options: AegisSessionCookieOptions = {},
): NextResponse {
  response.cookies.set({
    name: options.name ?? DEFAULT_AEGIS_SESSION_COOKIE_NAME,
    value,
    path: options.path ?? "/",
    ...(options.domain !== undefined ? { domain: options.domain } : {}),
    secure: options.secure ?? true,
    httpOnly: options.httpOnly ?? true,
    sameSite: options.sameSite ?? "lax",
    ...(options.maxAge !== undefined ? { maxAge: options.maxAge } : {}),
  });

  return response;
}

export function clearSessionCookie(
  response: NextResponse,
  options: AegisSessionCookieOptions = {},
): NextResponse {
  response.cookies.set({
    name: options.name ?? DEFAULT_AEGIS_SESSION_COOKIE_NAME,
    value: "",
    path: options.path ?? "/",
    ...(options.domain !== undefined ? { domain: options.domain } : {}),
    secure: options.secure ?? true,
    httpOnly: options.httpOnly ?? true,
    sameSite: options.sameSite ?? "lax",
    maxAge: 0,
  });

  return response;
}
