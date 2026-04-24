import {
  AegisApiError,
  AegisClient,
  type AegisClientConfig,
  type AegisLogger,
  type Identity,
  type SessionValidation,
  type User,
} from "@junaadh/aegis";
import { cookies } from "next/headers";

import { getBearerToken, getCookieHeader } from "../node/request";
import {
  AegisServerAuthError,
  requireAuthenticatedSession,
} from "../node/session";
import {
  DEFAULT_AEGIS_SESSION_COOKIE_NAME,
  getSessionCookie,
  type AegisCookieStore,
} from "./cookies";

export type AegisServerClientConfig = Omit<AegisClientConfig, "token" | "fetch"> & {
  fetch?: typeof fetch;
  logger?: AegisLogger;
  sessionCookieName?: string;
};

function withCookieHeader(
  baseFetch: typeof fetch,
  cookieHeader: string,
): typeof fetch {
  return async (input, init) => {
    const headers = new Headers(init?.headers);
    headers.set("cookie", cookieHeader);

    return baseFetch(input, {
      ...init,
      headers,
      credentials: "include",
    });
  };
}

function isUnauthorized(error: unknown): boolean {
  return error instanceof AegisApiError && error.status === 401;
}

function toClientConfig(
  config: AegisServerClientConfig,
): AegisClientConfig {
  return {
    baseUrl: config.baseUrl,
    ...(config.internalToken !== undefined
      ? { internalToken: config.internalToken }
      : {}),
    ...(config.headers !== undefined ? { headers: config.headers } : {}),
    ...(config.credentials !== undefined
      ? { credentials: config.credentials }
      : {}),
    ...(config.fetch !== undefined ? { fetch: config.fetch } : {}),
    ...(config.logger !== undefined ? { logger: config.logger } : {}),
  };
}

export class AegisServerClient {
  private readonly config: AegisServerClientConfig;
  private readonly internalClient: AegisClient;

  constructor(config: AegisServerClientConfig) {
    this.config = config;
    this.internalClient = new AegisClient(toClientConfig(config));
  }

  async getSessionTokenFromCookies(
    store?: AegisCookieStore,
  ): Promise<string | undefined> {
    const cookieStore = store ?? (await cookies());
    return getSessionCookie(
      cookieStore,
      this.config.sessionCookieName ?? DEFAULT_AEGIS_SESSION_COOKIE_NAME,
    );
  }

  async validateSessionToken(
    token: string,
  ): Promise<SessionValidation | null> {
    const session = await this.internalClient.internal.validateSession({ token });
    return session.valid ? session : null;
  }

  async getSessionFromCookies(
    store?: AegisCookieStore,
  ): Promise<SessionValidation | null> {
    const token = await this.getSessionTokenFromCookies(store);
    if (!token) {
      return null;
    }

    return this.validateSessionToken(token);
  }

  async requireSession(
    store?: AegisCookieStore,
  ): Promise<SessionValidation> {
    const session = await this.getSessionFromCookies(store);
    requireAuthenticatedSession(session);
    return session;
  }

  async getIdentityFromCookies(
    store?: AegisCookieStore,
  ): Promise<Identity | null> {
    const token = await this.getSessionTokenFromCookies(store);
    if (!token) {
      return null;
    }

    const cookieName =
      this.config.sessionCookieName ?? DEFAULT_AEGIS_SESSION_COOKIE_NAME;
    const cookieHeader = `${cookieName}=${token}`;
    const client = new AegisClient({
      baseUrl: this.config.baseUrl,
      ...(this.config.headers !== undefined ? { headers: this.config.headers } : {}),
      ...(this.config.credentials !== undefined
        ? { credentials: this.config.credentials }
        : {}),
      fetch: withCookieHeader(this.config.fetch ?? fetch, cookieHeader),
      ...(this.config.logger !== undefined ? { logger: this.config.logger } : {}),
    });

    try {
      return await client.auth.me();
    } catch (error) {
      if (isUnauthorized(error)) {
        return null;
      }
      throw error;
    }
  }

  async requireUser(store?: AegisCookieStore): Promise<User> {
    const identity = await this.getIdentityFromCookies(store);
    if (!identity || identity.type !== "user") {
      throw new AegisServerAuthError("Aegis user session is required");
    }

    return identity.user;
  }

  async validateBearerToken(
    request: Request | { headers: HeadersInit },
  ): Promise<SessionValidation | null> {
    const token = getBearerToken(request);
    if (!token) {
      return null;
    }

    return this.validateSessionToken(token);
  }

  get client(): AegisClient {
    return this.internalClient;
  }
}

export function createAegisServerClient(
  config: AegisServerClientConfig,
): AegisServerClient {
  return new AegisServerClient(config);
}

export function getRequestCookieHeader(request: Request | { headers: HeadersInit }): string | undefined {
  return getCookieHeader(request);
}
