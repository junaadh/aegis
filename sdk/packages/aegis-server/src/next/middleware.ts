import type { SessionValidation, AegisLogger } from "@aegis/core";
import { NextResponse, type NextRequest, type NextMiddleware } from "next/server";

import { getBearerToken } from "../node/request";
import { applySessionHeaders, isUserSession } from "../node/session";
import { DEFAULT_AEGIS_SESSION_COOKIE_NAME } from "./cookies";
import {
  createAegisServerClient,
  type AegisServerClientConfig,
} from "./server-client";

type MaybePromise<T> = T | Promise<T>;

export type AegisMiddlewareContext = {
  request: NextRequest;
  session: SessionValidation | null;
};

export type AegisMiddlewareOptions = AegisServerClientConfig & {
  requireAuth?: boolean;
  requireUser?: boolean;
  publicPaths?: string[];
  redirectTo?: string;
  onAuthorized?: (
    context: AegisMiddlewareContext,
  ) => MaybePromise<Response | NextResponse | void>;
  onUnauthorized?: (
    context: AegisMiddlewareContext,
  ) => MaybePromise<Response | NextResponse | void>;
  logger?: AegisLogger;
};

function isPublicPath(pathname: string, publicPaths: string[]): boolean {
  return publicPaths.some((path) => pathname === path || pathname.startsWith(`${path}/`));
}

function defaultUnauthorizedResponse(
  request: NextRequest,
  redirectTo?: string,
): NextResponse {
  if (redirectTo) {
    return NextResponse.redirect(new URL(redirectTo, request.url));
  }

  return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
}

export function aegisMiddleware(
  options: AegisMiddlewareOptions,
): NextMiddleware {
  return async (request) => {
    if (isPublicPath(request.nextUrl.pathname, options.publicPaths ?? [])) {
      return NextResponse.next();
    }

    const serverClient = createAegisServerClient(options);
    const bearerToken = getBearerToken(request);
    const sessionCookieName =
      options.sessionCookieName ?? DEFAULT_AEGIS_SESSION_COOKIE_NAME;
    const sessionToken = request.cookies.get(sessionCookieName)?.value;

    let session: SessionValidation | null = null;
    if (bearerToken) {
      session = await serverClient.validateSessionToken(bearerToken);
    } else if (sessionToken) {
      session = await serverClient.validateSessionToken(sessionToken);
    }

    options.logger?.debug?.("Aegis middleware evaluated request", {
      pathname: request.nextUrl.pathname,
      authenticated: session?.valid ?? false,
      hasBearerToken: Boolean(bearerToken),
      hasSessionCookie: Boolean(sessionToken),
    });

    if ((options.requireAuth && !session?.valid) || (options.requireUser && !isUserSession(session))) {
      const context = { request, session };
      const custom = await options.onUnauthorized?.(context);
      return custom ?? defaultUnauthorizedResponse(request, options.redirectTo);
    }

    const forwardedHeaders = new Headers(request.headers);
    applySessionHeaders(forwardedHeaders, session);

    const authorizedContext = { request, session };
    const custom = await options.onAuthorized?.(authorizedContext);
    if (custom) {
      return custom;
    }

    return NextResponse.next({
      request: {
        headers: forwardedHeaders,
      },
    });
  };
}
