export {
  DEFAULT_AEGIS_SESSION_COOKIE_NAME,
  aegisMiddleware,
  clearSessionCookie,
  createAegisServerClient,
  getCookieStore,
  getSessionCookie,
  setSessionCookie,
} from "./next";
export type {
  AegisMiddlewareContext,
  AegisMiddlewareOptions,
  AegisServerClientConfig,
} from "./next";
export {
  AEGIS_AUTHENTICATED_HEADER,
  AEGIS_GUEST_ID_HEADER,
  AEGIS_MFA_VERIFIED_HEADER,
  AEGIS_STATUS_HEADER,
  AEGIS_USER_ID_HEADER,
  AegisServerAuthError,
  applySessionHeaders,
  getBearerToken,
  getCookieHeader,
  getCookieValue,
  getHeader,
  isAuthenticatedSession,
  isUserSession,
  requireAuthenticatedSession,
  requireUserSession,
} from "./node";
