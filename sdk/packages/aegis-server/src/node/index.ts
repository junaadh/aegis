export {
  getBearerToken,
  getCookieHeader,
  getCookieValue,
  getHeader,
} from "./request";
export {
  AEGIS_AUTHENTICATED_HEADER,
  AEGIS_GUEST_ID_HEADER,
  AEGIS_MFA_VERIFIED_HEADER,
  AEGIS_STATUS_HEADER,
  AEGIS_USER_ID_HEADER,
  AegisServerAuthError,
  applySessionHeaders,
  isAuthenticatedSession,
  isUserSession,
  requireAuthenticatedSession,
  requireUserSession,
} from "./session";
