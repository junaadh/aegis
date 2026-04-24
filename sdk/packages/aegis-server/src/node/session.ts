import type { SessionValidation } from "@junaadh/aegis";

export const AEGIS_AUTHENTICATED_HEADER = "x-aegis-authenticated";
export const AEGIS_USER_ID_HEADER = "x-aegis-user-id";
export const AEGIS_GUEST_ID_HEADER = "x-aegis-guest-id";
export const AEGIS_STATUS_HEADER = "x-aegis-session-status";
export const AEGIS_MFA_VERIFIED_HEADER = "x-aegis-mfa-verified";

export class AegisServerAuthError extends Error {
  constructor(message: string = "Aegis authentication required") {
    super(message);
    this.name = "AegisServerAuthError";
  }
}

export function isAuthenticatedSession(
  session: SessionValidation | null | undefined,
): session is SessionValidation {
  return Boolean(session?.valid);
}

export function isUserSession(
  session: SessionValidation | null | undefined,
): session is SessionValidation & { userId: string } {
  return Boolean(session?.valid && session.userId);
}

export function requireAuthenticatedSession(
  session: SessionValidation | null | undefined,
  message?: string,
): asserts session is SessionValidation {
  if (!isAuthenticatedSession(session)) {
    throw new AegisServerAuthError(message ?? "Aegis session is required");
  }
}

export function requireUserSession(
  session: SessionValidation | null | undefined,
  message?: string,
): asserts session is SessionValidation & { userId: string } {
  if (!isUserSession(session)) {
    throw new AegisServerAuthError(message ?? "Aegis user session is required");
  }
}

export function applySessionHeaders(
  headers: Headers,
  session: SessionValidation | null | undefined,
): Headers {
  headers.set(AEGIS_AUTHENTICATED_HEADER, session?.valid ? "true" : "false");

  if (session?.userId) {
    headers.set(AEGIS_USER_ID_HEADER, session.userId);
  }
  if (session?.guestId) {
    headers.set(AEGIS_GUEST_ID_HEADER, session.guestId);
  }
  if (session?.status) {
    headers.set(AEGIS_STATUS_HEADER, session.status);
  }

  headers.set(AEGIS_MFA_VERIFIED_HEADER, session?.mfaVerified ? "true" : "false");
  return headers;
}
