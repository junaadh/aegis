import type { IdentityDto, PaginatedResponseDto } from "./user.dto";

export type SessionDto = {
  expiresAt: string;
  mfaVerified: boolean;
};

export type SessionValidateRequestDto = {
  token: string;
};

export type SessionValidateResponseDto = {
  valid: boolean;
  userId?: string;
  guestId?: string;
  status?: string;
  expiresAt?: string;
  roles: string[];
  mfaVerified: boolean;
};

export type SessionRevokeRequestDto = {
  sessionId?: string;
};

export type LoginAuthenticatedResponseDto = {
  status: "authenticated";
  identity: IdentityDto;
  session: SessionDto;
};

export type LoginRequiresMfaResponseDto = {
  status: "requiresMfa";
  session: SessionDto;
};

export type LoginResponseDto =
  | LoginAuthenticatedResponseDto
  | LoginRequiresMfaResponseDto;

export type AdminSessionListQueryDto = {
  userId?: string;
  activeOnly?: boolean;
  page?: number;
  perPage?: number;
};

export type AdminSessionListItemResponseDto = {
  id: string;
  identityType: string;
  identityId: string;
  expiresAt: string;
  lastSeenAt: string;
  mfaVerified: boolean;
  userAgent?: string;
  ipAddress?: string;
};

export type AdminSessionDetailResponseDto = {
  id: string;
  identityType: string;
  identityId: string;
  expiresAt: string;
  lastSeenAt: string;
  mfaVerified: boolean;
  userAgent?: string;
  ipAddress?: string;
  metadata: unknown;
};

export type AdminSessionListResponseDto = PaginatedResponseDto<AdminSessionListItemResponseDto>;
