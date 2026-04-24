import type {
  LoginResponseDto,
  SessionDto,
  SessionValidateResponseDto,
} from "../dto/session.dto";
import type { LoginResult, Session, SessionValidation } from "../domain/session";
import { mapIdentityDtoToDomain } from "./user.mapper";

function toDate(value: string): Date {
  return new Date(value);
}

export function mapSessionDtoToDomain(dto: SessionDto): Session {
  return {
    expiresAt: toDate(dto.expiresAt),
    mfaVerified: dto.mfaVerified,
  };
}

export function mapLoginDtoToDomain(dto: LoginResponseDto): LoginResult {
  if (dto.status === "authenticated") {
    return {
      status: "authenticated",
      identity: mapIdentityDtoToDomain(dto.identity),
      session: mapSessionDtoToDomain(dto.session),
    };
  }

  return {
    status: "requiresMfa",
    session: mapSessionDtoToDomain(dto.session),
  };
}

export function mapSessionValidationDtoToDomain(
  dto: SessionValidateResponseDto,
): SessionValidation {
  return {
    valid: dto.valid,
    ...(dto.userId !== undefined ? { userId: dto.userId } : {}),
    ...(dto.guestId !== undefined ? { guestId: dto.guestId } : {}),
    ...(dto.status !== undefined ? { status: dto.status } : {}),
    ...(dto.expiresAt !== undefined ? { expiresAt: toDate(dto.expiresAt) } : {}),
    roles: dto.roles,
    mfaVerified: dto.mfaVerified,
  };
}
