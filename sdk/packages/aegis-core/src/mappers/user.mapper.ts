import type { AuthResponseDto } from "../dto/auth.dto";
import type {
  GuestDto,
  GuestIdentityDto,
  IdentityDto,
  IdentityLookupResponseDto,
  UserDto,
  UserIdentityDto,
} from "../dto/user.dto";
import type { AuthResult } from "../domain/session";
import type { Guest, Identity, IdentityLookup, User } from "../domain/user";

function toDate(value: string): Date {
  return new Date(value);
}

export function mapUserDtoToDomain(dto: UserDto): User {
  return {
    id: dto.id,
    email: dto.email,
    displayName: dto.displayName,
    status: dto.status,
    emailVerified: dto.emailVerified,
    roles: dto.roles,
    metadata: dto.metadata,
    createdAt: toDate(dto.createdAt),
    updatedAt: toDate(dto.updatedAt),
  };
}

export function mapGuestDtoToDomain(dto: GuestDto): Guest {
  return {
    id: dto.id,
    ...(dto.email !== undefined ? { email: dto.email } : {}),
    status: dto.status,
    expiresAt: toDate(dto.expiresAt),
  };
}

export function mapIdentityDtoToDomain(dto: IdentityDto): Identity {
  if (dto.type === "user") {
    return {
      type: "user",
      user: mapUserDtoToDomain(dto as UserIdentityDto),
    };
  }

  return {
    type: "guest",
    guest: mapGuestDtoToDomain(dto as GuestIdentityDto),
  };
}

export function mapIdentityLookupDtoToDomain(
  dto: IdentityLookupResponseDto,
): IdentityLookup {
  return {
    ...(dto.id !== undefined ? { id: dto.id } : {}),
    ...(dto.email !== undefined ? { email: dto.email } : {}),
    ...(dto.displayName !== undefined ? { displayName: dto.displayName } : {}),
    ...(dto.status !== undefined ? { status: dto.status } : {}),
    ...(dto.emailVerified !== undefined
      ? { emailVerified: dto.emailVerified }
      : {}),
    ...(dto.roles !== undefined ? { roles: dto.roles } : {}),
    ...(dto.metadata !== undefined ? { metadata: dto.metadata } : {}),
  };
}

export function mapAuthDtoToDomain(dto: AuthResponseDto): AuthResult {
  return {
    identity: mapIdentityDtoToDomain(dto.identity),
    session: {
      expiresAt: toDate(dto.session.expiresAt),
      mfaVerified: dto.session.mfaVerified,
    },
  };
}
