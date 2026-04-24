export { AegisClient } from "./client";
export type {
  AegisClientConfig,
  AegisLogContext,
  AegisLogger,
} from "./config";
export { AegisApiError } from "./errors";
export {
  AegisConfigurationError,
  AegisError,
  AegisInvalidResponseError,
} from "./errors";
export type {
  AegisApiErrResponse,
  AegisApiErrorBody,
  AegisApiMeta,
  AegisApiOkResponse,
  AegisApiResponse,
} from "./errors";
export type { AuthResult, LoginResult, Session, SessionValidation } from "./domain/session";
export type { Guest, Identity, IdentityLookup, User } from "./domain/user";
export type {
  ApiStatusResponseDto,
  AuthResponseDto,
  GuestConvertRequestDto,
  GuestCreateRequestDto,
  GuestEmailRequestDto,
  LoginRequestDto,
  SignupRequestDto,
} from "./dto/auth.dto";
export type {
  AdminSessionDetailResponseDto,
  AdminSessionListItemResponseDto,
  AdminSessionListQueryDto,
  LoginResponseDto,
  SessionDto,
  SessionRevokeRequestDto,
  SessionValidateRequestDto,
  SessionValidateResponseDto,
} from "./dto/session.dto";
export type {
  AdminGuestDetailResponseDto,
  AdminGuestListItemResponseDto,
  AdminGuestListQueryDto,
  AdminUserCredentialSummaryResponseDto,
  AdminUserDetailResponseDto,
  AdminUserListItemResponseDto,
  AdminUserListQueryDto,
  ComponentStatusDto,
  GuestDto,
  HealthResponseDto,
  IdentityDto,
  IdentityLookupResponseDto,
  OverviewResponseDto,
  PaginatedResponseDto,
  UpdateProfileRequestDto,
  UserDto,
  UserLookupByEmailRequestDto,
  UserLookupRequestDto,
  UserPublicDto,
} from "./dto/user.dto";
export { mapSessionDtoToDomain, mapLoginDtoToDomain, mapSessionValidationDtoToDomain } from "./mappers/session.mapper";
export {
  mapAuthDtoToDomain,
  mapGuestDtoToDomain,
  mapIdentityDtoToDomain,
  mapIdentityLookupDtoToDomain,
  mapUserDtoToDomain,
} from "./mappers/user.mapper";
