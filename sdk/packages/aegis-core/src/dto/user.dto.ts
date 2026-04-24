export type PaginatedResponseDto<T> = {
  items: T[];
  page: number;
  perPage: number;
  total: number;
};

export type ComponentStatusDto = {
  status: string;
  latencyMs?: number;
  details?: unknown;
};

export type HealthResponseDto = {
  status: string;
  version: string;
  uptimeSeconds: number;
  database: ComponentStatusDto;
  cache: ComponentStatusDto;
  emailEnabled: boolean;
  outboxPending: number;
};

export type OverviewResponseDto = {
  totalUsers: number;
  activeUsers: number;
  totalGuests: number;
  activeGuests: number;
  activeSessions: number;
  emailEnabled: boolean;
};

export type UserDto = {
  id: string;
  email: string;
  displayName: string;
  status: string;
  emailVerified: boolean;
  roles: string[];
  metadata: unknown;
  createdAt: string;
  updatedAt: string;
};

export type UserPublicDto = {
  id: string;
  displayName: string;
};

export type GuestDto = {
  id: string;
  email?: string;
  status: string;
  expiresAt: string;
};

export type UserIdentityDto = {
  type: "user";
  user: UserDto;
};

export type GuestIdentityDto = {
  type: "guest";
  guest: GuestDto;
};

export type IdentityDto = UserIdentityDto | GuestIdentityDto;

export type IdentityLookupResponseDto = {
  id?: string;
  email?: string;
  displayName?: string;
  status?: string;
  emailVerified?: boolean;
  roles?: string[];
  metadata?: unknown;
};

export type UserLookupRequestDto = {
  userId: string;
};

export type UserLookupByEmailRequestDto = {
  email: string;
};

export type UpdateProfileRequestDto = {
  displayName?: string;
};

export type AdminUserListQueryDto = {
  status?: string;
  verified?: boolean;
  role?: string;
  q?: string;
  page?: number;
  perPage?: number;
  sort?: string;
  order?: string;
};

export type AdminUserListItemResponseDto = {
  id: string;
  email: string;
  displayName: string;
  status: string;
  emailVerified: boolean;
  createdAt: string;
  updatedAt: string;
};

export type AdminUserCredentialSummaryResponseDto = {
  hasPassword: boolean;
  passkeyCount: number;
  totpEnabled: boolean;
};

export type AdminUserDetailResponseDto = {
  id: string;
  email: string;
  displayName: string;
  status: string;
  emailVerifiedAt?: string;
  metadata: unknown;
  roles: string[];
  credentials: AdminUserCredentialSummaryResponseDto;
  sessionCount: number;
  lastSeenAt?: string;
  createdAt: string;
  updatedAt: string;
};

export type AdminGuestListQueryDto = {
  status?: string;
  page?: number;
  perPage?: number;
  sort?: string;
  order?: string;
};

export type AdminGuestListItemResponseDto = {
  id: string;
  email?: string;
  status: string;
  convertedTo?: string;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
};

export type AdminGuestDetailResponseDto = {
  id: string;
  email?: string;
  status: string;
  convertedTo?: string;
  metadata: unknown;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
};
