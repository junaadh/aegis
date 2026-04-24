import type { ApiStatusResponseDto } from "../dto/auth.dto";
import type {
  AdminGuestDetailResponseDto,
  AdminGuestListItemResponseDto,
  AdminGuestListQueryDto,
  AdminUserDetailResponseDto,
  AdminUserListItemResponseDto,
  AdminUserListQueryDto,
  IdentityLookupResponseDto,
  PaginatedResponseDto,
  UserLookupByEmailRequestDto,
  UserLookupRequestDto,
} from "../dto/user.dto";
import type { IdentityLookup } from "../domain/user";
import { AegisHttpClient } from "../http";
import { mapIdentityLookupDtoToDomain } from "../mappers/user.mapper";

export class AegisUsersEndpoints {
  constructor(private readonly http: AegisHttpClient) {}

  async lookup(input: UserLookupRequestDto): Promise<IdentityLookup> {
    const dto = await this.http.post<IdentityLookupResponseDto, UserLookupRequestDto>(
      "/internal/user/lookup",
      {
        auth: "internal",
        body: input,
      },
    );
    return mapIdentityLookupDtoToDomain(dto);
  }

  async lookupByEmail(
    input: UserLookupByEmailRequestDto,
  ): Promise<IdentityLookup> {
    const dto = await this.http.post<
      IdentityLookupResponseDto,
      UserLookupByEmailRequestDto
    >("/internal/user/lookup-by-email", {
      auth: "internal",
      body: input,
    });
    return mapIdentityLookupDtoToDomain(dto);
  }

  async list(
    query: AdminUserListQueryDto = {},
  ): Promise<PaginatedResponseDto<AdminUserListItemResponseDto>> {
    return this.http.get<PaginatedResponseDto<AdminUserListItemResponseDto>>(
      "/internal/users",
      {
        auth: "internal",
        query,
      },
    );
  }

  async getById(id: string): Promise<AdminUserDetailResponseDto> {
    return this.http.get<AdminUserDetailResponseDto>(`/internal/users/${id}`, {
      auth: "internal",
    });
  }

  async getRoles(id: string): Promise<{ roles: string[] }> {
    return this.http.get<{ roles: string[] }>(`/internal/users/${id}/roles`, {
      auth: "internal",
    });
  }

  async disable(id: string): Promise<ApiStatusResponseDto> {
    return this.http.post<ApiStatusResponseDto>(`/internal/users/${id}/disable`, {
      auth: "internal",
    });
  }

  async enable(id: string): Promise<ApiStatusResponseDto> {
    return this.http.post<ApiStatusResponseDto>(`/internal/users/${id}/enable`, {
      auth: "internal",
    });
  }

  async revokeSessions(id: string): Promise<ApiStatusResponseDto> {
    return this.http.post<ApiStatusResponseDto>(
      `/internal/users/${id}/revoke-sessions`,
      {
        auth: "internal",
      },
    );
  }

  async listGuests(
    query: AdminGuestListQueryDto = {},
  ): Promise<PaginatedResponseDto<AdminGuestListItemResponseDto>> {
    return this.http.get<PaginatedResponseDto<AdminGuestListItemResponseDto>>(
      "/internal/guests",
      {
        auth: "internal",
        query,
      },
    );
  }

  async getGuestById(id: string): Promise<AdminGuestDetailResponseDto> {
    return this.http.get<AdminGuestDetailResponseDto>(`/internal/guests/${id}`, {
      auth: "internal",
    });
  }
}
