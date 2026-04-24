import type { ApiStatusResponseDto } from "../dto/auth.dto";
import type {
  AdminSessionDetailResponseDto,
  AdminSessionListItemResponseDto,
  AdminSessionListQueryDto,
  SessionRevokeRequestDto,
} from "../dto/session.dto";
import type { PaginatedResponseDto } from "../dto/user.dto";
import { AegisHttpClient } from "../http";

export class AegisSessionsEndpoints {
  constructor(private readonly http: AegisHttpClient) {}

  async revoke(input: SessionRevokeRequestDto = {}): Promise<ApiStatusResponseDto> {
    return this.http.post<ApiStatusResponseDto, SessionRevokeRequestDto>(
      "/auth/session/revoke",
      {
        auth: "session",
        body: input,
      },
    );
  }

  async revokeAll(): Promise<ApiStatusResponseDto> {
    return this.http.post<ApiStatusResponseDto>("/auth/session/revoke-all", {
      auth: "session",
    });
  }

  async list(
    query: AdminSessionListQueryDto = {},
  ): Promise<PaginatedResponseDto<AdminSessionListItemResponseDto>> {
    return this.http.get<PaginatedResponseDto<AdminSessionListItemResponseDto>>(
      "/internal/sessions",
      {
        auth: "internal",
        query,
      },
    );
  }

  async getById(id: string): Promise<AdminSessionDetailResponseDto> {
    return this.http.get<AdminSessionDetailResponseDto>(`/internal/sessions/${id}`, {
      auth: "internal",
    });
  }

  async revokeById(id: string): Promise<ApiStatusResponseDto> {
    return this.http.post<ApiStatusResponseDto>(`/internal/sessions/${id}/revoke`, {
      auth: "internal",
    });
  }
}
