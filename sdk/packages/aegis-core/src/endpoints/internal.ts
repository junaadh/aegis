import type {
  HealthResponseDto,
  OverviewResponseDto,
} from "../dto/user.dto";
import type {
  SessionValidateRequestDto,
  SessionValidateResponseDto,
} from "../dto/session.dto";
import type { SessionValidation } from "../domain/session";
import { AegisHttpClient } from "../http";
import { mapSessionValidationDtoToDomain } from "../mappers/session.mapper";

export class AegisInternalEndpoints {
  constructor(private readonly http: AegisHttpClient) {}

  async health(): Promise<HealthResponseDto> {
    return this.http.get<HealthResponseDto>("/internal/health", {
      auth: "internal",
    });
  }

  async overview(): Promise<OverviewResponseDto> {
    return this.http.get<OverviewResponseDto>("/internal/overview", {
      auth: "internal",
    });
  }

  async validateSession(
    input: SessionValidateRequestDto,
  ): Promise<SessionValidation> {
    const dto = await this.http.post<
      SessionValidateResponseDto,
      SessionValidateRequestDto
    >("/internal/session/validate", {
      auth: "internal",
      body: input,
    });
    return mapSessionValidationDtoToDomain(dto);
  }
}
