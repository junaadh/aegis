import type {
  ApiStatusResponseDto,
  AuthResponseDto,
  GuestConvertRequestDto,
  GuestCreateRequestDto,
  GuestEmailRequestDto,
  LoginRequestDto,
  SignupRequestDto,
} from "../dto/auth.dto";
import type { LoginResponseDto } from "../dto/session.dto";
import type { UpdateProfileRequestDto } from "../dto/user.dto";
import type { AuthResult, LoginResult } from "../domain/session";
import type { Identity } from "../domain/user";
import { AegisHttpClient } from "../http";
import { mapLoginDtoToDomain } from "../mappers/session.mapper";
import { mapAuthDtoToDomain, mapIdentityDtoToDomain } from "../mappers/user.mapper";

export class AegisAuthEndpoints {
  constructor(private readonly http: AegisHttpClient) {}

  async signup(input: SignupRequestDto): Promise<AuthResult> {
    const dto = await this.http.post<AuthResponseDto, SignupRequestDto>("/auth/signup", {
      auth: "session",
      body: input,
    });
    return mapAuthDtoToDomain(dto);
  }

  async login(input: LoginRequestDto): Promise<LoginResult> {
    const dto = await this.http.post<LoginResponseDto, LoginRequestDto>("/auth/login", {
      auth: "session",
      body: input,
    });
    return mapLoginDtoToDomain(dto);
  }

  async logout(): Promise<ApiStatusResponseDto> {
    return this.http.post<ApiStatusResponseDto>("/auth/logout", {
      auth: "session",
    });
  }

  async me(): Promise<Identity> {
    const dto = await this.http.get<import("../dto/user.dto").IdentityDto>("/auth/me", {
      auth: "session",
    });
    return mapIdentityDtoToDomain(dto);
  }

  async updateProfile(input: UpdateProfileRequestDto): Promise<Identity> {
    const dto = await this.http.patch<import("../dto/user.dto").IdentityDto, UpdateProfileRequestDto>(
      "/auth/me",
      {
        auth: "session",
        body: input,
      },
    );
    return mapIdentityDtoToDomain(dto);
  }

  async createGuest(
    input: GuestCreateRequestDto = {},
  ): Promise<AuthResult> {
    const dto = await this.http.post<AuthResponseDto, GuestCreateRequestDto>("/auth/guest", {
      body: input,
    });
    return mapAuthDtoToDomain(dto);
  }

  async associateGuestEmail(
    input: GuestEmailRequestDto,
  ): Promise<Identity> {
    const dto = await this.http.patch<import("../dto/user.dto").IdentityDto, GuestEmailRequestDto>(
      "/auth/guest/email",
      {
        auth: "session",
        body: input,
      },
    );
    return mapIdentityDtoToDomain(dto);
  }

  async convertGuest(input: GuestConvertRequestDto): Promise<AuthResult> {
    const dto = await this.http.post<AuthResponseDto, GuestConvertRequestDto>(
      "/auth/guest/convert",
      {
        auth: "session",
        body: input,
      },
    );
    return mapAuthDtoToDomain(dto);
  }
}
