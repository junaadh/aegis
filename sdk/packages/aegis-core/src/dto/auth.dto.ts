import type { IdentityDto } from "./user.dto";
import type { SessionDto } from "./session.dto";

export type SignupRequestDto = {
  email: string;
  password: string;
  displayName: string;
};

export type LoginRequestDto = {
  email: string;
  password: string;
};

export type GuestCreateRequestDto = Record<string, never>;

export type GuestEmailRequestDto = {
  email: string;
};

export type GuestConvertRequestDto = {
  email?: string;
  password: string;
  displayName?: string;
};

export type AuthResponseDto = {
  identity: IdentityDto;
  session: SessionDto;
};

export type ApiStatusResponseDto = {
  status: string;
};
