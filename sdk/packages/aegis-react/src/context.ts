"use client";

import type {
  AegisClient,
  AegisClientConfig,
  AuthResult,
  Guest,
  GuestConvertRequestDto,
  Identity,
  LoginRequestDto,
  LoginResult,
  Session,
  SignupRequestDto,
  User,
} from "@aegis/core";
import { createContext, useContext } from "react";

export type AegisReactError = Error | null;

export type AegisAuthState = {
  identity: Identity | null;
  session: Session | null;
  loading: boolean;
  authenticating: boolean;
  error: AegisReactError;
};

export type AegisContextValue = AegisAuthState & {
  client: AegisClient;
  isAuthenticated: boolean;
  user: User | null;
  guest: Guest | null;
  refresh: () => Promise<Identity | null>;
  login: (input: LoginRequestDto) => Promise<LoginResult>;
  logout: () => Promise<void>;
  signup: (input: SignupRequestDto) => Promise<AuthResult>;
  convertGuest: (input: GuestConvertRequestDto) => Promise<AuthResult>;
  clearError: () => void;
};

export type AegisProviderProps = {
  children: React.ReactNode;
  baseUrl: string;
  token?: string;
  headers?: AegisClientConfig["headers"];
  credentials?: AegisClientConfig["credentials"];
  logger?: AegisClientConfig["logger"];
  initialIdentity?: Identity | null;
  initialSession?: Session | null;
  autoLoadUser?: boolean;
};

export const AegisContext = createContext<AegisContextValue | null>(null);

export function useAegisContext(): AegisContextValue {
  const value = useContext(AegisContext);
  if (!value) {
    throw new Error("Aegis hooks must be used within an AegisProvider");
  }

  return value;
}
