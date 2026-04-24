"use client";

import {
  AegisApiError,
  AegisClient,
  type AuthResult,
  type GuestConvertRequestDto,
  type Identity,
  type LoginRequestDto,
  type LoginResult,
  type Session,
  type SignupRequestDto,
} from "@junaadh/aegis";
import { useEffect, useRef, useState } from "react";

import {
  AegisContext,
  type AegisAuthState,
  type AegisProviderProps,
} from "./context";

function toAuthState(
  identity: Identity | null,
  session: Session | null,
  loading: boolean,
): AegisAuthState {
  return {
    identity,
    session,
    loading,
    authenticating: false,
    error: null,
  };
}

function isUnauthorized(error: unknown): boolean {
  return error instanceof AegisApiError && error.status === 401;
}

export function AegisProvider({
  children,
  baseUrl,
  token,
  headers,
  credentials,
  logger,
  initialIdentity = null,
  initialSession = null,
  autoLoadUser = true,
}: AegisProviderProps) {
  const clientRef = useRef<AegisClient | null>(null);
  if (!clientRef.current) {
    clientRef.current = new AegisClient({
      baseUrl,
      ...(token !== undefined ? { token } : {}),
      ...(headers !== undefined ? { headers } : {}),
      ...(credentials !== undefined ? { credentials } : {}),
      ...(logger !== undefined ? { logger } : {}),
    });
  }

  const client = clientRef.current;
  const [state, setState] = useState<AegisAuthState>(() =>
    toAuthState(initialIdentity, initialSession, autoLoadUser && !initialIdentity),
  );

  async function refresh(): Promise<Identity | null> {
    setState((current) => ({ ...current, loading: true, error: null }));

    try {
      const identity = await client.auth.me();
      setState((current) => ({
        ...current,
        identity,
        loading: false,
        error: null,
      }));
      return identity;
    } catch (error) {
      if (isUnauthorized(error)) {
        setState((current) => ({
          ...current,
          identity: null,
          session: null,
          loading: false,
          error: null,
        }));
        return null;
      }

      const normalized = error instanceof Error ? error : new Error(String(error));
      setState((current) => ({
        ...current,
        loading: false,
        error: normalized,
      }));
      throw normalized;
    }
  }

  useEffect(() => {
    if (!autoLoadUser || initialIdentity) {
      return;
    }

    void refresh();
  }, [autoLoadUser, initialIdentity]);

  async function login(input: LoginRequestDto): Promise<LoginResult> {
    setState((current) => ({ ...current, authenticating: true, error: null }));

    try {
      const result = await client.auth.login(input);
      setState((current) => ({
        ...current,
        identity: result.status === "authenticated" ? result.identity : null,
        session: result.session,
        authenticating: false,
        loading: false,
        error: null,
      }));
      return result;
    } catch (error) {
      const normalized = error instanceof Error ? error : new Error(String(error));
      setState((current) => ({
        ...current,
        authenticating: false,
        loading: false,
        error: normalized,
      }));
      throw normalized;
    }
  }

  async function signup(input: SignupRequestDto): Promise<AuthResult> {
    setState((current) => ({ ...current, authenticating: true, error: null }));

    try {
      const result = await client.auth.signup(input);
      setState((current) => ({
        ...current,
        identity: result.identity,
        session: result.session,
        authenticating: false,
        loading: false,
        error: null,
      }));
      return result;
    } catch (error) {
      const normalized = error instanceof Error ? error : new Error(String(error));
      setState((current) => ({
        ...current,
        authenticating: false,
        loading: false,
        error: normalized,
      }));
      throw normalized;
    }
  }

  async function convertGuest(
    input: GuestConvertRequestDto,
  ): Promise<AuthResult> {
    setState((current) => ({ ...current, authenticating: true, error: null }));

    try {
      const result = await client.auth.convertGuest(input);
      setState((current) => ({
        ...current,
        identity: result.identity,
        session: result.session,
        authenticating: false,
        loading: false,
        error: null,
      }));
      return result;
    } catch (error) {
      const normalized = error instanceof Error ? error : new Error(String(error));
      setState((current) => ({
        ...current,
        authenticating: false,
        loading: false,
        error: normalized,
      }));
      throw normalized;
    }
  }

  async function logout(): Promise<void> {
    setState((current) => ({ ...current, authenticating: true, error: null }));

    try {
      await client.auth.logout();
      setState({
        identity: null,
        session: null,
        loading: false,
        authenticating: false,
        error: null,
      });
    } catch (error) {
      const normalized = error instanceof Error ? error : new Error(String(error));
      setState((current) => ({
        ...current,
        authenticating: false,
        error: normalized,
      }));
      throw normalized;
    }
  }

  const user = state.identity?.type === "user" ? state.identity.user : null;
  const guest = state.identity?.type === "guest" ? state.identity.guest : null;

  return (
    <AegisContext.Provider
      value={{
        ...state,
        client,
        isAuthenticated: state.identity !== null,
        user,
        guest,
        refresh,
        login,
        logout,
        signup,
        convertGuest,
        clearError: () => setState((current) => ({ ...current, error: null })),
      }}
    >
      {children}
    </AegisContext.Provider>
  );
}
