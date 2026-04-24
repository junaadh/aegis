"use client";

import { useAegisContext } from "../context";

export function useSession() {
  const context = useAegisContext();

  return {
    session: context.session,
    identity: context.identity,
    isAuthenticated: context.isAuthenticated,
    loading: context.loading,
    authenticating: context.authenticating,
    error: context.error,
    refresh: context.refresh,
  };
}
