"use client";

import { useAegisContext } from "../context";

export function useUser() {
  const context = useAegisContext();

  return {
    user: context.user,
    loading: context.loading,
    authenticating: context.authenticating,
    error: context.error,
    isAuthenticated: context.isAuthenticated,
    refresh: context.refresh,
  };
}
