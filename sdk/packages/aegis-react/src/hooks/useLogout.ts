"use client";

import { useAegisContext } from "../context";

export function useLogout() {
  const context = useAegisContext();

  return {
    logout: context.logout,
    authenticating: context.authenticating,
    error: context.error,
    clearError: context.clearError,
  };
}
