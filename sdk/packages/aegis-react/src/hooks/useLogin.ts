"use client";

import { useAegisContext } from "../context";

export function useLogin() {
  const context = useAegisContext();

  return {
    login: context.login,
    authenticating: context.authenticating,
    error: context.error,
    clearError: context.clearError,
  };
}
