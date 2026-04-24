"use client";

import { useAegisContext } from "../context";

export function useSignup() {
  const context = useAegisContext();

  return {
    signup: context.signup,
    convertGuest: context.convertGuest,
    authenticating: context.authenticating,
    error: context.error,
    clearError: context.clearError,
  };
}
