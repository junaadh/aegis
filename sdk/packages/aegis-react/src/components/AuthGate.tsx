"use client";

import type { ReactNode } from "react";

import { useSession } from "../hooks/useSession";

export type AuthGateProps = {
  children: ReactNode;
  fallback?: ReactNode;
  loadingFallback?: ReactNode;
  requireUser?: boolean;
};

export function AuthGate({
  children,
  fallback = null,
  loadingFallback = null,
  requireUser = false,
}: AuthGateProps) {
  const { identity, loading, isAuthenticated } = useSession();

  if (loading) {
    return <>{loadingFallback}</>;
  }

  if (!isAuthenticated) {
    return <>{fallback}</>;
  }

  if (requireUser && identity?.type !== "user") {
    return <>{fallback}</>;
  }

  return <>{children}</>;
}
