"use client";

export { AegisProvider } from "./AegisProvider";
export { AuthGate } from "./components/AuthGate";
export { useLogin, useLogout, useSession, useSignup, useUser } from "./hooks";
export type { AuthGateProps } from "./components/AuthGate";
export type {
  AegisAuthState,
  AegisContextValue,
  AegisProviderProps,
  AegisReactError,
} from "./context";
