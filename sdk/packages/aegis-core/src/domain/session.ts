import type { Identity } from "./user";

export type Session = {
  expiresAt: Date;
  mfaVerified: boolean;
};

export type AuthResult = {
  identity: Identity;
  session: Session;
};

export type LoginResult =
  | {
      status: "authenticated";
      identity: Identity;
      session: Session;
    }
  | {
      status: "requiresMfa";
      session: Session;
    };

export type SessionValidation = {
  valid: boolean;
  userId?: string;
  guestId?: string;
  status?: string;
  expiresAt?: Date;
  roles: string[];
  mfaVerified: boolean;
};
