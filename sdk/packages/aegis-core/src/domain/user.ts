export type User = {
  id: string;
  email: string;
  displayName: string;
  status: string;
  emailVerified: boolean;
  roles: string[];
  metadata: unknown;
  createdAt: Date;
  updatedAt: Date;
};

export type Guest = {
  id: string;
  email?: string;
  status: string;
  expiresAt: Date;
};

export type Identity =
  | {
      type: "user";
      user: User;
    }
  | {
      type: "guest";
      guest: Guest;
    };

export type IdentityLookup = {
  id?: string;
  email?: string;
  displayName?: string;
  status?: string;
  emailVerified?: boolean;
  roles?: string[];
  metadata?: unknown;
};
