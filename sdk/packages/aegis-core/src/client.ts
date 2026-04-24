import type { AegisClientConfig } from "./config";
import { AegisAuthEndpoints } from "./endpoints/auth";
import { AegisInternalEndpoints } from "./endpoints/internal";
import { AegisSessionsEndpoints } from "./endpoints/sessions";
import { AegisUsersEndpoints } from "./endpoints/users";
import { AegisHttpClient } from "./http";

export class AegisClient {
  readonly auth: AegisAuthEndpoints;
  readonly users: AegisUsersEndpoints;
  readonly sessions: AegisSessionsEndpoints;
  readonly internal: AegisInternalEndpoints;

  constructor(config: AegisClientConfig) {
    const http = new AegisHttpClient(config);

    this.auth = new AegisAuthEndpoints(http);
    this.users = new AegisUsersEndpoints(http);
    this.sessions = new AegisSessionsEndpoints(http);
    this.internal = new AegisInternalEndpoints(http);
  }
}
