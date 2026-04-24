import { describe, expect, it } from "bun:test";

import { AegisApiError, AegisClient } from "../src";
import {
  BASE_URL,
  INTERNAL_TOKEN,
  createCookieFetch,
  testEmail,
  verifyEmail,
  waitForMailpitToken,
} from "../../../test/support";

const PASSWORD = "Password123!Test";

describe("@junaadh/aegis integration", () => {
  it("signs up, verifies, logs in, fetches me, validates, and logs out against aegisd", async () => {
    const cookie = createCookieFetch();
    const client = new AegisClient({
      baseUrl: BASE_URL,
      internalToken: INTERNAL_TOKEN,
      fetch: cookie.fetch,
    });
    const email = testEmail("sdk-core");

    const signup = await client.auth.signup({
      email,
      password: PASSWORD,
      displayName: "SDK Core",
    });
    expect(signup.identity.type).toBe("user");
    expect(cookie.getCookie()).toContain("aegis_session=");

    const verifyToken = await waitForMailpitToken(
      email,
      "Use this verification token to verify your account: ",
    );
    await verifyEmail(verifyToken);

    const login = await client.auth.login({ email, password: PASSWORD });
    expect(login.status).toBe("authenticated");

    const me = await client.auth.me();
    expect(me.type).toBe("user");
    if (me.type !== "user") {
      throw new Error("expected user identity");
    }
    expect(me.user.email).toBe(email);

    const sessionToken = cookie.getCookie()?.split("=")[1];
    expect(sessionToken).toBeTruthy();

    const validation = await client.internal.validateSession({ token: sessionToken! });
    expect(validation.valid).toBe(true);
    expect(validation.userId).toBeTruthy();

    await client.auth.logout();
    await expect(client.auth.me()).rejects.toBeInstanceOf(AegisApiError);
  });

  it("maps API failures into AegisApiError with status, code, message, and requestId", async () => {
    const cookie = createCookieFetch();
    const client = new AegisClient({ baseUrl: BASE_URL, fetch: cookie.fetch });
    const email = testEmail("sdk-core-error");

    await client.auth.signup({
      email,
      password: PASSWORD,
      displayName: "SDK Error",
    });

    try {
      await client.auth.signup({
        email,
        password: PASSWORD,
        displayName: "SDK Error",
      });
      throw new Error("expected duplicate signup to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(AegisApiError);
      const apiError = error as AegisApiError;
      expect(apiError.status).toBe(409);
      expect(apiError.code).toBe("USER_ALREADY_EXISTS");
      expect(apiError.message).toBeTruthy();
      expect(apiError.requestId).toBeTruthy();
      expect(apiError.meta).toBeDefined();
    }
  });
});
