import { describe, expect, it } from "bun:test";

import { AegisClient } from "@junaadh/aegis";
import {
  createAegisServerClient,
  getBearerToken,
  getCookieHeader,
  getCookieValue,
} from "../src";
import {
  BASE_URL,
  INTERNAL_TOKEN,
  createCookieFetch,
  testEmail,
  verifyEmail,
  waitForMailpitToken,
} from "../../../test/support";

const PASSWORD = "Password123!Test";

describe("@junaadh/aegis-server integration", () => {
  it("validates a real session using the internal endpoint and cookie store helper", async () => {
    const cookie = createCookieFetch();
    const client = new AegisClient({
      baseUrl: BASE_URL,
      internalToken: INTERNAL_TOKEN,
      fetch: cookie.fetch,
    });
    const email = testEmail("sdk-server");

    await client.auth.signup({
      email,
      password: PASSWORD,
      displayName: "SDK Server",
    });

    const verifyToken = await waitForMailpitToken(
      email,
      "Use this verification token to verify your account: ",
    );
    await verifyEmail(verifyToken);
    await client.auth.login({ email, password: PASSWORD });

    const cookieHeader = cookie.getCookie();
    expect(cookieHeader).toContain("aegis_session=");
    const token = getCookieValue(cookieHeader, "aegis_session");
    expect(token).toBeTruthy();

    const serverClient = createAegisServerClient({
      baseUrl: BASE_URL,
      internalToken: INTERNAL_TOKEN,
    });

    const session = await serverClient.validateSessionToken(token!);
    expect(session?.valid).toBe(true);
    expect(session?.userId).toBeTruthy();

    const fromCookies = await serverClient.getSessionFromCookies({
      get(name: string) {
        if (name !== "aegis_session" || !token) {
          return undefined;
        }
        return { value: token };
      },
    });
    expect(fromCookies?.valid).toBe(true);
  });

  it("rejects invalid sessions and parses cookie and bearer headers correctly", async () => {
    const serverClient = createAegisServerClient({
      baseUrl: BASE_URL,
      internalToken: INTERNAL_TOKEN,
    });

    const invalid = await serverClient.validateSessionToken("not-a-real-session");
    expect(invalid).toBeNull();

    const request = new Request(`${BASE_URL}/demo`, {
      headers: {
        authorization: "Bearer bearer-token",
        cookie: "aegis_session=session-token; other=value",
      },
    });

    expect(getBearerToken(request)).toBe("bearer-token");
    expect(getCookieHeader(request)).toContain("aegis_session=session-token");
    expect(getCookieValue(getCookieHeader(request), "aegis_session")).toBe(
      "session-token",
    );
  });
});
