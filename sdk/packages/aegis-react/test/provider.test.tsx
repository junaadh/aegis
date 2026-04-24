import { afterEach, beforeEach, describe, expect, it, mock } from "bun:test";
import React from "react";
import TestRenderer, { act } from "react-test-renderer";

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

const consoleError = console.error;

const state = {
  me: mock(async () => ({
    type: "user" as const,
    user: { id: "user_1", email: "react@example.test", displayName: "React" },
  })),
  login: mock(async () => ({
    status: "authenticated" as const,
    identity: {
      type: "user" as const,
      user: { id: "user_1", email: "react@example.test", displayName: "React" },
    },
    session: { expiresAt: new Date().toISOString(), mfaVerified: false },
  })),
  signup: mock(async () => ({
    identity: {
      type: "user" as const,
      user: { id: "user_1", email: "react@example.test", displayName: "React" },
    },
    session: { expiresAt: new Date().toISOString(), mfaVerified: false },
  })),
  convertGuest: mock(async () => ({
    identity: {
      type: "user" as const,
      user: { id: "user_1", email: "react@example.test", displayName: "React" },
    },
    session: { expiresAt: new Date().toISOString(), mfaVerified: false },
  })),
  logout: mock(async () => undefined),
};

class MockAegisApiError extends Error {
  constructor(public readonly status: number) {
    super(`status ${status}`);
    this.name = "AegisApiError";
  }
}

mock.module("@junaadh/aegis", () => ({
  AegisApiError: MockAegisApiError,
  AegisClient: class MockClient {
    auth = {
      me: state.me,
      login: state.login,
      signup: state.signup,
      convertGuest: state.convertGuest,
      logout: state.logout,
    };
  },
}));

import { AegisProvider } from "../src/AegisProvider";
import { useAegisContext } from "../src/context";

function Probe() {
  const aegis = useAegisContext();
  return (
    <div>
      <span id="state" loading={String(aegis.loading)} authenticated={String(aegis.isAuthenticated)} />
      <button
        onClick={() => {
          void aegis.login({ email: "react@example.test", password: "Password123!" });
        }}
      />
      <button
        id="logout"
        onClick={() => {
          void aegis.logout();
        }}
      />
    </div>
  );
}

describe("@junaadh/aegis-react provider", () => {
  beforeEach(() => {
    state.me.mockClear();
    state.login.mockClear();
    state.signup.mockClear();
    state.convertGuest.mockClear();
    state.logout.mockClear();
    console.error = (...args: unknown[]) => {
      const [first] = args;
      if (
        typeof first === "string" &&
        first.includes("react-test-renderer is deprecated")
      ) {
        return;
      }
      consoleError(...args);
    };
  });

  afterEach(() => {
    mock.restore();
    console.error = consoleError;
  });

  it("auto-loads the current user and updates auth state", async () => {
    let renderer: TestRenderer.ReactTestRenderer;

    await act(async () => {
      renderer = TestRenderer.create(
        <AegisProvider baseUrl="http://127.0.0.1:4001">
          <Probe />
        </AegisProvider>,
      );
      await Promise.resolve();
    });

    expect(state.me).toHaveBeenCalledTimes(1);
    const value = renderer!.root.findByProps({ id: "state" });
    expect(value.props.loading).toBe("false");
    expect(value.props.authenticated).toBe("true");

    await act(async () => {
      renderer!.root.findAllByType("button")[0]?.props.onClick();
      await Promise.resolve();
    });

    expect(state.login).toHaveBeenCalledTimes(1);

    await act(async () => {
      renderer!.root.findByProps({ id: "logout" }).props.onClick();
      await Promise.resolve();
    });

    expect(state.logout).toHaveBeenCalledTimes(1);

    await act(async () => {
      renderer!.unmount();
    });
  });
});
