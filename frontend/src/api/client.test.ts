import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, authToken, captureFragmentToken, setAuthToken } from "./client";

describe("captureFragmentToken", () => {
  afterEach(() => {
    window.sessionStorage.clear();
    window.localStorage.clear();
    window.history.replaceState(null, "", "/v2/");
  });

  it("stores a #token= fragment in sessionStorage and strips it", () => {
    const applied = captureFragmentToken("#token=secret-token");
    expect(applied).toBe(true);
    expect(authToken()).toBe("secret-token");
    expect(window.location.hash).toBe("");
  });

  it("decodes URI-encoded tokens", () => {
    captureFragmentToken("#token=a%20b%2Fc");
    expect(authToken()).toBe("a b/c");
  });

  it("returns false when no token fragment exists", () => {
    expect(captureFragmentToken("")).toBe(false);
    expect(captureFragmentToken("#section")).toBe(false);
  });

  it("falls back to the v1 localStorage token", () => {
    window.localStorage.setItem("rapidtriage.authToken", "legacy-token");
    expect(authToken()).toBe("legacy-token");
  });
});

describe("api", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    window.sessionStorage.clear();
    window.localStorage.clear();
  });

  it("sends the token as X-RapidTriage-Token", async () => {
    setAuthToken("abc123");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response('{"ok": true}', {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await api("/api/runs");
    const headers = fetchMock.mock.calls[0]?.[1]?.headers as Record<string, string>;
    expect(headers["X-RapidTriage-Token"]).toBe("abc123");
  });

  it("throws ApiError with status and detail on failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response('{"detail": "missing or invalid RapidTriage auth token"}', {
          status: 401,
          headers: { "content-type": "application/json" },
        }),
      ),
    );
    await expect(api("/api/runs")).rejects.toMatchObject({
      name: "ApiError",
      status: 401,
      message: "missing or invalid RapidTriage auth token",
    });
    await expect(api("/api/runs")).rejects.toBeInstanceOf(ApiError);
  });
});
