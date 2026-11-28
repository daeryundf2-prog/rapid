import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  api,
  authToken,
  captureFragmentToken,
  downloadNameFromDisposition,
  setAuthToken,
} from "./client";

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

describe("422 details (D1 /flags/row, review follow-up)", () => {
  it("surfaces the Korean detail string and validation message lists", async () => {
    const { errorMessageFromDetail, api, ApiError } = await import("./client");
    expect(errorMessageFromDetail("알 수 없는 kind입니다: zzz")).toBe("알 수 없는 kind입니다: zzz");
    expect(
      errorMessageFromDetail([{ msg: "record_index는 0 이상이어야 합니다" }, { msg: "kind가 필요합니다" }]),
    ).toBe("record_index는 0 이상이어야 합니다 · kind가 필요합니다");
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ detail: "알 수 없는 kind입니다: zzz" }), {
            status: 422,
            headers: { "content-type": "application/json" },
          }),
      ),
    );
    const error = await api("/api/runs/r/flags/row?kind=zzz&record_index=0").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as Error).message).toBe("알 수 없는 kind입니다: zzz");
    expect((error as InstanceType<typeof ApiError>).status).toBe(422);
    vi.unstubAllGlobals();
  });
});

describe("downloadNameFromDisposition (원격 윈도우 다운로드)", () => {
  it("reads an RFC 5987 filename* (Starlette's only form for a Korean name)", () => {
    expect(
      downloadNameFromDisposition(
        "attachment; filename*=utf-8''%ED%95%9C%EA%B8%80%ED%8C%8C%EC%9D%BC.txt",
        "fallback.txt",
      ),
    ).toBe("한글파일.txt");
  });

  it("prefers filename* over the ASCII fallback the server sends beside it", () => {
    expect(
      downloadNameFromDisposition(
        "attachment; filename=\"report.csv\"; filename*=utf-8''%EB%B3%B4%EA%B3%A0%EC%84%9C.csv",
        "fallback.csv",
      ),
    ).toBe("보고서.csv");
  });

  it("keeps a quoted ASCII name and its spaces", () => {
    expect(downloadNameFromDisposition('attachment; filename="case report.docx"', "fallback.docx")).toBe(
      "case report.docx",
    );
  });

  it("replaces characters Windows rejects in a file name", () => {
    expect(downloadNameFromDisposition("attachment; filename*=utf-8''a%3Ab%7Cc.txt", "fallback.txt")).toBe(
      "a_b_c.txt",
    );
  });

  it("falls back when the header is missing or undecodable", () => {
    expect(downloadNameFromDisposition("", "fallback.json")).toBe("fallback.json");
    expect(downloadNameFromDisposition("attachment", "fallback.json")).toBe("fallback.json");
    expect(downloadNameFromDisposition("attachment; filename*=utf-8''%E0%A4%A.txt", "fallback.json")).toBe(
      "%E0%A4%A.txt",
    );
  });
});
