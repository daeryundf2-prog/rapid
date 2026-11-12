import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, apiResponse } from "./client";
import {
  apiErrorFromBody,
  apiErrorFromFetchFailure,
  errorMessageFromDetail,
  isAbortError,
  isGenericMessage,
  NETWORK_UNREACHABLE,
  REQUEST_ABORTED,
  REQUEST_TIMEOUT,
} from "./errors";

const HANGUL = /[가-힣]/;

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

async function failure(promise: Promise<unknown>): Promise<ApiError> {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(ApiError);
  return error as ApiError;
}

afterEach(() => vi.unstubAllGlobals());

describe("apiErrorFromBody — D.7 envelope", () => {
  it("prefers the top-level code / message / hint and keeps detail untouched", () => {
    const error = apiErrorFromBody(404, {
      detail: "런을 찾을 수 없습니다",
      code: "RUN_NOT_FOUND",
      message: "해당 런을 찾지 못했습니다",
      hint: "런 목록에서 런 ID를 확인하세요",
    });
    expect(error).toMatchObject({
      status: 404,
      code: "RUN_NOT_FOUND",
      message: "해당 런을 찾지 못했습니다",
      hint: "런 목록에서 런 ID를 확인하세요",
      detail: "런을 찾을 수 없습니다",
      crashId: null,
      isAbort: false,
    });
  });

  it("keeps a 422 detail list as-is (AnalysisDialog reads loc/msg from it)", () => {
    const detail = [{ loc: ["body", "name"], msg: "Field required" }];
    const error = apiErrorFromBody(422, {
      detail,
      code: "VALIDATION_FAILED",
      message: "입력값 검사를 통과하지 못했습니다",
      hint: "표시된 항목을 고친 뒤 다시 시도하세요",
    });
    expect(error.detail).toBe(detail);
    expect(error.message).toBe("입력값 검사를 통과하지 못했습니다");
  });

  it("carries crash_id from a 500 body", () => {
    const error = apiErrorFromBody(500, {
      detail: "internal RapidTriage error; local crash report written",
      code: "INTERNAL_ERROR",
      message: "서버 내부 오류가 발생했습니다",
      hint: "오류 ID(crash_id)를 기록해 관리자에게 알리세요",
      crash_id: "crash-20261112-abc",
    });
    expect(error.crashId).toBe("crash-20261112-abc");
    expect(error.code).toBe("INTERNAL_ERROR");
  });

  it("reads code / message from an output-guard detail object", () => {
    const error = apiErrorFromBody(422, {
      detail: { code: "OUTPUT_INSIDE_EVIDENCE", message: "출력 위치가 증거 경로 안입니다" },
    });
    expect(error.code).toBe("OUTPUT_INSIDE_EVIDENCE");
    expect(error.message).toBe("출력 위치가 증거 경로 안입니다");
    expect(error.hint).toMatch(HANGUL);
  });
});

describe("apiErrorFromBody — old servers (no envelope)", () => {
  it.each([
    [404, { detail: "Not Found" }, "NOT_FOUND", "요청한 대상을 찾지 못했습니다"],
    [
      405,
      { detail: "Method Not Allowed" },
      "METHOD_NOT_ALLOWED",
      "이 주소는 해당 요청 방식(메서드)을 지원하지 않습니다",
    ],
    [500, { detail: "internal RapidTriage error" }, "INTERNAL_ERROR", "서버 내부 오류가 발생했습니다"],
    [503, { detail: "pytsk3 missing" }, "SERVICE_UNAVAILABLE", "지금은 이 기능을 쓸 수 없습니다"],
    [418, { detail: "teapot" }, "BAD_REQUEST", "요청 내용이 올바르지 않습니다"],
    [502, undefined, "INTERNAL_ERROR", "서버 내부 오류가 발생했습니다"],
  ])("status %i with %j → %s in Korean", (status, body, code, message) => {
    const error = apiErrorFromBody(status, body);
    expect(error.code).toBe(code);
    expect(error.message).toBe(message);
    expect(error.hint).toMatch(HANGUL);
  });

  it("keeps a Korean detail string and a Korean 422 list", () => {
    expect(apiErrorFromBody(422, { detail: "알 수 없는 kind입니다: zzz" }).message).toBe(
      "알 수 없는 kind입니다: zzz",
    );
    expect(apiErrorFromBody(422, { detail: [{ msg: "kind가 필요합니다" }, { msg: "0 이상" }] }).message).toBe(
      "kind가 필요합니다 · 0 이상",
    );
  });

  it("never uses an English pydantic list or an English envelope message", () => {
    expect(apiErrorFromBody(422, { detail: [{ msg: "Field required" }] }).message).toBe(
      "입력값 검사를 통과하지 못했습니다",
    );
    expect(apiErrorFromBody(400, { detail: "x", message: "Bad thing" }).message).toBe(
      "요청 내용이 올바르지 않습니다",
    );
  });

  it("errorMessageFromDetail never falls back to English", () => {
    expect(errorMessageFromDetail(undefined)).toMatch(HANGUL);
    expect(errorMessageFromDetail({})).toMatch(HANGUL);
    expect(errorMessageFromDetail("Not Found", 404)).toBe("요청한 대상을 찾지 못했습니다");
  });
});

describe("api() — fetch failures become front-end codes", () => {
  it("TypeError (Failed to fetch) → NETWORK_UNREACHABLE in Korean", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    const error = await failure(api("/api/runs"));
    expect(error).toMatchObject({
      status: 0,
      code: NETWORK_UNREACHABLE,
      message: "서버에 연결하지 못했습니다",
    });
    expect(error.message).not.toMatch(/Failed to fetch/);
    expect(error.hint).toMatch(HANGUL);
    expect(error.isAbort).toBe(false);
  });

  it("an aborted signal → REQUEST_ABORTED (isAbort)", async () => {
    const controller = new AbortController();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_path: string, init: RequestInit) => {
        controller.abort();
        throw init.signal?.reason ?? new DOMException("The operation was aborted.", "AbortError");
      }),
    );
    const error = await failure(api("/api/runs", { signal: controller.signal }));
    expect(error.code).toBe(REQUEST_ABORTED);
    expect(error.isAbort).toBe(true);
    expect(isAbortError(error)).toBe(true);
    expect(error.message).toMatch(HANGUL);
  });

  it("a TimeoutError → REQUEST_TIMEOUT", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new DOMException("signal timed out", "TimeoutError")));
    const error = await failure(api("/api/runs"));
    expect(error).toMatchObject({ code: REQUEST_TIMEOUT, message: "응답 시간이 초과되었습니다" });
  });

  it("a timed-out signal reason wins over the AbortError fetch throws", () => {
    const signal = { aborted: true, reason: new DOMException("timed out", "TimeoutError") } as AbortSignal;
    expect(apiErrorFromFetchFailure(new DOMException("aborted", "AbortError"), signal).code).toBe(
      REQUEST_TIMEOUT,
    );
  });

  it("apiResponse maps failures the same way and reads the envelope", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new TypeError("NetworkError when attempting to fetch resource.")),
    );
    expect((await failure(apiResponse("/api/x"))).code).toBe(NETWORK_UNREACHABLE);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          {
            detail: "export not found",
            code: "EXPORT_NOT_WRITTEN",
            message: "저장된 내보내기 결과가 없습니다",
          },
          404,
        ),
      ),
    );
    const error = await failure(apiResponse("/api/x"));
    expect(error).toMatchObject({
      status: 404,
      code: "EXPORT_NOT_WRITTEN",
      message: "저장된 내보내기 결과가 없습니다",
    });
    expect(error.hint).toMatch(HANGUL);
  });

  it("a non-JSON error body (proxy page) still yields Korean", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("<html>Bad Gateway</html>", { status: 502, statusText: "Bad Gateway" })),
    );
    const error = await failure(api("/api/x"));
    expect(error.status).toBe(502);
    expect(error.message).toMatch(HANGUL);
  });

  it("isAbortError recognizes a raw AbortError and rejects other errors", () => {
    expect(isAbortError(new DOMException("x", "AbortError"))).toBe(true);
    expect(isAbortError(new ApiError("x", 404, null))).toBe(false);
    expect(isAbortError(null)).toBe(false);
  });

  it("isGenericMessage tells a status-default sentence from a specific one", () => {
    expect(isGenericMessage(apiErrorFromBody(422, { detail: [{ msg: "Field required" }] }))).toBe(true);
    expect(isGenericMessage(apiErrorFromBody(422, { detail: "알 수 없는 kind입니다: zzz" }))).toBe(false);
  });

  it("legacy positional constructor still works and derives the code from status", () => {
    const error = new ApiError("필드 검색은 색인이 필요합니다", 409, null);
    expect(error).toMatchObject({ status: 409, code: "CONFLICT", detail: null, name: "ApiError" });
    expect(error.hint).toMatch(HANGUL);
  });
});
