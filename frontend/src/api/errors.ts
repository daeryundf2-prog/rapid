// Front-end error normalization (R8 T-008, r8-contracts D.7).
//
// The server adds `code` / `message` (Korean) / `hint` at the top level of every 4xx/5xx JSON body
// and keeps `detail` in its old shape (string, 422 list, or `{code, message}` object); 500 bodies
// carry `crash_id`. Older servers send only `detail`. `ApiError` reads both, and fetch failures
// (network, timeout, abort) become the front-end-only codes. `error.message` is always Korean —
// never the browser's own English fetch error or an English server literal such as "Not Found".
//
// Sentences and hints mirror `docs/api-error-codes.md` (generated from
// `rapidtriage/core/error_codes.py`); codes are never renamed, only added.

export type ErrorText = { readonly message: string; readonly hint: string };

/** Front-end-only codes (`network` category of the code table). */
export const NETWORK_UNREACHABLE = "NETWORK_UNREACHABLE";
export const REQUEST_TIMEOUT = "REQUEST_TIMEOUT";
export const REQUEST_ABORTED = "REQUEST_ABORTED";

/** Korean sentence + hint per code the front end may have to fill in itself. */
export const ERROR_TEXT: Readonly<Record<string, ErrorText>> = {
  BAD_REQUEST: { message: "요청 내용이 올바르지 않습니다", hint: "입력값을 확인한 뒤 다시 시도하세요" },
  UNAUTHORIZED: {
    message: "인증 토큰이 없거나 맞지 않습니다",
    hint: "콘솔을 서버가 알려 준 주소로 다시 여세요",
  },
  FORBIDDEN: { message: "이 요청은 허용되지 않습니다", hint: "허용된 주소·경로에서 다시 시도하세요" },
  NOT_FOUND: { message: "요청한 대상을 찾지 못했습니다", hint: "주소나 ID를 확인하세요" },
  METHOD_NOT_ALLOWED: {
    message: "이 주소는 해당 요청 방식(메서드)을 지원하지 않습니다",
    hint: "API 문서에서 허용된 메서드를 확인하세요",
  },
  TIME_BUDGET_EXCEEDED: {
    message: "시간 예산 안에 요청을 마치지 못했습니다",
    hint: "조건을 좁혀 다시 시도하세요",
  },
  CONFLICT: {
    message: "현재 상태와 맞지 않아 요청을 처리하지 못했습니다",
    hint: "상태를 새로 고친 뒤 다시 시도하세요",
  },
  PAYLOAD_TOO_LARGE: {
    message: "대상이 너무 커서 처리하지 않았습니다",
    hint: "더 작은 범위를 고르거나 원본을 직접 내보내세요",
  },
  UNSUPPORTED_MEDIA: {
    message: "지원하지 않는 요청 형식입니다",
    hint: "JSON 본문(application/json)으로 보내세요",
  },
  RANGE_NOT_SATISFIABLE: {
    message: "요청한 위치가 파일 범위를 벗어났습니다",
    hint: "파일 크기 안의 오프셋을 지정하세요",
  },
  VALIDATION_FAILED: {
    message: "입력값 검사를 통과하지 못했습니다",
    hint: "표시된 항목을 고친 뒤 다시 시도하세요",
  },
  TOO_MANY_REQUESTS: { message: "동시에 처리 중인 요청이 너무 많습니다", hint: "잠시 뒤 다시 시도하세요" },
  INTERNAL_ERROR: {
    message: "서버 내부 오류가 발생했습니다",
    hint: "오류 ID(crash_id)를 기록해 관리자에게 알리세요",
  },
  SERVICE_UNAVAILABLE: {
    message: "지금은 이 기능을 쓸 수 없습니다",
    hint: "잠시 뒤 다시 시도하거나 서버 구성(필요한 구성 요소)을 확인하세요",
  },
  [NETWORK_UNREACHABLE]: {
    message: "서버에 연결하지 못했습니다",
    hint: "서버가 실행 중인지 확인한 뒤 다시 시도하세요",
  },
  [REQUEST_TIMEOUT]: { message: "응답 시간이 초과되었습니다", hint: "잠시 뒤 다시 시도하세요" },
  [REQUEST_ABORTED]: { message: "요청이 중단되었습니다", hint: "필요하면 다시 시도하세요" },
};

/** Same table as `STATUS_DEFAULT_CODES` in `rapidtriage/core/error_codes.py` (+ 503 from `errors.py`). */
const STATUS_DEFAULT_CODES: Readonly<Record<number, string>> = {
  400: "BAD_REQUEST",
  401: "UNAUTHORIZED",
  403: "FORBIDDEN",
  404: "NOT_FOUND",
  405: "METHOD_NOT_ALLOWED",
  408: "TIME_BUDGET_EXCEEDED",
  409: "CONFLICT",
  413: "PAYLOAD_TOO_LARGE",
  415: "UNSUPPORTED_MEDIA",
  416: "RANGE_NOT_SATISFIABLE",
  422: "VALIDATION_FAILED",
  429: "TOO_MANY_REQUESTS",
  500: "INTERNAL_ERROR",
  503: "SERVICE_UNAVAILABLE",
};

/** Used when neither the body nor the status names anything better. */
const GENERIC_TEXT: ErrorText = { message: "요청을 처리하지 못했습니다", hint: "잠시 뒤 다시 시도하세요" };

const HANGUL = /[가-힣]/;

/** The code an HTTP status maps to when the body names none (same rule as the server). */
export function defaultCodeForStatus(status: number): string {
  return STATUS_DEFAULT_CODES[status] ?? (status >= 500 ? "INTERNAL_ERROR" : "BAD_REQUEST");
}

function textFor(code: string): ErrorText {
  return ERROR_TEXT[code] ?? GENERIC_TEXT;
}

export type ApiErrorOptions = {
  code?: string;
  hint?: string;
  crashId?: string | null;
  cause?: unknown;
};

/**
 * Every failed request the console makes. `status` is the HTTP status, or 0 when no response
 * arrived (`NETWORK_UNREACHABLE` / `REQUEST_TIMEOUT` / `REQUEST_ABORTED`). `detail` keeps the
 * server's `detail` exactly as sent (old callers read 422 lists from it).
 */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;
  readonly code: string;
  readonly hint: string;
  readonly crashId: string | null;

  constructor(message: string, status: number, detail: unknown, options: ApiErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.code = options.code || (status > 0 ? defaultCodeForStatus(status) : NETWORK_UNREACHABLE);
    this.hint = options.hint ?? textFor(this.code).hint;
    this.crashId = options.crashId ?? null;
  }

  /** The caller cancelled the request (unmount, superseded query): screens should show nothing. */
  get isAbort(): boolean {
    return this.code === REQUEST_ABORTED;
  }
}

/** True for a cancelled request — an `ApiError` with `REQUEST_ABORTED` or a raw `AbortError`. */
export function isAbortError(error: unknown): boolean {
  if (error instanceof ApiError) return error.isAbort;
  return Boolean(error && typeof error === "object" && (error as { name?: unknown }).name === "AbortError");
}

/**
 * True when the message is only the code's generic sentence (the server or this module had nothing
 * more specific) — a screen may then show its own, more precise Korean sentence instead.
 */
export function isGenericMessage(error: ApiError): boolean {
  return error.message === (ERROR_TEXT[error.code] ?? GENERIC_TEXT).message;
}

function stringField(value: unknown, key: string): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "";
  const field = (value as Record<string, unknown>)[key];
  return typeof field === "string" ? field.trim() : "";
}

function korean(text: string): string {
  return text && HANGUL.test(text) ? text : "";
}

/** Korean text carried by an old-style `detail` (string, 422 `[{msg}]` list or `{message}`), or "". */
function koreanFromDetail(detail: unknown): string {
  if (typeof detail === "string") return korean(detail.trim());
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) =>
        item && typeof item === "object" && "msg" in item ? String(item.msg) : String(item ?? ""),
      )
      .map((text) => text.trim())
      .filter(Boolean);
    return korean(messages.join(" · "));
  }
  return korean(stringField(detail, "message"));
}

/**
 * The sentence shown for a `detail` (old servers): the Korean text it carries, else the Korean
 * sentence for `status`. Never "[object Object]", never an English literal.
 */
export function errorMessageFromDetail(detail: unknown, status = 0): string {
  return (
    koreanFromDetail(detail) ||
    (status > 0 ? textFor(defaultCodeForStatus(status)).message : GENERIC_TEXT.message)
  );
}

/**
 * Build the `ApiError` for an error response body (already parsed; `undefined` when the body was
 * not JSON). Order (D.7 / T-008): top-level `message` → `detail.message` → string `detail` →
 * Korean status default. English text never becomes `message`.
 */
export function apiErrorFromBody(status: number, body: unknown): ApiError {
  const envelope =
    body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
  const detail = "detail" in envelope ? envelope.detail : body;
  const code = stringField(envelope, "code") || stringField(detail, "code") || defaultCodeForStatus(status);
  const fallback = ERROR_TEXT[code] ?? textFor(defaultCodeForStatus(status));
  const message = korean(stringField(envelope, "message")) || koreanFromDetail(detail) || fallback.message;
  const hint = korean(stringField(envelope, "hint")) || korean(stringField(detail, "hint")) || fallback.hint;
  const crashId = stringField(envelope, "crash_id") || null;
  return new ApiError(message, status, detail, { code, hint, crashId });
}

/** Read a non-2xx `Response` into an `ApiError` (a non-JSON or unreadable body still yields Korean text). */
export async function apiErrorFromResponse(response: Response): Promise<ApiError> {
  let body: unknown;
  try {
    const text = await response.text();
    body = text.trim() ? JSON.parse(text) : undefined;
  } catch {
    body = undefined;
  }
  return apiErrorFromBody(response.status, body);
}

function errorName(error: unknown): string {
  return error && typeof error === "object" ? String((error as { name?: unknown }).name ?? "") : "";
}

/**
 * Map whatever `fetch` (or reading its body) threw to an `ApiError`: a timeout
 * (`AbortSignal.timeout`, `TimeoutError`) → `REQUEST_TIMEOUT`, a cancelled signal / `AbortError` →
 * `REQUEST_ABORTED`, anything else (the `TypeError` of a refused connection, a dropped body) →
 * `NETWORK_UNREACHABLE`. An `ApiError` passes through unchanged.
 */
export function apiErrorFromFetchFailure(error: unknown, signal?: AbortSignal | null): ApiError {
  if (error instanceof ApiError) return error;
  const reason = signal?.aborted ? signal.reason : undefined;
  let code = NETWORK_UNREACHABLE;
  if (errorName(error) === "TimeoutError" || errorName(reason) === "TimeoutError") code = REQUEST_TIMEOUT;
  else if (signal?.aborted || errorName(error) === "AbortError") code = REQUEST_ABORTED;
  const text = textFor(code);
  return new ApiError(text.message, 0, null, { code, hint: text.hint, cause: error });
}
