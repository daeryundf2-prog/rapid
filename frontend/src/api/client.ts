// Token + fetch plumbing shared by every endpoint wrapper.
//
// Token sources, in priority order:
//   1. `#token=` URL fragment (server prints a launch URL) — moved into
//      sessionStorage and stripped from the address bar immediately.
//   2. sessionStorage (this session's token).
//   3. localStorage `rapidtriage.authToken` (v1 console compatibility — the
//      classic UI stores the token there, so a returning analyst stays signed
//      in when opening /v2).

const TOKEN_KEY = "rapidtriage.authToken";

export class ApiError extends Error {
  readonly status: number;
  readonly detail: unknown;

  constructor(message: string, status: number, detail: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export function captureFragmentToken(
  hash: string = window.location.hash,
  apply: (token: string) => void = setAuthToken,
  strip: () => void = stripFragment,
): boolean {
  const match = hash.match(/[#&]token=([^&]+)/);
  if (!match?.[1]) return false;
  apply(decodeURIComponent(match[1]));
  strip();
  return true;
}

function stripFragment(): void {
  window.history.replaceState(null, "", window.location.pathname + window.location.search);
}

export function authToken(): string {
  try {
    return window.sessionStorage.getItem(TOKEN_KEY) || window.localStorage.getItem(TOKEN_KEY) || "";
  } catch {
    return "";
  }
}

export function setAuthToken(token: string): void {
  try {
    window.sessionStorage.setItem(TOKEN_KEY, token);
  } catch {
    // Storage may be disabled; the caller still sees 401s and can re-enter it.
  }
}

export function clearAuthToken(): void {
  try {
    window.sessionStorage.removeItem(TOKEN_KEY);
    window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    // Ignore storage failures.
  }
}

export function errorMessageFromDetail(detail: unknown): string {
  if (typeof detail === "string") return detail;
  // FastAPI validation errors (422): a list of {msg} — show the messages, never "[object Object]".
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => (item && typeof item === "object" && "msg" in item ? String(item.msg) : String(item)))
      .filter(Boolean);
    if (messages.length) return messages.join(" · ");
  }
  if (detail && typeof detail === "object" && "message" in detail) {
    const message = (detail as { message?: unknown }).message;
    if (typeof message === "string") return message;
  }
  return String(detail || "Request failed");
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = authToken();
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "X-RapidTriage-Token": token } : {}),
      ...(options.headers || {}),
    },
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({ detail: response.statusText }));
    const raw = (detail as { detail?: unknown }).detail ?? detail;
    throw new ApiError(errorMessageFromDetail(raw), response.status, raw);
  }
  const contentType = response.headers.get("content-type") || "";
  return (contentType.includes("application/json") ? response.json() : response.text()) as Promise<T>;
}

/**
 * Authenticated raw fetch for binary/streamed bodies (the token rides only in
 * a header, so `<a href>`/`<img src>` cannot load originals). Non-2xx → ApiError.
 */
export async function apiResponse(path: string, init: { signal?: AbortSignal } = {}): Promise<Response> {
  const token = authToken();
  const response = await fetch(path, {
    headers: token ? { "X-RapidTriage-Token": token } : {},
    signal: init.signal,
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({ detail: response.statusText }));
    const raw = (detail as { detail?: unknown }).detail ?? detail;
    throw new ApiError(errorMessageFromDetail(raw), response.status, raw);
  }
  return response;
}

/** Characters a Windows client cannot put in a file name (the console is used remotely from Windows). */
const UNSAFE_IN_FILENAME = /[\\/:*?"<>|]/g;

/**
 * Download name from a Content-Disposition header. Starlette sends a non-ASCII name only as
 * RFC 5987 `filename*=utf-8''…`, so a Korean or spaced name must be read from there first; the
 * quoted `filename=` form is the ASCII fallback.
 */
export function downloadNameFromDisposition(disposition: string, fallbackName: string): string {
  const extended = disposition.match(/filename\*\s*=\s*[^']*'[^']*'([^;]+)/i);
  const plain = disposition.match(/filename\s*=\s*(?:"([^"]*)"|([^";]+))/i);
  const raw = (extended?.[1] ?? plain?.[1] ?? plain?.[2] ?? "").trim();
  if (!raw) return fallbackName;
  let name = raw;
  try {
    name = decodeURIComponent(raw);
  } catch {
    name = raw;
  }
  const printable = [...name].filter((character) => (character.codePointAt(0) ?? 0) >= 0x20).join("");
  // `/` and `\` are already replaced, so "../x" cannot traverse; a name of only dots is the
  // remaining bad case. A leading dot is kept: ".bash_history" must save under its own name.
  const safe = printable.replace(UNSAFE_IN_FILENAME, "_").trim();
  if (/^\.+$/.test(safe)) return fallbackName;
  return safe || fallbackName;
}

/** Fetch an authenticated file (the token header cannot ride on a plain link) and hand it to the browser as a download. */
export async function downloadFile(path: string, fallbackName: string): Promise<string> {
  const response = await apiResponse(path);
  const disposition = response.headers.get("content-disposition") || "";
  const filename = downloadNameFromDisposition(disposition, fallbackName);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  return filename;
}
