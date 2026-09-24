// ES module extracted from app.js — RapidForensic analyst console.

export async function api(path, options = {}) {
  const token = authToken();
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "X-RapidTriage-Token": token } : {}),
      ...(options.headers || {}),
    },
    ...options,
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => ({ detail: response.statusText }));
    const error = new Error(errorMessageFromDetail(detail.detail || detail || response.statusText));
    error.detail = detail.detail || detail;
    error.status = response.status;
    throw error;
  }
  const contentType = response.headers.get("content-type") || "";
  return contentType.includes("application/json") ? response.json() : response.text();
}

export function errorMessageFromDetail(detail) {
  if (typeof detail === "string") return detail;
  if (detail?.message) return detail.message;
  if (detail?.source_path_resolution) {
    const resolution = detail.source_path_resolution;
    return `Source path unresolved after ${resolution.candidate_count || 0} candidate(s).`;
  }
  return String(detail || "Request failed");
}

export function authToken() {
  try {
    return window.localStorage.getItem("rapidtriage.authToken") || "";
  } catch {
    return "";
  }
}

export function setAuthToken(token) {
  try {
    window.localStorage.setItem("rapidtriage.authToken", token);
  } catch {
    // localStorage may be disabled; the console still reports the failure.
  }
}

// First-run handoff: the CLI prints http://host/#token=<token> so the
// analyst does not have to copy anything. Fragments never reach the
// server; read once, persist, and strip it from the address bar.
try {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const handoffToken = fragment.get("token");
  if (handoffToken) {
    setAuthToken(handoffToken);
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
  }
} catch {
  // Non-critical: the token bar remains the manual path.
}
