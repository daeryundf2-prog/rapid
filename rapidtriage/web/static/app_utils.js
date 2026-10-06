// ES module extracted from app.js — RapidForensic analyst console.
import { TAB_LABELS } from "./app_workbench_config.js";

export function metric(label, value) {
  return `<div class="metric"><b>${escapeHtml(value ?? 0)}</b><span>${escapeHtml(label)}</span></div>`;
}

export function setStatus(element, text, className) {
  element.textContent = text;
  element.className = `status-pill ${className}`;
}

export function statusClass(status) {
  if (status === "completed") return "ok";
  if (status === "failed") return "failed";
  return "";
}

export function titleCase(value) {
  return value.slice(0, 1).toUpperCase() + value.slice(1);
}

export function kbd(value) {
  return `<kbd>${escapeHtml(value)}</kbd>`;
}

export function tabLabel(value) {
  return TAB_LABELS[value] || titleCase(value);
}

export function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

export function safeCssToken(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "unknown";
}

export function highlightSnippet(value, keywords) {
  const text = String(value ?? "");
  const needles = (Array.isArray(keywords) ? keywords : [keywords])
    .map((keyword) => String(keyword || "").trim())
    .filter(Boolean)
    .sort((a, b) => b.length - a.length)
    .map(escapeRegExp);
  if (!text || !needles.length) return escapeHtml(text);
  // Match on the raw text, then escape each segment — wrapping escaped text
  // directly could split entities like &amp; and corrupt the output.
  const pattern = new RegExp(`(${needles.join("|")})`, "gi");
  let html = "";
  let cursor = 0;
  for (const hit of text.matchAll(pattern)) {
    html += escapeHtml(text.slice(cursor, hit.index));
    html += `<mark>${escapeHtml(hit[0])}</mark>`;
    cursor = hit.index + hit[0].length;
  }
  return html + escapeHtml(text.slice(cursor));
}

export function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function columnarPagination(columnar) {
  const offset = Number(columnar?.offset || 0);
  const limit = Number(columnar?.limit || 0);
  return {
    offset,
    limit,
    total: Number(columnar?.total_count || 0),
    returned: Number(columnar?.returned_count || 0),
    has_more: !!columnar?.has_more,
    next_offset: columnar?.next_offset ?? null,
    previous_offset:
      columnar?.previous_offset ?? (offset > 0 ? Math.max(0, offset - limit) : null),
  };
}

export function fileName(path) {
  return String(path || "").split(/[\\/]/).filter(Boolean).pop() || String(path || "");
}

export function formatBytes(value) {
  const size = Number(value || 0);
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

export function storageAvailable() {
  try {
    const key = "rapidtriage.storage.check";
    window.localStorage.setItem(key, "1");
    window.localStorage.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

// --- Dev-mode flag (engineering/QC surface gate) -------------------------------
// Diagnostics drawer, smoke checkpoints, commercial-readiness gate, and the
// crash dashboard are engineering surfaces; they stay hidden until the
// operator opts in via the "개발자 도구" toggle or a `?dev` query flag.
// Persistence mirrors the other rapidtriage.* localStorage keys.
const DEV_MODE_STORAGE_KEY = "rapidtriage.devMode";

export function devModeEnabled() {
  let queryFlag = false;
  try {
    queryFlag = new URLSearchParams(window.location.search).has("dev");
  } catch {
    queryFlag = false;
  }
  if (queryFlag) setDevMode(true);
  if (!storageAvailable()) return queryFlag;
  try {
    return window.localStorage.getItem(DEV_MODE_STORAGE_KEY) === "1" || queryFlag;
  } catch {
    return queryFlag;
  }
}

export function setDevMode(enabled) {
  if (!storageAvailable()) return;
  try {
    if (enabled) {
      window.localStorage.setItem(DEV_MODE_STORAGE_KEY, "1");
    } else {
      window.localStorage.removeItem(DEV_MODE_STORAGE_KEY);
    }
  } catch {
    // Dev-mode persistence is a convenience only; the toggle still re-renders.
  }
}
