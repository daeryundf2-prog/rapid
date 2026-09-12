// ES module extracted from app.js — RapidForensic analyst console.
import { TAB_LABELS } from "./app_workbench_config.js";

export function metric(label, value) {
  return `<div class="metric"><b>${value ?? 0}</b><span>${escapeHtml(label)}</span></div>`;
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
  let html = escapeHtml(value);
  for (const keyword of keywords) {
    const needle = String(keyword || "").trim();
    if (!needle) continue;
    html = html.replace(new RegExp(`(${escapeRegExp(escapeHtml(needle))})`, "gi"), "<mark>$1</mark>");
  }
  return html;
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
