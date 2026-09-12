// Session, search-draft, and virtualized-window persistence for the
// RapidForensic analyst console. Shared workbench state lives in app.js and is
// read here through live bindings; session restore writes back through
// applySessionSnapshot.
import { WORKBENCH_SESSION_CONTRACT } from "./app_workbench_config.js";
import { escapeHtml, kbd, storageAvailable } from "./app_utils.js";
import {
  SEARCH_HISTORY_PREFIX,
  SEARCH_STORAGE_PREFIX,
  VIRTUAL_TABLE_ROW_LIMIT,
  VIRTUAL_WINDOW_STORAGE_PREFIX,
  VIRTUALIZATION_ASSESSMENT,
  WORKBENCH_SESSION_STORAGE_KEY,
  activeArtifactFilter,
  activeStageId,
  activeStageSubactionId,
  activeTab,
  activeViewGroup,
  applyColumnPreset,
  applySessionSnapshot,
  applyWorkbenchFilters,
  bindCaseDbBatchButtons,
  bindCaseDbReportExportButton,
  bindCaseDbReviewButtons,
  bindSearchPresetButtons,
  bindSearchResultButtons,
  currentCaseDbSearchPayload,
  currentSearchPayload,
  currentWorkbenchControls,
  detailPanel,
  groupForTab,
  renderCaseDbSearchResult,
  renderSearchResults,
  selectedRunId,
  virtualWindowOffsets,
} from "./app.js";

export function getWorkbenchSession() {
  if (!storageAvailable()) return {};
  try {
    const payload = JSON.parse(window.localStorage.getItem(WORKBENCH_SESSION_STORAGE_KEY) || "{}");
    return payload && typeof payload === "object" ? payload : {};
  } catch {
    return {};
  }
}

export function persistWorkbenchSession(extra = {}) {
  if (!storageAvailable()) return;
  const payload = {
    profile_version: WORKBENCH_SESSION_CONTRACT.profile_version,
    selectedRunId,
    activeTab,
    activeViewGroup,
    activeArtifactFilter,
    activeStageId,
    activeStageSubactionId,
    tableControls: currentWorkbenchControls(),
    virtualWindowOffsets,
    updated_at: new Date().toISOString(),
    ...extra,
  };
  window.localStorage.setItem(WORKBENCH_SESSION_STORAGE_KEY, JSON.stringify(payload));
}

export function restoreWorkbenchSession() {
  const payload = getWorkbenchSession();
  if (!payload?.selectedRunId) return;
  let selectedRunId = null;
  let activeTab = "summary";
  let activeViewGroup = "triage";
  let activeArtifactFilter = "";
  let activeStageId = "";
  let activeStageSubactionId = "";
  selectedRunId = payload.selectedRunId;
  activeTab = payload.activeTab || "summary";
  activeViewGroup = payload.activeViewGroup || groupForTab(activeTab);
  activeArtifactFilter = payload.activeArtifactFilter || "";
  activeStageId = payload.activeStageId || "";
  activeStageSubactionId = payload.activeStageSubactionId || "";
  applySessionSnapshot({
    selectedRunId,
    activeTab,
    activeViewGroup,
    activeArtifactFilter,
    activeStageId,
    activeStageSubactionId,
  });
}

export function restoreWorkbenchControls() {
  const controls = getWorkbenchSession().tableControls || {};
  const mapping = [
    ["#tableFilter", controls.visible_filter],
    ["#sourceFilterInput", controls.source_filter],
    ["#timeFilterInput", controls.time_filter],
  ];
  for (const [selector, value] of mapping) {
    const input = detailPanel.querySelector(selector);
    if (input && value !== undefined) input.value = value || "";
  }
  const preset = controls.column_preset || "analyst";
  const presetInput = detailPanel.querySelector("#columnPresetInput");
  if (presetInput) presetInput.value = preset;
  applyColumnPreset(preset);
  applyWorkbenchFilters();
}

export function virtualizedRows(rows, windowKey = "default") {
  const total = (rows || []).length;
  const offset = virtualWindowOffset(windowKey, total);
  return (rows || []).slice(offset, offset + VIRTUAL_TABLE_ROW_LIMIT);
}

export function virtualWindowStorageKey() {
  return `${VIRTUAL_WINDOW_STORAGE_PREFIX}${selectedRunId || "default"}`;
}

export function loadVirtualWindowOffsets() {
  if (!storageAvailable()) return;
  try {
    const saved = JSON.parse(window.localStorage.getItem(virtualWindowStorageKey()) || "{}");
    for (const [key, value] of Object.entries(saved || {})) {
      virtualWindowOffsets[key] = Math.max(0, Number(value) || 0);
    }
  } catch {
    // Ignore corrupt client-side viewport state; server data remains authoritative.
  }
}

export function persistVirtualWindowOffset(windowKey, offset) {
  if (!storageAvailable()) return;
  try {
    const saved = JSON.parse(window.localStorage.getItem(virtualWindowStorageKey()) || "{}");
    saved[windowKey] = Math.max(0, Number(offset) || 0);
    window.localStorage.setItem(virtualWindowStorageKey(), JSON.stringify(saved));
  } catch {
    // Viewport persistence is a convenience, never a blocker for evidence review.
  }
}

export function virtualWindowOffset(windowKey, total) {
  const rawOffset = Number(virtualWindowOffsets[windowKey] || 0);
  const safeTotal = Math.max(0, Number(total) || 0);
  const maxOffset = Math.max(0, safeTotal - VIRTUAL_TABLE_ROW_LIMIT);
  const clamped = Math.min(Math.max(0, rawOffset), maxOffset);
  virtualWindowOffsets[windowKey] = clamped;
  return clamped;
}

export function renderVirtualizationNotice(rows, visibleRows, label, windowKey = "default") {
  const total = (rows || []).length;
  const visible = (visibleRows || []).length;
  const offset = virtualWindowOffset(windowKey, total);
  const start = total ? offset + 1 : 0;
  const end = offset + visible;
  if (total <= visible) return "";
  return `
    <div class="pagination-bar virtual-window-card" data-commercial-gap="#79">
      <span>Rendering ${start}-${end} of ${total} ${escapeHtml(label)}. The DOM only keeps ${visible} rows mounted for responsiveness.</span>
      <div class="pagination-actions">
        <button class="secondary-button" type="button" data-virtual-window-key="${escapeHtml(windowKey)}" data-virtual-window-offset="${Math.max(0, offset - VIRTUAL_TABLE_ROW_LIMIT)}" ${offset <= 0 ? "disabled" : ""}>${kbd("[")} Previous window</button>
        <button class="secondary-button" type="button" data-virtual-window-key="${escapeHtml(windowKey)}" data-virtual-window-offset="${Math.min(Math.max(0, total - VIRTUAL_TABLE_ROW_LIMIT), offset + VIRTUAL_TABLE_ROW_LIMIT)}" ${end >= total ? "disabled" : ""}>Next window ${kbd("]")}</button>
      </div>
      ${renderVirtualWindowJumpControl(windowKey, total, offset, label)}
      <small>${escapeHtml(VIRTUALIZATION_ASSESSMENT.status)} · max ${VIRTUALIZATION_ASSESSMENT.row_limit} rows · ${escapeHtml(VIRTUALIZATION_ASSESSMENT.commercial_gap_ids.join(","))}</small>
    </div>
  `;
}

export function renderVirtualWindowJumpControl(windowKey, total, offset, label) {
  return `
    <form class="virtual-window-jump" data-virtual-window-jump-key="${escapeHtml(windowKey)}" data-virtual-window-total="${total}">
      <label>
        Jump to row
        <input type="number" min="1" max="${total}" value="${Math.min(total, offset + 1)}" inputmode="numeric" aria-label="Jump to ${escapeHtml(label)} row" />
      </label>
      <button class="mini-inline-button" type="submit">Go</button>
    </form>
  `;
}

export function bindVirtualWindowButtons() {
  for (const button of detailPanel.querySelectorAll("[data-virtual-window-key]")) {
    if (button.dataset.virtualWindowBound) continue;
    button.dataset.virtualWindowBound = "1";
    button.addEventListener("click", () => {
      setVirtualWindowOffset(button.dataset.virtualWindowKey, Number(button.dataset.virtualWindowOffset || 0));
    });
  }
  for (const form of detailPanel.querySelectorAll("[data-virtual-window-jump-key]")) {
    if (form.dataset.virtualWindowBound) continue;
    form.dataset.virtualWindowBound = "1";
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const input = form.querySelector("input");
      const total = Number(form.dataset.virtualWindowTotal || 0);
      const requestedRow = Math.max(1, Math.min(total || 1, Number(input?.value || 1)));
      const alignedOffset = Math.floor((requestedRow - 1) / VIRTUAL_TABLE_ROW_LIMIT) * VIRTUAL_TABLE_ROW_LIMIT;
      setVirtualWindowOffset(form.dataset.virtualWindowJumpKey, alignedOffset);
    });
  }
}

export function setVirtualWindowOffset(windowKey, offset) {
  virtualWindowOffsets[windowKey] = Math.max(0, Number(offset) || 0);
  persistVirtualWindowOffset(windowKey, virtualWindowOffsets[windowKey]);
  if (windowKey === "search" && currentSearchPayload) {
    const pane = detailPanel.querySelector(".search-results-pane");
    if (pane) {
      pane.innerHTML = renderSearchResults(currentSearchPayload, currentSearchPayload.matches || []);
      bindSearchResultButtons();
      bindSearchPresetButtons(detailPanel.querySelector("#unifiedSearchForm"));
      bindVirtualWindowButtons();
    }
  }
  if (windowKey === "caseDb" && currentCaseDbSearchPayload) {
    const output = detailPanel.querySelector("#caseDbResult");
    if (output) {
      output.innerHTML = renderCaseDbSearchResult(currentCaseDbSearchPayload);
      const importForm = detailPanel.querySelector("#caseDbImportForm");
      const database = importForm?.elements.database?.value || "";
      const caseId = importForm?.elements.case_id?.value || "";
      if (database && caseId) {
        bindCaseDbReviewButtons(database, caseId);
        bindCaseDbBatchButtons(database, caseId);
        bindCaseDbReportExportButton(database, caseId);
      }
      bindVirtualWindowButtons();
    }
  }
}

export function searchStorageKey() {
  return `${SEARCH_STORAGE_PREFIX}${selectedRunId || "default"}`;
}

export function searchHistoryStorageKey() {
  return `${SEARCH_HISTORY_PREFIX}${selectedRunId || "default"}`;
}

export function caseDbHistoryStorageKey() {
  return `${SEARCH_HISTORY_PREFIX}caseDb.${selectedRunId || "default"}`;
}

export function getSearchDraft() {
  const defaults = {
    keywords: [],
    ocr: true,
    source: "",
    extension: "",
    path_contains: "",
    search_mode: "exact",
    fuzzy_distance: 1,
    proximity_window: 0,
    hide_known_good: false,
    keyword_packs: [],
  };
  if (!storageAvailable()) return defaults;
  try {
    const payload = JSON.parse(window.localStorage.getItem(searchStorageKey()) || "{}");
    return {
      ...defaults,
      ...payload,
      keywords: Array.isArray(payload.keywords) ? payload.keywords.map(String).filter(Boolean) : [],
      keyword_packs: Array.isArray(payload.keyword_packs) ? payload.keyword_packs.map(String).filter(Boolean) : [],
      hide_known_good: Boolean(payload.hide_known_good),
    };
  } catch {
    return defaults;
  }
}

export function setSearchDraft(payload) {
  if (!storageAvailable()) return;
  try {
    window.localStorage.setItem(searchStorageKey(), JSON.stringify(payload || {}));
  } catch {
    // Search drafts are convenience state only; failure should not block review.
  }
}

export function getSearchHistory() {
  if (!storageAvailable()) return [];
  try {
    const payload = JSON.parse(window.localStorage.getItem(searchHistoryStorageKey()) || "[]");
    return Array.isArray(payload) ? payload : [];
  } catch {
    return [];
  }
}

export function rememberSearchKeywords(entry) {
  if (!storageAvailable()) return;
  const keywords = Array.isArray(entry?.keywords) ? entry.keywords.map(String).filter(Boolean) : [];
  if (!keywords.length) return;
  const key = keywords.join("\u0000").toLowerCase();
  const history = getSearchHistory().filter((item) => {
    const itemKey = (item.keywords || []).join("\u0000").toLowerCase();
    return itemKey !== key;
  });
  history.unshift({
    keywords,
    source: entry.source || "",
    extension: entry.extension || "",
    path_contains: entry.path_contains || "",
    saved_at: new Date().toISOString(),
  });
  try {
    window.localStorage.setItem(searchHistoryStorageKey(), JSON.stringify(history.slice(0, 12)));
  } catch {
    // Recent search chips are optional UI state.
  }
}

export function getCaseDbKeywordHistory() {
  if (!storageAvailable()) return [];
  try {
    const payload = JSON.parse(window.localStorage.getItem(caseDbHistoryStorageKey()) || "[]");
    return Array.isArray(payload) ? payload.filter((item) => Array.isArray(item.keywords)) : [];
  } catch {
    return [];
  }
}

export function rememberCaseDbKeywords(entry) {
  if (!storageAvailable()) return;
  const normalized = {
    keywords: (entry.keywords || []).map(String).filter(Boolean),
    source: (entry.sources || [])[0] || "",
    review_status: entry.review_status || "",
    verification_status: entry.verification_status || "",
    updated_at: new Date().toISOString(),
  };
  const signature = JSON.stringify({
    keywords: normalized.keywords.map((item) => item.toLowerCase()),
    source: normalized.source,
    review_status: normalized.review_status,
    verification_status: normalized.verification_status,
  });
  const history = getCaseDbKeywordHistory().filter((item) => {
    const itemSignature = JSON.stringify({
      keywords: (item.keywords || []).map((keyword) => String(keyword).toLowerCase()),
      source: item.source || "",
      review_status: item.review_status || "",
      verification_status: item.verification_status || "",
    });
    return itemSignature !== signature;
  });
  window.localStorage.setItem(caseDbHistoryStorageKey(), JSON.stringify([normalized, ...history].slice(0, 12)));
}
