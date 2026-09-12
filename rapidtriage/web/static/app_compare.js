// ES module extracted from app.js — RapidForensic analyst console.
import { api } from "./app_api.js";
import { escapeHtml, fileName, storageAvailable } from "./app_utils.js";
import {
  COMPARE_LIMIT,
  COMPARE_STORAGE_PREFIX,
  activeTab,
  bindCopyButtons,
  detailPanel,
  loadEvidencePreview,
  renderCompareCitationBundle,
  selectedRunId,
  switchTab,
} from "./app.js";

export function compareItemFromFileSearchMatch(payload, match) {
  return {
    path: payload.path || match.source_path || "",
    title: match.citation || `${payload.name || "source"} hit`,
    source: "source-search",
    kind: payload.mime_type || payload.extension || "",
    preview: match.compare_preview || match.snippet || "",
    pointer: match.pointer || "",
  };
}

export function compareButton(item) {
  if (!item?.path) return "";
  return `<button class="icon-action" type="button" title="비교 트레이에 고정" data-compare-item="${escapeHtml(JSON.stringify(item))}">비교</button>`;
}

export function compareItemFromMatch(match, context = null) {
  return {
    path: match.path || "",
    title: match.title || fileName(match.path) || "search hit",
    source: match.source || context?.source || activeTab,
    kind: match.kind || "",
    preview: match.preview || context?.note || "",
    pointer: context?.pointer || match.pointer || "",
  };
}

export function compareItemFromPreview(payload, reviewContext = null) {
  const previewText = payload.text
    ? `${payload.text.slice(0, 1200)}${payload.truncated || payload.text.length > 1200 ? "\n..." : ""}`
    : payload.preview_type === "image"
      ? "이미지 증거를 비교함에 고정했습니다. 미리보기로 원본 이미지를 다시 열 수 있습니다."
      : payload.message || "";
  return {
    path: payload.path || "",
    title: payload.name || fileName(payload.path) || "evidence",
    source: reviewContext?.source || activeTab,
    kind: payload.mime_type || payload.preview_type || "",
    preview: previewText,
    pointer: reviewContext?.pointer || "",
  };
}

export function compareItemFromBookmark(bookmark) {
  const snapshot = bookmark.snapshot || {};
  const reference = bookmark.reference || {};
  const review = bookmark.review || {};
  return {
    path: snapshot.path || "",
    title: bookmark.summary || fileName(snapshot.path) || bookmark.bookmark_id || "reviewed evidence",
    source: reference.command || "review",
    kind: review.status || "",
    preview: bookmark.note || "",
    pointer: reference.pointer || "",
  };
}

export function compareStorageKey() {
  return `${COMPARE_STORAGE_PREFIX}${selectedRunId || "default"}`;
}

export function getCompareItems() {
  if (!storageAvailable()) return [];
  try {
    const payload = JSON.parse(window.localStorage.getItem(compareStorageKey()) || "[]");
    return Array.isArray(payload) ? payload.filter((item) => item?.path).slice(0, COMPARE_LIMIT) : [];
  } catch {
    return [];
  }
}

export function setCompareItems(items) {
  if (!storageAvailable()) return;
  window.localStorage.setItem(compareStorageKey(), JSON.stringify(items.slice(0, COMPARE_LIMIT)));
}

export function addCompareItem(item) {
  if (!item?.path) return;
  const nextItem = { ...item, added_at: new Date().toISOString() };
  const existing = getCompareItems().filter((candidate) => candidate.path !== item.path);
  setCompareItems([nextItem, ...existing].slice(0, COMPARE_LIMIT));
  refreshCompareTray();
}

export function removeCompareItem(path) {
  setCompareItems(getCompareItems().filter((item) => item.path !== path));
  refreshCompareTray();
}

export function clearCompareItems() {
  setCompareItems([]);
  refreshCompareTray();
}

export function renderCompareTray() {
  const items = getCompareItems();
  const primary = items.slice(0, 2);
  return `
    <section id="compareTray" class="compare-tray ${items.length ? "" : "empty"}" aria-label="증거 비교 보관함">
      <div class="compare-heading">
        <div>
          <p class="eyebrow">비교 보관함</p>
          <h3>증거 A/B 비교</h3>
        </div>
        <div class="detail-actions">
          <span class="status-pill">${items.length}/${COMPARE_LIMIT}</span>
          <button class="secondary-button" type="button" data-open-compare-diff ${items.length >= 2 ? "" : "disabled"}>원문 차이 보기</button>
          <button class="secondary-button" type="button" data-clear-compare ${items.length ? "" : "disabled"}>비우기</button>
        </div>
      </div>
      ${items.length ? renderCompareItems(primary, items.slice(2)) : '<p class="empty-state">검색 결과나 원본 뷰어에서 “비교함에 추가”를 누르면 탭을 오가도 자료가 여기 남습니다.</p>'}
      ${items.length ? renderCompareCitationBundle(items) : ""}
      <section id="compareDiffPanel"></section>
    </section>
  `;
}

export function renderCompareItems(primaryItems, overflowItems) {
  return `
    <div class="compare-grid">
      ${[0, 1].map((index) => renderCompareSlot(primaryItems[index], index)).join("")}
    </div>
    ${overflowItems.length ? `
      <div class="compare-overflow">
        ${overflowItems.map((item) => `
          <button class="compare-chip" type="button" data-preview-compare-path="${escapeHtml(item.path)}" title="${escapeHtml(item.path)}">
            ${escapeHtml(item.title || fileName(item.path))}
          </button>
        `).join("")}
      </div>
    ` : ""}
  `;
}

export function renderCompareSlot(item, index) {
  const label = index === 0 ? "A" : "B";
  if (!item) {
    return `
      <article class="compare-slot placeholder">
        <strong>${label}</strong>
        <p>비교할 자료를 하나 더 고정하세요.</p>
      </article>
    `;
  }
  return `
    <article class="compare-slot">
      <div class="compare-slot-top">
        <strong>${label}</strong>
        <button class="icon-action" type="button" data-remove-compare-path="${escapeHtml(item.path)}">제거</button>
      </div>
      <h4>${escapeHtml(item.title || fileName(item.path))}</h4>
      <div class="viewer-meta">
        <span>${escapeHtml(item.source || "source")}</span>
        <span>${escapeHtml(item.kind || "")}</span>
      </div>
      <p>${escapeHtml(item.preview || item.path)}</p>
      <div class="review-actions">
        <button class="secondary-button" type="button" data-preview-compare-path="${escapeHtml(item.path)}">미리보기 ${label}</button>
        <button class="icon-action" type="button" data-copy-path="${escapeHtml(item.path)}">경로 복사</button>
      </div>
    </article>
  `;
}

export function refreshCompareTray() {
  const tray = detailPanel.querySelector("#compareTray");
  if (!tray) return;
  tray.outerHTML = renderCompareTray();
  bindCompareActions();
}

export function bindCompareActions() {
  bindCopyButtons();
  for (const button of detailPanel.querySelectorAll("[data-compare-item]")) {
    if (button.dataset.compareBound) continue;
    button.dataset.compareBound = "1";
    button.addEventListener("click", () => {
      const item = parseCompareItem(button.dataset.compareItem);
      addCompareItem(item);
      button.textContent = "추가됨";
    });
  }
  const clearButton = detailPanel.querySelector("[data-clear-compare]");
  if (clearButton && !clearButton.dataset.compareBound) {
    clearButton.dataset.compareBound = "1";
    clearButton.addEventListener("click", clearCompareItems);
  }
  const diffButton = detailPanel.querySelector("[data-open-compare-diff]");
  if (diffButton && !diffButton.dataset.compareBound) {
    diffButton.dataset.compareBound = "1";
    diffButton.addEventListener("click", openCompareDiff);
  }
  for (const button of detailPanel.querySelectorAll("[data-remove-compare-path]")) {
    if (button.dataset.compareBound) continue;
    button.dataset.compareBound = "1";
    button.addEventListener("click", () => removeCompareItem(button.dataset.removeComparePath));
  }
  for (const button of detailPanel.querySelectorAll("[data-preview-compare-path]")) {
    if (button.dataset.compareBound) continue;
    button.dataset.compareBound = "1";
    button.addEventListener("click", async () => {
      await previewCompareItem(button.dataset.previewComparePath);
    });
  }
}

export async function openCompareDiff() {
  const panel = detailPanel.querySelector("#compareDiffPanel");
  const [left, right] = getCompareItems();
  if (!panel || !left?.path || !right?.path) return;
  panel.innerHTML = '<p class="empty-state">A/B 원문 미리보기를 불러오고 있습니다.</p>';
  try {
    const [leftPayload, rightPayload] = await Promise.all([
      api(`/api/runs/${selectedRunId}/source-preview?path=${encodeURIComponent(left.path)}`),
      api(`/api/runs/${selectedRunId}/source-preview?path=${encodeURIComponent(right.path)}`),
    ]);
    panel.innerHTML = renderCompareDiff(leftPayload, rightPayload);
  } catch (error) {
    panel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  }
}

export function renderCompareDiff(left, right) {
  if (left.preview_type !== "text" || right.preview_type !== "text") {
    return '<p class="empty-state">원문 차이 보기는 두 항목 모두 텍스트 미리보기가 있을 때 사용할 수 있습니다.</p>';
  }
  const leftLines = String(left.text || "").split(/\r?\n/);
  const rightLines = String(right.text || "").split(/\r?\n/);
  const leftSet = new Set(leftLines);
  const rightSet = new Set(rightLines);
  const onlyLeft = leftLines.filter((line) => line.trim() && !rightSet.has(line)).slice(0, 80);
  const onlyRight = rightLines.filter((line) => line.trim() && !leftSet.has(line)).slice(0, 80);
  return `
    <section class="compare-diff">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">text diff</p>
          <h3>${escapeHtml(left.name)} vs ${escapeHtml(right.name)}</h3>
        </div>
        <span class="status-pill">${onlyLeft.length + onlyRight.length} differences</span>
      </div>
      <div class="compare-grid">
        <article class="compare-slot">
          <strong>Only in A</strong>
          <pre class="viewer-text">${escapeHtml(onlyLeft.join("\n") || "No unique text in first preview.")}</pre>
        </article>
        <article class="compare-slot">
          <strong>Only in B</strong>
          <pre class="viewer-text">${escapeHtml(onlyRight.join("\n") || "No unique text in second preview.")}</pre>
        </article>
      </div>
    </section>
  `;
}

export function parseCompareItem(value) {
  if (!value) return null;
  try {
    const item = JSON.parse(value);
    return item && typeof item === "object" ? item : null;
  } catch {
    return null;
  }
}

export async function previewCompareItem(path) {
  if (!path) return;
  if (!detailPanel.querySelector("#evidenceViewer")) {
    await switchTab("search");
  }
  await loadEvidencePreview(path);
}
