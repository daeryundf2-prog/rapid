// ArtifactGrid screen module (R3-2). Flattens grouped artifact payloads into a
// virtualized row stream and renders validation summaries. Dependencies are
// injected once via initArtifactGrid; page-fetch state lives in this module.

import { escapeHtml, formatNumber, kbd } from "./app_utils.js";

let artifactActionButtons, artifactPreviewText, artifactSourceCategory,
  compactRowFilterText, getActiveArtifactFilter, getDetailPanel,
  getSelectedRunId, queueVirtualTable, renderArtifactDetails,
  renderArtifactValidationBadges, renderPaginationControls, rowInspectorAttributes,
  rowText, api, PAGE_SIZE;

export function initArtifactGrid(deps) {
  ({
    api, artifactActionButtons, artifactPreviewText, artifactSourceCategory,
    compactRowFilterText, getActiveArtifactFilter, getDetailPanel,
    getSelectedRunId, queueVirtualTable, renderArtifactDetails,
    renderArtifactValidationBadges, renderPaginationControls,
    rowInspectorAttributes, rowText,
    PAGE_SIZE,
  } = deps);
}

let artifactsPagePagination = null;
let extraArtifactRows = [];
let extraArtifactRowsRunId = null;
let extraNextOffset; // undefined = first page only, null = exhausted

export async function loadMoreArtifactRows() {
  if (artifactsPageLoading || artifactsPagePagination?.next_offset == null) return 0;
  const selectedRunId = getSelectedRunId();
  artifactsPageLoading = true;
  const nextOffset = artifactsPagePagination.next_offset;
  try {
    const payload = await api(`/api/runs/${encodeURIComponent(selectedRunId)}/artifacts?offset=${nextOffset}&limit=${PAGE_SIZE}`);
    const rows = flattenArtifactRows(payload.artifacts || {});
    extraArtifactRows = extraArtifactRows.concat(rows);
    extraNextOffset = artifactGroupNextOffset(payload.artifacts || {});
    artifactsPagePagination = { ...artifactsPagePagination, next_offset: extraNextOffset };
    return rows.length;
  } catch {
    extraNextOffset = null;
    artifactsPagePagination = { ...artifactsPagePagination, next_offset: null };
    return 0;
  } finally {
    artifactsPageLoading = false;
  }
}
let artifactsPageLoading = false;
let activeArtifactType = "";

export function setActiveArtifactType(value) {
  activeArtifactType = String(value || "");
}

export function getActiveArtifactType() {
  return activeArtifactType;
}

const TYPE_GRID_ROW_LIMIT = 400;
const TYPE_GRID_COLUMN_LIMIT = 6;
const TYPE_GRID_SKIP_DETAIL_KEYS = new Set([
  "parser", "parser_version", "source_path", "source_format",
]);

function artifactRowType(kind, artifact) {
  return String(artifact?.artifact_type || kind || "unknown");
}

function detailScalarValue(value) {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return value;
  }
  return undefined;
}

function flattenDetailFields(details, prefix = "", depth = 0, out = {}) {
  if (!details || typeof details !== "object") return out;
  for (const [key, value] of Object.entries(details)) {
    const flatKey = prefix ? `${prefix}.${key}` : key;
    const scalar = detailScalarValue(value);
    if (scalar !== undefined) {
      out[flatKey] = scalar;
      continue;
    }
    if (depth < 2 && value && typeof value === "object" && !Array.isArray(value)) {
      flattenDetailFields(value, flatKey, depth + 1, out);
    }
  }
  return out;
}

function pickTypeGridColumns(rows) {
  const stats = new Map();
  for (const { artifact } of rows) {
    const flat = flattenDetailFields(artifact?.details);
    for (const [key, value] of Object.entries(flat)) {
      const root = key.split(".", 1)[0];
      if (TYPE_GRID_SKIP_DETAIL_KEYS.has(root)) continue;
      let entry = stats.get(key);
      if (!entry) {
        entry = { count: 0, values: new Set() };
        stats.set(key, entry);
      }
      entry.count += 1;
      if (entry.values.size < 8) entry.values.add(String(value));
    }
  }
  return [...stats.entries()]
    .sort((a, b) => {
      const distinctA = a[1].values.size > 1 ? 1 : 0;
      const distinctB = b[1].values.size > 1 ? 1 : 0;
      if (distinctA !== distinctB) return distinctB - distinctA;
      if (a[1].count !== b[1].count) return b[1].count - a[1].count;
      return a[0].localeCompare(b[0]);
    })
    .slice(0, TYPE_GRID_COLUMN_LIMIT)
    .map(([key]) => key);
}

function artifactRowLabel(kind, artifact) {
  const details = artifact?.details || {};
  return artifact?.path || details.entry_name || details.source_path || artifact?.title || kind;
}

function artifactRowAttributes(kind, index, artifact) {
  const sourceCategory = artifactSourceCategory(kind, artifact);
  const context = { source: `artifacts:${kind}`, pointer: `/${kind}/${index}`, title: artifact.artifact_type || kind, note: artifactPreviewText(artifact), path: artifact.path || "", tags: ["artifact", kind, artifact.artifact_type].filter(Boolean) };
  const inspector = {
    title: artifactPreviewText(artifact),
    source: kind,
    kind: artifact.artifact_type || "artifact",
    provider: artifact.provider || "",
    timestamp: artifact.timestamp || artifact.last_write_time || "",
    path: artifact.path || "",
    pointer: context.pointer,
    preview: artifactPreviewText(artifact),
    chips: ["artifact", kind, artifact.artifact_type, artifact.provider].filter(Boolean),
    reviewContext: context,
  };
  return `class="selectable-result-row" data-source-category="${escapeHtml(sourceCategory)}" data-filter="${rowText({ kind, ...artifact })}" ${rowInspectorAttributes(inspector)} ${artifact.path ? `data-viewer-row-path="${escapeHtml(artifact.path)}" data-review-context="${escapeHtml(JSON.stringify(context))}"` : ""}`;
}

const TYPE_GRID_TIMESTAMP_KEYS = [
  "timestamp", "last_write_time", "mtime", "created", "modified", "datetime",
];

function artifactRowTimestamp(artifact, flat) {
  const top = artifact?.timestamp || artifact?.last_write_time;
  if (top) return top;
  for (const key of TYPE_GRID_TIMESTAMP_KEYS) {
    if (flat[key]) return flat[key];
    const match = Object.keys(flat).find((k) => k.endsWith(`.${key}`));
    if (match) return flat[match];
  }
  return "";
}

function renderTypeDataGrid(rows, type) {
  const capped = rows.slice(0, TYPE_GRID_ROW_LIMIT);
  const flats = capped.map(({ artifact }) => flattenDetailFields(artifact?.details));
  const hasTimestamp = capped.some((_, i) => artifactRowTimestamp(capped[i].artifact, flats[i]));
  const order = capped.map((_, i) => i);
  if (hasTimestamp) {
    const stamp = (i) => {
      const raw = artifactRowTimestamp(capped[i].artifact, flats[i]);
      const parsed = Date.parse(String(raw));
      return Number.isNaN(parsed) ? Number.NEGATIVE_INFINITY : parsed;
    };
    order.sort((a, b) => stamp(b) - stamp(a));
  }
  const shown = order.map((i) => capped[i]);
  const sortedFlats = order.map((i) => flats[i]);
  const extraColumns = pickTypeGridColumns(shown).filter((key) => {
    if (!hasTimestamp) return true;
    return !TYPE_GRID_TIMESTAMP_KEYS.includes(key.split(".").pop());
  });
  const header = ["대상", ...(hasTimestamp ? ["시각"] : []), ...extraColumns, "경로", "검토"];
  const body = shown.map(({ kind, index, artifact }, i) => {
    const details = artifact?.details || {};
    const flat = sortedFlats[i];
    return `
      <tr ${artifactRowAttributes(kind, index, artifact)}>
        <td><strong>${escapeHtml(fileLabel(artifactRowLabel(kind, artifact)))}</strong></td>
        ${hasTimestamp ? `<td class="num">${escapeHtml(artifactRowTimestamp(artifact, flat))}</td>` : ""}
        ${extraColumns.map((key) => `<td>${escapeHtml(flat[key] ?? "")}</td>`).join("")}
        <td class="path-cell"><code>${escapeHtml(artifact?.path || details.source_path || "")}</code></td>
        <td class="action-stack">${artifactActionButtons(kind, index, artifact)}</td>
      </tr>
    `;
  }).join("");
  const overflow = rows.length > shown.length
    ? `<p class="help-text">상위 ${formatNumber(shown.length)}행만 표시 — 나머지는 표 필터를 좁히거나 산출물 파일에서 확인하세요.</p>`
    : "";
  return `
    <div class="result-table-scroll artifact-type-grid" role="region" aria-label="${escapeHtml(type)} 데이터 행">
      <table class="data-table result-table">
        <thead><tr>${header.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead>
        <tbody>${body}</tbody>
      </table>
    </div>
    ${overflow}
  `;
}

function fileLabel(path) {
  return String(path || "").split(/[\\/]/).filter(Boolean).pop() || String(path || "");
}

function artifactTypeCounts(rows, groups = {}) {
  const counts = new Map();
  const summarized = new Set();
  for (const [kind, payload] of Object.entries(groups)) {
    const typeCounts = payload?.summary?.artifact_type_counts;
    if (typeCounts && typeof typeCounts === "object") {
      summarized.add(kind);
      for (const [type, count] of Object.entries(typeCounts)) {
        counts.set(type, (counts.get(type) || 0) + Number(count || 0));
      }
    }
  }
  for (const { kind, artifact } of rows) {
    if (summarized.has(kind)) continue;
    const type = artifactRowType(kind, artifact);
    counts.set(type, (counts.get(type) || 0) + 1);
  }
  return counts;
}

function renderTypeChipBar(rows, groups = {}, total = 0) {
  const counts = artifactTypeCounts(rows, groups);
  const types = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (!types.length) return "";
  return `
    <div class="artifact-type-chip-bar" role="group" aria-label="아티팩트 유형별 보기" data-testid="artifact-type-chip-bar">
      <button type="button" class="artifact-type-chip ${activeArtifactType ? "" : "active"}" aria-pressed="${activeArtifactType ? "false" : "true"}" data-artifact-type="">전체 ${formatNumber(total || rows.length)}</button>
      ${types.map(([type, count]) => `
        <button type="button" class="artifact-type-chip ${activeArtifactType === type ? "active" : ""}" aria-pressed="${activeArtifactType === type ? "true" : "false"}" data-artifact-type="${escapeHtml(type)}">${escapeHtml(type)} <b>${formatNumber(count)}</b></button>
      `).join("")}
    </div>
  `;
}

export function filteredPagination(total, collection) {
  return {
    collection,
    offset: 0,
    limit: Math.max(total, 1),
    returned: total,
    total,
    previous_offset: null,
    next_offset: null,
  };
}

export function artifactPaginationSummary(groups, returned) {
  let total = 0;
  let limit = 0;
  let offset = null;
  let previousOffset = null;
  let nextOffset = null;
  for (const artifactPayload of Object.values(groups || {})) {
    const pagination = artifactPayload?.pagination;
    if (!pagination) continue;
    total += Number(pagination.total || 0);
    limit = Math.max(limit, Number(pagination.limit || 0));
    offset = offset === null ? Number(pagination.offset || 0) : Math.min(offset, Number(pagination.offset || 0));
    if (pagination.previous_offset !== null && pagination.previous_offset !== undefined) {
      previousOffset = previousOffset === null ? Number(pagination.previous_offset || 0) : Math.min(previousOffset, Number(pagination.previous_offset || 0));
    }
    if (pagination.next_offset !== null && pagination.next_offset !== undefined) {
      nextOffset = nextOffset === null ? Number(pagination.next_offset || 0) : Math.min(nextOffset, Number(pagination.next_offset || 0));
    }
  }
  if (!limit && !total && !returned) return null;
  return {
    collection: "artifacts",
    offset: offset ?? 0,
    limit: limit || Math.max(returned, 1),
    returned,
    total: total || returned,
    previous_offset: previousOffset,
    next_offset: nextOffset,
  };
}

export function flattenArtifactRows(groups, offsetBase = 0) {
  const rows = [];
  for (const [kind, artifactPayload] of Object.entries(groups || {})) {
    const offset = artifactPayload.pagination?.offset || offsetBase;
    for (const [index, artifact] of (artifactPayload.artifacts || []).entries()) {
      const row = { kind, index: offset + index, artifact };
      row.filterText = compactRowFilterText({ kind, ...artifact });
      row.sourceCategory = artifactSourceCategory(kind, artifact);
      rows.push(row);
    }
  }
  return rows;
}

export function artifactGroupNextOffset(groups) {
  let next = null;
  for (const artifactPayload of Object.values(groups || {})) {
    const candidate = artifactPayload?.pagination?.next_offset;
    if (candidate !== null && candidate !== undefined) {
      next = next === null ? Number(candidate) : Math.min(next, Number(candidate));
    }
  }
  return next;
}

export function artifactGroupTotal(groups) {
  let total = 0;
  for (const artifactPayload of Object.values(groups || {})) {
    total += Number(artifactPayload?.pagination?.total || artifactPayload?.artifacts?.length || 0);
  }
  return total;
}

export function artifactCommercialBlockers(details) {
  const blockers = new Set();
  const candidateLists = [
    details.commercial_grade_blockers,
    details.evtx_commercial_readiness_profile?.blockers,
    details.registry_native_depth_readiness_profile?.blockers,
    details.ntfs_native_depth_readiness_profile?.blockers,
    details.account_privilege_deep_parse_profile?.commercial_grade_blockers,
    details.execution_artifact_validation_profile?.commercial_grade_blockers,
    details.execution_report_grade_assessment?.blockers,
    details.os_account_report_grade_assessment?.blockers,
    details.registry_report_grade_assessment?.blockers,
    details.ntfs_report_grade_assessment?.blockers,
  ];
  for (const list of candidateLists) {
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      if (item) blockers.add(String(item));
    }
  }
  return Array.from(blockers);
}

export function summarizeArtifactValidation(rows) {
  const gapCounts = new Map();
  const blockerCounts = new Map();
  let validationRequired = 0;
  let notCommercialReady = 0;
  let reportable = 0;
  let blockerTotal = 0;
  for (const row of rows) {
    const artifact = row.artifact || {};
    const details = artifact.details || {};
    const gates = Array.isArray(details.core_accuracy_gates) ? details.core_accuracy_gates : [];
    if (details.validation_required || gates.some((gate) => gate.status === "validation-required")) {
      validationRequired += 1;
    }
    if (details.reportability === "reportable") {
      reportable += 1;
    }
    if (details.commercial_grade_ready === false || gates.some((gate) => gate.commercial_grade_ready === false)) {
      notCommercialReady += 1;
    }
    for (const gate of gates) {
      if (gate.gap_id) gapCounts.set(gate.gap_id, (gapCounts.get(gate.gap_id) || 0) + 1);
    }
    for (const blocker of artifactCommercialBlockers(details)) {
      blockerTotal += 1;
      blockerCounts.set(blocker, (blockerCounts.get(blocker) || 0) + 1);
    }
  }
  const byCount = ([leftKey, leftCount], [rightKey, rightCount]) => rightCount - leftCount || String(leftKey).localeCompare(String(rightKey));
  return {
    total: rows.length,
    validationRequired,
    notCommercialReady,
    reportable,
    blockerTotal,
    topGaps: Array.from(gapCounts.entries()).sort(byCount).slice(0, 5),
    topBlockers: Array.from(blockerCounts.entries()).sort(byCount).slice(0, 5),
  };
}

export function renderArtifactValidationSummary(rows) {
  const summary = summarizeArtifactValidation(rows);
  if (!summary.total) return "";
  return `
    <section class="artifact-validation-summary" aria-label="Artifact validation summary" data-testid="artifact-validation-summary">
      <div>
        <p class="eyebrow">artifact validation</p>
        <strong>${escapeHtml(summary.total)} row(s) · ${escapeHtml(summary.validationRequired)} need validation · ${escapeHtml(summary.notCommercialReady)} not commercial-ready</strong>
        <span>${escapeHtml(summary.reportable)} reportable row(s) · ${escapeHtml(summary.blockerTotal)} blocker reference(s)</span>
      </div>
      <div class="artifact-validation-summary-grid">
        <article>
          <strong>Top gaps</strong>
          <span>${escapeHtml(summary.topGaps.map(([gap, count]) => `${gap} ${count}`).join(" · ") || "No gap gates")}</span>
        </article>
        <article>
          <strong>Top blockers</strong>
          <span>${escapeHtml(summary.topBlockers.map(([blocker, count]) => `${blocker} ${count}`).join(" · ") || "No blocker listed")}</span>
        </article>
      </div>
    </section>
  `;
}

export function renderArtifactRow({ kind, index, artifact }) {
  return `
    <tr ${artifactRowAttributes(kind, index, artifact)}>
      <td>${escapeHtml(kind)}</td>
      <td>${escapeHtml(artifact.artifact_type)}</td>
      <td>${escapeHtml(artifact.provider)}</td>
      <td>
        <strong>${escapeHtml(artifactPreviewText(artifact))}</strong>
        ${renderArtifactValidationBadges(artifact)}
        <span>${escapeHtml(artifact.path || "")}</span>
        ${renderArtifactDetails(artifact)}
      </td>
      <td class="action-stack">${artifactActionButtons(kind, index, artifact)}</td>
    </tr>
  `;
}

export function queueArtifactsNextPage(table) {
  const detailPanel = getDetailPanel();
  const selectedRunId = getSelectedRunId();
  if (artifactsPageLoading || artifactsPagePagination?.next_offset == null) return;
  artifactsPageLoading = true;
  const nextOffset = artifactsPagePagination.next_offset;
  const existingCount = table.items.length;
  api(`/api/runs/${encodeURIComponent(selectedRunId)}/artifacts?offset=${nextOffset}&limit=${PAGE_SIZE}`)
    .then((payload) => {
      const rows = flattenArtifactRows(payload.artifacts || {});
      table.appendItems(rows);
      extraArtifactRows = extraArtifactRows.concat(rows);
      extraNextOffset = artifactGroupNextOffset(payload.artifacts || {});
      artifactsPagePagination = {
        ...artifactsPagePagination,
        next_offset: extraNextOffset,
        returned: existingCount + rows.length,
      };
      const notice = detailPanel.querySelector("[data-artifact-virtual-notice]");
      if (notice) {
        notice.textContent = `로드됨 ${formatNumber(table.count)}건 / 전체 ${formatNumber(artifactGroupTotal(payload.artifacts || {}) || table.count)}건 · 스크롤 가상화`;
      }
    })
    .catch(() => {
      extraNextOffset = null;
      artifactsPagePagination = { ...artifactsPagePagination, next_offset: null };
    })
    .finally(() => {
      artifactsPageLoading = false;
    });
}

export function renderArtifacts(payload) {
  const activeArtifactFilter = getActiveArtifactFilter();
  const groups = payload.artifacts || {};
  const runId = getSelectedRunId();
  if (runId !== extraArtifactRowsRunId) {
    extraArtifactRows = [];
    extraArtifactRowsRunId = runId;
    extraNextOffset = undefined;
  }
  const rows = flattenArtifactRows(groups).concat(extraArtifactRows);
  const scopedRows = activeArtifactFilter
    ? rows.filter(({ kind, artifact }) => artifactSourceCategory(kind, artifact) === activeArtifactFilter)
    : rows;
  const pagination = activeArtifactFilter
    ? filteredPagination(scopedRows.length, "artifacts")
    : artifactPaginationSummary(groups, rows.length);
  artifactsPagePagination = activeArtifactFilter
    ? { next_offset: null }
    : { next_offset: extraNextOffset !== undefined ? extraNextOffset : artifactGroupNextOffset(groups) };
  artifactsPageLoading = false;
  const typeChipBar = renderTypeChipBar(scopedRows, activeArtifactFilter ? {} : groups, pagination?.total);
  if (activeArtifactType) {
    const typeRows = scopedRows.filter(({ kind, artifact }) => artifactRowType(kind, artifact) === activeArtifactType);
    const typeCounts = artifactTypeCounts(scopedRows, activeArtifactFilter ? {} : groups);
    const typeTotal = typeCounts.get(activeArtifactType) || typeRows.length;
    if (!typeRows.length) {
      return `${typeChipBar}<p class="empty-state">이 유형의 행이 없습니다.${artifactsPagePagination?.next_offset != null ? ' <button type="button" class="mini-link" data-artifact-load-more>더 불러오기</button>' : ""}</p>`;
    }
    const moreButton = artifactsPagePagination?.next_offset != null && typeRows.length < typeTotal
      ? ` <button type="button" class="mini-link" data-artifact-load-more>다음 페이지 불러오기 (전체 ${formatNumber(typeTotal)}건 중 ${formatNumber(typeRows.length)}행 로드됨)</button>`
      : "";
    return `
      ${typeChipBar}
      <div class="pagination-bar">
        <span aria-live="polite">${escapeHtml(activeArtifactType)} · ${formatNumber(typeRows.length)}행 / 전체 ${formatNumber(typeTotal)}건 — 유형별 데이터 표</span>${moreButton}
      </div>
      ${renderTypeDataGrid(typeRows, activeArtifactType)}
    `;
  }
  const displayRows = scopedRows;
  if (!displayRows.length) return `${typeChipBar}<p class="empty-state">No artifact rows.</p>`;
  queueVirtualTable({
    key: "artifacts",
    colCount: 5,
    estimatedRowHeight: 96,
    items: displayRows,
    renderRow: renderArtifactRow,
    onNeedMore: (_endIndex, table) => queueArtifactsNextPage(table),
  });
  return `
    ${typeChipBar}
    <div class="pagination-bar">
      <span data-artifact-virtual-notice aria-live="polite">로드됨 ${formatNumber(displayRows.length)}건 / 전체 ${formatNumber(pagination.total || displayRows.length)}건 · 스크롤 가상화 · ${kbd("J")}/${kbd("K")} 행 이동</span>
    </div>
    ${renderArtifactValidationSummary(displayRows)}
    <div class="review-list-shell" role="region" aria-label="Artifact result list">
      <table class="data-table">
        <thead><tr><th>Kind</th><th>Type</th><th>Provider</th><th>Evidence</th><th></th></tr></thead>
        <tbody data-virtual-key="artifacts"></tbody>
      </table>
    </div>
    ${renderPaginationControls(pagination, "artifacts")}
  `;
}
