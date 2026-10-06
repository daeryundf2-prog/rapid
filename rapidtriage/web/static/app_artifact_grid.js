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

function pickTypeGridColumns(rows) {
  const frequency = new Map();
  for (const { artifact } of rows) {
    const details = artifact?.details;
    if (!details || typeof details !== "object") continue;
    for (const [key, value] of Object.entries(details)) {
      if (TYPE_GRID_SKIP_DETAIL_KEYS.has(key)) continue;
      if (detailScalarValue(value) === undefined) continue;
      frequency.set(key, (frequency.get(key) || 0) + 1);
    }
  }
  return [...frequency.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, TYPE_GRID_COLUMN_LIMIT)
    .map(([key]) => key);
}

function artifactRowLabel(kind, artifact) {
  const details = artifact?.details || {};
  return artifact?.path || details.entry_name || details.source_path || artifact?.title || kind;
}

function renderTypeDataGrid(rows, type) {
  const shown = rows.slice(0, TYPE_GRID_ROW_LIMIT);
  const extraColumns = pickTypeGridColumns(shown);
  const header = ["대상", ...extraColumns, "경로"];
  const body = shown.map(({ kind, index, artifact }) => {
    const details = artifact?.details || {};
    return `
      <tr>
        <td><strong>${escapeHtml(fileLabel(artifactRowLabel(kind, artifact)))}</strong></td>
        ${extraColumns.map((key) => `<td>${escapeHtml(detailScalarValue(details[key]) ?? "")}</td>`).join("")}
        <td class="path-cell"><code>${escapeHtml(artifact?.path || details.source_path || "")}</code></td>
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

function renderTypeChipBar(rows) {
  const counts = new Map();
  for (const { kind, artifact } of rows) {
    const type = artifactRowType(kind, artifact);
    counts.set(type, (counts.get(type) || 0) + 1);
  }
  const types = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  if (!types.length) return "";
  return `
    <div class="artifact-type-chip-bar" role="group" aria-label="아티팩트 유형별 보기" data-testid="artifact-type-chip-bar">
      <button type="button" class="artifact-type-chip ${activeArtifactType ? "" : "active"}" data-artifact-type="">전체 ${formatNumber(rows.length)}</button>
      ${types.map(([type, count]) => `
        <button type="button" class="artifact-type-chip ${activeArtifactType === type ? "active" : ""}" data-artifact-type="${escapeHtml(type)}">${escapeHtml(type)} <b>${formatNumber(count)}</b></button>
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
  return `
    <tr class="selectable-result-row" data-source-category="${escapeHtml(sourceCategory)}" data-filter="${rowText({ kind, ...artifact })}" ${rowInspectorAttributes(inspector)} ${artifact.path ? `data-viewer-row-path="${escapeHtml(artifact.path)}" data-review-context="${escapeHtml(JSON.stringify(context))}"` : ""}>
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
      artifactsPagePagination = {
        ...artifactsPagePagination,
        next_offset: artifactGroupNextOffset(payload.artifacts || {}),
        returned: existingCount + rows.length,
      };
      const notice = detailPanel.querySelector("[data-artifact-virtual-notice]");
      if (notice) {
        notice.textContent = `로드됨 ${formatNumber(table.count)}건 / 전체 ${formatNumber(artifactGroupTotal(payload.artifacts || {}) || table.count)}건 · 스크롤 가상화`;
      }
    })
    .catch(() => {
      artifactsPagePagination = { ...artifactsPagePagination, next_offset: null };
    })
    .finally(() => {
      artifactsPageLoading = false;
    });
}

export function renderArtifacts(payload) {
  const activeArtifactFilter = getActiveArtifactFilter();
  const groups = payload.artifacts || {};
  const rows = flattenArtifactRows(groups);
  const typeChipBar = renderTypeChipBar(rows);
  if (activeArtifactType) {
    const typeRows = rows.filter(({ kind, artifact }) => artifactRowType(kind, artifact) === activeArtifactType);
    if (!typeRows.length) return `${typeChipBar}<p class="empty-state">이 유형의 행이 없습니다.</p>`;
    return `
      ${typeChipBar}
      <div class="pagination-bar">
        <span>${escapeHtml(activeArtifactType)} · ${formatNumber(typeRows.length)}행 — 유형별 데이터 표</span>
      </div>
      ${renderTypeDataGrid(typeRows, activeArtifactType)}
    `;
  }
  const displayRows = activeArtifactFilter
    ? rows.filter(({ kind, artifact }) => artifactSourceCategory(kind, artifact) === activeArtifactFilter)
    : rows;
  const pagination = activeArtifactFilter
    ? filteredPagination(displayRows.length, "artifacts")
    : artifactPaginationSummary(groups, rows.length);
  if (!displayRows.length) return '<p class="empty-state">No artifact rows.</p>';
  // Track pagination for the infinite-scroll fetcher: only when the artifact
  // filter is off do backend pages map 1:1 onto the virtual row space.
  artifactsPagePagination = activeArtifactFilter
    ? { next_offset: null }
    : { next_offset: artifactGroupNextOffset(groups) };
  artifactsPageLoading = false;
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
      <span data-artifact-virtual-notice>로드됨 ${formatNumber(displayRows.length)}건 / 전체 ${formatNumber(pagination.total || displayRows.length)}건 · 스크롤 가상화 · ${kbd("J")}/${kbd("K")} 행 이동</span>
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
