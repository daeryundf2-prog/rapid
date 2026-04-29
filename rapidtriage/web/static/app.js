const apiStatus = document.querySelector("#apiStatus");
const runForm = document.querySelector("#runForm");
const runButton = document.querySelector("#runButton");
const importForm = document.querySelector("#importForm");
const importButton = document.querySelector("#importButton");
const refreshButton = document.querySelector("#refreshButton");
const sampleRunButton = document.querySelector("#sampleRunButton");
const doctorButton = document.querySelector("#doctorButton");
const evidenceCheckButton = document.querySelector("#evidenceCheckButton");
const evidenceCheckStatus = document.querySelector("#evidenceCheckStatus");
const collectPlanButton = document.querySelector("#collectPlanButton");
const runList = document.querySelector("#runList");
const detailPanel = document.querySelector("#detailPanel");
const RUN_FORM_STORAGE_KEY = "rapidtriage.runForm.v1";
const SEARCH_STORAGE_PREFIX = "rapidtriage.search.";
const SEARCH_HISTORY_PREFIX = "rapidtriage.searchHistory.";
const COMPARE_STORAGE_PREFIX = "rapidtriage.compare.";
const REVIEW_SELECTION_STORAGE_PREFIX = "rapidtriage.reviewSelection.";
const SEARCH_PRESETS = [
  { label: "Credentials", keywords: ["password", "secret", "token", "credential"] },
  { label: "Web activity", keywords: ["download", "login", "history", "browser"] },
  { label: "Money trail", keywords: ["invoice", "wire", "account", "transfer"] },
  { label: "Intrusion", keywords: ["powershell", "rundll32", "remote", "persistence"] },
];
const PROCESSING_PROFILES = {
  fast: {
    title: "Fast first pass",
    summary: "Indexes and classifies first, skips extraction by default, and is the safest start for large evidence.",
    badges: ["read-only", "no extraction", "fast triage"],
  },
  standard: {
    title: "Standard bounded extraction",
    summary: "Runs the same triage plus capped extraction so reviewable copies are available without runaway output size.",
    badges: ["bounded extraction", "512 MB cap", "1000 file cap"],
  },
  deep: {
    title: "Deep uncapped extraction",
    summary: "Removes extraction caps for deliberate deep review. Use after fast/standard tells you where to focus.",
    badges: ["extracts matches", "no cap", "slow/heavy"],
  },
};
const RUN_MODE_COLLECTORS = {
  seizure: ["browser", "recent files", "OS/account", "event logs", "remote access", "execution", "prefetch", "MFT/USN", "Windows system", "macOS"],
  fraud: ["browser", "recent files", "OS/account", "event logs", "remote access", "execution", "prefetch", "MFT/USN", "Windows system", "macOS"],
  hacking: ["browser", "recent files", "OS/account", "event logs", "remote access", "execution", "prefetch", "MFT/USN", "Windows system", "macOS"],
  recovery: ["recent files", "OS/account", "event logs", "remote access", "prefetch", "MFT/USN", "macOS"],
};
const PAGE_SIZE = 250;
const VIRTUAL_TABLE_ROW_LIMIT = 300;
const VIRTUALIZATION_ASSESSMENT = {
  commercial_gap_ids: ["#79"],
  status: "bounded-dom-window",
  row_limit: VIRTUAL_TABLE_ROW_LIMIT,
};
const COMPARE_LIMIT = 6;
const VIEW_GROUPS = [
  {
    id: "triage",
    label: "Triage",
    summary: "Inventory first, one bounded table at a time.",
    tabs: ["summary", "files", "docs", "artifacts", "timeline", "indicators"],
  },
  {
    id: "find",
    label: "Find",
    summary: "Search documents, logs, web artifacts, metadata, and OCR.",
    tabs: ["search"],
  },
  {
    id: "review",
    label: "Review",
    summary: "Classify hits, add notes, and separate evidence from noise.",
    tabs: ["review"],
  },
  {
    id: "deliver",
    label: "Deliver",
    summary: "Read generated reports and export submission material.",
    tabs: ["report"],
  },
];
const TAB_LABELS = {
  summary: "Overview",
  search: "Keyword search",
  review: "Review board",
  timeline: "Timeline",
  indicators: "Indicators",
  artifacts: "Artifacts",
  files: "Files",
  docs: "Documents",
  report: "Run report",
};
const SHORTCUTS = [
  { keys: ["1", "2", "3", "4"], label: "Switch Triage / Find / Review / Deliver" },
  { keys: ["Ctrl K", "Cmd K"], label: "Open entire case search" },
  { keys: ["Ctrl F", "Cmd F"], label: "Search current file, or filter visible rows" },
  { keys: ["[", "]"], label: "Previous / next page in heavy tables" },
  { keys: ["Alt [", "Alt ]"], label: "Previous / next opened search hit" },
  { keys: ["Alt R"], label: "Mark the open viewer hit relevant and save" },
  { keys: ["Alt X"], label: "Reject the open viewer hit as not relevant and save" },
  { keys: ["Alt I"], label: "Toggle include-in-report for the open viewer hit" },
  { keys: ["?"], label: "Show or hide this shortcut guide" },
];

let selectedRunId = null;
let selectedRun = null;
let activeTab = "summary";
let activeViewGroup = "triage";
let pollTimer = null;
const pageOffsets = { timeline: 0, artifacts: 0, files: 0, docs: 0, indicators: 0 };

async function api(path, options = {}) {
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
    throw new Error(detail.detail || response.statusText);
  }
  const contentType = response.headers.get("content-type") || "";
  return contentType.includes("application/json") ? response.json() : response.text();
}

function authToken() {
  try {
    return window.localStorage.getItem("rapidtriage.authToken") || "";
  } catch {
    return "";
  }
}

async function checkHealth() {
  try {
    await api("/api/health");
    setStatus(apiStatus, "online", "ok");
  } catch (error) {
    setStatus(apiStatus, "offline", "failed");
  }
}

async function loadRuns() {
  const payload = await api("/api/runs");
  renderRunList(payload.runs || []);
  if (selectedRunId) {
    const match = (payload.runs || []).find((run) => run.run_id === selectedRunId);
    if (match && match.status !== selectedRun?.status) {
      await loadRunDetail(selectedRunId, activeTab);
    }
  }
}

function renderRunList(runs) {
  runList.innerHTML = "";
  if (!runs.length) {
    runList.innerHTML = renderEmptyRunList();
    return;
  }
  for (const run of runs) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `run-item ${run.run_id === selectedRunId ? "selected" : ""}`;
    button.innerHTML = `
      <span>
        <strong>${escapeHtml(run.request.mode)} · ${escapeHtml(run.run_id)}</strong>
        <span>${escapeHtml(run.origin || "web")} · ${escapeHtml(run.request.root || run.request.output_dir || "")}</span>
      </span>
      <span class="status-pill ${statusClass(run.status)}">${escapeHtml(run.status)}</span>
    `;
    button.addEventListener("click", () => loadRunDetail(run.run_id, activeTab));
    runList.appendChild(button);
  }
}

function renderEmptyRunList() {
  return `
    <section class="empty-state-card">
      <p class="eyebrow">first run</p>
      <h3>Start with the sample, then move to real evidence</h3>
      <p>처음이면 샘플 케이스로 UI 흐름을 익힌 뒤 실제 증거를 넣는 쪽이 가장 안전합니다.</p>
      <div class="command-list">
        <code>Click “Check runtime” to verify optional tools.</code>
        <code>Click “Run sample case” to create a safe practice case.</code>
        <code>Use Import run if you already have rapidtriage output.</code>
      </div>
      <p class="help-text">Existing run output이 있다면 왼쪽의 Import run으로 바로 불러올 수 있습니다.</p>
    </section>
  `;
}

async function loadRunDetail(runId, tab = "summary") {
  selectedRunId = runId;
  activeTab = tab;
  activeViewGroup = groupForTab(tab);
  selectedRun = await api(`/api/runs/${runId}`);
  if (selectedRun.status !== "completed" || !selectedRun.summary) {
    detailPanel.innerHTML = renderPendingRun(selectedRun);
    return;
  }
  detailPanel.innerHTML = renderDetailShell(selectedRun, activeTab);
  bindTabButtons();
  await renderActiveTab();
}

function renderPendingRun(run) {
  return `
    <div class="detail-topline">
      <div>
        <p class="eyebrow">${escapeHtml(run.request.mode)}</p>
        <h3>${escapeHtml(run.run_id)}</h3>
      </div>
      <span class="status-pill ${statusClass(run.status)}">${escapeHtml(run.status)}</span>
    </div>
    <section class="guidance-card">
      <p class="eyebrow">working</p>
      <h3>${run.error ? "Run needs attention" : "Run is still processing"}</h3>
      <p>${run.error ? escapeHtml(run.error) : "You can keep this page open. The list refreshes automatically and the run will open when it completes."}</p>
      ${renderRunStepList(run.steps || [])}
      ${run.error ? '<p class="help-text">실패한 단계만 확인한 뒤 같은 output directory로 재실행하면 완료된 산출물을 최대한 보존하면서 다시 점검할 수 있습니다.</p>' : ""}
    </section>
  `;
}

function renderRunStepList(steps) {
  if (!steps.length) return "";
  return `
    <div class="step-list run-step-list">
      ${steps.map((step) => `
        <span class="step-item ${step.status === "completed" ? "done" : ""} ${step.status === "failed" ? "failed" : ""}">
          ${escapeHtml(step.name || "step")}: ${escapeHtml(step.status || "pending")}
        </span>
      `).join("")}
    </div>
  `;
}

function renderDetailShell(run, tab) {
  activeViewGroup = groupForTab(tab);
  const tabs = tabsForGroup(activeViewGroup);
  const group = viewGroupById(activeViewGroup);
  return `
    <div class="detail-topline">
      <div>
        <p class="eyebrow">${escapeHtml(run.request.mode)}</p>
        <h3>${escapeHtml(run.run_id)}</h3>
      </div>
      <div class="detail-actions">
        <a class="link-button" href="/api/runs/${encodeURIComponent(run.run_id)}/outputs/report/file">Report</a>
        <button id="removeRunButton" class="secondary-button danger" type="button">Remove</button>
        <span class="status-pill ok">completed</span>
      </div>
    </div>
    ${renderViewSwitcher(activeViewGroup)}
    <p class="view-helper">${escapeHtml(group.summary)}</p>
    ${renderShortcutHelp()}
    ${renderCompareTray()}
    <div class="tab-row">
      ${tabs.map((item) => `<button class="tab-button ${item === tab ? "active" : ""}" data-tab="${item}" type="button">${escapeHtml(tabLabel(item))}</button>`).join("")}
    </div>
    <div class="filter-row">
      <input id="tableFilter" placeholder="Filter visible rows" />
      <button id="clearFilter" type="button">Clear</button>
    </div>
    <div id="tabBody" class="tab-body"></div>
  `;
}

function bindTabButtons() {
  for (const button of detailPanel.querySelectorAll(".view-button")) {
    button.addEventListener("click", async () => {
      const nextGroup = button.dataset.viewGroup;
      const tabs = tabsForGroup(nextGroup);
      if (!tabs.length) return;
      activeViewGroup = nextGroup;
      activeTab = tabs.includes(activeTab) ? activeTab : tabs[0];
      detailPanel.innerHTML = renderDetailShell(selectedRun, activeTab);
      bindTabButtons();
      await renderActiveTab();
    });
  }
  for (const button of detailPanel.querySelectorAll(".tab-button")) {
    button.addEventListener("click", async () => {
      activeTab = button.dataset.tab;
      activeViewGroup = groupForTab(activeTab);
      for (const item of detailPanel.querySelectorAll(".tab-button")) {
        item.classList.toggle("active", item === button);
      }
      await renderActiveTab();
    });
  }
  detailPanel.querySelector("#clearFilter")?.addEventListener("click", () => {
    const input = detailPanel.querySelector("#tableFilter");
    input.value = "";
    applyFilter("");
  });
  detailPanel.querySelector("#tableFilter")?.addEventListener("input", (event) => {
    applyFilter(event.target.value);
  });
  detailPanel.querySelector("#removeRunButton")?.addEventListener("click", removeSelectedRun);
  bindCompareActions();
}

function renderViewSwitcher(activeGroup) {
  return `
    <nav class="view-switcher" aria-label="Case workflow views">
      ${VIEW_GROUPS.map((group) => `
        <button class="view-button ${group.id === activeGroup ? "active" : ""}" data-view-group="${escapeHtml(group.id)}" type="button">
          <strong>${escapeHtml(group.label)}</strong>
          <span>${escapeHtml(group.tabs.map(tabLabel).join(" / "))}</span>
          <kbd>${escapeHtml(String(VIEW_GROUPS.findIndex((item) => item.id === group.id) + 1))}</kbd>
        </button>
      `).join("")}
    </nav>
  `;
}

function renderShortcutHelp() {
  return `
    <details id="shortcutHelp" class="shortcut-help">
      <summary>Keyboard shortcuts ${kbd("?")}</summary>
      <div class="shortcut-grid">
        ${SHORTCUTS.map((item) => `
          <div class="shortcut-row">
            <span>${item.keys.map(kbd).join("")}</span>
            <strong>${escapeHtml(item.label)}</strong>
          </div>
        `).join("")}
      </div>
    </details>
  `;
}

async function renderActiveTab() {
  const body = detailPanel.querySelector("#tabBody");
  const filter = detailPanel.querySelector("#tableFilter");
  if (filter) filter.value = "";
  body.innerHTML = '<p class="empty-state">Loading...</p>';
  try {
    if (activeTab === "summary") body.innerHTML = renderSummary(selectedRun.summary);
    if (activeTab === "search") body.innerHTML = renderSearch();
    if (activeTab === "timeline") body.innerHTML = renderTimeline(await api(pagedUrl("timeline")));
    if (activeTab === "indicators") body.innerHTML = renderIndicators(await api(pagedUrl("indicators")));
    if (activeTab === "artifacts") body.innerHTML = renderArtifacts(await api(pagedUrl("artifacts")));
    if (activeTab === "files") body.innerHTML = renderFiles(await api(pagedUrl("files")));
    if (activeTab === "docs") body.innerHTML = renderDocs(await api(pagedUrl("docs")));
    if (activeTab === "report") body.innerHTML = renderReport(await api(`/api/runs/${selectedRunId}/report`));
    if (activeTab === "review" || activeTab === "bookmarks") body.innerHTML = renderReviewBoard(await api(`/api/runs/${selectedRunId}/case`));
  } catch (error) {
    body.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  }
  bindPanelActions();
  bindBookmarkButtons();
  bindSearchForm();
}

function renderSummary(payload) {
  const summary = payload.summary || {};
  const outputs = payload.outputs || {};
  return `
    ${renderWorkflowGuide(summary)}
    ${renderRunActionStrip(payload)}
    ${renderProcessingSummary(payload)}
    ${renderWorkspaceCards(summary)}
    <div class="metric-grid">
      ${metric("Document matches", summary.document_match_count)}
      ${metric("File candidates", summary.file_candidate_count)}
      ${metric("Timeline events", summary.timeline_event_count)}
      ${metric("Indicators", payload.steps?.find((step) => step.name === "indicators")?.indicator_count || 0)}
      ${metric("Extracted files", (summary.docs_extracted_count || 0) + (summary.files_extracted_count || 0))}
    </div>
    ${renderCaseDbPanel(payload)}
    <div class="split-grid">
      <section>
        <h3>Highlights</h3>
        ${renderHighlightList(payload.highlights || {})}
      </section>
      <section>
        <h3>Outputs</h3>
        <ul class="output-list">
          ${Object.entries(outputs).map(([name, path]) => `
            <li>
              <strong>${escapeHtml(name)}</strong>
              <a href="/api/runs/${encodeURIComponent(selectedRunId)}/outputs/${encodeURIComponent(name)}/file">Download</a>
              <br><span>${escapeHtml(path)}</span>
            </li>
          `).join("")}
        </ul>
      </section>
    </div>
  `;
}

function renderRunActionStrip(payload) {
  const outputs = payload.outputs || {};
  const hasReport = Boolean(outputs.report);
  return `
    <section class="run-action-strip" aria-label="Run completion actions">
      <div>
        <p class="eyebrow">run complete actions</p>
        <h3>Move from processing to evidence review</h3>
        <p>완료된 실행에서 바로 Case DB 준비, 전체 검색, 리뷰 보드, 보고서/제출 묶음으로 넘어갑니다.</p>
      </div>
      <div class="run-action-buttons">
        <button class="secondary-button" type="button" data-focus-case-db="1">Prepare Case DB</button>
        <button class="secondary-button" type="button" data-open-tab="search">Search evidence</button>
        <button class="secondary-button" type="button" data-open-tab="review">Review decisions</button>
        <button class="secondary-button" type="button" data-open-tab="report">${hasReport ? "Open report" : "Report tools"}</button>
      </div>
    </section>
  `;
}

function renderProcessingSummary(payload) {
  const processing = payload.processing || {};
  const caps = processing.caps || {};
  const warnings = Array.isArray(processing.warnings) ? processing.warnings : [];
  const steps = Array.isArray(payload.steps) ? payload.steps : [];
  return `
    <section class="processing-summary" aria-label="Processing transparency">
      <div class="processing-summary-head">
        <div>
          <p class="eyebrow">processing evidence</p>
          <h3>${escapeHtml(processing.profile_label || "Processing profile")}</h3>
          <p>Run summary shows what was processed, skipped, capped, or empty so “completed” never hides missing work.</p>
        </div>
        <span class="warning-badge ${escapeHtml(processing.highest_warning_level || "none")}">
          ${escapeHtml(processing.highest_warning_level || "none")} · ${formatNumber(processing.warning_count || 0)}
        </span>
      </div>
      ${renderParserWarningBadges(payload)}
      <div class="processing-caps">
        <span>${processing.read_only ? "Read-only on" : "Extraction allowed"}</span>
        <span>${processing.dry_run ? "Dry run on" : "Dry run off"}</span>
        <span>Max extract: ${caps.max_extract_size_bytes ? formatBytes(caps.max_extract_size_bytes) : "uncapped"}</span>
        <span>Max files: ${caps.max_file_count ? formatNumber(caps.max_file_count) : "uncapped"}</span>
      </div>
      ${warnings.length ? `
        <div class="processing-warning-list">
          ${warnings.slice(0, 8).map((item) => `
            <div class="processing-warning ${escapeHtml(item.level || "notice")}">
              <strong>${escapeHtml(item.step || "step")}</strong>
              <span>${escapeHtml(item.message || "")}</span>
            </div>
          `).join("")}
        </div>
      ` : '<p class="empty-state">No processing warnings.</p>'}
      <div class="processing-step-grid">
        ${steps.map((step) => renderProcessingStep(step)).join("")}
      </div>
    </section>
  `;
}

function renderParserWarningBadges(payload) {
  const steps = Array.isArray(payload.steps) ? payload.steps : [];
  const warningSteps = steps.filter((step) => (step.warning_level || "none") !== "none");
  const zeroSteps = steps.filter((step) => stepHasZeroRows(step));
  const reusedSteps = steps.filter((step) => Boolean(step.reused));
  const badges = [
    {
      label: "Warnings",
      value: warningSteps.length,
      tone: warningSteps.length ? "warning" : "none",
      title: warningSteps.map((step) => step.name).join(", ") || "No warning steps",
    },
    {
      label: "Zero-row parsers",
      value: zeroSteps.length,
      tone: zeroSteps.length ? "notice" : "none",
      title: zeroSteps.map((step) => step.name).join(", ") || "No empty parser outputs",
    },
    {
      label: "Reused outputs",
      value: reusedSteps.length,
      tone: reusedSteps.length ? "notice" : "none",
      title: reusedSteps.map((step) => step.name).join(", ") || "No reused outputs",
    },
  ];
  return `
    <div class="parser-badge-row" aria-label="Parser warning badges">
      ${badges.map((badge) => `
        <span class="parser-badge ${escapeHtml(badge.tone)}" title="${escapeHtml(badge.title)}">
          ${escapeHtml(badge.label)} · ${formatNumber(badge.value)}
        </span>
      `).join("")}
    </div>
  `;
}

function stepHasZeroRows(step) {
  if (!step || (step.warning_level || "none") === "none") return false;
  const countKeys = ["provider_count", "candidate_count", "document_count", "scanned_file_count", "artifact_count", "event_count", "indicator_count"];
  return countKeys.some((key) => Number(step[key]) === 0);
}

function renderProcessingStep(step) {
  const safeStep = step || {};
  const details = Object.entries(safeStep)
    .filter(([key]) => !["name", "status", "output", "warning_level", "warning_messages"].includes(key))
    .slice(0, 4)
    .map(([key, value]) => `${key}=${typeof value === "object" ? JSON.stringify(value) : value}`)
    .join(", ");
  return `
    <article class="processing-step ${escapeHtml(safeStep.warning_level || "none")}">
      <div>
        <strong>${escapeHtml(safeStep.name || "step")}</strong>
        <span>${escapeHtml(safeStep.status || "unknown")}</span>
      </div>
      <p>${escapeHtml(details || "no metrics")}</p>
      ${(safeStep.warning_messages || []).slice(0, 2).map((message) => `<small>${escapeHtml(message)}</small>`).join("")}
    </article>
  `;
}

function renderCaseDbPanel(payload) {
  const outputDir = payload.output_dir || "";
  const defaultDb = outputDir ? `${outputDir.replace(/[\\/]$/, "")}/rapidtriage-case.db` : "rapidtriage-case.db";
  const defaultCaseId = selectedRunId ? `run-${selectedRunId}` : "CASE-001";
  return `
    <section class="guidance-card case-db-panel">
      <p class="eyebrow">Case DB workspace</p>
      <h3>Search and review with persistent citations</h3>
      <p>This run is prepared automatically before Case DB search, so analysts can move from keywords to review marks without manually importing JSON first.</p>
      <form id="caseDbImportForm" class="search-form">
        <label>Database path <input name="database" value="${escapeHtml(defaultDb)}" required /></label>
        <label>Case ID <input name="case_id" value="${escapeHtml(defaultCaseId)}" required /></label>
        <label>Case name <input name="name" value="${escapeHtml(payload.mode || "rapidtriage run")}" /></label>
        <button id="caseDbImportButton" type="submit">Prepare Case DB</button>
      </form>
      <form id="caseDbSearchForm" class="search-form">
        <label>DB keywords <input name="keywords" placeholder="password, powershell, download" required /></label>
        <label>Source filter
          <select name="source">
            <option value="">All sources</option>
            <option value="documents">Documents</option>
            <option value="files">Files</option>
            <option value="artifacts">Artifacts</option>
            <option value="indicators">Indicators</option>
            <option value="timeline">Timeline</option>
          </select>
        </label>
        <label>Verification
          <select name="verification_status">
            <option value="">All statuses</option>
            <option value="unverified">Unverified</option>
            <option value="source_opened">Source opened</option>
            <option value="cross_checked">Cross checked</option>
            <option value="verified">Verified</option>
            <option value="rejected">Rejected</option>
          </select>
        </label>
        <label>Review
          <select name="review_status">
            <option value="">All review marks</option>
            <option value="unreviewed">Unreviewed</option>
            <option value="relevant">Relevant</option>
            <option value="needs-review">Needs review</option>
            <option value="excluded">Excluded</option>
            <option value="not-relevant">Not relevant</option>
          </select>
        </label>
        <label>Save search as <input name="save_as" placeholder="Credential hits, PowerShell triage..." /></label>
        <button id="caseDbSearchButton" type="submit">Search Case DB</button>
        <button class="secondary-button" id="caseDbSavedSearchButton" type="button">Load saved searches</button>
      </form>
      <section id="caseDbSavedSearches" class="viewer-panel compact">
        <p class="empty-state">Saved searches and recent DB keywords appear here after the Case DB is prepared.</p>
      </section>
      <section id="caseDbResult" class="viewer-panel">
        <p class="empty-state">Enter keywords and search. The Case DB will be prepared automatically if needed.</p>
      </section>
    </section>
  `;
}

function renderWorkspaceCards(summary) {
  const cards = [
    {
      label: "1. Triage",
      title: "Start with bounded inventory",
      text: "Open only the files, document hits, artifacts, or timeline page you need. Each heavy table is loaded in small pages.",
      metric: `${formatNumber((summary.file_candidate_count || 0) + (summary.document_match_count || 0))} indexed rows`,
      tab: "files",
    },
    {
      label: "2. Find",
      title: "Search across evidence",
      text: "Keyword search reaches documents, logs, browser/web artifacts, file metadata, timeline rows, and optional OCR.",
      metric: `${formatNumber(summary.document_match_count || 0)} document hits`,
      tab: "search",
    },
    {
      label: "3. Review",
      title: "Turn hits into decisions",
      text: "Preview the source, tag the hit, mark relevance, and decide whether it belongs in the report set.",
      metric: `${formatNumber(summary.report_item_count || 0)} report candidates`,
      tab: "review",
    },
    {
      label: "4. Deliver",
      title: "Prepare handoff material",
      text: "Read the run report, then jump to the review board for submission hashes and the case report draft.",
      metric: "report + hashes",
      tab: "report",
    },
  ];
  return `
    <section class="workspace-grid" aria-label="Workflow overview">
      ${cards.map((card) => `
        <article class="workspace-card" data-filter="${rowText(card)}">
          <p class="eyebrow">${escapeHtml(card.label)}</p>
          <h3>${escapeHtml(card.title)}</h3>
          <p>${escapeHtml(card.text)}</p>
          <div class="workspace-card-footer">
            <span>${escapeHtml(card.metric)}</span>
            <button class="secondary-button" type="button" data-open-tab="${escapeHtml(card.tab)}">Open</button>
          </div>
        </article>
      `).join("")}
    </section>
  `;
}

function renderWorkflowGuide(summary) {
  const hasSearchableData = (summary.document_match_count || 0) + (summary.file_candidate_count || 0) + (summary.timeline_event_count || 0) > 0;
  return `
    <section class="guidance-card">
      <div>
        <p class="eyebrow">recommended next steps</p>
        <h3>Search, inspect, then review evidence</h3>
      </div>
      <div class="step-list">
        <span class="step-item done">Run complete</span>
        <span class="step-item ${hasSearchableData ? "done" : ""}">Searchable outputs ready</span>
        <span class="step-item">Review and classify hits</span>
        <span class="step-item">Use report candidates</span>
      </div>
      <div class="guidance-actions">
        <button class="secondary-button" type="button" data-open-tab="search">Start keyword search</button>
        <button class="secondary-button" type="button" data-open-tab="review">Open review board</button>
      </div>
      <p class="help-text">헷갈리면 순서는 단순합니다: 전체 검색 -> 뷰어로 원본 확인 -> relevant/excluded 표시 -> 보고서 후보만 남기기.</p>
    </section>
  `;
}

function renderHighlightList(highlights) {
  const rows = [
    ...(highlights.recent_file_candidates || []),
    ...(highlights.large_file_candidates || []),
    ...(highlights.preferred_location_candidates || []),
  ].slice(0, 12);
  if (!rows.length) return '<p class="empty-state">No highlight rows.</p>';
  return `<div class="dense-list">${rows.map((item) => `<div class="dense-row"><strong>${escapeHtml(item.name || item.path || "item")}</strong><span>${escapeHtml(item.path || item.summary || "")}</span></div>`).join("")}</div>`;
}

function renderTimeline(payload) {
  const rows = payload.events || [];
  const offset = payload.pagination?.offset || 0;
  if (!rows.length) return '<p class="empty-state">No timeline events.</p>';
  return `
    ${renderPaginationNotice(payload.pagination, "timeline")}
    <table class="data-table">
      <thead><tr><th>Time</th><th>Source</th><th>Type</th><th>Summary</th><th></th></tr></thead>
      <tbody>
        ${rows.map((event, index) => `
          <tr data-filter="${rowText(event)}">
            <td>${escapeHtml(event.timestamp)}</td>
            <td>${escapeHtml(event.source)}</td>
            <td>${escapeHtml(event.event_type)}</td>
            <td><strong>${escapeHtml(event.summary)}</strong><span>${escapeHtml(event.path || "")}</span></td>
            <td>${bookmarkButton("timeline", `/events/${offset + index}`, event.summary)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
    ${renderPaginationControls(payload.pagination, "timeline")}
  `;
}

function renderIndicators(payload) {
  const rows = payload.indicators || [];
  const summary = payload.summary || {};
  const offset = payload.pagination?.offset || 0;
  if (!rows.length) return '<p class="empty-state">No indicators were found in this run.</p>';
  return `
    <section class="guidance-card">
      <div>
        <p class="eyebrow">ioc review</p>
        <h3>URLs, domains, IPs, and hashes found across the run</h3>
      </div>
      <p>Use this as a pivot list. Matched rules and risk flags are triage signals, not final attribution; verify the source rows before reporting.</p>
      <div class="metric-grid">
        ${metric("Indicators", summary.indicator_count)}
        ${metric("Rule hits", summary.matched_indicator_count)}
        ${metric("Types", Object.keys(summary.type_counts || {}).length)}
        ${metric("Sources", Object.keys(summary.source_output_counts || {}).length)}
      </div>
    </section>
    ${renderPaginationNotice(payload.pagination, "indicators")}
    <table class="data-table">
      <thead><tr><th>Indicator</th><th>Count</th><th>Risk / Rules</th><th>Sources</th><th></th></tr></thead>
      <tbody>
        ${rows.map((indicator, index) => `
          <tr data-filter="${rowText(indicator)}">
            <td>
              <strong>${escapeHtml(indicator.value)}</strong>
              <span>${escapeHtml([indicator.type, indicator.classification].filter(Boolean).join(" · "))}</span>
            </td>
            <td>${formatNumber(indicator.count || 0)}</td>
            <td>
              ${renderChipList([...(indicator.risk_flags || []), ...(indicator.matched_rules || []).map((rule) => `rule:${rule}`)])}
            </td>
            <td>${renderIndicatorSources(indicator.sources || [])}</td>
            <td>${bookmarkButton("indicators", `/indicators/${offset + index}`, indicator.value)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
    ${renderPaginationControls(payload.pagination, "indicators")}
  `;
}

function renderIndicatorSources(sources) {
  if (!sources.length) return '<span class="empty-state">No source pointers.</span>';
  return `
    <details class="match-details">
      <summary>${sources.length} source pointer(s)</summary>
      <div class="dense-list">
        ${sources.slice(0, 8).map((source) => `
          <div class="dense-row">
            <strong>${escapeHtml([source.output, source.pointer].filter(Boolean).join(" · "))}</strong>
            <span>${escapeHtml([source.path || source.source_path, source.artifact_type || source.event_type || source.kind].filter(Boolean).join(" · "))}</span>
          </div>
        `).join("")}
      </div>
    </details>
  `;
}

function renderChipList(items) {
  const chips = Array.from(new Set((items || []).filter(Boolean)));
  if (!chips.length) return '<span class="empty-state">No risk flags.</span>';
  return `<div class="eventlog-chip-row">${chips.map((chip) => `<span>${escapeHtml(chip)}</span>`).join("")}</div>`;
}

function renderArtifacts(payload) {
  const groups = payload.artifacts || {};
  const rows = [];
  let pagination = null;
  for (const [kind, artifactPayload] of Object.entries(groups)) {
    const offset = artifactPayload.pagination?.offset || 0;
    if (!pagination && artifactPayload.pagination) pagination = artifactPayload.pagination;
    for (const [index, artifact] of (artifactPayload.artifacts || []).entries()) {
      rows.push({ kind, index: offset + index, artifact });
    }
  }
  if (!rows.length) return '<p class="empty-state">No artifact rows.</p>';
  return `
    ${renderPaginationNotice(pagination, "artifacts")}
    <table class="data-table">
      <thead><tr><th>Kind</th><th>Type</th><th>Provider</th><th>Evidence</th><th></th></tr></thead>
      <tbody>
        ${rows.map(({ kind, index, artifact }) => `
          <tr data-filter="${rowText({ kind, ...artifact })}">
            <td>${escapeHtml(kind)}</td>
            <td>${escapeHtml(artifact.artifact_type)}</td>
            <td>${escapeHtml(artifact.provider)}</td>
            <td>
              <strong>${escapeHtml(artifactPreviewText(artifact))}</strong>
              <span>${escapeHtml(artifact.path || "")}</span>
              ${renderArtifactDetails(artifact)}
            </td>
            <td class="action-stack">${artifactActionButtons(kind, index, artifact)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
    ${renderPaginationControls(pagination, "artifacts")}
  `;
}

function artifactPreviewText(artifact) {
  const details = artifact.details || {};
  if (details.event_id) {
    return [
      `Event ${details.event_id}`,
      details.event_category,
      details.user_name || details.target_user_name ? `user=${details.user_name || details.target_user_name}` : "",
      details.source_ip ? `ip=${details.source_ip}` : "",
      details.command_line || details.script_block_text ? `cmd=${details.command_line || details.script_block_text}` : "",
    ].filter(Boolean).join(" · ");
  }
  if (details.ai_usage_count) {
    const firstAi = Array.isArray(details.ai_usage) ? details.ai_usage[0] : null;
    const service = firstAi?.ai_service || details.ai_service || "AI usage";
    const hint = firstAi?.query_hint || firstAi?.prompt_hint || firstAi?.title || firstAi?.url || "";
    return [service, hint].filter(Boolean).join(" · ");
  }
  if (details.ai_conversation_candidate_count) {
    const firstConversation = Array.isArray(details.conversation_candidates) ? details.conversation_candidates[0] : null;
    return ["AI conversation", firstConversation?.text || `${details.ai_conversation_candidate_count} candidate(s)`].filter(Boolean).join(" · ");
  }
  for (const key of ["command_line", "script_block_text", "file_path", "executable_path", "ai_service", "domain", "source_url", "target_path", "entry_name", "service_name", "process_name"]) {
    if (details[key]) return String(details[key]);
  }
  return artifact.artifact_type || "artifact";
}

function renderArtifactDetails(artifact) {
  if (!artifact.details) return "";
  const eventLogCard = renderEventLogArtifactCard(artifact);
  const aiUsageCard = renderAiUsageArtifactCard(artifact);
  const aiConversationCard = renderAiConversationArtifactCard(artifact);
  return `
    ${eventLogCard}
    ${aiUsageCard}
    ${aiConversationCard}
    <details class="match-details">
      <summary>Inspect artifact details</summary>
      <pre>${escapeHtml(JSON.stringify(artifact.details, null, 2))}</pre>
    </details>
  `;
}

function renderEventLogArtifactCard(artifact) {
  if (!["eventlog-event", "eventlog-detection"].includes(artifact.artifact_type)) return "";
  const details = artifact.details || {};
  const chips = [
    details.event_id ? `Event ${details.event_id}` : "",
    details.event_family || details.event_category || "",
    details.channel_family || details.channel || "",
    details.risk_score !== undefined ? `risk ${details.risk_score}` : "",
    details.coverage_status || "",
  ].filter(Boolean);
  const rows = [
    ["Time", details.timestamp || details.event_created_at],
    ["Channel", details.channel],
    ["Provider", details.provider_name],
    ["Computer", details.computer],
    ["User", details.user_name || details.target_user_name || details.subject_user_name],
    ["Source IP", details.source_ip],
    ["Destination", [details.destination_hostname, details.destination_ip, details.destination_port].filter(Boolean).join(":")],
    ["Process", details.process_name || details.new_process_name],
    ["Command", details.command_line || details.script_block_text],
    ["Rule", details.rule?.title || details.rule?.id],
    ["Recommendation", details.triage_recommendation],
  ].filter(([, value]) => value !== undefined && value !== null && String(value).trim());
  return `
    <section class="eventlog-card">
      <div class="eventlog-card-header">
        <strong>${escapeHtml(artifact.artifact_type === "eventlog-detection" ? "Detection" : "Windows Event")}</strong>
        <span>${escapeHtml(details.event_description || details.event_category || "")}</span>
      </div>
      <div class="eventlog-chip-row">${chips.map((chip) => `<span>${escapeHtml(chip)}</span>`).join("")}</div>
      <dl class="eventlog-fields">
        ${rows.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(String(value))}</dd>`).join("")}
      </dl>
    </section>
  `;
}

function renderAiUsageArtifactCard(artifact) {
  const details = artifact.details || {};
  if (!["browser-ai-usage", "macos-browser-ai-usage", "browser-history-downloads", "browser-history", "macos-browser-history-downloads"].includes(artifact.artifact_type)) return "";
  const rows = Array.isArray(details.ai_usage) ? details.ai_usage : [];
  if (!rows.length) return "";
  const chips = [
    details.browser,
    details.profile,
    details.user ? `user ${details.user}` : "",
    `${rows.length} AI visit(s)`,
    details.coverage_status || "",
  ].filter(Boolean);
  const topRows = rows.slice(0, 5);
  return `
    <section class="eventlog-card">
      <div class="eventlog-card-header">
        <strong>AI Usage</strong>
        <span>${escapeHtml(details.triage_recommendation || "AI service visits detected from browser history.")}</span>
      </div>
      <div class="eventlog-chip-row">${chips.map((chip) => `<span>${escapeHtml(chip)}</span>`).join("")}</div>
      <dl class="eventlog-fields">
        ${topRows.map((row) => `
          <dt>${escapeHtml(row.ai_service || "AI")}</dt>
          <dd>${escapeHtml([row.last_visited_at, row.query_hint || row.prompt_hint || row.title || row.url].filter(Boolean).join(" · "))}</dd>
        `).join("")}
      </dl>
    </section>
  `;
}

function renderAiConversationArtifactCard(artifact) {
  const details = artifact.details || {};
  if (!["browser-ai-conversation", "macos-browser-ai-conversation"].includes(artifact.artifact_type)) return "";
  const rows = Array.isArray(details.conversation_candidates) ? details.conversation_candidates : [];
  if (!rows.length) return "";
  const chips = [
    details.browser,
    details.profile,
    details.user ? `user ${details.user}` : "",
    `${details.question_count || 0} question(s)`,
    `${details.answer_count || 0} answer(s)`,
    details.coverage_status || "",
  ].filter(Boolean);
  return `
    <section class="eventlog-card">
      <div class="eventlog-card-header">
        <strong>AI Conversation Candidates</strong>
        <span>${escapeHtml(details.triage_recommendation || "Recovered browser-storage snippets that need raw-source verification.")}</span>
      </div>
      <div class="eventlog-chip-row">${chips.map((chip) => `<span>${escapeHtml(chip)}</span>`).join("")}</div>
      <dl class="eventlog-fields">
        ${rows.slice(0, 6).map((row) => `
          <dt>${escapeHtml([row.ai_service, row.direction || row.role].filter(Boolean).join(" · "))}</dt>
          <dd>${escapeHtml(row.text || "")}<br><small>${escapeHtml(row.storage_area || row.source_path || "")}</small></dd>
        `).join("")}
      </dl>
    </section>
  `;
}

function artifactActionButtons(kind, index, artifact) {
  const context = {
    source: `artifacts:${kind}`,
    pointer: `/artifacts/${index}`,
    title: artifact.artifact_type || "artifact",
    note: artifactPreviewText(artifact),
    path: artifact.path || "",
    tags: ["artifact", kind, artifact.artifact_type].filter(Boolean),
  };
  const match = {
    source: "artifacts",
    kind,
    path: artifact.path || "",
    title: artifact.artifact_type || kind,
    preview: context.note,
    pointer: context.pointer,
  };
  const items = [];
  if (match.path) {
    items.push(viewSourceButton(match, context));
    items.push(sourceFileLink(match));
    items.push(compareButton(compareItemFromMatch(match, context)));
  }
  items.push(bookmarkButton(context.source, context.pointer, context.note || context.title));
  return items.join("");
}

function renderFiles(payload) {
  const rows = payload.candidates || [];
  const offset = payload.pagination?.offset || 0;
  if (!rows.length) return '<p class="empty-state">No file candidates.</p>';
  return `
    ${renderPaginationNotice(payload.pagination, "files")}
    <table class="data-table">
      <thead><tr><th>Name</th><th>Categories</th><th>Size</th><th>Modified</th><th></th></tr></thead>
      <tbody>
        ${rows.map((file, index) => `
          <tr data-filter="${rowText(file)}">
            <td><strong>${escapeHtml(file.name)}</strong><span>${escapeHtml(file.path)}</span></td>
            <td>${escapeHtml((file.categories || []).join(", "))}</td>
            <td>${formatBytes(file.size)}</td>
            <td>${escapeHtml(file.modified_at)}</td>
            <td>${bookmarkButton("files", `/candidates/${offset + index}`, file.name)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
    ${renderPaginationControls(payload.pagination, "files")}
  `;
}

function renderDocs(payload) {
  const rows = payload.results || [];
  const offset = payload.pagination?.offset || 0;
  if (!rows.length) return '<p class="empty-state">No document matches.</p>';
  return `
    ${renderPaginationNotice(payload.pagination, "docs")}
    <table class="data-table">
      <thead><tr><th>Document</th><th>Kind</th><th>Keywords</th><th>Preview</th><th></th></tr></thead>
      <tbody>
        ${rows.map((doc, index) => `
          <tr data-filter="${rowText(doc)}">
            <td><strong>${escapeHtml(fileName(doc.path))}</strong><span>${escapeHtml(doc.path)}</span></td>
            <td>${escapeHtml(doc.kind)}</td>
            <td>${escapeHtml((doc.matched_keywords || []).join(", "))}</td>
            <td>${escapeHtml(doc.preview || "")}</td>
            <td>${bookmarkButton("docs", `/results/${offset + index}`, fileName(doc.path))}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
    ${renderPaginationControls(payload.pagination, "docs")}
  `;
}

function renderSearch(payload = null) {
  const rows = payload?.matches || [];
  const draft = payload
    ? {
        keywords: payload.keywords || [],
        ocr: payload.ocr?.enabled !== false,
        source: (payload.options?.sources || [])[0] || "",
        extension: (payload.options?.extensions || [])[0] || "",
        path_contains: payload.options?.path_contains || "",
      }
    : getSearchDraft();
  const draftText = (draft.keywords || []).join(", ");
  return `
    <form id="unifiedSearchForm" class="search-form">
      <label>
        Entire case search ${kbd("Ctrl K")}
        <input id="unifiedSearchInput" value="${escapeHtml(draftText)}" placeholder="Search documents, web history, logs, OCR..." required />
      </label>
      <div class="field-grid search-filter-grid">
        <label>
          Source
          <select id="unifiedSearchSource">
            <option value="">All sources</option>
            <option value="documents" ${draft.source === "documents" ? "selected" : ""}>Documents</option>
            <option value="files" ${draft.source === "files" ? "selected" : ""}>File metadata</option>
            <option value="web" ${draft.source === "web" ? "selected" : ""}>Web artifacts</option>
            <option value="indicators" ${draft.source === "indicators" ? "selected" : ""}>Indicators</option>
            <option value="artifacts" ${draft.source === "artifacts" ? "selected" : ""}>Other artifacts</option>
            <option value="timeline" ${draft.source === "timeline" ? "selected" : ""}>Timeline</option>
            <option value="ocr" ${draft.source === "ocr" ? "selected" : ""}>OCR</option>
          </select>
        </label>
        <label>
          Extension
          <input id="unifiedSearchExtension" value="${escapeHtml(draft.extension || "")}" placeholder=".pdf, .log, .sqlite" />
        </label>
      </div>
      <label>
        Path contains
        <input id="unifiedSearchPath" value="${escapeHtml(draft.path_contains || "")}" placeholder="Users, Downloads, AppData..." />
      </label>
      <label class="check-label"><input id="unifiedSearchOcr" type="checkbox" ${draft.ocr === false ? "" : "checked"} /> Include OCR on image candidates</label>
      <button id="unifiedSearchButton" type="submit">Search evidence</button>
    </form>
    ${renderRecentSearchChips()}
    <div class="preset-row" aria-label="Keyword presets">
      ${SEARCH_PRESETS.map((preset) => `<button class="preset-chip" type="button" data-keywords="${escapeHtml(preset.keywords.join(", "))}">${escapeHtml(preset.label)}</button>`).join("")}
    </div>
    <p class="help-text">Tip: this searches the whole case. Open a result in the viewer to search only inside that file.</p>
    <section id="evidenceViewer" class="viewer-panel">
      <p class="empty-state">Select a search result to preview evidence here.</p>
    </section>
    ${payload ? renderSearchResults(payload, rows) : '<p class="empty-state">Enter one or more keywords. Separate multiple terms with commas.</p>'}
  `;
}

function renderSearchResults(payload, rows) {
  const summary = payload.summary || {};
  const visibleRows = virtualizedRows(rows);
  if (!rows.length) {
    const ocrErrors = payload.ocr?.errors || [];
    return `
      <div class="metric-grid search-metrics">
        ${metric("Matches", summary.match_count)}
        ${metric("OCR errors", summary.ocr_error_count)}
      </div>
      <p class="empty-state">No matches found.</p>
      ${renderOcrErrors(ocrErrors)}
    `;
  }
  return `
    <div class="metric-grid search-metrics">
      ${metric("Matches", summary.match_count)}
      ${metric("Sources", Object.keys(summary.source_counts || {}).length)}
      ${metric("OCR errors", summary.ocr_error_count)}
      ${metric("Keywords", (payload.keywords || []).length)}
    </div>
    ${renderSearchAnalysis(payload.analysis)}
    ${renderVirtualizationNotice(rows, visibleRows, "search matches")}
    <table class="data-table">
      <thead><tr><th>Source</th><th>Item</th><th>Keywords</th><th>Preview / Evidence</th><th></th></tr></thead>
      <tbody>
        ${visibleRows.map((match, index) => `
          <tr data-filter="${rowText(match)}">
            <td>${escapeHtml(match.source)}<span>${escapeHtml(match.kind || "")}</span></td>
            <td><strong>${escapeHtml(match.title || fileName(match.path))}</strong><span>${escapeHtml(match.path || "")}</span></td>
            <td>${escapeHtml((match.matched_keywords || []).join(", "))}</td>
            <td>
              ${escapeHtml(match.preview || "")}
              ${renderSearchMetadata(match)}
            </td>
            <td class="action-stack">
              ${reviewActionButtons(match, index)}
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
    ${renderOcrErrors(payload.ocr?.errors || [])}
  `;
}

function renderSearchAnalysis(analysis) {
  if (!analysis) return "";
  const clusters = analysis.clusters?.clusters || [];
  const entities = analysis.entities?.entities || [];
  const hypotheses = analysis.workbook?.hypotheses || [];
  const timelineEvents = analysis.timeline?.events || [];
  const graphSummary = analysis.graph?.summary || {};
  return `
    <section class="analysis-grid" aria-label="Search analysis pivots">
      <article class="analysis-card">
        <p class="eyebrow">clusters</p>
        <h3>Review by repeated patterns</h3>
        ${clusters.length ? clusters.slice(0, 5).map((cluster) => `
          <button class="analysis-chip" type="button" data-filter="${escapeHtml(String(cluster.value || ""))}">
            <strong>${escapeHtml(cluster.label || "Cluster")}</strong>
            <span>${escapeHtml(cluster.match_count)} hits · ${escapeHtml(cluster.review_hint || "")}</span>
          </button>
        `).join("") : '<p class="help-text">No repeated clusters yet.</p>'}
      </article>
      <article class="analysis-card">
        <p class="eyebrow">entities</p>
        <h3>Pivot people, accounts, URLs</h3>
        ${entities.length ? entities.slice(0, 8).map((entity) => `
          <button class="entity-pill" type="button" data-filter="${escapeHtml(entity.value || "")}">
            ${escapeHtml(entity.type)} · ${escapeHtml(entity.value)} <span>${escapeHtml(entity.count)}</span>
          </button>
        `).join("") : '<p class="help-text">No entities extracted from current hits.</p>'}
      </article>
      <article class="analysis-card">
        <p class="eyebrow">workbook</p>
        <h3>Draft hypotheses</h3>
        ${hypotheses.length ? hypotheses.slice(0, 4).map((hypothesis) => `
          <details class="hypothesis-card">
            <summary>${escapeHtml(hypothesis.title || hypothesis.key || "Hypothesis")}</summary>
            <p>${escapeHtml(hypothesis.rationale || "")}</p>
            <span>${escapeHtml((hypothesis.evidence_cluster_ids || []).length)} linked cluster(s)</span>
          </details>
        `).join("") : '<p class="help-text">No workbook hypotheses generated.</p>'}
      </article>
      <article class="analysis-card">
        <p class="eyebrow">graph / timeline</p>
        <h3>Relationship scale</h3>
        <div class="mini-stat-row">
          <span>${escapeHtml(graphSummary.node_count || 0)} nodes</span>
          <span>${escapeHtml(graphSummary.edge_count || 0)} edges</span>
          <span>${escapeHtml(timelineEvents.length)} timeline anchors</span>
        </div>
        ${timelineEvents.length ? `
          <ol class="timeline-mini">
            ${timelineEvents.slice(0, 4).map((event) => `
              <li><b>${escapeHtml(String(event.timestamp || "").slice(0, 19))}</b><span>${escapeHtml(event.title || event.path || "")}</span></li>
            `).join("")}
          </ol>
        ` : '<p class="help-text">No timestamp anchors in current hits.</p>'}
      </article>
    </section>
    ${renderAnalysisLimitations(analysis.limitations || [])}
  `;
}

function renderAnalysisLimitations(limitations) {
  if (!limitations.length) return "";
  return `
    <details class="analysis-limitations">
      <summary>Analysis limits and validation reminders</summary>
      <ul>${limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </details>
  `;
}

function renderRecentSearchChips() {
  const history = getSearchHistory().slice(0, 8);
  if (!history.length) return "";
  return `
    <div class="preset-row recent-search-row" aria-label="Recent searches">
      <span class="help-text">Recent:</span>
      ${history.map((entry) => `
        <button class="preset-chip" type="button" data-keywords="${escapeHtml((entry.keywords || []).join(", "))}">
          ${escapeHtml((entry.keywords || []).join(", "))}
        </button>
      `).join("")}
    </div>
  `;
}

function renderOcrErrors(errors) {
  if (!errors.length) return "";
  return `
    <details class="ocr-errors">
      <summary>OCR skipped/failed for ${errors.length} item(s)</summary>
      <div class="dense-list">
        ${errors.slice(0, 20).map((item) => `<div class="dense-row"><strong>${escapeHtml(item.path || "OCR")}</strong><span>${escapeHtml(item.error)}</span></div>`).join("")}
      </div>
    </details>
  `;
}

function renderSearchMetadata(match) {
  if (!match.metadata) return "";
  return `
    <details class="match-details">
      <summary>Inspect matched data</summary>
      <pre>${escapeHtml(JSON.stringify(match.metadata, null, 2))}</pre>
    </details>
  `;
}

function bindSearchForm() {
  const form = detailPanel.querySelector("#unifiedSearchForm");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const input = detailPanel.querySelector("#unifiedSearchInput");
    const button = detailPanel.querySelector("#unifiedSearchButton");
    const includeOcr = detailPanel.querySelector("#unifiedSearchOcr")?.checked ?? true;
    const source = detailPanel.querySelector("#unifiedSearchSource")?.value || "";
    const extension = detailPanel.querySelector("#unifiedSearchExtension")?.value || "";
    const pathContains = detailPanel.querySelector("#unifiedSearchPath")?.value || "";
    const keywords = String(input.value || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    if (!keywords.length) return;
    setSearchDraft({ keywords, ocr: includeOcr, source, extension, path_contains: pathContains });
    rememberSearchKeywords({ keywords, source, extension, path_contains: pathContains });
    button.disabled = true;
    button.textContent = "Searching...";
    try {
      const params = new URLSearchParams();
      for (const keyword of keywords) params.append("keyword", keyword);
      params.set("ocr", includeOcr ? "true" : "false");
      if (source) params.append("source", source);
      if (extension) params.append("extension", extension);
      if (pathContains) params.set("path_contains", pathContains);
      const payload = await api(`/api/runs/${selectedRunId}/search?${params.toString()}`);
      detailPanel.querySelector("#tabBody").innerHTML = renderSearch(payload);
      bindSearchForm();
      bindBookmarkButtons();
    } catch (error) {
      detailPanel.querySelector("#tabBody").insertAdjacentHTML("beforeend", `<p class="empty-state">${escapeHtml(error.message)}</p>`);
    } finally {
      const nextButton = detailPanel.querySelector("#unifiedSearchButton");
      if (nextButton) {
        nextButton.disabled = false;
        nextButton.textContent = "Search evidence";
      }
    }
  });
  for (const button of detailPanel.querySelectorAll("[data-view-source-path]")) {
    button.addEventListener("click", async () => {
      await loadEvidencePreview(
        button.dataset.viewSourcePath,
        parseReviewContext(button.dataset.reviewContext),
        button.dataset.searchResultIndex,
      );
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-keywords]")) {
    button.addEventListener("click", () => {
      const input = detailPanel.querySelector("#unifiedSearchInput");
      if (!input) return;
      input.value = button.dataset.keywords || "";
      form.requestSubmit();
    });
  }
  for (const button of detailPanel.querySelectorAll(".analysis-chip[data-filter], .entity-pill[data-filter]")) {
    button.addEventListener("click", () => applyFilter(button.dataset.filter || ""));
  }
}

async function loadEvidencePreview(path, reviewContext = null, searchResultIndex = null) {
  const viewer = detailPanel.querySelector("#evidenceViewer");
  if (!viewer || !path) return;
  if (searchResultIndex !== null && searchResultIndex !== undefined && searchResultIndex !== "") {
    viewer.dataset.currentSearchResultIndex = String(searchResultIndex);
  }
  viewer.innerHTML = '<p class="empty-state">Loading preview...</p>';
  try {
    const payload = await api(`/api/runs/${selectedRunId}/source-preview?path=${encodeURIComponent(path)}`);
    viewer.innerHTML = renderEvidenceViewer(payload, reviewContext);
    if (searchResultIndex !== null && searchResultIndex !== undefined && searchResultIndex !== "") {
      viewer.dataset.currentSearchResultIndex = String(searchResultIndex);
    }
    bindViewerButtons();
  } catch (error) {
    viewer.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  }
}

function renderEvidenceViewer(payload, reviewContext = null) {
  const openLink = `<a class="mini-link" href="${escapeHtml(payload.download_url)}" target="_blank" rel="noreferrer">Open source</a>`;
  const copyButton = `<button class="icon-action" type="button" data-copy-path="${escapeHtml(payload.path)}">Copy path</button>`;
  const pinButton = `<button class="icon-action" type="button" data-compare-item="${escapeHtml(JSON.stringify(compareItemFromPreview(payload, reviewContext)))}">Pin compare</button>`;
  const hashButton = `<button class="icon-action" type="button" data-source-hash-path="${escapeHtml(payload.path)}">Compute hashes</button>`;
  let body = `<p class="empty-state">${escapeHtml(payload.message || "No preview available.")}</p>`;
  if (payload.preview_type === "image") {
    body = renderImagePreview(payload.image || {}, payload);
  }
  if (payload.preview_type === "text") {
    body = `
      <pre class="viewer-text">${escapeHtml(payload.text || "")}</pre>
      ${payload.truncated ? '<p class="empty-state">Preview truncated for performance.</p>' : ""}
    `;
  }
  if (payload.preview_type === "sqlite") {
    body = renderSqlitePreview(payload.sqlite || {});
  }
  if (payload.preview_type === "json") {
    body = renderJsonPreview(payload.json || {}, payload);
  }
  if (payload.preview_type === "xml") {
    body = renderXmlPreview(payload.xml || {}, payload);
  }
  if (payload.preview_type === "email") {
    body = renderEmailPreview(payload.email || {}, payload);
  }
  if (payload.preview_type === "hex") {
    body = renderHexPreview(payload.hex || {}, payload);
  }
  if (payload.preview_type === "media") {
    body = renderMediaPreview(payload.media || {}, payload);
  }
  return `
    <div class="viewer-header">
      <div>
        <p class="eyebrow">evidence viewer</p>
        <h3>${escapeHtml(payload.name)}</h3>
      </div>
      <div class="detail-actions">${openLink}${copyButton}${pinButton}${hashButton}</div>
    </div>
    <div class="viewer-meta">
      <span>${escapeHtml(payload.mime_type)}</span>
      <span>${formatBytes(payload.size)}</span>
      <span>${escapeHtml(payload.path)}</span>
    </div>
    <section id="sourceMetadataPanel" class="source-metadata-panel">
      <p class="help-text">해시는 큰 파일에서 시간이 걸릴 수 있어 필요할 때만 계산합니다.</p>
    </section>
    ${renderViewerActionGuide(payload)}
    ${renderViewerMetadata(payload.viewer_metadata || {})}
    ${renderFileSearchBox(payload)}
    ${renderReviewCapture(reviewContext, payload)}
    ${body}
  `;
}

function renderViewerActionGuide(payload) {
  const actions = payload.viewer_actions || [];
  const limitations = payload.viewer_limitations || [];
  if (!actions.length && !limitations.length) return "";
  return `
    <section class="source-metadata-panel viewer-action-guide">
      <div>
        <p class="eyebrow">verification guide</p>
        <h4>Preview, verify, then review</h4>
      </div>
      ${actions.length ? `
        <div class="viewer-action-grid">
          ${actions.map((action) => renderViewerAction(action, payload)).join("")}
        </div>
      ` : ""}
      ${limitations.length ? `
        <ul class="viewer-limitations">
          ${limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
        </ul>
      ` : ""}
    </section>
  `;
}

function renderViewerAction(action, payload) {
  const label = escapeHtml(action.label || action.id || "Action");
  const purpose = escapeHtml(action.purpose || "");
  const badge = action.heavy ? '<span class="status-pill warning">heavy</span>' : '<span class="status-pill">fast</span>';
  let control = "";
  if (action.id === "hash") {
    control = `<button class="mini-inline-button" type="button" data-source-hash-path="${escapeHtml(payload.path)}">Run</button>`;
  } else if (action.id === "search-current-file") {
    control = `<span>${kbd("Ctrl F")}</span>`;
  } else if (action.url) {
    control = `<a class="mini-link" href="${escapeHtml(action.url)}" target="_blank" rel="noreferrer">Open</a>`;
  } else if (action.id === "pin-compare") {
    control = `<span>Pin compare</span>`;
  } else if (action.id === "save-review") {
    control = `<span>${kbd("Alt R")}</span>`;
  }
  return `
    <article class="viewer-action-card">
      <div>
        <strong>${label}</strong>
        <span>${purpose}</span>
      </div>
      <div class="viewer-action-control">${badge}${control}</div>
    </article>
  `;
}

function renderViewerMetadata(metadata) {
  if (!Object.keys(metadata || {}).length) return "";
  return `
    <section class="source-metadata-panel">
      <div class="metadata-grid">
        ${metric("Viewer", metadata.parser || "source-viewer")}
        ${metric("Strategy", metadata.strategy || "unknown")}
        ${metric("Status", metadata.preview_status || "unknown")}
        ${metric("Format", metadata.source_format || "unknown")}
      </div>
    </section>
  `;
}

function renderSqlitePreview(sqlite) {
  const tables = sqlite.tables || [];
  if (!tables.length) {
    return `<p class="empty-state">${escapeHtml(sqlite.error || "No user tables were found in this SQLite database.")}</p>`;
  }
  const metadata = sqlite.database_metadata || {};
  return `
    <section class="sqlite-preview">
      <div class="file-search-summary">
        ${metric("Tables", sqlite.table_count)}
        ${metric("Previewed", tables.length)}
        ${metric("Rows/table", sqlite.row_limit)}
        ${metric("Page size", metadata.page_size || "n/a")}
      </div>
      <p class="help-text">SQLite viewer is read-only and capped for performance. It shows schema, indexes, bounded rows, and supports keyword search inside text columns.</p>
      ${tables.map((table) => `
        <article class="viewer-panel sqlite-table-card">
          <div class="viewer-header compact">
            <div>
              <p class="eyebrow">sqlite table</p>
              <h3>${escapeHtml(table.name)}</h3>
            </div>
            <span class="status-pill">${escapeHtml(table.row_count ?? "unknown")} rows</span>
          </div>
          <p class="help-text">
            Columns: ${escapeHtml(table.column_count ?? 0)}
            ${table.primary_key_columns?.length ? ` · PK: ${escapeHtml(table.primary_key_columns.join(", "))}` : ""}
            ${table.indexes?.length ? ` · Indexes: ${escapeHtml(table.indexes.map((index) => index.name).join(", "))}` : ""}
          </p>
          ${table.schema_sql ? `<pre class="code-preview compact">${escapeHtml(table.schema_sql)}</pre>` : ""}
          <div class="table-wrap">
            <table class="data-table">
              <thead>
                <tr>${(table.columns || []).map((column) => {
                  const detail = (table.column_details || []).find((item) => item.name === column) || {};
                  const typeLabel = detail.type ? `<small>${escapeHtml(detail.type)}</small>` : "";
                  return `<th>${escapeHtml(column)} ${typeLabel}</th>`;
                }).join("")}</tr>
              </thead>
              <tbody>
                ${(table.rows || []).map((row) => `
                  <tr>
                    ${(table.columns || []).map((column) => `<td>${escapeHtml(formatSqliteCell(row.values?.[column]))}</td>`).join("")}
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
          ${(table.truncated_rows || table.truncated_columns) ? '<p class="help-text">Preview capped: narrow with source search or export the table with a dedicated SQLite tool for full review.</p>' : ""}
        </article>
      `).join("")}
      ${sqlite.truncated ? '<p class="help-text">Additional tables are hidden to keep the viewer responsive.</p>' : ""}
    </section>
  `;
}

function renderImagePreview(imagePayload, payload) {
  const gallery = imagePayload.gallery_review || {};
  const tags = gallery.tag_suggestions || [];
  const hashes = imagePayload.hashes || {};
  return `
    <section class="structured-preview image-gallery-preview">
      <div class="file-search-summary">
        ${metric("Size", imagePayload.width && imagePayload.height ? `${imagePayload.width}x${imagePayload.height}` : "unknown")}
        ${metric("Bucket", imagePayload.similarity_bucket || "n/a")}
        ${metric("OCR", imagePayload.ocr_plan?.status || "n/a")}
        ${metric("Decoded", imagePayload.decoded ? "yes" : "no")}
      </div>
      <img class="viewer-image" src="${escapeHtml(payload.image_url)}" alt="${escapeHtml(payload.name)}" />
      <div class="viewer-meta">
        ${tags.map((tag) => `<span>${escapeHtml(tag)}</span>`).join("")}
      </div>
      <p class="help-text">Gallery review hint: ${escapeHtml(gallery.report_selection_hint || "Verify hashes and context before report use.")}</p>
      ${hashes.sha256 ? `<p class="help-text">Source SHA256: ${escapeHtml(hashes.sha256)}</p>` : ""}
      ${imagePayload.perceptual_hash ? `<p class="help-text">Perceptual hash: ${escapeHtml(imagePayload.perceptual_hash)} · compare-ready: ${gallery.compare_ready ? "yes" : "no"}</p>` : ""}
      ${imagePayload.ocr_sidecar?.text ? `<details><summary>OCR sidecar excerpt</summary><pre class="viewer-text">${escapeHtml(imagePayload.ocr_sidecar.text)}</pre></details>` : ""}
      ${imagePayload.translation_sidecar?.text ? `<details><summary>Translation sidecar excerpt</summary><pre class="viewer-text">${escapeHtml(imagePayload.translation_sidecar.text)}</pre></details>` : ""}
    </section>
  `;
}

function renderJsonPreview(json, payload) {
  const summary = json.summary || {};
  return `
    <section class="structured-preview">
      <div class="file-search-summary">
        ${metric("JSON items", json.item_count ?? 0)}
        ${metric("Limit", json.item_limit ?? "n/a")}
        ${metric("Type", summary.type || "json")}
      </div>
      <p class="help-text">JSON viewer is capped and read-only. Use file search above for exact keyword hits.</p>
      <pre class="viewer-text">${escapeHtml(JSON.stringify(summary, null, 2))}</pre>
      ${payload.text ? `<details><summary>Formatted source excerpt</summary><pre class="viewer-text">${escapeHtml(payload.text)}</pre></details>` : ""}
      ${json.truncated ? '<p class="help-text">JSON preview was capped for performance.</p>' : ""}
    </section>
  `;
}

function renderXmlPreview(xml, payload) {
  const nodes = xml.nodes || [];
  return `
    <section class="structured-preview">
      <div class="file-search-summary">
        ${metric("Root", xml.root_tag || "unknown")}
        ${metric("Nodes", nodes.length)}
        ${metric("Limit", xml.node_limit ?? "n/a")}
      </div>
      <p class="help-text">XML viewer shows a bounded element outline for fast review. Use file search for exact text hits.</p>
      <div class="dense-list">
        ${nodes.map((node) => `
          <article class="dense-row">
            <strong>${escapeHtml(node.path || node.tag || "")}</strong>
            <span>${escapeHtml(node.text || "")}</span>
            <small>${escapeHtml(Object.entries(node.attributes || {}).map(([key, value]) => `${key}=${value}`).join(" · "))}</small>
          </article>
        `).join("")}
      </div>
      ${payload.text ? `<details><summary>Raw XML excerpt</summary><pre class="viewer-text">${escapeHtml(payload.text)}</pre></details>` : ""}
      ${xml.truncated ? '<p class="help-text">XML outline was capped for performance.</p>' : ""}
    </section>
  `;
}

function renderEmailPreview(emailPayload, payload) {
  const messages = emailPayload.messages || [];
  const threads = emailPayload.threads || [];
  return `
    <section class="structured-preview">
      <div class="file-search-summary">
        ${metric("Messages", emailPayload.message_count ?? messages.length)}
        ${metric("Threads", emailPayload.thread_count ?? threads.length)}
        ${metric("Limit", emailPayload.message_limit ?? "n/a")}
        ${metric("Preview", payload.truncated ? "capped" : "complete")}
      </div>
      <p class="help-text">Email viewer extracts headers, body preview, and attachment names without loading external content.</p>
      ${threads.length ? `
        <div class="thread-strip">
          ${threads.map((thread) => `
            <article class="thread-card">
              <strong>${escapeHtml(thread.subject || "(no subject)")}</strong>
              <span>${escapeHtml(thread.message_count)} msg · ${escapeHtml(thread.attachment_count)} attachment(s)</span>
              <small>${escapeHtml((thread.participants || []).join(" · "))}</small>
            </article>
          `).join("")}
        </div>
      ` : ""}
      <div class="dense-list">
        ${messages.map((message) => `
          <article class="dense-row">
            <strong>${escapeHtml(message.subject || "(no subject)")}</strong>
            <span>${escapeHtml([message.from, message.to, message.date].filter(Boolean).join(" -> "))}</span>
            <small>${escapeHtml(message.body_preview || "")}</small>
            ${(message.attachments || []).length ? `<small>Attachments: ${escapeHtml((message.attachments || []).map((item) => item.filename || item.content_type).join(", "))}</small>` : ""}
          </article>
        `).join("")}
      </div>
      ${emailPayload.truncated ? '<p class="help-text">Email preview was capped for performance.</p>' : ""}
    </section>
  `;
}

function renderHexPreview(hexPayload, payload) {
  const rows = hexPayload.rows || [];
  return `
    <section class="structured-preview">
      <div class="file-search-summary">
        ${metric("Bytes", hexPayload.bytes_read ?? 0)}
        ${metric("Max", hexPayload.max_bytes ?? "n/a")}
        ${metric("Rows", rows.length)}
        ${metric("Range", `${hexPayload.first_offset_hex || "0x0"}-${hexPayload.last_offset_hex || "n/a"}`)}
      </div>
      <p class="help-text">Hex viewer is read-only and bounded. Preview SHA256: ${escapeHtml(hexPayload.preview_sha256 || "n/a")}. Use source metadata to compute full-file hashes before reporting byte offsets.</p>
      <div class="hex-table" role="table" aria-label="Hex preview for ${escapeHtml(payload.name || "source")}">
        ${rows.map((row) => `
          <div class="hex-row" role="row">
            <code class="hex-offset">${escapeHtml(row.offset_hex)}</code>
            <code class="hex-bytes">${escapeHtml(row.hex)}</code>
            <code class="hex-ascii">${escapeHtml(row.ascii)}</code>
          </div>
        `).join("")}
      </div>
      ${hexPayload.truncated ? '<p class="help-text">Hex preview was capped for performance. Open source for full byte review.</p>' : ""}
    </section>
  `;
}

function renderMediaPreview(mediaPayload, payload) {
  const metadata = mediaPayload.metadata || {};
  const sidecars = mediaPayload.transcript_sidecars || [];
  const review = mediaPayload.review || {};
  const sourceHashes = mediaPayload.source_hashes || {};
  return `
    <section class="structured-preview">
      <div class="file-search-summary">
        ${metric("Type", mediaPayload.mime_type || payload.mime_type || "media")}
        ${metric("Duration", metadata.duration_seconds ?? "unknown")}
        ${metric("Transcripts", mediaPayload.transcript_sidecar_count ?? sidecars.length)}
        ${metric("Alignment", review.transcript_alignment || "n/a")}
      </div>
      <p class="help-text">Media preview keeps playback/transcoding out of the browser and shows bounded metadata/transcript sidecars for safe review. ${escapeHtml(review.report_selection_hint || "")}</p>
      ${sourceHashes.sha256 ? `<p class="help-text">Source SHA256: ${escapeHtml(sourceHashes.sha256)}</p>` : ""}
      <div class="metadata-grid">
        ${metric("Channels", metadata.audio_channels ?? "n/a")}
        ${metric("Sample rate", metadata.sample_rate ?? "n/a")}
        ${metric("Frames", metadata.frame_count ?? "n/a")}
      </div>
      ${sidecars.length ? `
        <div class="dense-list">
          ${sidecars.map((sidecar) => `
            <article class="dense-row">
              <strong>${escapeHtml(sidecar.name || "transcript")}</strong>
              <span>${escapeHtml(sidecar.path || "")}</span>
              <small>${escapeHtml(sidecar.preview || "")}</small>
              ${(sidecar.cues || []).length ? `<small>Cues: ${escapeHtml(sidecar.cues.slice(0, 3).map((cue) => `${cue.start}-${cue.end}: ${cue.text}`).join(" | "))}</small>` : ""}
            </article>
          `).join("")}
        </div>
      ` : '<p class="empty-state">No transcript sidecar was found next to this media file.</p>'}
      ${(mediaPayload.limitations || []).length ? `<ul class="viewer-limitations">${mediaPayload.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>` : ""}
    </section>
  `;
}

function formatSqliteCell(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function renderFileSearchBox(payload) {
  return `
    <form id="fileSearchForm" class="file-search-form" data-file-search-path="${escapeHtml(payload.path)}">
      <label>
        Search inside this file ${kbd("Ctrl F")}
        <input name="keyword" placeholder="Find text only in ${escapeHtml(payload.name)}" />
      </label>
      <button type="submit">Search file</button>
      <span id="fileSearchStatus" class="review-save-status"></span>
    </form>
    <section id="fileSearchResults" class="file-search-results"></section>
  `;
}

function renderReviewCapture(reviewContext, payload) {
  if (!reviewContext?.source || !reviewContext?.pointer) {
    return '<p class="empty-state">This source can be previewed, but it is not tied to a saved result pointer for review.</p>';
  }
  const suggestedTags = Array.from(new Set([...(reviewContext.tags || []), payload.extension?.replace(".", "")].filter(Boolean))).join(", ");
  return `
    <form id="viewerReviewForm" class="review-capture" data-review-context="${escapeHtml(JSON.stringify(reviewContext))}">
      <div>
        <p class="eyebrow">review decision</p>
        <h3>Check, classify, and organize this hit</h3>
      </div>
      <div class="review-grid">
        <label>
          Decision
          <select name="status">
            <option value="needs-review">Needs review</option>
            <option value="relevant">Relevant</option>
            <option value="not-relevant">Not relevant</option>
            <option value="unreviewed">Unreviewed</option>
          </select>
        </label>
        <label>
          Tags
          <input name="tags" value="${escapeHtml(suggestedTags)}" placeholder="credential, browser, suspicious-login" />
        </label>
      </div>
      <label>
        Analyst note
        <textarea name="note" rows="3" placeholder="Why this matters, what to verify next, or why it is noise.">${escapeHtml(reviewContext.note || "")}</textarea>
      </label>
      <div class="review-actions">
        <label class="check-label"><input name="include_in_report" type="checkbox" /> Include in report set</label>
        <button type="submit">Save review decision</button>
        <span id="viewerReviewStatus" class="review-save-status"></span>
      </div>
    </form>
  `;
}

function bindViewerButtons() {
  bindCopyButtons();
  bindCompareActions();
  for (const button of detailPanel.querySelectorAll("[data-source-hash-path]")) {
    if (button.dataset.hashBound) continue;
    button.dataset.hashBound = "1";
    button.addEventListener("click", async () => {
      await loadSourceMetadata(button.dataset.sourceHashPath, button);
    });
  }
  const fileSearchForm = detailPanel.querySelector("#fileSearchForm");
  if (fileSearchForm) fileSearchForm.addEventListener("submit", searchCurrentFile);
  const reviewForm = detailPanel.querySelector("#viewerReviewForm");
  if (reviewForm) {
    reviewForm.addEventListener("submit", saveViewerReview);
    reviewForm.querySelector("[name='status']")?.addEventListener("change", (event) => {
      const includeInput = reviewForm.querySelector("[name='include_in_report']");
      if (includeInput && event.target.value === "relevant") includeInput.checked = true;
    });
  }
}

async function loadSourceMetadata(path, button) {
  const panel = detailPanel.querySelector("#sourceMetadataPanel");
  if (!panel || !path) return;
  button.disabled = true;
  button.textContent = "Hashing...";
  panel.innerHTML = '<p class="empty-state">Computing MD5/SHA1/SHA256 for this source file...</p>';
  try {
    const payload = await api(`/api/runs/${selectedRunId}/source-metadata?path=${encodeURIComponent(path)}&hash=true`);
    panel.innerHTML = renderSourceMetadata(payload);
    bindCopyButtons();
  } catch (error) {
    panel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "Compute hashes";
  }
}

function renderSourceMetadata(payload) {
  const hashes = payload.hashes || {};
  return `
    <div class="metadata-grid">
      ${metric("Size", formatBytes(payload.size))}
      ${metric("Hash", escapeHtml(payload.hash_status || "unknown"))}
      ${metric("Extension", escapeHtml(payload.extension || "(none)"))}
      ${metric("MIME", escapeHtml(payload.mime_type || "unknown"))}
    </div>
    <div class="hash-list">
      ${Object.entries(hashes).map(([name, value]) => `
        <div class="hash-row">
          <strong>${escapeHtml(name.toUpperCase())}</strong>
          <code>${escapeHtml(value)}</code>
          <button class="icon-action" type="button" data-copy-path="${escapeHtml(value)}">Copy</button>
        </div>
      `).join("")}
    </div>
  `;
}

async function searchCurrentFile(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const status = form.querySelector("#fileSearchStatus");
  const output = detailPanel.querySelector("#fileSearchResults");
  const input = form.elements.keyword;
  const keywords = String(input?.value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (!keywords.length || !form.dataset.fileSearchPath) return;
  status.textContent = "Searching this file...";
  output.innerHTML = "";
  try {
    const params = new URLSearchParams();
    params.set("path", form.dataset.fileSearchPath);
    for (const keyword of keywords) params.append("keyword", keyword);
    const payload = await api(`/api/runs/${selectedRunId}/source-search?${params.toString()}`);
    output.innerHTML = renderFileSearchResults(payload);
    bindCopyButtons();
    bindCompareActions();
    bindFileSearchHitActions();
  } catch (error) {
    output.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    status.textContent = "";
  }
}

function renderFileSearchResults(payload) {
  const rows = payload.matches || [];
  if (!payload.searchable) {
    return `<p class="empty-state">${escapeHtml(payload.message || "This file is not searchable.")}</p>`;
  }
  if (!rows.length) {
    return `
      <div class="file-search-summary">
        ${metric("File matches", 0)}
        ${metric("Keywords", (payload.keywords || []).length)}
      </div>
      <p class="empty-state">No matches in this file.</p>
    `;
  }
  return `
    <div class="file-search-summary">
      ${metric("File matches", payload.summary?.match_count)}
      ${metric("Keywords", (payload.keywords || []).length)}
    </div>
    <div class="dense-list">
      ${rows.map((match) => `
        <article class="dense-row">
          <strong>Line ${escapeHtml(match.line)} · ${escapeHtml(match.keyword)}</strong>
          <span>${highlightSnippet(match.snippet || "", payload.keywords || [])}</span>
          <small>${escapeHtml(match.citation || "")}</small>
          <div class="review-actions">
            ${compareButton(compareItemFromFileSearchMatch(payload, match))}
            <button class="icon-action" type="button" data-copy-path="${escapeHtml(match.citation || match.snippet || "")}">Copy citation</button>
            <button class="icon-action" type="button" data-copy-path="${escapeHtml(match.compare_preview || match.snippet || "")}">Copy snippet</button>
            <button class="icon-action" type="button" data-review-note-text="${escapeHtml(reviewNoteFromFileSearchMatch(match))}">Add to review note</button>
          </div>
        </article>
      `).join("")}
    </div>
    ${payload.truncated ? '<p class="help-text">Results were capped for performance. Narrow the keyword if needed.</p>' : ""}
  `;
}

function compareItemFromFileSearchMatch(payload, match) {
  return {
    path: payload.path || match.source_path || "",
    title: match.citation || `${payload.name || "source"} hit`,
    source: "source-search",
    kind: payload.mime_type || payload.extension || "",
    preview: match.compare_preview || match.snippet || "",
    pointer: match.pointer || "",
  };
}

function reviewNoteFromFileSearchMatch(match) {
  return [
    `Current-file hit: ${match.citation || match.match_id || "source-search hit"}`,
    match.snippet ? `Snippet: ${match.snippet}` : "",
    match.review_hint ? `Review hint: ${match.review_hint}` : "",
  ].filter(Boolean).join("\n");
}

function bindFileSearchHitActions() {
  for (const button of detailPanel.querySelectorAll("[data-review-note-text]")) {
    if (button.dataset.reviewNoteBound) continue;
    button.dataset.reviewNoteBound = "1";
    button.addEventListener("click", () => appendViewerReviewNote(button.dataset.reviewNoteText || "", button));
  }
}

function appendViewerReviewNote(note, button = null) {
  const form = detailPanel.querySelector("#viewerReviewForm");
  const noteInput = form?.elements.note;
  if (!noteInput || !note) {
    if (button) {
      button.textContent = "No review form";
      button.disabled = true;
    }
    return false;
  }
  const existing = String(noteInput.value || "").trim();
  noteInput.value = [existing, note.trim()].filter(Boolean).join("\n\n");
  const tagInput = form.elements.tags;
  if (tagInput) {
    tagInput.value = mergeTagText(tagInput.value, ["source-search-hit"]);
  }
  noteInput.focus();
  if (button) button.textContent = "Added";
  return true;
}

function mergeTagText(value, additions) {
  const tags = new Set(parseTags(value));
  for (const addition of additions) {
    if (addition) tags.add(addition);
  }
  return Array.from(tags).join(", ");
}

async function saveViewerReview(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const status = form.querySelector("#viewerReviewStatus");
  const context = parseReviewContext(form.dataset.reviewContext);
  if (!context?.source || !context?.pointer) return;
  const request = {
    source: context.source,
    pointer: context.pointer,
    tag: activeTab === "search" ? "search-hit" : activeTab,
    tags: parseTags(form.elements.tags?.value || ""),
    note: form.elements.note?.value || context.note || "",
    review_status: form.elements.status?.value || "needs-review",
    include_in_report: Boolean(form.elements.include_in_report?.checked),
  };
  status.textContent = "Saving...";
  try {
    await api(`/api/runs/${selectedRunId}/bookmarks`, {
      method: "POST",
      body: JSON.stringify(request),
    });
    status.innerHTML = 'Saved to review board <button class="mini-inline-button" type="button" data-open-tab="review">Open review</button>';
    bindPanelActions();
  } catch (error) {
    status.textContent = `Failed: ${error.message}`;
  }
}

async function saveCaseReport(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const status = form.querySelector("#caseReportStatus");
  const request = {
    template: form.elements.template?.value || "legal-handoff",
    title: form.elements.title?.value || null,
    case_number: form.elements.case_number?.value || null,
    investigator: form.elements.investigator?.value || null,
    organization: form.elements.organization?.value || null,
    requester: form.elements.requester?.value || null,
    scope: form.elements.scope?.value || null,
    conclusion: form.elements.conclusion?.value || null,
    include_all: Boolean(form.elements.include_all?.checked),
    max_items: Number(form.elements.max_items?.value || 500),
  };
  status.textContent = "Generating...";
  try {
    const payload = await api(`/api/runs/${selectedRunId}/case-report`, {
      method: "POST",
      body: JSON.stringify(request),
    });
    const baseUrl = `/api/runs/${encodeURIComponent(selectedRunId)}/case-report/file`;
    status.innerHTML = [
      "Saved",
      `<a class="mini-link" href="${baseUrl}" target="_blank" rel="noreferrer">Markdown</a>`,
      `<a class="mini-link" href="${baseUrl}/html" target="_blank" rel="noreferrer">HTML</a>`,
      `<a class="mini-link" href="${baseUrl}/docx" target="_blank" rel="noreferrer">DOCX</a>`,
      `<a class="mini-link" href="${baseUrl}/pdf" target="_blank" rel="noreferrer">PDF</a>`,
      `<a class="mini-link" href="${baseUrl}/manifest" target="_blank" rel="noreferrer">Hashes</a>`,
      '<button class="mini-inline-button" type="button" data-open-tab="review">Back to review</button>',
    ].join(" ");
    if (payload.report_path) {
      status.insertAdjacentHTML("beforeend", ` <span>${escapeHtml(payload.report_path)}</span>`);
    }
  } catch (error) {
    status.textContent = `Failed: ${error.message}`;
  }
}

async function createReviewerBundle(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const status = form.querySelector("#reviewerBundleStatus");
  const request = {
    title: form.elements.title?.value || null,
    include_all: Boolean(form.elements.include_all?.checked),
    max_items: Number(form.elements.max_items?.value || 500),
  };
  status.textContent = "Building reviewer bundle...";
  try {
    const payload = await api(`/api/runs/${selectedRunId}/reviewer-bundle`, {
      method: "POST",
      body: JSON.stringify(request),
    });
    const archiveUrl = `/api/runs/${encodeURIComponent(selectedRunId)}/reviewer-bundle/file`;
    status.innerHTML = [
      "Saved",
      `<a class="mini-link" href="${archiveUrl}" target="_blank" rel="noreferrer">Download ZIP</a>`,
      payload.outputs?.selected_evidence ? `<span>Selected JSON: ${escapeHtml(payload.outputs.selected_evidence)}</span>` : "",
      payload.outputs?.bundle_manifest ? `<span>Bundle manifest: ${escapeHtml(payload.outputs.bundle_manifest)}</span>` : "",
      payload.outputs?.reviewer ? `<span>${escapeHtml(payload.outputs.reviewer)}</span>` : "",
    ].filter(Boolean).join(" ");
  } catch (error) {
    status.textContent = `Failed: ${error.message}`;
  }
}

function parseReviewContext(value) {
  if (!value) return null;
  try {
    const payload = JSON.parse(value);
    return payload && typeof payload === "object" ? payload : null;
  } catch {
    return null;
  }
}

function parseTags(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function renderReport(markdown) {
  return `
    <section class="guidance-card">
      <div>
        <p class="eyebrow">deliver</p>
        <h3>Package the case without loading every row</h3>
      </div>
      <p>This view keeps the generated run report separate from evidence review. Use the review board to produce the submission hash manifest and case report draft from checked evidence.</p>
      <div class="guidance-actions">
        <button class="secondary-button" type="button" data-open-tab="review">Open review board</button>
        <a class="link-button" href="/api/runs/${encodeURIComponent(selectedRunId)}/outputs/report/file">Download run report</a>
      </div>
      <p class="help-text">Workflow reminder: classify hits in Review, generate a hash manifest, then generate the case report or reviewer bundle from checked evidence only.</p>
    </section>
    <pre class="report-view">${escapeHtml(markdown)}</pre>
  `;
}

function renderReviewBoard(payload) {
  if (!payload.exists || !payload.case) {
    return `
      <section class="guidance-card">
        <p class="eyebrow">review board</p>
        <h3>No reviewed evidence yet</h3>
        <p>Use Search, open a result in the viewer, then save a review decision. Your decisions become the case board here.</p>
        <div class="guidance-actions">
          <button class="secondary-button" type="button" data-open-tab="search">Go to search</button>
        </div>
      </section>
    `;
  }
  const bookmarks = payload.case.bookmarks || [];
  if (!bookmarks.length) {
    return `
      <section class="guidance-card">
        <p class="eyebrow">review board</p>
        <h3>No reviewed evidence yet</h3>
        <p>Classify search hits as relevant, needs review, or not relevant to build this board.</p>
        <div class="guidance-actions">
          <button class="secondary-button" type="button" data-open-tab="search">Go to search</button>
        </div>
      </section>
    `;
  }
  const summary = payload.case.summary || {};
  const groups = groupBookmarksByReviewStatus(bookmarks);
  return `
    <div class="case-path">${escapeHtml(payload.case_path)}</div>
    <div class="metric-grid">
      ${metric("Reviewed items", summary.bookmark_count)}
      ${metric("Report candidates", summary.report_item_count)}
      ${metric("Relevant", summary.review_status_counts?.relevant)}
      ${metric("Needs review", summary.review_status_counts?.["needs-review"])}
    </div>
    ${renderSubmissionManifestPanel(summary)}
    ${renderCaseReportPanel(summary, payload.case)}
    ${renderReviewerBundlePanel(summary, payload.case)}
    ${renderReviewSelectionTray(bookmarks)}
    <p class="empty-state">Use this board to separate report-ready evidence from noise. The saved structure lives in rapidtriage-case.json.</p>
    ${["relevant", "needs-review", "not-relevant", "unreviewed"].map((status) => renderReviewGroup(status, groups[status] || [])).join("")}
  `;
}

function renderReviewSelectionTray(bookmarks) {
  const selectedIds = getReviewSelection();
  const selectedBookmarks = bookmarks.filter((bookmark) => selectedIds.includes(String(bookmark.bookmark_id || "")));
  const reportSelectedCount = selectedBookmarks.filter((bookmark) => Boolean(bookmark.review?.include_in_report)).length;
  return `
    <section id="reviewSelectionTray" class="review-selection-tray ${selectedBookmarks.length ? "" : "empty"}">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">review selection</p>
          <h3>현재 검토 묶음</h3>
        </div>
        <div class="detail-actions">
          <span class="status-pill">${selectedBookmarks.length}</span>
          <span class="status-pill">${reportSelectedCount} report set</span>
          <button class="secondary-button" type="button" data-clear-review-selection ${selectedBookmarks.length ? "" : "disabled"}>Clear selection</button>
        </div>
      </div>
      ${selectedBookmarks.length ? `
        <div class="dense-list">
          ${selectedBookmarks.map((bookmark) => {
            const review = bookmark.review || {};
            const snapshot = bookmark.snapshot || {};
            return `
              <div class="dense-row">
                <strong>${escapeHtml(bookmark.summary || bookmark.bookmark_id)}</strong>
                <span>${escapeHtml(review.status || "unreviewed")} · ${review.include_in_report ? "report set" : "not in report"} · ${escapeHtml(snapshot.path || "")}</span>
              </div>
            `;
          }).join("")}
        </div>
      ` : '<p class="empty-state">리뷰 카드에서 Select를 누르면 현재 검토 중인 증거 묶음이 여기에 유지됩니다.</p>'}
    </section>
  `;
}

function renderSubmissionManifestPanel(summary) {
  const reportCount = Number(summary.report_item_count || 0);
  const disabled = reportCount ? "" : "disabled";
  const fileUrl = `/api/runs/${encodeURIComponent(selectedRunId)}/submission-manifest/file`;
  const jsonUrl = `/api/runs/${encodeURIComponent(selectedRunId)}/submission-manifest`;
  return `
    <section class="guidance-card">
      <div>
        <p class="eyebrow">submission hashes</p>
        <h3>Prepare a court-friendly hash manifest</h3>
      </div>
      <p>Builds MD5, SHA1, and SHA256 for report-candidate evidence only, then saves rapidtriage-submission-manifest.json in the run output directory.</p>
      <div class="guidance-actions">
        <a class="link-button ${disabled}" href="${reportCount ? fileUrl : "#"}" target="_blank" rel="noreferrer">Download hash manifest</a>
        <a class="link-button ${disabled}" href="${reportCount ? jsonUrl : "#"}" target="_blank" rel="noreferrer">Preview JSON</a>
      </div>
      <p class="help-text">Use this before report/bundle export. It is the evidence integrity anchor for selected report candidates.</p>
      ${reportCount ? "" : '<p class="help-text">Mark evidence as “Include in report set” before generating the submission manifest.</p>'}
    </section>
  `;
}

function renderCaseReportPanel(summary, casePayload) {
  const reportCount = Number(summary.report_item_count || 0);
  return `
    <section class="guidance-card">
      <div>
        <p class="eyebrow">report drafting</p>
        <h3>Write a submission-style investigation report</h3>
      </div>
      <p>Creates rapidtriage-case-report.md from case metadata, reviewed evidence, analyst notes, and the submission hash manifest.</p>
      <p class="help-text">Template guide: Legal handoff keeps attorney/reviewer noise low, Executive summary hides most technical detail, Technical appendix preserves parser/hash context, Hash-only focuses on evidence integrity.</p>
      <form id="caseReportForm" class="report-form">
        <div class="report-grid">
          <label>
            Template
            <select name="template">
              <option value="legal-handoff">Legal handoff</option>
              <option value="executive-summary">Executive summary</option>
              <option value="technical-appendix">Technical appendix</option>
              <option value="hash-only">Hash-only appendix</option>
            </select>
          </label>
          <label>
            Report title
            <input name="title" value="${escapeHtml(casePayload.title || "Digital forensic analysis report")}" />
          </label>
          <label>
            Case number
            <input name="case_number" value="${escapeHtml(casePayload.case_id || "")}" />
          </label>
          <label>
            Investigator
            <input name="investigator" placeholder="Analyst name" />
          </label>
          <label>
            Organization
            <input name="organization" placeholder="Agency / company" />
          </label>
          <label>
            Requester
            <input name="requester" placeholder="Requesting party" />
          </label>
          <label>
            Max evidence items
            <input name="max_items" type="number" min="1" max="5000" value="500" />
          </label>
        </div>
        <label>
          Scope
          <textarea name="scope" rows="3">검토 대상으로 지정된 증거 파일과 rapidtriage 분석 산출물을 기준으로 작성함.</textarea>
        </label>
        <label>
          Conclusion / opinion
          <textarea name="conclusion" rows="3">검토 결과 및 증거 해시는 아래 항목과 같음.</textarea>
        </label>
        <div class="review-actions">
          <label class="check-label"><input name="include_all" type="checkbox" /> Include every reviewed bookmark, not only report candidates</label>
          <button type="submit" ${reportCount ? "" : "disabled"}>Generate report draft</button>
          <span id="caseReportStatus" class="review-save-status"></span>
        </div>
      </form>
      ${reportCount ? "" : '<p class="help-text">Mark evidence as “Include in report set” before generating a report draft.</p>'}
    </section>
  `;
}

function renderReviewerBundlePanel(summary, casePayload) {
  const reportCount = Number(summary.report_item_count || 0);
  return `
    <section class="guidance-card">
      <div>
        <p class="eyebrow">portable reviewer bundle</p>
        <h3>Share selected review material without the original image</h3>
      </div>
      <p>Builds a static HTML/JSON/DOCX/PDF/ZIP reviewer package from report candidates, review notes, and hashes. It does not copy the original evidence image.</p>
      <p class="help-text">The ZIP includes reviewer HTML, selected evidence JSON, report exports, hash manifests, audit JSON, and a bundle manifest. Share it only after checking the archive SHA256.</p>
      <form id="reviewerBundleForm" class="report-form">
        <div class="report-grid">
          <label>
            Bundle title
            <input name="title" value="${escapeHtml(casePayload.title || "RapidTriage reviewer bundle")}" />
          </label>
          <label>
            Max evidence items
            <input name="max_items" type="number" min="1" max="5000" value="500" />
          </label>
        </div>
        <div class="review-actions">
          <label class="check-label"><input name="include_all" type="checkbox" /> Include every reviewed bookmark, not only report candidates</label>
          <button type="submit" ${reportCount ? "" : "disabled"}>Build reviewer bundle</button>
          <span id="reviewerBundleStatus" class="review-save-status"></span>
        </div>
      </form>
      ${reportCount ? "" : '<p class="help-text">Mark evidence as “Include in report set” before building a reviewer bundle.</p>'}
    </section>
  `;
}

function groupBookmarksByReviewStatus(bookmarks) {
  return bookmarks.reduce((groups, bookmark) => {
    const status = bookmark.review?.status || "unreviewed";
    if (!groups[status]) groups[status] = [];
    groups[status].push(bookmark);
    return groups;
  }, {});
}

function renderReviewGroup(status, bookmarks) {
  const labelMap = {
    relevant: "Relevant evidence",
    "needs-review": "Needs review",
    "not-relevant": "Not relevant / noise",
    unreviewed: "Unreviewed bookmarks",
  };
  return `
    <section class="review-group">
      <div class="review-group-header">
        <h3>${escapeHtml(labelMap[status] || status)}</h3>
        <span class="status-pill">${bookmarks.length}</span>
      </div>
      ${bookmarks.length ? bookmarks.map(renderReviewCard).join("") : '<p class="empty-state">No items in this bucket.</p>'}
    </section>
  `;
}

function renderReviewCard(bookmark) {
  const review = bookmark.review || {};
  const snapshot = bookmark.snapshot || {};
  const reference = bookmark.reference || {};
  const reportBadge = review.include_in_report ? '<span class="review-badge report">report set</span>' : '<span class="review-badge">not in report</span>';
  const compareButton = snapshot.path ? `<button class="icon-action" type="button" data-compare-item="${escapeHtml(JSON.stringify(compareItemFromBookmark(bookmark)))}">Pin compare</button>` : "";
  const bookmarkId = String(bookmark.bookmark_id || "");
  const selected = getReviewSelection().includes(bookmarkId);
  return `
    <article class="review-card ${selected ? "selected" : ""}" data-filter="${rowText(bookmark)}" data-review-card-id="${escapeHtml(bookmarkId)}">
      <div class="review-card-top">
        <strong>${escapeHtml(bookmark.summary || bookmark.bookmark_id)}</strong>
        <div class="detail-actions">
          ${reportBadge}
          <button class="icon-action" type="button" data-toggle-review-selection="${escapeHtml(bookmarkId)}">${selected ? "Selected" : "Select"}</button>
        </div>
      </div>
      <div class="viewer-meta">
        <span>${escapeHtml(reference.command || "source")}</span>
        <span>${escapeHtml(snapshot.timestamp || bookmark.updated_at || "")}</span>
        <span>${escapeHtml(snapshot.path || "")}</span>
      </div>
      <p>${escapeHtml(bookmark.note || "No analyst note yet.")}</p>
      ${renderSourceHitNotes(bookmark.note || "")}
      <div class="tag-row">${(bookmark.tags || []).map((tag) => `<span>${escapeHtml(tag)}</span>`).join("")}</div>
      <code>${escapeHtml(reference.pointer || "")}</code>
      ${renderReviewHistory(bookmark)}
      ${compareButton ? `<div class="review-actions">${compareButton}</div>` : ""}
    </article>
  `;
}

function renderSourceHitNotes(note) {
  const hits = sourceHitNotes(note);
  if (!hits.length) return "";
  return `
    <div class="source-hit-list">
      <strong>Current-file cited hits</strong>
      ${hits.map((hit) => `
        <div class="source-hit-item">
          <span class="source-hit-citation">${escapeHtml(hit.citation)}</span>
          ${hit.snippet ? `<span class="source-hit-snippet">${escapeHtml(hit.snippet)}</span>` : ""}
          ${hit.reviewHint ? `<span class="source-hit-hint">${escapeHtml(hit.reviewHint)}</span>` : ""}
        </div>
      `).join("")}
    </div>
  `;
}

function sourceHitNotes(note) {
  const hits = [];
  let current = null;
  for (const rawLine of String(note || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.toLowerCase().startsWith("current-file hit:")) {
      current = { citation: line.replace(/^current-file hit:\s*/i, "") };
      if (current.citation) hits.push(current);
      continue;
    }
    if (!current || !line) continue;
    if (line.toLowerCase().startsWith("snippet:")) {
      current.snippet = line.replace(/^snippet:\s*/i, "");
      continue;
    }
    if (line.toLowerCase().startsWith("review hint:")) {
      current.reviewHint = line.replace(/^review hint:\s*/i, "");
      continue;
    }
    if (line.toLowerCase().includes("verify") || line.toLowerCase().includes("review")) {
      if (!current.reviewHint) current.reviewHint = line;
    }
  }
  return hits;
}

function renderReviewHistory(bookmark) {
  const history = Array.isArray(bookmark.review_history) ? bookmark.review_history : [];
  if (!history.length) return "";
  const latest = history[history.length - 1] || {};
  return `
    <details class="review-history">
      <summary>Review history · ${history.length} revision(s), latest ${escapeHtml(latest.action || "updated")}</summary>
      <div class="dense-list">
        ${history.slice(-5).reverse().map((entry) => `
          <div class="dense-row">
            <strong>${escapeHtml(entry.action || "revision")} · ${escapeHtml(entry.status || "")} · ${escapeHtml(entry.at || "")}</strong>
            <span>${escapeHtml((entry.changed_fields || []).join(", ") || "snapshot")}</span>
          </div>
        `).join("")}
      </div>
    </details>
  `;
}

function bindBookmarkButtons() {
  for (const button of detailPanel.querySelectorAll("[data-bookmark-source]")) {
    button.addEventListener("click", async () => {
      const tag = activeTab === "artifacts" ? "artifact" : activeTab;
      button.disabled = true;
      button.textContent = "Saving";
      try {
        await api(`/api/runs/${selectedRunId}/bookmarks`, {
          method: "POST",
          body: JSON.stringify({
            source: button.dataset.bookmarkSource,
            pointer: button.dataset.bookmarkPointer,
            tag,
            note: button.dataset.bookmarkNote || "",
          }),
        });
        button.textContent = "Saved";
      } catch (error) {
        button.textContent = "Failed";
        button.title = error.message;
      }
    });
  }
}

function bookmarkButton(source, pointer, note) {
  return `<button class="icon-action" type="button" title="Save bookmark" data-bookmark-source="${escapeHtml(source)}" data-bookmark-pointer="${escapeHtml(pointer)}" data-bookmark-note="${escapeHtml(note || "")}">Mark</button>`;
}

function bookmarkContextForMatch(match) {
  const sourceMap = {
    documents: "docs",
    files: "files",
    ocr: "files",
    timeline: "timeline",
    web: "artifacts:browser",
    artifacts: `artifacts:${match.kind || ""}`,
  };
  const source = sourceMap[match.source];
  if (!source || !match.pointer) return null;
  return {
    source,
    pointer: match.pointer,
    title: match.title || fileName(match.path) || "search hit",
    note: match.preview || "",
    path: match.path || "",
    tags: [match.source, match.kind].filter(Boolean),
  };
}

function reviewActionButtons(match, searchResultIndex = null) {
  const context = bookmarkContextForMatch(match);
  const items = [];
  if (match.path) {
    items.push(viewSourceButton(match, context, searchResultIndex));
    items.push(sourceFileLink(match));
    items.push(compareButton(compareItemFromMatch(match, context)));
  }
  if (context) {
    items.push(bookmarkButton(context.source, context.pointer, context.note || context.title));
  }
  return items.join("");
}

function compareButton(item) {
  if (!item?.path) return "";
  return `<button class="icon-action" type="button" data-compare-item="${escapeHtml(JSON.stringify(item))}">Pin compare</button>`;
}

function compareItemFromMatch(match, context = null) {
  return {
    path: match.path || "",
    title: match.title || fileName(match.path) || "search hit",
    source: match.source || context?.source || activeTab,
    kind: match.kind || "",
    preview: match.preview || context?.note || "",
    pointer: context?.pointer || match.pointer || "",
  };
}

function compareItemFromPreview(payload, reviewContext = null) {
  const previewText = payload.text
    ? `${payload.text.slice(0, 1200)}${payload.truncated || payload.text.length > 1200 ? "\n..." : ""}`
    : payload.preview_type === "image"
      ? "Image evidence pinned. Use Preview to reopen the visual source."
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

function compareItemFromBookmark(bookmark) {
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

function viewSourceButton(match, context, searchResultIndex = null) {
  if (!match.path) return "";
  const indexAttribute = searchResultIndex === null || searchResultIndex === undefined ? "" : ` data-search-result-index="${escapeHtml(searchResultIndex)}"`;
  return `<button class="icon-action" type="button" data-view-source-path="${escapeHtml(match.path)}" data-review-context="${escapeHtml(JSON.stringify(context || {}))}"${indexAttribute}>View / review</button>`;
}

function sourceFileLink(match) {
  if (!match.path) return "";
  const url = `/api/runs/${encodeURIComponent(selectedRunId)}/source-file?path=${encodeURIComponent(match.path)}`;
  return `<a class="mini-link" href="${url}" target="_blank" rel="noreferrer">Open source</a>`;
}

function applyFilter(value) {
  const needle = value.trim().toLowerCase();
  for (const row of detailPanel.querySelectorAll("[data-filter]")) {
    row.hidden = needle && !row.dataset.filter.includes(needle);
  }
}

function metric(label, value) {
  return `<div class="metric"><b>${value ?? 0}</b><span>${escapeHtml(label)}</span></div>`;
}

function setStatus(element, text, className) {
  element.textContent = text;
  element.className = `status-pill ${className}`;
}

function statusClass(status) {
  if (status === "completed") return "ok";
  if (status === "failed") return "failed";
  return "";
}

function titleCase(value) {
  return value.slice(0, 1).toUpperCase() + value.slice(1);
}

function kbd(value) {
  return `<kbd>${escapeHtml(value)}</kbd>`;
}

function tabLabel(value) {
  return TAB_LABELS[value] || titleCase(value);
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString();
}

function rowText(value) {
  return escapeHtml(JSON.stringify(value || {}).toLowerCase());
}

function highlightSnippet(value, keywords) {
  let html = escapeHtml(value);
  for (const keyword of keywords) {
    const needle = String(keyword || "").trim();
    if (!needle) continue;
    html = html.replace(new RegExp(`(${escapeRegExp(escapeHtml(needle))})`, "gi"), "<mark>$1</mark>");
  }
  return html;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function fileName(path) {
  return String(path || "").split(/[\\/]/).filter(Boolean).pop() || String(path || "");
}

function formatBytes(value) {
  const size = Number(value || 0);
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

function compareStorageKey() {
  return `${COMPARE_STORAGE_PREFIX}${selectedRunId || "default"}`;
}

function getCompareItems() {
  if (!storageAvailable()) return [];
  try {
    const payload = JSON.parse(window.localStorage.getItem(compareStorageKey()) || "[]");
    return Array.isArray(payload) ? payload.filter((item) => item?.path).slice(0, COMPARE_LIMIT) : [];
  } catch {
    return [];
  }
}

function setCompareItems(items) {
  if (!storageAvailable()) return;
  window.localStorage.setItem(compareStorageKey(), JSON.stringify(items.slice(0, COMPARE_LIMIT)));
}

function addCompareItem(item) {
  if (!item?.path) return;
  const nextItem = { ...item, added_at: new Date().toISOString() };
  const existing = getCompareItems().filter((candidate) => candidate.path !== item.path);
  setCompareItems([nextItem, ...existing].slice(0, COMPARE_LIMIT));
  refreshCompareTray();
}

function removeCompareItem(path) {
  setCompareItems(getCompareItems().filter((item) => item.path !== path));
  refreshCompareTray();
}

function clearCompareItems() {
  setCompareItems([]);
  refreshCompareTray();
}

function renderCompareTray() {
  const items = getCompareItems();
  const primary = items.slice(0, 2);
  return `
    <section id="compareTray" class="compare-tray ${items.length ? "" : "empty"}" aria-label="Pinned evidence comparison">
      <div class="compare-heading">
        <div>
          <p class="eyebrow">compare tray</p>
          <h3>A/B 자료 비교</h3>
        </div>
        <div class="detail-actions">
          <span class="status-pill">${items.length}/${COMPARE_LIMIT}</span>
          <button class="secondary-button" type="button" data-open-compare-diff ${items.length >= 2 ? "" : "disabled"}>Text diff A/B</button>
          <button class="secondary-button" type="button" data-clear-compare ${items.length ? "" : "disabled"}>Clear</button>
        </div>
      </div>
      ${items.length ? renderCompareItems(primary, items.slice(2)) : '<p class="empty-state">검색 결과나 뷰어에서 “Pin compare”를 눌러두면 탭을 오가도 자료가 여기 남습니다.</p>'}
      <section id="compareDiffPanel"></section>
    </section>
  `;
}

function renderCompareItems(primaryItems, overflowItems) {
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

function renderCompareSlot(item, index) {
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
        <button class="icon-action" type="button" data-remove-compare-path="${escapeHtml(item.path)}">Remove</button>
      </div>
      <h4>${escapeHtml(item.title || fileName(item.path))}</h4>
      <div class="viewer-meta">
        <span>${escapeHtml(item.source || "source")}</span>
        <span>${escapeHtml(item.kind || "")}</span>
      </div>
      <p>${escapeHtml(item.preview || item.path)}</p>
      <div class="review-actions">
        <button class="secondary-button" type="button" data-preview-compare-path="${escapeHtml(item.path)}">Preview ${label}</button>
        <button class="icon-action" type="button" data-copy-path="${escapeHtml(item.path)}">Copy path</button>
      </div>
    </article>
  `;
}

function refreshCompareTray() {
  const tray = detailPanel.querySelector("#compareTray");
  if (!tray) return;
  tray.outerHTML = renderCompareTray();
  bindCompareActions();
}

function bindCompareActions() {
  bindCopyButtons();
  for (const button of detailPanel.querySelectorAll("[data-compare-item]")) {
    if (button.dataset.compareBound) continue;
    button.dataset.compareBound = "1";
    button.addEventListener("click", () => {
      const item = parseCompareItem(button.dataset.compareItem);
      addCompareItem(item);
      button.textContent = "Pinned";
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

async function openCompareDiff() {
  const panel = detailPanel.querySelector("#compareDiffPanel");
  const [left, right] = getCompareItems();
  if (!panel || !left?.path || !right?.path) return;
  panel.innerHTML = '<p class="empty-state">Loading A/B text previews...</p>';
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

function renderCompareDiff(left, right) {
  if (left.preview_type !== "text" || right.preview_type !== "text") {
    return '<p class="empty-state">Text diff is available only when both pinned items have text previews.</p>';
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

function bindCopyButtons() {
  for (const button of detailPanel.querySelectorAll("[data-copy-path]")) {
    if (button.dataset.copyBound) continue;
    button.dataset.copyBound = "1";
    button.addEventListener("click", async () => {
      await navigator.clipboard?.writeText(button.dataset.copyPath || "");
      button.textContent = "Copied";
    });
  }
}

function parseCompareItem(value) {
  if (!value) return null;
  try {
    const item = JSON.parse(value);
    return item && typeof item === "object" ? item : null;
  } catch {
    return null;
  }
}

function parseJsonDataset(value) {
  if (!value) return null;
  try {
    const item = JSON.parse(value);
    return item && typeof item === "object" ? item : null;
  } catch {
    return null;
  }
}

async function previewCompareItem(path) {
  if (!path) return;
  if (!detailPanel.querySelector("#evidenceViewer")) {
    await switchTab("search");
  }
  await loadEvidencePreview(path);
}

function bindPanelActions() {
  for (const button of detailPanel.querySelectorAll("[data-open-tab]")) {
    button.addEventListener("click", async () => {
      await switchTab(button.dataset.openTab);
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-focus-case-db]")) {
    button.addEventListener("click", () => {
      detailPanel.querySelector(".case-db-panel")?.scrollIntoView({ behavior: "smooth", block: "start" });
      detailPanel.querySelector("#caseDbImportButton")?.focus();
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-page-tab]")) {
    button.addEventListener("click", async () => {
      const tab = button.dataset.pageTab;
      pageOffsets[tab] = Number(button.dataset.pageOffset || 0);
      await switchTab(tab);
    });
  }
  const reportForm = detailPanel.querySelector("#caseReportForm");
  if (reportForm) reportForm.addEventListener("submit", saveCaseReport);
  const bundleForm = detailPanel.querySelector("#reviewerBundleForm");
  if (bundleForm) bundleForm.addEventListener("submit", createReviewerBundle);
  bindCaseDbPanel();
  bindCompareActions();
  bindReviewSelectionActions();
}

function bindCaseDbPanel() {
  const importForm = detailPanel.querySelector("#caseDbImportForm");
  const searchForm = detailPanel.querySelector("#caseDbSearchForm");
  const savedSearchButton = detailPanel.querySelector("#caseDbSavedSearchButton");
  if (importForm) {
    importForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const output = detailPanel.querySelector("#caseDbResult");
      const button = detailPanel.querySelector("#caseDbImportButton");
      const formData = new FormData(importForm);
      const request = {
        database: String(formData.get("database") || ""),
        case_id: String(formData.get("case_id") || ""),
        name: String(formData.get("name") || ""),
      };
      button.disabled = true;
      button.textContent = "Preparing...";
      try {
        const payload = await ensureSelectedRunCaseDb(request);
        output.innerHTML = renderCaseDbEnsureResult(payload);
        await loadCaseDbSavedSearches(payload.database, payload.case_id);
      } catch (error) {
        output.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
      } finally {
        button.disabled = false;
        button.textContent = "Prepare Case DB";
      }
    });
  }
  if (searchForm && importForm) {
    searchForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const output = detailPanel.querySelector("#caseDbResult");
      const button = detailPanel.querySelector("#caseDbSearchButton");
      const importData = new FormData(importForm);
      const searchData = new FormData(searchForm);
      const keywords = String(searchData.get("keywords") || "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
      const source = String(searchData.get("source") || "");
      const reviewStatus = String(searchData.get("review_status") || "");
      const verificationStatus = String(searchData.get("verification_status") || "");
      const saveAs = String(searchData.get("save_as") || "").trim();
      const request = {
        database: String(importData.get("database") || ""),
        case_id: String(importData.get("case_id") || ""),
        keywords,
        sources: source ? [source] : null,
        review_status: reviewStatus || null,
        verification_status: verificationStatus || null,
        save_as: saveAs || null,
        limit: 100,
      };
      button.disabled = true;
      button.textContent = "Preparing...";
      try {
        const ensurePayload = await ensureSelectedRunCaseDb({
          database: request.database,
          case_id: request.case_id,
          name: String(importData.get("name") || ""),
        });
        request.database = ensurePayload.database;
        request.case_id = ensurePayload.case_id;
        importForm.elements.database.value = ensurePayload.database;
        importForm.elements.case_id.value = ensurePayload.case_id;
        button.textContent = "Searching...";
        const payload = await api("/api/case-db/search", { method: "POST", body: JSON.stringify(request) });
        output.innerHTML = renderCaseDbSearchResult(payload);
        rememberCaseDbKeywords(request);
        await loadCaseDbSavedSearches(request.database, request.case_id);
        bindCaseDbReviewButtons(request.database, request.case_id);
        bindCaseDbBatchButtons(request.database, request.case_id);
        bindCaseDbReportExportButton(request.database, request.case_id);
      } catch (error) {
        output.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
      } finally {
        button.disabled = false;
        button.textContent = "Search Case DB";
      }
    });
  }
  if (savedSearchButton && importForm) {
    savedSearchButton.addEventListener("click", async () => {
      const importData = new FormData(importForm);
      await loadCaseDbSavedSearches(String(importData.get("database") || ""), String(importData.get("case_id") || ""));
    });
  }
}

async function ensureSelectedRunCaseDb(request) {
  if (!selectedRunId) throw new Error("Select a completed run first.");
  return api(`/api/runs/${encodeURIComponent(selectedRunId)}/case-db/ensure`, {
    method: "POST",
    body: JSON.stringify(request),
  });
}

async function loadCaseDbSavedSearches(database, caseId) {
  const panel = detailPanel.querySelector("#caseDbSavedSearches");
  if (!panel || !database || !caseId) return;
  panel.innerHTML = '<p class="empty-state">Loading saved searches...</p>';
  try {
    const payload = await api("/api/case-db/saved-searches/list", {
      method: "POST",
      body: JSON.stringify({ database, case_id: caseId }),
    });
    panel.innerHTML = renderCaseDbSavedSearches(payload.saved_searches || []);
    bindCaseDbSavedSearchButtons();
  } catch (error) {
    panel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  }
}

function renderCaseDbSavedSearches(savedSearches) {
  const recent = getCaseDbKeywordHistory().slice(0, 6);
  if (!savedSearches.length && !recent.length) {
    return '<p class="empty-state">No saved searches yet. Search once and use “Save search as” to keep it.</p>';
  }
  return `
    <div class="review-group-header">
      <div>
        <p class="eyebrow">saved searches</p>
        <h3>Repeat useful searches without retyping</h3>
      </div>
      <span class="status-pill">${savedSearches.length}</span>
    </div>
    <div class="preset-row">
      ${savedSearches.map((item) => `
        <button class="preset-chip" type="button" data-case-db-saved-search="${escapeHtml(JSON.stringify(item))}">
          ${escapeHtml(item.name || (item.keywords || []).join(", "))}
        </button>
      `).join("")}
      ${recent.map((item) => `
        <button class="preset-chip quiet" type="button" data-case-db-keywords="${escapeHtml((item.keywords || []).join(", "))}">
          recent: ${escapeHtml((item.keywords || []).join(", "))}
        </button>
      `).join("")}
    </div>
  `;
}

function bindCaseDbSavedSearchButtons() {
  const searchForm = detailPanel.querySelector("#caseDbSearchForm");
  if (!searchForm) return;
  for (const button of detailPanel.querySelectorAll("[data-case-db-saved-search]")) {
    button.addEventListener("click", () => {
      const item = parseJsonDataset(button.dataset.caseDbSavedSearch);
      applyCaseDbSearchPreset(searchForm, item);
      searchForm.requestSubmit();
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-case-db-keywords]")) {
    button.addEventListener("click", () => {
      searchForm.elements.keywords.value = button.dataset.caseDbKeywords || "";
      searchForm.requestSubmit();
    });
  }
}

function applyCaseDbSearchPreset(form, item) {
  if (!item || typeof item !== "object") return;
  form.elements.keywords.value = (item.keywords || []).join(", ");
  form.elements.source.value = (item.sources || [])[0] || "";
  form.elements.review_status.value = item.review_status || "";
  form.elements.verification_status.value = item.verification_status || "";
}

function renderCaseDbEnsureResult(payload) {
  const summary = payload.storage?.summary || payload.import_result?.summary || {};
  return `
    <div class="metric-grid">
      ${metric("Files", summary.file_record_count)}
      ${metric("Indexed docs", summary.indexed_document_count)}
      ${metric("Artifacts", summary.artifact_count)}
      ${metric("Events", summary.event_count)}
    </div>
    <p class="help-text">${payload.imported ? "Prepared" : "Reused"} case ${escapeHtml(payload.case_id)} at ${escapeHtml(payload.database)}.</p>
  `;
}

function renderCaseDbSearchResult(payload) {
  const rows = payload.matches || [];
  const visibleRows = virtualizedRows(rows);
  const saved = payload.saved_search;
  if (!rows.length) {
    return `
      ${saved ? `<p class="help-text">Saved search: ${escapeHtml(saved.name)} (${escapeHtml(saved.citation_id)})</p>` : ""}
      <p class="empty-state">No Case DB matches found.</p>
    `;
  }
  return `
    ${saved ? `<p class="help-text">Saved search: ${escapeHtml(saved.name)} (${escapeHtml(saved.citation_id)})</p>` : ""}
    <div class="metric-grid">
      ${metric("DB matches", payload.summary?.match_count)}
      ${metric("Sources", Object.keys(payload.summary?.source_counts || {}).length)}
      ${metric("Keywords", (payload.keywords || []).length)}
      ${metric("High priority", payload.summary?.priority_counts?.high)}
    </div>
    <section class="review-selection-tray">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">batch review</p>
          <h3>Mark repetitive results together</h3>
        </div>
        <div class="detail-actions">
          <button class="secondary-button" type="button" data-case-db-select="visible">Select visible</button>
          <button class="secondary-button" type="button" data-case-db-select="low">Select low priority</button>
          <button class="secondary-button" type="button" data-case-db-batch="verify">Verify selected</button>
          <button class="secondary-button" type="button" data-case-db-batch="reject">Reject selected</button>
          <button class="secondary-button" type="button" data-case-db-export-report>Export report candidates</button>
        </div>
      </div>
      <p class="help-text">Select rows that are clearly related, then apply the same review status in one action.</p>
      <span id="caseDbBatchStatus" class="review-save-status"></span>
    </section>
    ${renderVirtualizationNotice(rows, visibleRows, "Case DB matches")}
    <table class="data-table">
      <thead><tr><th>Select</th><th>Citation</th><th>Priority</th><th>Source</th><th>Item</th><th>Review</th><th></th></tr></thead>
      <tbody>
        ${visibleRows.map((match) => {
          const review = match.review || {};
          const sourceRef = match.source_reference || {};
          const targetPayload = {
            target_type: match.target_type,
            target_id: match.target_id,
          };
          return `
            <tr data-filter="${rowText(match)}" data-case-db-priority="${escapeHtml(match.review_priority?.level || "low")}">
              <td><input type="checkbox" data-case-db-target="${escapeHtml(JSON.stringify(targetPayload))}" /></td>
              <td><strong>${escapeHtml(match.citation_id || "")}</strong><span>${escapeHtml(match.target_type || "")}:${escapeHtml(match.target_id || "")}</span></td>
              <td>${priorityBadge(match.review_priority)}<span>${escapeHtml(match.review_priority?.recommended_action || "")}</span></td>
              <td>${escapeHtml(match.source || "")}<span>${escapeHtml(match.kind || "")}</span></td>
              <td><strong>${escapeHtml(match.title || "")}</strong><span>${escapeHtml(match.preview || match.path || "")}</span>${sourceReferenceLine(sourceRef)}</td>
              <td>
                ${escapeHtml(review.status || "unreviewed")}
                <span>${escapeHtml(review.verification_status || "unverified")}</span>
                <span>${escapeHtml([review.assignee, review.priority].filter(Boolean).join(" · "))}</span>
              </td>
              <td class="action-stack">
                <button class="icon-action" type="button" data-case-db-review="${escapeHtml(JSON.stringify({
                  target_type: match.target_type,
                  target_id: match.target_id,
                  status: "relevant",
                  verification_status: "source_opened",
                  include_in_report: true,
                  priority: match.review_priority?.level === "high" ? "high" : "normal",
                  assignee: review.assignee || "triage",
                  note: match.preview || match.title || "",
                  tags: [match.source, match.kind].filter(Boolean),
                }))}">Verify</button>
                <button class="icon-action" type="button" data-case-db-review="${escapeHtml(JSON.stringify({
                  target_type: match.target_type,
                  target_id: match.target_id,
                  status: "excluded",
                  verification_status: "rejected",
                  include_in_report: false,
                  priority: "low",
                  assignee: review.assignee || "triage",
                  note: match.preview || match.title || "",
                  tags: [match.source, "excluded"].filter(Boolean),
                }))}">Reject</button>
              </td>
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
  `;
}

function priorityBadge(priority) {
  const level = priority?.level || "low";
  const score = priority?.score ?? 0;
  const reasons = Array.isArray(priority?.reasons) ? priority.reasons.join(" · ") : "";
  return `<span class="review-badge priority-${escapeHtml(level)}" title="${escapeHtml(reasons)}">${escapeHtml(level)} ${escapeHtml(score)}</span>`;
}

function sourceReferenceLine(reference) {
  if (!reference || !Object.keys(reference).length) return "";
  const hash = reference.source_hashes?.sha256 || reference.record_hashes?.sha256 || "";
  const parts = [
    reference.parser ? `parser ${reference.parser}${reference.parser_version ? ` v${reference.parser_version}` : ""}` : "",
    reference.source_format ? `format ${reference.source_format}` : "",
    hash ? `sha256 ${String(hash).slice(0, 12)}...` : "",
  ].filter(Boolean);
  return parts.length ? `<span class="source-reference">${escapeHtml(parts.join(" · "))}</span>` : "";
}

function bindCaseDbReportExportButton(database, caseId) {
  const button = detailPanel.querySelector("[data-case-db-export-report]");
  if (!button) return;
  button.addEventListener("click", async () => {
    const status = detailPanel.querySelector("#caseDbBatchStatus");
    button.disabled = true;
    button.textContent = "Exporting...";
    try {
      const payload = await api("/api/case-db/report-export", {
        method: "POST",
        body: JSON.stringify({ database, case_id: caseId, include_all: false, max_items: 500 }),
      });
      if (status) status.textContent = `Exported ${payload.summary?.exported_item_count || 0} report candidate(s) from Case DB.`;
    } catch (error) {
      if (status) status.textContent = `Failed: ${error.message}`;
    } finally {
      button.disabled = false;
      button.textContent = "Export report candidates";
    }
  });
}

function bindCaseDbReviewButtons(database, caseId) {
  for (const button of detailPanel.querySelectorAll("[data-case-db-review]")) {
    button.addEventListener("click", async () => {
      const payload = JSON.parse(button.dataset.caseDbReview || "{}");
      button.disabled = true;
      button.textContent = "Saving";
      try {
        await api("/api/case-db/review", {
          method: "POST",
          body: JSON.stringify({ database, case_id: caseId, reviewer: "web-ui", ...payload }),
        });
        button.textContent = "Saved";
      } catch (error) {
        button.textContent = "Failed";
        button.title = error.message;
      }
    });
  }
}

function bindCaseDbBatchButtons(database, caseId) {
  for (const button of detailPanel.querySelectorAll("[data-case-db-select]")) {
    button.addEventListener("click", () => {
      const mode = button.dataset.caseDbSelect;
      const rows = Array.from(detailPanel.querySelectorAll("tr[data-case-db-priority]"));
      let selectedCount = 0;
      for (const row of rows) {
        const checkbox = row.querySelector("[data-case-db-target]");
        if (!checkbox || row.hidden) continue;
        const shouldSelect = mode === "visible" || row.dataset.caseDbPriority === "low";
        if (shouldSelect) {
          checkbox.checked = true;
          selectedCount += 1;
        }
      }
      const status = detailPanel.querySelector("#caseDbBatchStatus");
      if (status) status.textContent = `Selected ${selectedCount} ${mode === "low" ? "low-priority" : "visible"} result(s).`;
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-case-db-batch]")) {
    button.addEventListener("click", async () => {
      const action = button.dataset.caseDbBatch;
      const targets = Array.from(detailPanel.querySelectorAll("[data-case-db-target]:checked"))
        .map((input) => JSON.parse(input.dataset.caseDbTarget || "{}"))
        .filter((item) => item.target_type && item.target_id);
      const status = detailPanel.querySelector("#caseDbBatchStatus");
      if (!targets.length) {
        if (status) status.textContent = "Select at least one result first.";
        return;
      }
      const payload = action === "reject"
        ? {
            status: "excluded",
            verification_status: "rejected",
            include_in_report: false,
            priority: "low",
            assignee: "triage",
            tags: ["batch", "excluded"],
            note: "Batch rejected from Case DB result list.",
          }
        : {
            status: "relevant",
            verification_status: "source_opened",
            include_in_report: true,
            priority: "high",
            assignee: "triage",
            tags: ["batch", "report"],
            note: "Batch verified from Case DB result list.",
          };
      button.disabled = true;
      if (status) status.textContent = `Updating ${targets.length} result(s)...`;
      try {
        const result = await api("/api/case-db/review-batch", {
          method: "POST",
          body: JSON.stringify({ database, case_id: caseId, targets, reviewer: "web-ui", ...payload }),
        });
        if (status) status.textContent = `Updated ${result.updated_count || targets.length} result(s). Re-run search to refresh review badges.`;
      } catch (error) {
        if (status) status.textContent = `Failed: ${error.message}`;
      } finally {
        button.disabled = false;
      }
    });
  }
}

function reviewSelectionStorageKey() {
  return `${REVIEW_SELECTION_STORAGE_PREFIX}${selectedRunId || "default"}`;
}

function getReviewSelection() {
  if (!storageAvailable()) return [];
  try {
    const payload = JSON.parse(window.localStorage.getItem(reviewSelectionStorageKey()) || "[]");
    return Array.isArray(payload) ? payload.map(String).filter(Boolean) : [];
  } catch {
    return [];
  }
}

function setReviewSelection(ids) {
  if (!storageAvailable()) return;
  window.localStorage.setItem(reviewSelectionStorageKey(), JSON.stringify(Array.from(new Set(ids.map(String).filter(Boolean)))));
}

function bindReviewSelectionActions() {
  for (const button of detailPanel.querySelectorAll("[data-toggle-review-selection]")) {
    if (button.dataset.selectionBound) continue;
    button.dataset.selectionBound = "1";
    button.addEventListener("click", () => {
      const bookmarkId = button.dataset.toggleReviewSelection;
      const current = getReviewSelection();
      const next = current.includes(bookmarkId)
        ? current.filter((item) => item !== bookmarkId)
        : [...current, bookmarkId];
      setReviewSelection(next);
      refreshReviewSelectionUi();
    });
  }
  const clearButton = detailPanel.querySelector("[data-clear-review-selection]");
  if (clearButton && !clearButton.dataset.selectionBound) {
    clearButton.dataset.selectionBound = "1";
    clearButton.addEventListener("click", () => {
      setReviewSelection([]);
      refreshReviewSelectionUi();
    });
  }
}

function bindKeyboardShortcuts() {
  document.addEventListener("keydown", async (event) => {
    const commandShortcut = event.metaKey || event.ctrlKey;
    if (isTypingTarget(event.target) && !commandShortcut) return;
    if (event.key === "?") {
      event.preventDefault();
      toggleShortcutHelp();
      return;
    }
    if (commandShortcut && event.key.toLowerCase() === "k") {
      event.preventDefault();
      await openCaseSearch();
      return;
    }
    if (commandShortcut && event.key.toLowerCase() === "f") {
      event.preventDefault();
      focusContextSearch();
      return;
    }
    if (event.altKey && !event.metaKey && !event.ctrlKey && (event.key === "[" || event.key === "]")) {
      if (await openAdjacentSearchHit(event.key === "[" ? -1 : 1)) event.preventDefault();
      return;
    }
    if (event.altKey && !event.metaKey && !event.ctrlKey && event.key.toLowerCase() === "r") {
      if (await applyViewerReviewShortcut("relevant", true)) event.preventDefault();
      return;
    }
    if (event.altKey && !event.metaKey && !event.ctrlKey && event.key.toLowerCase() === "x") {
      if (await applyViewerReviewShortcut("not-relevant", false)) event.preventDefault();
      return;
    }
    if (event.altKey && !event.metaKey && !event.ctrlKey && event.key.toLowerCase() === "i") {
      if (toggleViewerReportShortcut()) event.preventDefault();
      return;
    }
    if (!event.metaKey && !event.ctrlKey && !event.altKey && /^[1-4]$/.test(event.key)) {
      event.preventDefault();
      await switchViewGroupByIndex(Number(event.key) - 1);
      return;
    }
    if (event.key === "[" || event.key === "]") {
      const direction = event.key === "[" ? "previous" : "next";
      if (await pageCurrentTable(direction)) event.preventDefault();
    }
  });
}

function isTypingTarget(target) {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  return tag === "input" || tag === "textarea" || tag === "select" || target.isContentEditable;
}

function toggleShortcutHelp() {
  const help = detailPanel.querySelector("#shortcutHelp");
  if (!help) return;
  help.open = !help.open;
}

async function openCaseSearch() {
  if (!selectedRunId) return;
  await switchTab("search");
  detailPanel.querySelector("#unifiedSearchInput")?.focus();
}

function focusContextSearch() {
  const fileSearchInput = detailPanel.querySelector("#fileSearchForm [name='keyword']");
  if (fileSearchInput) {
    fileSearchInput.focus();
    return;
  }
  detailPanel.querySelector("#tableFilter")?.focus();
}

async function applyViewerReviewShortcut(statusValue, includeInReport) {
  const form = detailPanel.querySelector("#viewerReviewForm");
  if (!form) return false;
  const status = form.querySelector("[name='status']");
  const includeInput = form.querySelector("[name='include_in_report']");
  if (status) status.value = statusValue;
  if (includeInput) includeInput.checked = includeInReport;
  await saveViewerReview({
    preventDefault() {},
    currentTarget: form,
  });
  return true;
}

function toggleViewerReportShortcut() {
  const form = detailPanel.querySelector("#viewerReviewForm");
  const includeInput = form?.querySelector("[name='include_in_report']");
  const status = form?.querySelector("#viewerReviewStatus");
  if (!includeInput) return false;
  includeInput.checked = !includeInput.checked;
  if (status) status.textContent = includeInput.checked ? "Include in report enabled. Save review to persist." : "Include in report disabled. Save review to persist.";
  return true;
}

async function openAdjacentSearchHit(delta) {
  if (activeTab !== "search") return false;
  const buttons = Array.from(detailPanel.querySelectorAll("[data-view-source-path][data-search-result-index]"));
  if (!buttons.length) return false;
  const viewer = detailPanel.querySelector("#evidenceViewer");
  const current = Number(viewer?.dataset.currentSearchResultIndex ?? buttons[0].dataset.searchResultIndex ?? 0);
  const nextIndex = Math.max(0, Math.min(buttons.length - 1, current + delta));
  const button = buttons.find((item) => Number(item.dataset.searchResultIndex) === nextIndex) || buttons[nextIndex];
  if (!button) return false;
  await loadEvidencePreview(button.dataset.viewSourcePath, parseReviewContext(button.dataset.reviewContext), button.dataset.searchResultIndex);
  button.closest("tr")?.scrollIntoView({ behavior: "smooth", block: "center" });
  return true;
}

async function switchViewGroupByIndex(index) {
  if (!selectedRunId || !VIEW_GROUPS[index]) return;
  const nextTab = VIEW_GROUPS[index].tabs[0];
  await switchTab(nextTab);
}

async function pageCurrentTable(direction) {
  if (!["timeline", "artifacts", "files", "docs"].includes(activeTab)) return false;
  const selector = `[data-page-tab="${CSS.escape(activeTab)}"]`;
  const buttons = Array.from(detailPanel.querySelectorAll(selector));
  const button = buttons.find((item) => item.textContent.toLowerCase().includes(direction));
  if (!button || button.disabled) return false;
  button.click();
  return true;
}

function refreshReviewSelectionUi() {
  const selectedIds = getReviewSelection();
  for (const card of detailPanel.querySelectorAll("[data-review-card-id]")) {
    const selected = selectedIds.includes(card.dataset.reviewCardId);
    card.classList.toggle("selected", selected);
    const button = card.querySelector("[data-toggle-review-selection]");
    if (button) button.textContent = selected ? "Selected" : "Select";
  }
  if (activeTab === "review") {
    void renderActiveTab();
  }
}

async function switchTab(tab) {
  if (!tab) return;
  activeTab = tab;
  const nextGroup = groupForTab(tab);
  const tabIsVisible = Array.from(detailPanel.querySelectorAll(".tab-button")).some((item) => item.dataset.tab === tab);
  if (activeViewGroup !== nextGroup || !tabIsVisible) {
    activeViewGroup = nextGroup;
    detailPanel.innerHTML = renderDetailShell(selectedRun, activeTab);
    bindTabButtons();
    await renderActiveTab();
    return;
  }
  for (const item of detailPanel.querySelectorAll(".tab-button")) {
    item.classList.toggle("active", item.dataset.tab === tab);
  }
  await renderActiveTab();
}

function viewGroupById(groupId) {
  return VIEW_GROUPS.find((group) => group.id === groupId) || VIEW_GROUPS[0];
}

function tabsForGroup(groupId) {
  return viewGroupById(groupId).tabs;
}

function groupForTab(tab) {
  return VIEW_GROUPS.find((group) => group.tabs.includes(tab))?.id || "triage";
}

function pagedUrl(tab) {
  const offset = pageOffsets[tab] || 0;
  return `/api/runs/${selectedRunId}/${tab}?offset=${offset}&limit=${PAGE_SIZE}`;
}

function renderPaginationNotice(pagination, tab) {
  if (!pagination) return "";
  const start = pagination.total ? pagination.offset + 1 : 0;
  const end = pagination.offset + pagination.returned;
  return `
    <div class="pagination-bar">
      <span>Showing ${start}-${end} of ${pagination.total} ${escapeHtml(tab)} row(s). Large outputs are loaded in ${pagination.limit}-row pages.</span>
    </div>
  `;
}

function renderPaginationControls(pagination, tab) {
  if (!pagination) return "";
  return `
    <div class="pagination-bar pagination-actions">
      <button class="secondary-button" type="button" data-page-tab="${escapeHtml(tab)}" data-page-offset="${pagination.previous_offset ?? 0}" ${pagination.previous_offset === null ? "disabled" : ""}>${kbd("[")} Previous page</button>
      <button class="secondary-button" type="button" data-page-tab="${escapeHtml(tab)}" data-page-offset="${pagination.next_offset ?? pagination.offset}" ${pagination.next_offset === null ? "disabled" : ""}>Next ${pagination.limit} ${kbd("]")}</button>
    </div>
  `;
}

function virtualizedRows(rows) {
  return (rows || []).slice(0, VIRTUAL_TABLE_ROW_LIMIT);
}

function renderVirtualizationNotice(rows, visibleRows, label) {
  const total = (rows || []).length;
  const visible = (visibleRows || []).length;
  if (total <= visible) return "";
  return `
    <div class="pagination-bar">
      <span data-commercial-gap="#79">Rendering ${visible} of ${total} ${escapeHtml(label)} to keep the browser responsive. Narrow the search, use filters, or page API-backed tabs for the rest.</span>
      <small>${escapeHtml(VIRTUALIZATION_ASSESSMENT.status)} · max ${VIRTUALIZATION_ASSESSMENT.row_limit} rows · ${escapeHtml(VIRTUALIZATION_ASSESSMENT.commercial_gap_ids.join(","))}</small>
    </div>
  `;
}

function storageAvailable() {
  try {
    window.localStorage.setItem("rapidtriage.storage-test", "1");
    window.localStorage.removeItem("rapidtriage.storage-test");
    return true;
  } catch {
    return false;
  }
}

function hydrateRunForm() {
  if (!storageAvailable()) return;
  const saved = JSON.parse(window.localStorage.getItem(RUN_FORM_STORAGE_KEY) || "{}");
  for (const [selector, key] of [
    ["#rootInput", "root"],
    ["#modeInput", "mode"],
    ["#inputKindInput", "inputKind"],
    ["#outputInput", "outputDir"],
    ["#processingProfileInput", "processingProfile"],
    ["#collectProfileInput", "collectProfile"],
    ["#maxExtractMbInput", "maxExtractMb"],
    ["#maxFileCountInput", "maxFileCount"],
    ["#importOutputInput", "importOutputDir"],
  ]) {
    const element = document.querySelector(selector);
    if (element && saved[key] !== undefined) element.value = saved[key];
  }
  for (const [selector, key] of [
    ["#readOnlyInput", "readOnly"],
    ["#dryRunInput", "dryRun"],
    ["#overwriteInput", "overwrite"],
  ]) {
    const element = document.querySelector(selector);
    if (element && saved[key] !== undefined) element.checked = Boolean(saved[key]);
  }
}

function persistRunForm() {
  if (!storageAvailable()) return;
  const payload = {
    root: document.querySelector("#rootInput")?.value || "",
    mode: document.querySelector("#modeInput")?.value || "fraud",
    inputKind: document.querySelector("#inputKindInput")?.value || "",
    outputDir: document.querySelector("#outputInput")?.value || "",
    processingProfile: document.querySelector("#processingProfileInput")?.value || "fast",
    collectProfile: document.querySelector("#collectProfileInput")?.value || "intrusion",
    maxExtractMb: document.querySelector("#maxExtractMbInput")?.value || "0",
    maxFileCount: document.querySelector("#maxFileCountInput")?.value || "0",
    importOutputDir: document.querySelector("#importOutputInput")?.value || "",
    readOnly: document.querySelector("#readOnlyInput")?.checked ?? true,
    dryRun: document.querySelector("#dryRunInput")?.checked ?? false,
    overwrite: document.querySelector("#overwriteInput")?.checked ?? false,
  };
  window.localStorage.setItem(RUN_FORM_STORAGE_KEY, JSON.stringify(payload));
}

function bindRunFormPersistence() {
  for (const selector of [
    "#rootInput",
    "#modeInput",
    "#inputKindInput",
    "#outputInput",
    "#processingProfileInput",
    "#collectProfileInput",
    "#maxExtractMbInput",
    "#maxFileCountInput",
    "#importOutputInput",
    "#readOnlyInput",
    "#dryRunInput",
    "#overwriteInput",
  ]) {
    document.querySelector(selector)?.addEventListener("input", persistRunForm);
    document.querySelector(selector)?.addEventListener("change", persistRunForm);
    document.querySelector(selector)?.addEventListener("input", refreshRunPlanPreview);
    document.querySelector(selector)?.addEventListener("change", refreshRunPlanPreview);
  }
  document.querySelector("#processingProfileInput")?.addEventListener("change", applyProcessingProfile);
  collectPlanButton?.addEventListener("click", previewCollectPlan);
}

function applyProcessingProfile() {
  const profile = document.querySelector("#processingProfileInput")?.value || "fast";
  const readOnly = document.querySelector("#readOnlyInput");
  const maxExtractMb = document.querySelector("#maxExtractMbInput");
  const maxFileCount = document.querySelector("#maxFileCountInput");
  const overwrite = document.querySelector("#overwriteInput");
  if (profile === "fast") {
    if (readOnly) readOnly.checked = true;
    if (maxExtractMb) maxExtractMb.value = "0";
    if (maxFileCount) maxFileCount.value = "0";
    if (overwrite) overwrite.checked = false;
  }
  if (profile === "standard") {
    if (readOnly) readOnly.checked = false;
    if (maxExtractMb) maxExtractMb.value = "512";
    if (maxFileCount) maxFileCount.value = "1000";
    if (overwrite) overwrite.checked = false;
  }
  if (profile === "deep") {
    if (readOnly) readOnly.checked = false;
    if (maxExtractMb) maxExtractMb.value = "0";
    if (maxFileCount) maxFileCount.value = "0";
  }
  persistRunForm();
  refreshRunPlanPreview();
}

function refreshRunPlanPreview() {
  const target = document.querySelector("#runPlanPreview");
  if (!target) return;
  const profileKey = document.querySelector("#processingProfileInput")?.value || "fast";
  const profile = PROCESSING_PROFILES[profileKey] || PROCESSING_PROFILES.fast;
  const readOnly = document.querySelector("#readOnlyInput")?.checked ?? true;
  const dryRun = document.querySelector("#dryRunInput")?.checked ?? false;
  const maxExtractBytes = extractLimitBytes();
  const maxFiles = Number(document.querySelector("#maxFileCountInput")?.value || 0);
  const mode = document.querySelector("#modeInput")?.value || "fraud";
  const collectors = RUN_MODE_COLLECTORS[mode] || RUN_MODE_COLLECTORS.fraud;
  const badges = [
    ...profile.badges,
    readOnly ? "read-only" : "extract allowed",
    dryRun ? "dry-run" : "writes output",
  ];
  target.innerHTML = `
    <p class="eyebrow">run plan preview</p>
    <h3>${escapeHtml(profile.title)} · ${escapeHtml(titleCase(mode))}</h3>
    <p>${escapeHtml(profile.summary)}</p>
    <p>Collectors: ${collectors.map((collector) => `<code>${escapeHtml(collector)}</code>`).join(" ")}</p>
    <div class="processing-caps">
      ${badges.map((badge) => `<span>${escapeHtml(badge)}</span>`).join("")}
      <span>Max extract: ${maxExtractBytes ? formatBytes(maxExtractBytes) : "uncapped/none"}</span>
      <span>Max files: ${Number.isFinite(maxFiles) && maxFiles > 0 ? formatNumber(maxFiles) : "uncapped/none"}</span>
    </div>
  `;
}

function extractLimitBytes() {
  const mb = Number(document.querySelector("#maxExtractMbInput")?.value || 0);
  if (!Number.isFinite(mb) || mb <= 0) return 0;
  return Math.floor(mb * 1024 * 1024);
}

async function previewCollectPlan() {
  const target = document.querySelector("#collectPlanPreview");
  const root = document.querySelector("#rootInput")?.value || "";
  const profile = document.querySelector("#collectProfileInput")?.value || "intrusion";
  const inputKind = document.querySelector("#inputKindInput")?.value || null;
  if (!target) return;
  if (!root.trim()) {
    target.innerHTML = '<p class="empty-state">Enter a mounted/exported evidence root first.</p>';
    return;
  }
  collectPlanButton.disabled = true;
  collectPlanButton.textContent = "Previewing...";
  target.innerHTML = '<p class="empty-state">Checking high-value target paths...</p>';
  try {
    const payload = await api("/api/collect/plan", {
      method: "POST",
      body: JSON.stringify({ root, profile, input_kind: inputKind }),
    });
    target.innerHTML = renderCollectPlanPreview(payload);
  } catch (error) {
    target.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    collectPlanButton.disabled = false;
    collectPlanButton.textContent = "Preview collection targets";
  }
}

function renderCollectPlanPreview(payload) {
  const summary = payload.summary || {};
  const categoryCounts = summary.category_counts || {};
  const presentTargets = (payload.targets || []).filter((target) => target.exists).slice(0, 8);
  const exportCommand = `rapidtriage collect-export ${shellQuote(payload.root || "ROOT")} ./collect-export --profile ${shellQuote(payload.profile || "intrusion")} --copy`;
  return `
    <div class="processing-caps">
      <span>Profile: ${escapeHtml(payload.profile || "")}</span>
      <span>Present: ${formatNumber(summary.present_count || 0)}</span>
      <span>Missing: ${formatNumber(summary.missing_count || 0)}</span>
      <span>Total targets: ${formatNumber(summary.target_count || 0)}</span>
    </div>
    <div class="processing-step-grid">
      ${Object.entries(categoryCounts).map(([category, counts]) => `
        <article class="processing-step ${counts.present_count ? "none" : "notice"}">
          <div>
            <strong>${escapeHtml(category)}</strong>
            <span>${formatNumber(counts.present_count || 0)}/${formatNumber(counts.target_count || 0)}</span>
          </div>
          <p>${formatNumber(counts.missing_count || 0)} missing targets</p>
        </article>
      `).join("")}
    </div>
    ${presentTargets.length ? `
      <div class="dense-list">
        ${presentTargets.map((target) => `
          <div class="dense-row">
            <strong>${escapeHtml(target.label || target.relative_path || "target")}</strong>
            <span>${escapeHtml(target.relative_path || target.path || "")}</span>
          </div>
        `).join("")}
      </div>
    ` : '<p class="empty-state">No target paths were found for this profile.</p>'}
    <div class="command-list">
      <code>${escapeHtml(exportCommand)}</code>
      <code>rapidtriage run ./collect-export/evidence --mode hacking --read-only</code>
    </div>
  `;
}

function shellQuote(value) {
  const text = String(value || "");
  if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(text)) return text;
  return `'${text.replace(/'/g, "'\\''")}'`;
}

function searchStorageKey() {
  return `${SEARCH_STORAGE_PREFIX}${selectedRunId || "default"}`;
}

function searchHistoryStorageKey() {
  return `${SEARCH_HISTORY_PREFIX}${selectedRunId || "default"}`;
}

function caseDbHistoryStorageKey() {
  return `${SEARCH_HISTORY_PREFIX}caseDb.${selectedRunId || "default"}`;
}

function getSearchDraft() {
  if (!storageAvailable()) return { keywords: [], ocr: true, source: "", extension: "", path_contains: "" };
  try {
    const payload = JSON.parse(window.localStorage.getItem(searchStorageKey()) || "{}");
    return {
      keywords: Array.isArray(payload.keywords) ? payload.keywords : [],
      ocr: payload.ocr !== false,
      source: payload.source || "",
      extension: payload.extension || "",
      path_contains: payload.path_contains || "",
    };
  } catch {
    return { keywords: [], ocr: true, source: "", extension: "", path_contains: "" };
  }
}

function setSearchDraft(payload) {
  if (!storageAvailable()) return;
  window.localStorage.setItem(searchStorageKey(), JSON.stringify(payload));
}

function getSearchHistory() {
  if (!storageAvailable()) return [];
  try {
    const payload = JSON.parse(window.localStorage.getItem(searchHistoryStorageKey()) || "[]");
    return Array.isArray(payload) ? payload.filter((item) => Array.isArray(item.keywords)) : [];
  } catch {
    return [];
  }
}

function rememberSearchKeywords(entry) {
  if (!storageAvailable()) return;
  const normalized = {
    keywords: (entry.keywords || []).map(String).filter(Boolean),
    source: entry.source || "",
    extension: entry.extension || "",
    path_contains: entry.path_contains || "",
    updated_at: new Date().toISOString(),
  };
  const signature = JSON.stringify({
    keywords: normalized.keywords.map((item) => item.toLowerCase()),
    source: normalized.source,
    extension: normalized.extension,
    path_contains: normalized.path_contains,
  });
  const history = getSearchHistory().filter((item) => {
    const itemSignature = JSON.stringify({
      keywords: (item.keywords || []).map((keyword) => String(keyword).toLowerCase()),
      source: item.source || "",
      extension: item.extension || "",
      path_contains: item.path_contains || "",
    });
    return itemSignature !== signature;
  });
  window.localStorage.setItem(searchHistoryStorageKey(), JSON.stringify([normalized, ...history].slice(0, 12)));
}

function getCaseDbKeywordHistory() {
  if (!storageAvailable()) return [];
  try {
    const payload = JSON.parse(window.localStorage.getItem(caseDbHistoryStorageKey()) || "[]");
    return Array.isArray(payload) ? payload.filter((item) => Array.isArray(item.keywords)) : [];
  } catch {
    return [];
  }
}

function rememberCaseDbKeywords(entry) {
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

runForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  runButton.disabled = true;
  runButton.textContent = "Starting...";
  const request = {
    root: document.querySelector("#rootInput").value,
    mode: document.querySelector("#modeInput").value,
    output_dir: document.querySelector("#outputInput").value || null,
    input_kind: document.querySelector("#inputKindInput").value || null,
    read_only: document.querySelector("#readOnlyInput").checked,
    dry_run: document.querySelector("#dryRunInput").checked,
    overwrite: document.querySelector("#overwriteInput").checked,
    max_extract_size_bytes: extractLimitBytes(),
    max_file_count: Number(document.querySelector("#maxFileCountInput")?.value || 0),
  };
  try {
    const run = await api("/api/runs", { method: "POST", body: JSON.stringify(request) });
    selectedRunId = run.run_id;
    activeTab = "summary";
    await loadRuns();
    await loadRunDetail(run.run_id, activeTab);
  } catch (error) {
    detailPanel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    runButton.disabled = false;
    runButton.textContent = "Start run";
  }
});

refreshButton.addEventListener("click", loadRuns);

importForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const outputDir = document.querySelector("#importOutputInput").value.trim();
  if (!outputDir) return;
  importButton.disabled = true;
  importButton.textContent = "Importing...";
  try {
    const run = await api("/api/runs/import", {
      method: "POST",
      body: JSON.stringify({ output_dir: outputDir }),
    });
    selectedRunId = run.run_id;
    activeTab = "summary";
    await loadRuns();
    await loadRunDetail(run.run_id, activeTab);
  } catch (error) {
    detailPanel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    importButton.disabled = false;
    importButton.textContent = "Import results";
  }
});

sampleRunButton?.addEventListener("click", async () => {
  sampleRunButton.disabled = true;
  sampleRunButton.textContent = "Creating sample...";
  detailPanel.innerHTML = `
    <section class="empty-state-card">
      <p class="eyebrow">sample case</p>
      <h3>Creating a safe practice case</h3>
      <p>샘플 증거를 만들고 read-only triage를 실행하는 중입니다. 보통 몇 초 안에 완료됩니다.</p>
    </section>
  `;
  try {
    const payload = await api("/api/sample-case/run", {
      method: "POST",
      body: JSON.stringify({ overwrite: true, read_only: true, mode: "fraud" }),
    });
    selectedRunId = payload.run.run_id;
    activeTab = "summary";
    await loadRuns();
    await loadRunDetail(payload.run.run_id, activeTab);
  } catch (error) {
    detailPanel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    sampleRunButton.disabled = false;
    sampleRunButton.textContent = "Run sample case";
  }
});

doctorButton?.addEventListener("click", async () => {
  doctorButton.disabled = true;
  doctorButton.textContent = "Checking...";
  try {
    const payload = await api("/api/doctor");
    detailPanel.innerHTML = renderDoctorPanel(payload);
  } catch (error) {
    detailPanel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    doctorButton.disabled = false;
    doctorButton.textContent = "Check runtime";
  }
});

evidenceCheckButton?.addEventListener("click", checkEvidenceSupport);

async function checkEvidenceSupport() {
  const root = document.querySelector("#rootInput")?.value?.trim();
  if (!root) {
    evidenceCheckStatus.textContent = "Enter a folder or evidence image path first.";
    return;
  }
  evidenceCheckButton.disabled = true;
  evidenceCheckButton.textContent = "Checking...";
  evidenceCheckStatus.textContent = "Inspecting evidence adapter support...";
  try {
    const payload = await api("/api/evidence/identify", {
      method: "POST",
      body: JSON.stringify({ path: root }),
    });
    evidenceCheckStatus.innerHTML = renderEvidenceCheckStatus(payload.result || {});
  } catch (error) {
    evidenceCheckStatus.textContent = error.message;
  } finally {
    evidenceCheckButton.disabled = false;
    evidenceCheckButton.textContent = "Check evidence support";
  }
}

function renderEvidenceCheckStatus(result) {
  const support = result.supported ? "supported" : "not supported";
  const action = result.can_extract || result.can_mount ? "direct handling available" : "mount/export first";
  const missing = (result.missing_tools || []).length ? ` Missing tools: ${(result.missing_tools || []).join(", ")}.` : "";
  return `
    <strong>${escapeHtml((result.detected_format || "unknown").toUpperCase())}</strong>
    · ${escapeHtml(result.adapter || "adapter")}
    · ${escapeHtml(support)}
    · ${escapeHtml(action)}.
    ${escapeHtml(result.message || "")}${escapeHtml(missing)}
  `;
}

function renderDoctorPanel(payload) {
  const checks = payload.checks || [];
  return `
    <section class="guidance-card">
      <p class="eyebrow">runtime check</p>
      <h3>RapidTriage is ${escapeHtml(payload.status || "unknown")}</h3>
      <div class="metric-grid">
        ${metric("OK", payload.summary?.ok)}
        ${metric("Warnings", payload.summary?.warn)}
        ${metric("Errors", payload.summary?.error)}
        ${metric("Checks", payload.summary?.check_count)}
      </div>
      <div class="dense-list">
        ${checks.map((check) => `
          <div class="dense-row">
            <strong>${escapeHtml(check.name || "")} · ${escapeHtml(check.status || "")}</strong>
            <span>${escapeHtml(check.summary || "")}</span>
            ${check.remediation ? `<span>${escapeHtml(check.remediation)}</span>` : ""}
          </div>
        `).join("")}
      </div>
    </section>
  `;
}

async function removeSelectedRun() {
  if (!selectedRunId) return;
  const runId = selectedRunId;
  try {
    await api(`/api/runs/${runId}`, { method: "DELETE" });
    selectedRunId = null;
    selectedRun = null;
    detailPanel.innerHTML = '<p class="empty-state">Run removed from the local catalog. Output files were not deleted.</p>';
    await loadRuns();
  } catch (error) {
    detailPanel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  }
}

hydrateRunForm();
bindRunFormPersistence();
refreshRunPlanPreview();
bindKeyboardShortcuts();
checkHealth();
loadRuns();
pollTimer = setInterval(loadRuns, 4000);
