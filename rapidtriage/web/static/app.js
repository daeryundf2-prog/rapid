const apiStatus = document.querySelector("#apiStatus");
const runForm = document.querySelector("#runForm");
const runButton = document.querySelector("#runButton");
const importForm = document.querySelector("#importForm");
const importButton = document.querySelector("#importButton");
const refreshButton = document.querySelector("#refreshButton");
const sampleRunButton = document.querySelector("#sampleRunButton");
const doctorButton = document.querySelector("#doctorButton");
const crashReportsButton = document.querySelector("#crashReportsButton");
const evidenceCheckButton = document.querySelector("#evidenceCheckButton");
const evidenceCheckStatus = document.querySelector("#evidenceCheckStatus");
const collectPlanButton = document.querySelector("#collectPlanButton");
const runList = document.querySelector("#runList");
const detailPanel = document.querySelector("#detailPanel");
const sideStagePanel = document.querySelector("#sideStagePanel");
const RUN_FORM_STORAGE_KEY = "rapidtriage.runForm.v1";
const WORKBENCH_SESSION_STORAGE_KEY = "rapidtriage.workbenchSession.v1";
const MAC_FIRST_EVIDENCE_STORAGE_KEY = "rapidtriage.macFirstEvidencePath.v1";
const SEARCH_STORAGE_PREFIX = "rapidtriage.search.";
const SEARCH_HISTORY_PREFIX = "rapidtriage.searchHistory.";
const COMPARE_STORAGE_PREFIX = "rapidtriage.compare.";
const REVIEW_SELECTION_STORAGE_PREFIX = "rapidtriage.reviewSelection.";
const VIRTUAL_WINDOW_STORAGE_PREFIX = "rapidtriage.virtualWindow.";
const VIEWER_NAVIGATION_STORAGE_PREFIX = "rapidtriage.viewerNavigation.";
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
  seizure: ["browser", "recent files", "email", "cloud", "mobile/chat", "KakaoTalk", "APK", "media", "memory", "OS/account", "event logs", "registry", "shellbags", "remote access", "execution", "prefetch", "MFT/USN", "Windows system", "macOS"],
  fraud: ["browser", "recent files", "email", "cloud", "mobile/chat", "KakaoTalk", "APK", "media", "memory", "OS/account", "event logs", "registry", "shellbags", "remote access", "execution", "prefetch", "MFT/USN", "Windows system", "macOS"],
  hacking: ["browser", "recent files", "email", "cloud", "mobile/chat", "KakaoTalk", "APK", "media", "memory", "OS/account", "event logs", "registry", "shellbags", "remote access", "execution", "prefetch", "MFT/USN", "Windows system", "macOS"],
  recovery: ["recent files", "email", "cloud", "mobile/chat", "KakaoTalk", "APK", "media", "memory", "OS/account", "event logs", "registry", "shellbags", "remote access", "prefetch", "MFT/USN", "macOS"],
};
const IMAGE_EVIDENCE_FORMATS = [
  {
    family: "ewf",
    label: "E01/Ex01",
    inputKind: "e01-derived",
    pattern: /(?:^|[\\/])[^\\/]+\.(?:e\d{2}|ex\d{2})(?:$|[\\/])/i,
  },
  {
    family: "raw",
    label: "RAW/DD/split",
    inputKind: "disk-image-derived",
    pattern: /\.(?:dd|raw|img|ima|001|000|0000|0001|00001)(?:$|[\\/])/i,
  },
  {
    family: "virtual-disk",
    label: "VHD/VMDK/QCOW",
    inputKind: "disk-image-derived",
    pattern: /\.(?:vhd|vhdx|vmdk|vdi|xva|qcow|qcow2)(?:$|[\\/])/i,
  },
  {
    family: "archive-image",
    label: "DMG/ISO/WIM",
    inputKind: "archive-image-derived",
    pattern: /\.(?:dmg|iso|wim|swm)(?:$|[\\/])/i,
  },
  {
    family: "forensic-container",
    label: "AFF/AD/L01",
    inputKind: "",
    pattern: /\.(?:aff|aff4|ad1|l01|lx01)(?:$|[\\/])/i,
  },
];
const E01_PRE_RUN_STEPS = [
  { label: "Input", text: "첫 E01/Ex01 세그먼트를 선택하고 segment order/integrity를 확인합니다." },
  { label: "Preflight", text: "ewfmount, mmls, tsk_recover 존재와 버전을 먼저 확인합니다." },
  { label: "Partition", text: "mmls 결과에서 지원 파일시스템 파티션을 자동 선택하거나 sector를 수동 지정합니다." },
  { label: "Extract", text: "read-only 우선으로 추출 provenance와 command history를 남깁니다." },
  { label: "Review", text: "추출 산출물을 검색, 뷰어, evidence tray, 보고서 후보로 이어갑니다." },
];
const PAGE_SIZE = 250;
const VIRTUAL_TABLE_ROW_LIMIT = 300;
const VIRTUALIZATION_ASSESSMENT = {
  commercial_gap_ids: ["#79"],
  status: "bounded-dom-window",
  row_limit: VIRTUAL_TABLE_ROW_LIMIT,
};
const COMPARE_LIMIT = 6;
const VIEWER_NAVIGATION_LIMIT = 30;
const COMMAND_PALETTE_RESULT_LIMIT = 12;
const GUI_CONTRACT_COPY_ALIASES = [
  `metric("Document errors", payload.summary?.document_error_count)`,
  "single-case workflow contract",
  "matched signals",
  "Find related",
  "Prepare report",
  "Do not conclude the mailbox is complete",
  "Copy citation",
];
let selectedRunId = null;
let selectedRun = null;
let activeTab = "summary";
let activeViewGroup = "triage";
let activeArtifactFilter = "";
let activeStageId = "";
let activeStageSubactionId = "";
let pollTimer = null;
let workbenchFilterTimer = null;
const pageOffsets = { timeline: 0, artifacts: 0, files: 0, docs: 0, indicators: 0 };
const virtualWindowOffsets = { search: 0, caseDb: 0 };
let currentSearchPayload = null;
let currentDocsIndexSearchPayload = null;
let currentCaseDbSearchPayload = null;

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
    const error = new Error(errorMessageFromDetail(detail.detail || detail || response.statusText));
    error.detail = detail.detail || detail;
    throw error;
  }
  const contentType = response.headers.get("content-type") || "";
  return contentType.includes("application/json") ? response.json() : response.text();
}

function errorMessageFromDetail(detail) {
  if (typeof detail === "string") return detail;
  if (detail?.message) return detail.message;
  if (detail?.source_path_resolution) {
    const resolution = detail.source_path_resolution;
    return `Source path unresolved after ${resolution.candidate_count || 0} candidate(s).`;
  }
  return String(detail || "Request failed");
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
    setStatus(apiStatus, "연결됨", "ok");
  } catch (error) {
    setStatus(apiStatus, "오프라인", "failed");
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
  document.body.classList.toggle("has-runs", Boolean(runs.length));
  document.body.classList.toggle("analysis-active", Boolean(selectedRunId));
  if (!runs.length) {
    runList.innerHTML = renderEmptyRunList();
    return;
  }
  for (const run of runs) {
    const request = run.request || {};
    const isSelected = run.run_id === selectedRunId;
    const mode = request.mode || "case";
    const root = request.root || request.output_dir || "";
    const button = document.createElement("button");
    button.type = "button";
    button.className = `run-item ${isSelected ? "selected" : ""}`;
    button.title = `${mode} · ${run.run_id} · ${run.status}`;
    button.setAttribute("aria-label", `${run.run_id} 케이스 열기, 모드 ${runModeLabel(mode)}, 상태 ${statusLabel(run.status)}`);
    button.innerHTML = `
      <span class="run-item-main">
        <span class="run-item-kicker">${escapeHtml(runModeLabel(mode))}</span>
        <strong>${escapeHtml(run.run_id)}</strong>
        <span class="run-item-path">${escapeHtml(run.origin || "web")} · ${escapeHtml(root)}</span>
      </span>
      <span class="run-item-meta">
        <span class="status-pill ${statusClass(run.status)}">${escapeHtml(statusLabel(run.status))}</span>
        <span class="run-item-open">${isSelected ? "열림" : "열기"}</span>
      </span>
    `;
    button.addEventListener("click", () => loadRunDetail(run.run_id, activeTab));
    runList.appendChild(button);
  }
}

function renderEmptyRunList() {
  return `
    <section class="empty-state-card">
      <p class="eyebrow">대기 중</p>
      <h3>아직 열린 케이스가 없습니다</h3>
      <p>증거 경로를 넣고 분석 실행을 누르거나, 샘플로 먼저 흐름을 확인하세요.</p>
      <div class="command-list">
        <code>환경 점검: 선택 도구와 런타임 확인</code>
        <code>샘플 실행: 안전한 연습 케이스 생성</code>
        <code>결과 불러오기: 기존 rapidtriage output 연결</code>
      </div>
    </section>
  `;
}

function runModeLabel(mode) {
  const labels = {
    fraud: "문서·부정 조사",
    seizure: "전수 수집",
    hacking: "침해사고",
    recovery: "복구",
    case: "케이스",
  };
  return labels[String(mode || "").toLowerCase()] || String(mode || "케이스");
}

function statusLabel(status) {
  const labels = {
    completed: "완료",
    running: "분석 중",
    queued: "대기",
    failed: "실패",
    cancelled: "취소",
    imported: "불러옴",
  };
  return labels[String(status || "").toLowerCase()] || String(status || "상태 없음");
}

async function loadRunDetail(runId, tab = "summary") {
  if (selectedRunId !== runId) {
    currentSearchPayload = null;
    currentDocsIndexSearchPayload = null;
    activeStageId = "";
    activeStageSubactionId = "";
  }
  selectedRunId = runId;
  document.body.classList.add("analysis-active");
  loadVirtualWindowOffsets();
  activeTab = tab;
  activeViewGroup = groupForTab(tab);
  selectedRun = await api(`/api/runs/${runId}`);
  if (selectedRun.status !== "completed" || !selectedRun.summary) {
    selectedRun.capabilities = null;
    detailPanel.innerHTML = renderPendingRun(selectedRun);
    persistWorkbenchSession();
    return;
  }
  selectedRun.capabilities = await loadRunCapabilities(runId);
  if (!activeStageId) activeStageId = stageIdForTab(caseStageFlow(selectedRun, activeTab, ""), activeTab);
  detailPanel.innerHTML = renderDetailShell(selectedRun, activeTab);
  updateSideStagePanel();
  bindTabButtons();
  restoreWorkbenchControls();
  bindMacFirstEvidenceControls();
  persistWorkbenchSession();
  loadRunValidationPackageSummary(runId);
  loadCommercialReadinessSummary();
  await renderActiveTab();
}

async function loadRunCapabilities(runId) {
  try {
    return await api(`/api/runs/${encodeURIComponent(runId)}/capabilities`);
  } catch {
    return null;
  }
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
  return `
    <section class="workbench-command-deck" aria-label="Case command deck">
      ${renderCaseHero(run)}
    </section>
    <div class="tab-row redundant-tab-row" aria-label="보조 탭 전환">
      ${tabs.map((item) => `<button class="tab-button ${item === tab ? "active" : ""}" data-tab="${item}" data-testid="tab-${escapeHtml(item)}" type="button">${escapeHtml(tabLabel(item))}</button>`).join("")}
    </div>
    ${renderWorkbenchLayoutFrame(run, tab)}
    <details class="workbench-intel-drawer">
      <summary>
        <span>개발/QC 진단</span>
        <strong>일반 분석에는 접어두기</strong>
      </summary>
      ${renderAdvancedDiagnosticsPanel(run, tab)}
    </details>
  `;
}

function renderAdvancedDiagnosticsPanel(run, tab) {
  const summary = run.summary?.summary || {};
  const processing = run.summary?.processing || {};
  const outputCount = Object.keys(run.summary?.outputs || {}).length;
  return `
    <section class="advanced-diagnostics-panel" data-testid="advanced-diagnostics-panel" aria-label="개발 및 검증 진단">
      <div class="advanced-diagnostics-copy">
        <p class="eyebrow">진단 전용</p>
        <h3>분석 흐름에 필요 없는 기능 상태는 여기로 분리했습니다</h3>
        <p>아래 정보는 구현 범위, 검증 상태, 성능 스모크 확인용입니다. 실제 증거 검토는 왼쪽 영역과 가운데 리뷰 화면에서 진행하세요.</p>
      </div>
      <div class="advanced-diagnostics-grid">
        ${metric("문서", summary.document_match_count)}
        ${metric("파일", summary.file_candidate_count)}
        ${metric("타임라인", summary.timeline_event_count)}
        ${metric("검증 이슈", processing.warning_count)}
        ${metric("산출물", outputCount)}
      </div>
      <details class="developer-diagnostics-drawer">
        <summary>
          <span>워크플로우/기능 구현 지도</span>
          <strong>개발자·QC용 상세 보기</strong>
        </summary>
        ${renderLazywebCommandCenter(run, tab)}
        ${renderForensicFeatureCatalog(run, tab)}
      </details>
      <details class="developer-diagnostics-drawer">
        <summary>
          <span>검증 리본 / 스모크 결과</span>
          <strong>테스트 근거 보기</strong>
        </summary>
        ${renderForensicRibbon(run)}
        ${renderWorkbenchSmokePanel(run)}
      </details>
    </section>
  `;
}

function workflowLanes() {
  if (typeof FORENSIC_WORKFLOW_LANES !== "undefined" && Array.isArray(FORENSIC_WORKFLOW_LANES)) {
    return FORENSIC_WORKFLOW_LANES;
  }
  return [];
}

function workflowLaneForTab(tab) {
  const lanes = workflowLanes();
  const groupId = groupForTab(tab);
  return lanes.find((lane) => lane.tab === tab || lane.id === groupId || (lane.id === "documents" && groupId === "documents"))
    || lanes[0]
    || { id: "triage", label: tabLabel(tab), tab, terms: [tab], modules: [] };
}

function renderWorkflowLaneBoard(run, tab) {
  const lanes = workflowLanes();
  if (!lanes.length) return "";
  const activeLane = workflowLaneForTab(tab);
  return `
    <section class="workflow-lane-board" aria-label="Forensic judgment workflows" data-testid="forensic-workflow-lanes">
      <div class="workflow-lane-board-copy">
        <p class="eyebrow">작업 모드</p>
        <h3>사건 질문별로 화면을 나눕니다</h3>
        <span>이미지 접수 후 검색, 아티팩트, 문서, 시간축으로 바로 이동합니다.</span>
      </div>
      <div class="workflow-lane-grid">
        ${lanes.map((lane) => {
          const signalCount = artifactGroupCount(run, lane.terms || [lane.tab]);
          const isActive = activeLane.id === lane.id || tab === lane.tab;
          return `
            <button class="workflow-lane-card ${isActive ? "active" : ""}" type="button" data-tab="${escapeHtml(lane.tab)}" data-workflow-lane="${escapeHtml(lane.id)}" aria-current="${isActive ? "step" : "false"}">
              <span class="workflow-lane-index">${escapeHtml(lane.shortcut || "")}</span>
              <strong>${escapeHtml(lane.label)}</strong>
              <em>${escapeHtml(lane.korean || lane.goal || "")}</em>
              <small>${escapeHtml(lane.question || "")}</small>
              <b>${formatNumber(signalCount)} signal(s)</b>
            </button>
          `;
        }).join("")}
      </div>
    </section>
  `;
}

function renderHumanActionGuide(run, tab) {
  const guide = humanActionGuideForTab(run, tab);
  return `
    <section class="human-action-guide" aria-label="Recommended next action" data-testid="human-action-guide">
      <div class="human-action-main">
        <p class="eyebrow">지금 할 일</p>
        <strong>${escapeHtml(guide.title)}</strong>
        <span>${escapeHtml(guide.body)}</span>
      </div>
      <div class="human-action-steps" aria-label="Suggested workflow">
        ${guide.steps.map((step, index) => `
          <span class="human-step-chip ${index === guide.activeStep ? "active" : ""}">
            <b>${index + 1}</b>${escapeHtml(step)}
          </span>
        `).join("")}
      </div>
      <div class="human-action-buttons">
        <button type="button" data-open-tab="${escapeHtml(guide.primaryTab)}">${escapeHtml(guide.primaryLabel)}</button>
        <button class="secondary-button" type="button" data-open-tab="${escapeHtml(guide.secondaryTab)}">${escapeHtml(guide.secondaryLabel)}</button>
      </div>
    </section>
  `;
}

function humanActionGuideForTab(run, tab) {
  const summary = run.summary?.summary || {};
  const docs = Number(summary.document_match_count || 0);
  const files = Number(summary.file_candidate_count || 0);
  const timeline = Number(summary.timeline_event_count || 0);
  const reportCandidates = Number(summary.report_item_count || 0);
  const artifactSignals = artifactGroupCount(run, ["evtx", "registry", "browser", "ai", "kakao", "mail", "message", "mft", "usn"]);
  const baseSteps = ["전체 검색", "원본 확인", "리뷰 표시", "보고서 정리"];
  const guides = {
    summary: {
      title: "먼저 전체 검색으로 사건 단서를 좁히세요",
      body: `${formatNumber(docs + files + timeline + artifactSignals)}개 후보를 바로 훑기보다 키워드로 좁히는 게 빠릅니다.`,
      primaryTab: "search",
      primaryLabel: "전체 검색 시작",
      secondaryTab: "artifacts",
      secondaryLabel: "아티팩트 보기",
      activeStep: 0,
    },
    search: {
      title: "검색어를 넣고, 결과 행을 열어 원본을 확인하세요",
      body: "결과는 증거가 아니라 후보입니다. 오른쪽 원본 뷰어에서 path, hash, locator를 확인한 뒤 리뷰로 넘기세요.",
      primaryTab: "review",
      primaryLabel: "리뷰 보드로 이동",
      secondaryTab: "artifacts",
      secondaryLabel: "관련 아티팩트 보기",
      activeStep: 1,
    },
    artifacts: {
      title: "중요 아티팩트부터 열고 검색 필터로 좁히세요",
      body: `${formatNumber(artifactSignals)}개 아티팩트 신호가 있습니다. EVTX, Registry, Browser, AI, Messenger를 먼저 확인하세요.`,
      primaryTab: "search",
      primaryLabel: "이 케이스 검색",
      secondaryTab: "timeline",
      secondaryLabel: "시간순으로 보기",
      activeStep: 1,
    },
    files: {
      title: "파일 후보는 필터 후 필요한 것만 열어보세요",
      body: `${formatNumber(files)}개 파일 후보가 있습니다. 대용량 케이스에서는 visible filter와 source filter를 먼저 쓰는 게 안전합니다.`,
      primaryTab: "search",
      primaryLabel: "파일 내용 검색",
      secondaryTab: "review",
      secondaryLabel: "선택 항목 리뷰",
      activeStep: 1,
    },
    docs: {
      title: "문서 히트는 문맥과 원본 위치를 같이 보세요",
      body: `${formatNumber(docs)}개 문서/텍스트 히트가 있습니다. 스니펫만 믿지 말고 source viewer에서 앞뒤 문맥을 확인하세요.`,
      primaryTab: "search",
      primaryLabel: "문서 재검색",
      secondaryTab: "review",
      secondaryLabel: "리뷰로 넘기기",
      activeStep: 1,
    },
    timeline: {
      title: "시간 흐름을 만든 뒤 의심 구간으로 피벗하세요",
      body: `${formatNumber(timeline)}개 타임라인 이벤트가 있습니다. 날짜 필터로 좁히고 관련 파일/로그/브라우저 흔적을 같이 여세요.`,
      primaryTab: "search",
      primaryLabel: "시간대 키워드 검색",
      secondaryTab: "artifacts",
      secondaryLabel: "아티팩트 대조",
      activeStep: 1,
    },
    indicators: {
      title: "IOC는 단독 결론보다 피벗 출발점으로 쓰세요",
      body: "IP, URL, 도메인, 해시는 관련 파일과 웹 기록, 실행 흔적까지 이어서 봐야 의미가 생깁니다.",
      primaryTab: "search",
      primaryLabel: "IOC로 검색",
      secondaryTab: "timeline",
      secondaryLabel: "시간대 확인",
      activeStep: 1,
    },
    review: {
      title: "증거 후보를 relevant / needs-review / excluded로 나누세요",
      body: `${formatNumber(reportCandidates)}개 보고서 후보가 있습니다. 확실한 항목만 include-in-report로 올리는 게 안전합니다.`,
      primaryTab: "report",
      primaryLabel: "보고서 정리",
      secondaryTab: "search",
      secondaryLabel: "더 찾기",
      activeStep: 2,
    },
    report: {
      title: "제출 전 hash, locator, limitation을 마지막으로 확인하세요",
      body: "보고서는 결론보다 출처가 중요합니다. source hash, parser version, offset/index, review state가 붙은 항목만 사용하세요.",
      primaryTab: "review",
      primaryLabel: "리뷰 상태 확인",
      secondaryTab: "summary",
      secondaryLabel: "검증 상태 보기",
      activeStep: 3,
    },
  };
  return { steps: baseSteps, ...(guides[tab] || guides.summary) };
}

function renderForensicFeatureCatalog(run, tab) {
  const catalog = typeof FORENSIC_FEATURE_CATALOG !== "undefined" ? FORENSIC_FEATURE_CATALOG : [];
  if (!catalog.length) return "";
  const totalModules = catalog.reduce((sum, item) => sum + (item.modules || []).length, 0);
  const capabilityGroups = visibleCapabilityGroupsForRun(run);
  const totalCapabilities = capabilityGroups.reduce((sum, group) => sum + (group.capabilities || []).length, 0);
  const capabilitySignals = capabilitySignalLookup(run.capabilities);
  const matchedSignals = run.capabilities?.summary?.signal_count;
  const activeModules = catalog.filter((item) => item.tab === tab);
  const visibleCards = [
    ...activeModules,
    ...catalog.filter((item) => item.tab !== tab),
  ];
  return `
    <section class="forensic-feature-catalog" aria-label="Forensic feature catalog" data-testid="forensic-feature-catalog">
      <div class="feature-catalog-head">
        <div>
          <p class="eyebrow">기능 지도</p>
          <h3>개발/QC 전용 기능 구현 지도</h3>
          <p>이 영역은 분석자가 매번 볼 화면이 아니라, 어떤 파서와 뷰어가 구현·검증됐는지 확인하는 내부 진단용입니다. 일반 검토는 왼쪽 분류와 가운데 리뷰 화면을 사용하세요.</p>
        </div>
        <div class="feature-catalog-stats" aria-label="Feature catalog totals">
          <span><strong>${formatNumber(catalog.length)}</strong> groups</span>
          <span><strong>${formatNumber(totalModules)}</strong> functions</span>
          <span><strong>${formatNumber(totalCapabilities)}</strong> visible steps</span>
          ${matchedSignals !== undefined ? `<span>일치 단서 <strong>${formatNumber(matchedSignals)}</strong>건</span>` : ""}
        </div>
      </div>
      <div class="feature-catalog-grid">
        ${visibleCards.map((item) => {
          const count = artifactGroupCount(run, item.terms || []);
          const filterTerm = item.terms?.[0] || item.id || item.label;
          return `
            <button class="feature-catalog-card ${item.tab === tab ? "active" : ""}" type="button" data-open-tab="${escapeHtml(item.tab)}" data-artifact-filter="${escapeHtml(filterTerm)}">
              <span class="feature-catalog-card-top">
                <strong>${escapeHtml(item.label)}</strong>
                <em>${formatNumber(count)} signal(s)</em>
              </span>
              <span class="feature-catalog-purpose">${escapeHtml(item.purpose || "")}</span>
              <span class="feature-module-strip">
                ${(item.modules || []).slice(0, 5).map((module) => `<i>${escapeHtml(module)}</i>`).join("")}
              </span>
              ${renderVisibleCapabilityGroups(item, capabilitySignals, capabilityGroups)}
            </button>
          `;
        }).join("")}
      </div>
    </section>
  `;
}

function visibleCapabilityGroupsForRun(run) {
  const apiGroups = run?.capabilities?.groups;
  if (Array.isArray(apiGroups) && apiGroups.length) {
    return apiGroups.map((group) => ({
      ...group,
      catalogId: group.catalogId || group.catalog_id,
      workflowStage: group.workflowStage || group.workflow_stage,
      capabilities: (group.capabilities || []).map((capability) => ({
        ...capability,
        artifactTypes: capability.artifactTypes || capability.artifact_types || [],
        guiSurfaces: capability.guiSurfaces || capability.gui_surfaces || [],
        nextAction: capability.nextAction || capability.next_action || "",
        workflowStage: capability.workflowStage || capability.workflow_stage || group.workflow_stage || group.workflowStage || "",
      })),
    }));
  }
  return typeof VISIBLE_FORENSIC_CAPABILITY_GROUPS !== "undefined" ? VISIBLE_FORENSIC_CAPABILITY_GROUPS : [];
}

function renderVisibleCapabilityGroups(item, capabilitySignals = new Map(), sourceGroups = null) {
  const allGroups = Array.isArray(sourceGroups) ? sourceGroups : visibleCapabilityGroupsForRun(null);
  const groups = allGroups.filter((group) => (group.catalogId || group.catalog_id) === item.id);
  if (!groups.length) return "";
  const statusLabels = typeof VISIBLE_CAPABILITY_STATUS_LABELS !== "undefined" ? VISIBLE_CAPABILITY_STATUS_LABELS : {};
  return `
    <span class="feature-capability-groups" aria-label="${escapeHtml(item.label)} visible capabilities">
      ${groups.map((group) => {
        const capabilities = group.capabilities || [];
        return `
          <span class="feature-capability-group">
            <span class="feature-capability-group-head">
              <b>${escapeHtml(group.label)}</b>
              <small>${formatNumber(capabilities.length)} 단계</small>
            </span>
            <span class="feature-capability-summary">${escapeHtml(group.summary || "")}</span>
            <span class="feature-capability-chip-row">
              ${capabilities.slice(0, 6).map((capability) => {
                const status = capability.status || "partial";
                const statusClassName = safeCssToken(status);
                const filterTerm = capability.terms?.[0] || capability.id || capability.label;
                const signal = capabilitySignals.get(capability.id);
                const signalCount = capability.signal_count ?? signal?.signal_count;
                const signalClass = Number(signalCount || 0) > 0 ? " has-signals" : "";
                const viewer = capability.viewer || "";
                const nextAction = capability.nextAction || capability.next_action || viewer;
                const workflowStage = capability.workflowStage || capability.workflow_stage || "";
                return `
                  <i class="feature-capability-chip status-${statusClassName}${signalClass}" data-capability-id="${escapeHtml(capability.id || "")}" data-capability-filter="${escapeHtml(filterTerm)}" data-capability-tab="${escapeHtml(capability.tab || item.tab || "artifacts")}" data-signal-count="${escapeHtml(signalCount ?? "")}" data-workflow-stage="${escapeHtml(workflowStage)}" data-viewer="${escapeHtml(viewer)}" title="${escapeHtml(nextAction)}">
                    <span>${escapeHtml(capability.label)}</span>
                    <em>${escapeHtml(statusLabels[status] || status)}</em>
                    ${signalCount !== undefined ? `<strong>${formatNumber(signalCount)}</strong>` : ""}
                  </i>
                `;
              }).join("")}
            </span>
          </span>
        `;
      }).join("")}
    </span>
  `;
}

function capabilitySignalLookup(payload) {
  const lookup = new Map();
  for (const group of payload?.groups || []) {
    for (const capability of group.capabilities || []) {
      if (capability?.id) lookup.set(capability.id, capability);
    }
  }
  return lookup;
}

function renderLazywebCommandCenter(run, tab) {
  const model = typeof LAZYWEB_WORKBENCH_MODEL !== "undefined"
    ? LAZYWEB_WORKBENCH_MODEL
    : { profile_version: "local-command-center-model", commands: [] };
  const commands = model.commands || [];
  const activeCommand = commands.find((command) => command.tab === tab) || commands[0] || {};
  const summary = run.summary?.summary || {};
  const processing = run.summary?.processing || {};
  const outputs = Object.keys(run.summary?.outputs || {});
  const signalCount = artifactGroupCount(run, [
    "evtx",
    "eventlog",
    "registry",
    "mft",
    "usn",
    "browser",
    "ai",
    "kakao",
    "email",
    "ocr",
    "timeline",
  ]);
  const metrics = [
    { label: "포렌식 단서", value: signalCount, hint: "아티팩트/검색 분류" },
    { label: "보고서 후보", value: Number(summary.report_item_count || 0), hint: "선별 완료" },
    { label: "산출물 포인터", value: outputs.length, hint: "원본 연결" },
    { label: "검증 이슈", value: Number(processing.warning_count || 0), hint: "제한사항" },
  ];
  return `
    <section class="lazyweb-command-center" aria-label="케이스 이동 패널" data-testid="lazyweb-command-center" data-model-contract="${escapeHtml(model.profile_version || "unknown")}">
      <div class="lazyweb-model-card">
        <p class="eyebrow">워크플로우 모델</p>
        <h3>화면 연결 상태를 점검합니다</h3>
        <p>증거 접수, 검색, 원본 검증, 선별, 보고 산출물이 올바른 탭과 필터로 이어지는지 확인하는 QC 패널입니다. 현재 작업은 <strong>${escapeHtml(activeCommand.label || tabLabel(tab))}</strong> 입니다.</p>
      </div>
      <div class="lazyweb-command-panel">
        <button class="lazyweb-search-command" type="button" data-command-palette-open aria-controls="commandPalette" aria-label="포렌식 명령 팔레트 열기">
          <span>빠른 이동</span>
          <strong>증거, 검색, 원본 검증, 선별, 보고서로 바로 이동</strong>
          <kbd>⌘K</kbd>
        </button>
        <div class="lazyweb-command-grid" role="list" aria-label="포렌식 작업 전환">
          ${commands.map((command) => `
            <button class="lazyweb-command-chip ${command.tab === tab ? "active" : ""}" type="button" role="listitem" data-open-tab="${escapeHtml(command.tab)}" data-artifact-filter="${escapeHtml(command.filter || "")}">
              <span>${escapeHtml(command.shortcut || "")}</span>
              <strong>${escapeHtml(command.label)}</strong>
              <em>${escapeHtml(command.hint)}</em>
            </button>
          `).join("")}
        </div>
      </div>
      <div class="lazyweb-metric-stack" aria-label="케이스 단서 요약">
        ${metrics.map((metric) => `
          <div class="lazyweb-metric">
            <strong>${formatNumber(metric.value)}</strong>
            <span>${escapeHtml(metric.label)}</span>
            <em>${escapeHtml(metric.hint)}</em>
          </div>
        `).join("")}
      </div>
    </section>
  `;
}

function renderForensicViewModeBar(run, tab) {
  return `
    <nav class="forensic-view-mode-bar" aria-label="Forensic evidence views" data-testid="forensic-view-mode-bar">
      ${FORENSIC_VIEW_MODES.map((mode) => {
        const terms = WORKBENCH_ARTIFACT_TREE_GROUPS.find((group) => group.tab === mode.tab)?.terms || [mode.tab];
        const count = artifactGroupCount(run, terms);
        return `
          <button class="forensic-view-mode ${mode.tab === tab ? "active" : ""}" type="button" data-tab="${escapeHtml(mode.tab)}" title="${escapeHtml(mode.hint)}" aria-current="${mode.tab === tab ? "page" : "false"}">
            <span>${escapeHtml(mode.icon)}</span>
            <strong>${escapeHtml(mode.label)}</strong>
            <em>${formatNumber(count)}</em>
          </button>
        `;
      }).join("")}
    </nav>
  `;
}

function renderTableControlBar(tab) {
  return `
    <section class="table-control-bar" aria-label="Large result table controls" data-testid="table-control-bar" data-control-contract="${escapeHtml(TABLE_CONTROL_CONTRACT.profile_version)}">
      <label>
        결과 내 검색
        <input id="tableFilter" placeholder="파일명, 경로, 계정, URL, 키워드" />
      </label>
      <label>
        표시 컬럼
        <select id="columnPresetInput" aria-label="Column display preset">
          <option value="analyst">분석 기본</option>
          <option value="compact">압축 보기</option>
          <option value="source">출처/인용 중심</option>
        </select>
      </label>
      <label>
        출처/아티팩트
        <input id="sourceFilterInput" placeholder="경로, provider, hive, DB" />
      </label>
      <label>
        시간 범위
        <input id="timeFilterInput" placeholder="YYYY-MM-DD 또는 시간 단서" />
      </label>
      <button id="clearFilter" type="button">필터 초기화</button>
      <span class="table-control-hint" title="filter text bounded to ${ROW_FILTER_TEXT_LIMIT} chars/row">${escapeHtml(tabLabel(tab))} · ${kbd("[")} ${kbd("]")} 페이지 이동 · 화면 행 ${VIRTUAL_TABLE_ROW_LIMIT}개 제한 · 행당 ${ROW_FILTER_TEXT_LIMIT}자까지만 필터</span>
    </section>
  `;
}

function caseStageFlow(run, tab, currentStageId = "") {
  const payload = normalizeRunPayload(run);
  const summary = payload.summary || {};
  const processing = payload.processing || {};
  const warningCount = Number(processing.warning_count || 0);
  const reportCandidates = Number(summary.report_item_count || 0);
  const docs = Number(summary.document_match_count || 0);
  const files = Number(summary.file_candidate_count || 0);
  const timeline = Number(summary.timeline_event_count || 0);
  const artifacts = artifactViewRowCount(run);
  const windowsActivity = artifactCategoryCount(run, "windows");
  const evtxCount = artifactRowGroupCount(run, ["evtx", "eventlog", "windows-event"]);
  const registryCount = artifactRowGroupCount(run, ["registry", "hive", "ntuser", "sam", "security", "system"]);
  const executionCount = artifactRowGroupCount(run, ["prefetch", "lnk", "amcache", "shimcache", "bam", "dam"]);
  const ntfsCount = artifactRowGroupCount(run, ["mft", "usn", "ntfs", "journal"]);
  const usbCount = artifactRowGroupCount(run, ["usb", "shellbag", "mount", "device", "drive"]);
  const edbCount = artifactRowGroupCount(run, ["edb", "windows-search", "ese", "srum"]);
  const browserAi = artifactCategoryCount(run, "web-ai") || artifactRowGroupCount(run, ["browser", "ai", "chatgpt", "claude", "gemini", "perplexity"]);
  const messengerMail = artifactRowGroupCount(run, ["kakao", "email", "mail", "pst", "ost", "telegram", "whatsapp", "signal"]);
  const mediaCount = artifactCategoryCount(run, "image") || artifactRowGroupCount(run, ["media", "ocr", "image", "photo", "video", "audio"]);
  const windowsSpecificCount = evtxCount + registryCount + executionCount + ntfsCount + usbCount + edbCount;
  const windowsEvidenceCount = windowsActivity || windowsSpecificCount;
  const classifiedActivity = windowsEvidenceCount + browserAi + messengerMail + mediaCount;
  const otherArtifactCount = Math.max(0, artifacts - classifiedActivity);
  const documentCount = artifactGroupCount(run, ["document", "pdf", "office", "docx", "xlsx", "pptx", "odt", "ods", "odp"]);
  const mailCount = artifactGroupCount(run, ["email", "mail", "eml", "mbox", "pst", "ost", "attachment"]);
  const messengerCount = artifactGroupCount(run, ["kakao", "whatsapp", "telegram", "signal", "line", "discord", "chat"]);
  const iocCount = artifactGroupCount(run, ["ioc", "indicator", "ip", "url", "domain", "hash"]);
  const reviewCount = reportCandidates || artifactGroupCount(run, ["review", "relevant", "citation", "report"]);
  const outputCount = Object.keys(payload.outputs || {}).length;
  const stages = [
    {
      id: "source",
      number: "1",
      label: "접수",
      title: "증거/이미지",
      body: "E01·RAW·Export, 원본 경로, 해시, 제한사항을 먼저 고정합니다.",
      tab: "summary",
      tabs: ["summary"],
      count: files || outputCount || 1,
      status: warningCount ? "검증" : "확인",
      subactions: [
        { id: "source-image", label: "이미지/E01", tab: "summary", count: files || outputCount || 1, filter: "E01 Ex01 RAW image" },
        { id: "source-extract", label: "추출 폴더", tab: "summary", count: outputCount, filter: "extract output" },
        { id: "source-hashes", label: "해시/제한", tab: "summary", count: warningCount, filter: "hash limitation" },
        { id: "source-outputs", label: "산출물 위치", tab: "summary", count: outputCount, filter: "output manifest" },
      ],
    },
    {
      id: "find",
      number: "2",
      label: "단서",
      title: "검색/단서",
      body: "키워드, URL, 계정, IOC처럼 사건 질문과 바로 연결되는 단서를 찾습니다.",
      tab: "search",
      tabs: ["search", "indicators"],
      count: docs + files + timeline + artifacts,
      status: "질의",
      subactions: [
        { id: "find-keyword-hits", label: "키워드/본문", tab: "search", count: docs, filter: "keyword document" },
        { id: "find-url-account", label: "URL/계정", tab: "search", count: browserAi + iocCount, filter: "url account browser" },
        { id: "find-ioc", label: "IOC/위험", tab: "indicators", count: iocCount, filter: "ioc indicator" },
        { id: "find-current-source", label: "현재 파일 검색", tab: "search", count: files, filter: "file path" },
      ],
    },
    {
      id: "content",
      number: "3",
      label: "검토",
      title: "자료 검토",
      body: "문서, 메일, 이미지/OCR, 메신저처럼 사람이 직접 보고 선별할 자료입니다.",
      tab: "docs",
      tabs: ["docs", "files"],
      count: docs + documentCount + mailCount + files + mediaCount + messengerMail + messengerCount,
      status: "열람",
      subactions: [
        { id: "content-docs", label: "문서/PDF", tab: "docs", count: documentCount || docs, filter: "pdf office document" },
        { id: "content-mail", label: "메일/첨부", tab: "docs", count: mailCount, filter: "mail email attachment" },
        { id: "content-images", label: "사진/OCR", tab: "files", count: mediaCount, filter: "image photo ocr", sourceCategory: "image" },
        { id: "content-video", label: "영상/오디오", tab: "files", count: artifactRowGroupCount(run, ["video", "audio"]), filter: "video audio media" },
        { id: "content-kakao", label: "KakaoTalk", tab: "artifacts", count: artifactRowGroupCount(run, ["kakao", "kakaotalk"]), filter: "kakao kakaotalk message" },
        { id: "content-messenger", label: "WhatsApp/Telegram", tab: "artifacts", count: artifactRowGroupCount(run, ["whatsapp", "telegram", "signal", "line", "discord"]), filter: "whatsapp telegram signal line discord" },
        { id: "content-mobile", label: "모바일/SMS", tab: "artifacts", count: artifactRowGroupCount(run, ["mobile", "android", "ios", "sms", "call"]), filter: "mobile android ios sms call" },
        { id: "content-reportable", label: "보고 후보", tab: "docs", count: reportCandidates, filter: "report candidate" },
      ],
    },
    {
      id: "activity",
      number: "4",
      label: "행위",
      title: "행위 흔적",
      body: "윈도우, 브라우저, 웹/AI, USB, 실행 흔적처럼 사용자의 행동을 봅니다.",
      tab: "artifacts",
      tabs: ["artifacts", "search"],
      count: artifacts,
      status: "분석",
      subactions: [
        { id: "activity-evtx", label: "EVTX", tab: "artifacts", count: evtxCount, filter: "evtx eventlog", sourceCategory: "windows" },
        { id: "activity-registry", label: "Registry/NTUSER", tab: "artifacts", count: registryCount, filter: "registry ntuser hive", sourceCategory: "windows" },
        { id: "activity-execution", label: "실행 흔적", tab: "artifacts", count: executionCount, filter: "prefetch lnk amcache shimcache", sourceCategory: "windows" },
        { id: "activity-ntfs", label: "MFT/USN", tab: "artifacts", count: ntfsCount, filter: "mft usn ntfs", sourceCategory: "windows" },
        { id: "activity-usb", label: "USB/Shellbag", tab: "artifacts", count: usbCount, filter: "usb shellbag", sourceCategory: "windows" },
        { id: "activity-edb", label: "EDB/검색", tab: "artifacts", count: edbCount, filter: "edb windows-search ese srum", sourceCategory: "windows" },
        { id: "activity-browser", label: "브라우저 기록", tab: "artifacts", count: artifactRowGroupCount(run, ["browser", "history", "chrome", "edge", "firefox", "safari"]), filter: "browser history chrome edge firefox safari", sourceCategory: "web-ai" },
        { id: "activity-download", label: "다운로드/캐시", tab: "artifacts", count: artifactRowGroupCount(run, ["download", "cache", "cookie", "session"]), filter: "download cache cookie session", sourceCategory: "web-ai" },
        { id: "activity-ai-chat", label: "AI 질문/답변", tab: "artifacts", count: artifactRowGroupCount(run, ["chatgpt", "claude", "gemini", "perplexity", "ai"]), filter: "chatgpt claude gemini perplexity ai", sourceCategory: "web-ai" },
        { id: "activity-other", label: "기타/미분류", tab: "artifacts", count: otherArtifactCount, filter: "artifact validation" },
      ],
    },
    {
      id: "timeline",
      number: "5",
      label: "시간",
      title: "타임라인",
      body: "파일, 이벤트, 웹/앱 흔적을 시간순으로 묶어 사건 흐름을 확인합니다.",
      tab: "timeline",
      tabs: ["timeline"],
      count: timeline,
      status: "정렬",
      subactions: [
        { id: "timeline-all", label: "전체 시간축", tab: "timeline", count: timeline, filter: "timeline" },
        { id: "timeline-windows", label: "윈도우 이벤트", tab: "timeline", count: evtxCount, filter: "eventlog evtx windows" },
        { id: "timeline-file-change", label: "파일 변경", tab: "timeline", count: ntfsCount + files, filter: "mft usn file" },
        { id: "timeline-web-ai", label: "웹/AI 활동", tab: "timeline", count: browserAi, filter: "browser ai url" },
        { id: "timeline-change", label: "삭제/변경", tab: "timeline", count: artifactGroupCount(run, ["deleted", "rename", "usn", "mft"]), filter: "deleted rename" },
      ],
    },
    {
      id: "deliver",
      number: "6",
      label: "보고",
      title: "리뷰/보고",
      body: "관련 있음, 재검토, 제외, 보고서 포함 상태와 citation을 고정합니다.",
      tab: "review",
      tabs: ["review", "report"],
      count: reviewCount + reportCandidates,
      status: "제출",
      subactions: [
        { id: "deliver-board", label: "리뷰보드", tab: "review", count: reviewCount, filter: "review relevant" },
        { id: "deliver-reportable", label: "보고 후보", tab: "report", count: reportCandidates, filter: "report candidate" },
        { id: "deliver-citation", label: "인용/해시", tab: "report", count: outputCount, filter: "citation hash manifest" },
        { id: "deliver-validation", label: "검증/제한", tab: "summary", count: warningCount, filter: "validation limitation" },
        { id: "deliver-outputs", label: "제출 산출물", tab: "report", count: outputCount, filter: "output bundle" },
      ],
    },
  ];
  const fallbackActiveId = stageIdForTab(stages, tab);
  const requestedStage = stages.find((stage) => stage.id === currentStageId);
  const activeId = requestedStage && requestedStage.tabs.includes(tab) ? currentStageId : fallbackActiveId;
  return stages.map((stage) => ({
    ...stage,
    active: stage.id === activeId,
  }));
}

function stageIdForTab(stages, tab) {
  return (stages || []).find((stage) => stage.tabs.includes(tab))?.id || "source";
}

function stageCountTitle(count, label = "발견 항목") {
  return `${label} ${formatNumber(count || 0)}건`;
}

function renderStageCountBadge(count, { tag = "b", className = "stage-count-badge", label = "발견 항목" } = {}) {
  const title = stageCountTitle(count, label);
  return `<${tag} class="${escapeHtml(className)}" title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}"><span>${formatNumber(count || 0)}</span><small>건</small></${tag}>`;
}

function renderCaseStageNavigator(run, tab) {
  const stages = caseStageFlow(run, tab, activeStageId);
  const capabilityGroups = visibleCapabilityGroupsForRun(run);
  const totalSubactions = stages.reduce((sum, stage) => sum + (stage.subactions || []).length, 0);
  const totalCapabilities = capabilityGroups.reduce((sum, group) => sum + (group.capabilities || []).length, 0);
  return `
    <section class="case-stage-navigator" aria-label="Case workflow stages" data-testid="case-stage-navigator">
      <div class="stage-navigator-header">
        <p class="eyebrow">분석 영역</p>
        <strong>자료 유형과 판단 목적별로 바로 이동</strong>
        <span class="stage-count-legend">숫자 = 발견 항목 수</span>
      </div>
      <div class="stage-nav-capability-summary" data-testid="stage-nav-capability-summary" aria-label="전체 기능 요약">
        <span><strong>${formatNumber(stages.length)}</strong>작업 입구</span>
        <span><strong>${formatNumber(totalSubactions)}</strong>세부 이동</span>
        <span><strong>${formatNumber(totalCapabilities)}</strong>기능 지도</span>
      </div>
      <p class="stage-nav-capability-note">기능을 줄인 것이 아니라, 분석자가 바로 판단할 수 있게 큰 동선으로 접어둔 상태입니다.</p>
      <div class="stage-navigator-list">
        ${stages.map((stage) => `
          <article class="stage-nav-item ${stage.active ? "active" : ""}" data-stage-id="${escapeHtml(stage.id)}">
            <button type="button" class="stage-nav-main" data-open-tab="${escapeHtml(stage.tab)}" data-stage-id="${escapeHtml(stage.id)}" data-nav-scope="workflow" aria-current="${stage.active ? "step" : "false"}">
              <span class="stage-nav-number">${escapeHtml(stage.number)}</span>
              <span class="stage-nav-copy">
                <em>${escapeHtml(stage.label)} · ${escapeHtml(stage.status)}</em>
                <strong>${escapeHtml(stage.title)}</strong>
                <small>${escapeHtml(stage.body)}</small>
              </span>
              ${renderStageCountBadge(stage.count)}
            </button>
            ${stage.active && stage.subactions.length ? `
              <details class="stage-nav-subactions-drawer" data-subaction-count="${escapeHtml(stage.subactions.length)}">
                <summary>
                  <span>세부 항목</span>
                  <strong>${escapeHtml(stage.subactions.length)}개</strong>
                </summary>
                <div class="stage-nav-subactions" aria-label="${escapeHtml(stage.label)} 하위 보기">
                ${stage.subactions.map((action) => {
                  const actionTabs = action.tabs || [action.tab];
                  const matchingActionIds = stage.subactions
                    .filter((candidate) => (candidate.tabs || [candidate.tab]).includes(tab))
                    .map((candidate) => candidate.id || candidate.label);
                  const fallbackActionId = matchingActionIds[0] || "";
                  const selectedActionId = matchingActionIds.includes(activeStageSubactionId) ? activeStageSubactionId : fallbackActionId;
                  const actionActive = stage.active && (action.id || action.label) === selectedActionId;
                  return `
                    <button type="button" class="stage-subaction ${actionActive ? "active" : ""}" data-open-tab="${escapeHtml(action.tab)}" data-stage-id="${escapeHtml(stage.id)}" data-stage-subaction="${escapeHtml(action.id || action.label)}" data-nav-scope="workflow" data-artifact-filter="${escapeHtml(action.filter || "")}" data-source-category-filter="${escapeHtml(action.sourceCategory || "")}" aria-current="${actionActive ? "page" : "false"}">
                      <span>${escapeHtml(action.label)}</span>
                      ${action.count !== undefined ? renderStageCountBadge(action.count, { tag: "em", className: "stage-subaction-count", label: `${action.label} 발견 항목` }) : ""}
                    </button>
                  `;
                }).join("")}
                </div>
              </details>
            ` : ""}
          </article>
        `).join("")}
      </div>
    </section>
  `;
}

function updateSideStagePanel() {
  if (!sideStagePanel) return;
  if (!selectedRun) {
    sideStagePanel.hidden = true;
    sideStagePanel.innerHTML = "";
    return;
  }
  sideStagePanel.hidden = false;
  sideStagePanel.innerHTML = renderCaseStageNavigator(selectedRun, activeTab);
  bindSideStagePanelActions();
}

function bindSideStagePanelActions() {
  if (!sideStagePanel) return;
  for (const button of sideStagePanel.querySelectorAll("[data-open-tab]")) {
    button.addEventListener("click", async () => {
      const stageId = button.dataset.stageId || activeStageId || "source";
      const stageSubactionId = button.dataset.stageSubaction || "";
      const targetTab = button.dataset.openTab || "summary";
      const sourceCategoryFilter = button.dataset.sourceCategoryFilter || "";
      const filter = button.dataset.artifactFilter || "";
      activeStageId = stageId;
      activeStageSubactionId = stageSubactionId;
      activeArtifactFilter = targetTab === "artifacts" ? sourceCategoryFilter : "";
      await switchTab(targetTab, { stageId, stageSubactionId, syncStage: true });
      applyArtifactTreeFilter(filter);
      refreshSourceNavigatorState();
    });
  }
}

function renderWorkbenchLayoutFrame(run, tab) {
  const summary = run.summary?.summary || {};
  const reportCandidates = Number(summary.report_item_count || 0);
  const activeLane = workflowLaneForTab(tab);
  return `
    <section class="case-workbench-layout judgment-workbench" aria-label="단일 케이스 검토 화면" data-testid="case-workbench-layout" data-workflow-lane="${escapeHtml(activeLane.id)}" data-placement-contract="${escapeHtml(FEATURE_PLACEMENT_CONTRACT.profile_version)}">
      <main class="workbench-result-zone primary-review-pane" aria-label="주요 증거 검토 영역" data-testid="workbench-result-table">
        <nav class="workbench-mode-strip source-navigator" aria-label="자료 유형 바로가기" data-testid="workbench-artifact-tree">
          ${renderEvidenceSourceNavigator(run, tab, { includeSourceCard: false })}
          <details class="artifact-pivot-drawer" hidden>
            <summary>아티팩트 빠른 이동</summary>
            <div class="artifact-tree-lane" data-testid="artifact-tree-lane-find">
              ${renderArtifactTreeRows(run, tab, ["윈도우", "웹 / AI", "Mail", "메신저", "모바일", "미디어 / OCR", "시간축", "검색"])}
            </div>
            <div class="artifact-tree-lane" data-testid="artifact-tree-lane-deliver">
              ${renderArtifactTreeRows(run, tab, ["보고서", "검증"])}
            </div>
          </details>
        </nav>
        ${renderForensicQuestionBar(run, tab)}
        ${renderValidationReadinessBanner(run, tab)}
        ${renderSecondaryWorkbenchControls(run, tab)}
        ${renderTableControlBar(tab)}
        <div class="workbench-region-header">
          <p class="eyebrow">검토 화면</p>
          <strong>${escapeHtml(tabLabel(tab))}</strong>
          <span>대량 결과는 cursor page와 가상 행으로 안전하게 나눠 봅니다.</span>
        </div>
        ${renderAdaptiveViewerHeader(run, tab)}
        <div id="tabBody" class="tab-body" data-testid="tab-body"></div>
      </main>
      ${renderIntelligencePanel(run, tab, reportCandidates)}
    </section>
  `;
}

function renderSecondaryWorkbenchControls(run, tab) {
  const summary = run.summary?.summary || {};
  const outputs = run.summary?.outputs || {};
  const readyCount = outputAvailabilityItems(run).filter((item) => item.status === "ready").length;
  const outputCount = Object.keys(outputs).length;
  const artifactCount = artifactViewRowCount(run);
  const docCount = Number(summary.document_match_count || 0);
  return `
    <details class="secondary-workbench-drawer" data-testid="secondary-workbench-drawer">
      <summary>
        <span>
          <strong>상태 · 피벗 · 단축키</strong>
          <em>필요할 때만 펼쳐서 봅니다</em>
        </span>
        <b>${formatNumber(readyCount)} ready · ${formatNumber(artifactCount)} artifacts · ${formatNumber(docCount)} docs · ${formatNumber(outputCount)} outputs</b>
      </summary>
      <div class="secondary-workbench-grid">
        ${renderOutputAvailabilityStrip(run, tab)}
        ${renderArtifactPivotStrip(run, tab)}
        ${renderOperatorShortcutStrip(tab)}
      </div>
    </details>
  `;
}

function renderValidationReadinessBanner(run, tab) {
  const summary = run.summary?.summary || {};
  const warningCount = Number(summary.warning_count || summary.validation_issue_count || 0);
  const reportCount = Number(summary.report_item_count || 0);
  const artifactRows = artifactViewRowCount(run);
  const status = warningCount ? "needs-validation" : "baseline";
  const label = warningCount ? `${formatNumber(warningCount)}개 검증 이슈` : "검증 이슈 0";
  return `
    <section class="validation-readiness-banner status-${safeCssToken(status)}" aria-label="검증 및 법정성 주의" data-testid="validation-readiness-banner">
      <div>
        <p class="eyebrow">검증 게이트</p>
        <strong>${escapeHtml(label)} · 원본 확인 후 판단</strong>
        <span>아티팩트 ${formatNumber(artifactRows)}개, 보고 후보 ${formatNumber(reportCount)}개. parser limitation, source hash, 원본 위치가 없는 항목은 제출 근거로 쓰지 않습니다.</span>
      </div>
      <div class="validation-gate-actions">
        <button class="secondary-button ${tab === "summary" ? "active" : ""}" type="button" data-open-tab="summary">원본/해시</button>
        <button class="secondary-button ${tab === "review" ? "active" : ""}" type="button" data-open-tab="review">선별 검증</button>
        <button class="secondary-button ${tab === "report" ? "active" : ""}" type="button" data-open-tab="report">보고 점검</button>
      </div>
    </section>
  `;
}

function renderOperatorShortcutStrip(tab) {
  const shortcuts = [
    { label: "명령/이동", keys: "Ctrl/Cmd K", action: "palette", attrs: "data-command-palette-open" },
    { label: "현재 화면 검색", keys: "Ctrl/Cmd F", action: "focus-context-search" },
    { label: "첫 결과 미리보기", keys: "Space", action: "preview-first-visible-row" },
    { label: "관련 있음 저장", keys: "Alt R", action: "mark-relevant" },
    { label: "리뷰 보드", keys: "5", action: "open-review", active: tab === "review" },
  ];
  return `
    <section class="operator-shortcut-strip" aria-label="분석 단축키" data-testid="operator-shortcut-strip">
      <strong>빠른 조작</strong>
      <div>
        ${shortcuts.map((shortcut) => `
          <button
            class="secondary-button operator-shortcut-button ${shortcut.active ? "active" : ""}"
            type="button"
            data-keyboard-action="${escapeHtml(shortcut.action)}"
            ${shortcut.attrs || ""}
          >
            <span>${escapeHtml(shortcut.label)}</span>
            ${kbd(shortcut.keys)}
          </button>
        `).join("")}
      </div>
    </section>
  `;
}

function renderArtifactPivotStrip(run, tab) {
  const pivots = artifactPivotItems(run);
  return `
    <section class="artifact-pivot-strip" aria-label="중요 아티팩트 빠른 피벗" data-testid="artifact-pivot-strip">
      <div class="artifact-pivot-title">
        <p class="eyebrow">아티팩트 피벗</p>
        <strong>행위 흔적 바로 열기</strong>
      </div>
      <div class="artifact-pivot-list">
        ${pivots.map((item) => `
          <button
            class="secondary-button artifact-pivot-chip ${artifactPivotActive(item, tab) ? "active" : ""}"
            type="button"
            data-open-tab="artifacts"
            data-nav-scope="artifact-pivot"
            data-artifact-filter="${escapeHtml(item.filter)}"
            title="${escapeHtml(item.hint)}"
          >
            <span>${escapeHtml(item.label)}</span>
            <em>${formatNumber(item.count)}</em>
          </button>
        `).join("")}
      </div>
    </section>
  `;
}

function artifactPivotItems(run) {
  const groups = [
    ["EVTX", "eventlog", ["evtx", "eventlog", "windows-event"]],
    ["Registry", "registry", ["registry", "hive", "ntuser", "sam", "security", "system"]],
    ["Browser/AI", "browser", ["browser", "history", "download", "ai", "chatgpt", "claude", "gemini", "perplexity"]],
    ["USB/외부장치", "usb", ["usb", "shellbag", "mount", "device", "drive"]],
    ["MFT/USN", "ntfs", ["mft", "usn", "ntfs", "journal"]],
    ["EDB/검색", "edb", ["edb", "windows-search", "ese", "srum"]],
    ["메신저", "messenger", ["kakao", "whatsapp", "telegram", "signal", "line", "discord", "chat"]],
    ["Media/OCR", "media", ["media", "image", "ocr", "video", "audio"]],
  ];
  return groups.map(([label, filter, terms]) => ({
    label,
    filter,
    terms,
    count: artifactGroupCount(run, terms),
    hint: `${label} 관련 parser 결과와 검증 필요 항목을 봅니다.`,
  }));
}

function artifactPivotActive(item, tab) {
  return tab === "artifacts" && String(activeArtifactFilter || "").toLowerCase() === String(item.filter || "").toLowerCase();
}

function renderOutputAvailabilityStrip(run, tab) {
  const items = outputAvailabilityItems(run);
  const issueCount = items.filter((item) => item.status !== "ready").length;
  return `
    <section class="output-availability-strip" aria-label="결과 산출물 준비 상태" data-testid="output-availability-strip">
      <div class="availability-strip-title">
        <p class="eyebrow">결과 준비 상태</p>
        <strong>열기 전에 데이터 상태 확인</strong>
        <span>${formatNumber(issueCount)}개 영역은 빈 결과/검증/선별이 더 필요합니다.</span>
      </div>
      <div class="availability-chip-list">
        ${items.map((item) => `
          <button
            class="secondary-button output-availability-chip status-${safeCssToken(item.status)} ${item.tab === tab ? "active" : ""}"
            type="button"
            data-open-tab="${escapeHtml(item.tab)}"
            data-nav-scope="availability"
            data-output-status="${escapeHtml(item.status)}"
            data-output-key="${escapeHtml(item.outputKeys.join(","))}"
            title="${escapeHtml(item.detail)}"
          >
            <span>${escapeHtml(item.label)}</span>
            <b>${formatNumber(item.count)}</b>
            <em>${escapeHtml(availabilityStatusLabel(item.status))}</em>
          </button>
        `).join("")}
      </div>
    </section>
  `;
}

function outputAvailabilityItems(run) {
  const summary = run.summary?.summary || {};
  const outputs = run.summary?.outputs || {};
  const artifactRows = artifactViewRowCount(run);
  const documentHits = Number(summary.document_match_count || 0);
  const fileCandidates = Number(summary.file_candidate_count || 0);
  const timelineEvents = Number(summary.timeline_event_count || 0);
  const reportCandidates = Number(summary.report_item_count || 0);
  const searchableSignals = artifactRows + documentHits + fileCandidates + timelineEvents;
  const artifactKeys = Object.keys(outputs).filter((key) => key.startsWith("artifacts_"));
  return [
    availabilityItem("접수/해시", "summary", Number(summary.scanned_file_count || 0), ["manifest", "fingerprint"], outputs, "증거 원본, 해시, manifest, 제한사항을 먼저 확인합니다."),
    availabilityItem("아티팩트", "artifacts", artifactRows, artifactKeys, outputs, "EVTX, Registry, Browser, AI, USB, MFT/USN parser 산출물입니다."),
    availabilityItem("문서/메일", "docs", documentHits, ["docs", "docs_index"], outputs, "문서, 메일, OCR, 본문 인덱스 산출물입니다."),
    availabilityItem("파일/미디어", "files", fileCandidates, ["files", "files_extract_manifest"], outputs, "파일 후보, 이미지/영상/해시 검토 산출물입니다."),
    availabilityItem("시간축", "timeline", timelineEvents, ["timeline"], outputs, "파일/로그/웹/앱 활동 시간축 산출물입니다."),
    availabilityItem("전체검색", "search", searchableSignals, ["docs_index", "files", "timeline", "indicators"], outputs, "키워드, 경로, URL, 계정 단서를 한 번에 찾는 검색 기반입니다."),
    availabilityItem("선별", "review", reportCandidates, ["summary"], outputs, "관련 있음, 재검토, 제외, 보고 포함 상태를 저장합니다.", { pendingWhenZero: true }),
    availabilityItem("보고서", "report", reportCandidates, ["report"], outputs, "검토된 증거를 hash/citation/limitation과 함께 제출 묶음으로 정리합니다.", { pendingWhenZero: true }),
  ];
}

function availabilityItem(label, tab, count, outputKeys, outputs, detail, options = {}) {
  const keys = (outputKeys || []).filter(Boolean);
  const present = keys.filter((key) => Object.prototype.hasOwnProperty.call(outputs, key));
  let status = "missing";
  if (present.length === keys.length && keys.length > 0) {
    status = Number(count || 0) > 0 ? "ready" : (options.pendingWhenZero ? "pending" : "empty");
  } else if (present.length > 0) {
    status = "partial";
  }
  return {
    label,
    tab,
    count: Number(count || 0),
    outputKeys: keys,
    status,
    detail,
  };
}

function availabilityStatusLabel(status) {
  const labels = {
    ready: "단서 있음",
    pending: "선별 전",
    partial: "부분 경로",
    empty: "단서 0",
    missing: "산출물 없음",
  };
  return labels[status] || status;
}

function renderForensicQuestionBar(run, tab) {
  const summary = run.summary?.summary || {};
  const questions = forensicQuestionItems(run);
  return `
    <details class="case-question-bar case-question-drawer" aria-label="포렌식 질문별 빠른 이동" data-testid="case-question-bar">
      <summary>
        <span>
          <em>질문 피벗</em>
          <strong>키워드·USB·웹/AI·문서·시간축으로 좁히기</strong>
        </span>
        <b>문서 ${formatNumber(summary.document_match_count || 0)} · 파일 ${formatNumber(summary.file_candidate_count || 0)} · 시간축 ${formatNumber(summary.timeline_event_count || 0)}</b>
      </summary>
      <div class="case-question-list">
        ${questions.map((item) => `
          <button
            class="secondary-button case-question-chip ${forensicQuestionActive(item, tab) ? "active" : ""}"
            type="button"
            data-open-tab="${escapeHtml(item.tab)}"
            data-nav-scope="case-question"
            data-artifact-filter="${escapeHtml(item.filter || "")}"
            title="${escapeHtml(item.hint)}"
          >
            <span>${escapeHtml(item.label)}</span>
            <em>${formatNumber(item.count)}</em>
          </button>
        `).join("")}
      </div>
    </details>
  `;
}

function forensicQuestionItems(run) {
  const summary = run.summary?.summary || {};
  const artifactRows = artifactViewRowCount(run);
  const documentHits = Number(summary.document_match_count || 0);
  const fileCandidates = Number(summary.file_candidate_count || 0);
  const timelineEvents = Number(summary.timeline_event_count || 0);
  const reportCandidates = Number(summary.report_item_count || 0);
  return [
    {
      label: "키워드 단서",
      tab: "search",
      filter: "",
      count: artifactRows + documentHits + fileCandidates + timelineEvents,
      hint: "전체 케이스에서 문서, 로그, OCR, 웹/AI 키워드 히트를 찾습니다.",
    },
    {
      label: "USB/반출",
      tab: "artifacts",
      filter: "usb",
      count: artifactGroupCount(run, ["usb", "shellbag", "mount", "device", "drive"]),
      hint: "USB 연결, ShellBag, 외부 저장장치, 다운로드/복사 후보를 확인합니다.",
    },
    {
      label: "웹·AI 사용",
      tab: "artifacts",
      filter: "browser ai chatgpt claude gemini perplexity",
      count: artifactGroupCount(run, ["browser", "history", "download", "ai", "chatgpt", "claude", "gemini", "perplexity"]),
      hint: "브라우저 방문, 다운로드, ChatGPT/Claude/Gemini/Perplexity 사용 흔적을 봅니다.",
    },
    {
      label: "문서·메일",
      tab: "docs",
      filter: "document email mail attachment ocr",
      count: documentHits,
      hint: "문서 본문, 메일, 첨부, OCR 히트를 리걸 리뷰 흐름으로 검토합니다.",
    },
    {
      label: "시간 재구성",
      tab: "timeline",
      filter: "timeline",
      count: timelineEvents,
      hint: "파일/로그/웹/앱 활동을 시간 순서로 맞춥니다.",
    },
    {
      label: "보고 후보",
      tab: "review",
      filter: "review report citation",
      count: reportCandidates,
      hint: "관련 있음, 재검토, 제외, 보고서 포함 상태를 정리합니다.",
    },
  ];
}

function forensicQuestionActive(item, tab) {
  if (item.tab !== tab) return false;
  if (item.tab !== "artifacts") return true;
  const filter = String(item.filter || "").toLowerCase();
  return !filter || String(activeArtifactFilter || "").toLowerCase() === filter;
}

function renderEvidenceSourceNavigator(run, tab, options = {}) {
  const summary = run.summary?.summary || {};
  const root = run.request?.root || run.summary?.output_dir || "not recorded";
  const includeSourceCard = options.includeSourceCard !== false;
  const artifactRows = artifactViewRowCount(run);
  const documentHits = Number(summary.document_match_count || 0);
  const fileCandidates = Number(summary.file_candidate_count || 0);
  const timelineEvents = Number(summary.timeline_event_count || 0);
  const reportCandidates = Number(summary.report_item_count || 0);
  const searchableSignals = artifactRows + documentHits + fileCandidates + timelineEvents;
  const sourceGroups = [
    {
      key: "artifacts",
      label: "행위흔적",
      tab: "artifacts",
      count: artifactRows,
      hint: "EVTX, Registry, USB, Browser, AI",
    },
    {
      key: "docs",
      label: "문서/메일",
      tab: "docs",
      count: documentHits,
      hint: "PDF, Office, 메일, 메신저, OCR",
    },
    {
      key: "media",
      label: "파일/미디어",
      tab: "files",
      count: fileCandidates,
      hint: "파일 후보, 이미지, 영상, 해시",
    },
    {
      key: "timeline",
      label: "시간축",
      tab: "timeline",
      count: timelineEvents,
      hint: "로그, 파일, 웹, 앱 활동 순서",
    },
    {
      key: "search",
      label: "전체검색",
      tab: "search",
      count: searchableSignals,
      hint: "키워드, 경로, 계정, URL, OCR",
    },
    {
      key: "review",
      label: "리뷰보드",
      tab: "review",
      count: reportCandidates,
      hint: "관련 있음, 재검토, 제외, 보고서 포함",
    },
    {
      key: "report",
      label: "산출물",
      tab: "report",
      count: reportCandidates,
      hint: "해시, 인용, 제한사항, 제출 산출물",
    },
  ];
  return `
    <section class="source-stack" aria-label="케이스 검토 모드" data-testid="evidence-source-stack">
      ${includeSourceCard ? `<div class="case-source-card">
        <p class="eyebrow">증거 출처</p>
        <strong>${escapeHtml(run.run_id || "current case")}</strong>
        <span title="${escapeHtml(root)}">${escapeHtml(root)}</span>
      </div>` : ""}
      ${sourceGroups.map((item) => `
        <button
          class="source-card ${sourceNavigatorItemActive(item, tab) ? "active" : ""}"
          type="button"
          data-open-tab="${escapeHtml(item.tab)}"
          data-nav-scope="source"
          data-source-key="${escapeHtml(item.key)}"
          data-source-category-filter="${escapeHtml(item.sourceCategory || "")}"
          aria-current="${sourceNavigatorItemActive(item, tab) ? "page" : "false"}"
          title="${escapeHtml(item.hint)}"
        >
          <span>
            <strong>${escapeHtml(item.label)}</strong>
            <small>${escapeHtml(item.hint)}</small>
          </span>
          <em>${formatNumber(item.count)}</em>
        </button>
      `).join("")}
    </section>
  `;
}

function sourceNavigatorItemActive(item, tab = activeTab) {
  if (item.tab !== tab) return false;
  if (item.tab !== "artifacts") return true;
  return String(item.sourceCategory || "") === String(activeArtifactFilter || "");
}

function renderAdaptiveViewerHeader(run, tab) {
  const profile = adaptiveViewerProfile(tab);
  return `
    <section class="adaptive-viewer-header" aria-label="상황별 증거 뷰어" data-testid="adaptive-evidence-viewer">
      <div>
        <p class="eyebrow">뷰어</p>
        <strong>${escapeHtml(profile.title)}</strong>
        <span>${escapeHtml(profile.body)}</span>
      </div>
      <div class="viewer-chip-row" aria-label="사용 가능한 뷰어">
        ${profile.viewers.map((viewer) => `<span>${escapeHtml(viewer)}</span>`).join("")}
      </div>
    </section>
  `;
}

function adaptiveViewerProfile(tab) {
  const profiles = {
    summary: {
      title: "증거 접수 현황",
      body: "증거 이미지와 추출 폴더의 출처, 해시, 제한사항, 마운트 필요 여부를 확인합니다.",
      viewers: ["E01 사전 확인", "해시", "원본 경로", "제한사항"],
    },
    search: {
      title: "키워드 선별 표",
      body: "전체 검색 결과를 표에서 선별하고, 선택 항목의 원본 위치와 리뷰 상태를 즉시 확인합니다.",
      viewers: ["결과 표", "본문", "현재 파일 검색", "원본 확인"],
    },
    artifacts: {
      title: "아티팩트별 행위 검토",
      body: "EVTX, Registry, Browser, AI, USB, MFT/USN을 같은 표가 아니라 아티팩트 의미별로 해석합니다.",
      viewers: ["EVTX", "Registry", "SQLite", "Browser", "Chat"],
    },
    indicators: {
      title: "IOC / 위험 단서",
      body: "IP, 도메인, URL, 해시를 단독 결론이 아닌 관련 파일/웹/시간대 피벗으로 사용합니다.",
      viewers: ["IOC 표", "관계 그래프", "시간축 피벗", "원본"],
    },
    files: {
      title: "파일 / 이미지 / Hex 확인",
      body: "대량 파일 목록을 선별한 뒤 이미지, 텍스트, hex 미리보기로 필요한 항목만 확인합니다.",
      viewers: ["파일 표", "이미지", "본문", "Hex", "해시"],
    },
    docs: {
      title: "문서 검토",
      body: "Relativity/Everlaw식 검토 흐름으로 문서, 메일, 메신저, OCR 히트를 태깅하고 보고서 후보화합니다.",
      viewers: ["문서", "메일", "대화", "OCR", "유사 항목"],
    },
    timeline: {
      title: "시간축 재구성",
      body: "로그/파일/웹/앱 활동을 시간대별로 묶고, 의심 구간에서 원본 아티팩트로 되돌아갑니다.",
      viewers: ["시간축", "이벤트 표", "타임존", "시계 오차", "피벗"],
    },
    review: {
      title: "증거 선별 보드",
      body: "관련 있음, 재검토, 제외, 보고서 포함 상태를 근거와 함께 고정합니다.",
      viewers: ["선별 표", "메모", "비교", "인용"],
    },
    report: {
      title: "보고서 / 제출 패키지",
      body: "선별된 증거만 해시, parser, source locator, limitation과 함께 산출물로 정리합니다.",
      viewers: ["보고서", "Manifest", "인용", "내보내기"],
    },
  };
  return profiles[tab] || profiles.summary;
}

function renderArtifactTreeRows(run, tab, labels) {
  return labels.map((label) => {
    const group = WORKBENCH_ARTIFACT_TREE_GROUPS.find((item) => item.label === label);
    if (!group) return "";
    const count = artifactGroupCount(run, group.terms);
    const filterTerm = group.terms?.[0] || group.label;
    const countLabel = count ? `단서 ${formatNumber(count)}건` : "아직 일치 단서 없음";
    return `
      <button class="artifact-tree-row ${tab === group.tab ? "active" : ""}" type="button" data-open-tab="${escapeHtml(group.tab)}" data-nav-scope="artifact-pivot" data-artifact-filter="${escapeHtml(filterTerm)}" aria-label="${escapeHtml(group.label)} 아티팩트 열기, ${escapeHtml(countLabel)}">
        <span>
          <strong>${escapeHtml(group.label)}</strong>
          <small>${escapeHtml(group.hint)}</small>
          <small class="artifact-tree-review-hint">${escapeHtml(count ? "결과 열기 및 필터" : "모듈 체크리스트 열기")}</small>
        </span>
        <em>${formatNumber(count)}</em>
      </button>
    `;
  }).join("");
}

function renderPreviewRail(run, tab, reportCandidates) {
  return renderIntelligencePanel(run, tab, reportCandidates);
}

function renderIntelligencePanel(run, tab, reportCandidates) {
  const activeLane = workflowLaneForTab(tab);
  const guide = humanActionGuideForTab(run, tab);
  const summary = run.summary?.summary || {};
  const processing = run.summary?.processing || {};
  const warningCount = Number(processing.warning_count || 0);
  const artifactSignals = artifactGroupCount(run, ["evtx", "registry", "browser", "ai", "usb", "mft", "usn", "mail", "kakao", "ocr"]);
  const documentHits = Number(summary.document_match_count || 0);
  const timelineEvents = Number(summary.timeline_event_count || 0);
  const priorityScore = Math.min(100, Math.round((warningCount * 12) + Math.min(artifactSignals, 40) + Math.min(documentHits / 5, 20) + Math.min(timelineEvents / 20, 18)));
  const keywordChips = intelligenceKeywordChips(run, tab);
  return `
    <aside class="workbench-preview-rail intelligence-panel" aria-label="검토 인사이트, 원본 확인, 선별 보관함, 보고 산출물" data-testid="workbench-preview-detail" data-preview-contract="${escapeHtml(PREVIEW_DETAIL_CONTRACT.profile_version)}">
      <section class="intel-score-card" data-testid="intelligence-panel">
        <p class="eyebrow">검토 인사이트</p>
        <strong>우선 확인 항목</strong>
        <span>${escapeHtml(activeLane.question || "현재 결과에서 확인해야 할 근거를 정리합니다.")}</span>
        <div class="intel-score-meter" style="--score:${priorityScore}">
          <b>${formatNumber(priorityScore)}</b>
          <em>검토 우선도</em>
        </div>
      </section>
      <section class="intel-action-card">
        <p class="eyebrow">권장 검토 순서</p>
        <strong>${escapeHtml(guide.title)}</strong>
        <ol>
          ${guide.steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}
        </ol>
      </section>
      ${renderIntelDrawer("기능/단서", "분석 모듈과 연결 키워드", `
        ${renderUsableCapabilityMap(run, tab)}
        <section class="intel-keyword-card">
          <p class="eyebrow">연결 단서</p>
          <div class="intel-keyword-cloud">
            ${keywordChips.map((item) => `<button type="button" data-open-tab="${escapeHtml(item.tab)}" data-nav-scope="artifact-pivot" data-artifact-filter="${escapeHtml(item.term)}">${escapeHtml(item.label)} <b>${formatNumber(item.count)}</b></button>`).join("")}
          </div>
        </section>
      `)}
      ${tab === "search" ? "" : renderIntelDrawer("빠른 원본", "선택 행 미리보기", renderWorkbenchEvidenceViewerSlot())}
      ${renderIntelDrawer("검증", "원본·해시·제한사항", `
        ${renderPreviewDetailCard(run, tab)}
        ${renderSourceLocatorCard(run)}
        ${renderHashVerificationCard(run)}
        ${renderLimitationWarningCard(run)}
      `)}
      ${renderIntelDrawer("선별/보고", `보고 후보 ${formatNumber(reportCandidates)}건`, `
        <section class="review-state-matrix" aria-label="선별 판정 상태">
          <p class="eyebrow">선별 상태</p>
          <span><b>관련 있음</b><em>보고서 후보</em></span>
          <span><b>재검토</b><em>추가 확인</em></span>
          <span><b>제외</b><em>노이즈 제거</em></span>
          <span><b>포함</b><em>제출 묶음</em></span>
        </section>
        <section class="evidence-tray-card" data-testid="evidence-tray">
          <p class="eyebrow">선별 보관함</p>
          <strong>보고서 후보 ${formatNumber(reportCandidates)}건</strong>
          <span>관련 있음, 재검토, 제외, 보고서 포함 상태를 누적합니다.</span>
          <div class="preview-action-row" data-testid="preview-review-actions">
            <button class="secondary-button" type="button" data-open-tab="review">선별 보드</button>
            <button class="secondary-button" type="button" data-open-tab="search">관련 검색</button>
          </div>
        </section>
        <section class="report-tray-card" data-testid="report-tray">
          <p class="eyebrow">보고 산출물</p>
          <strong>제출 패키지</strong>
          <span>검토된 항목만 hash manifest와 case report로 내보냅니다.</span>
          <button class="secondary-button" type="button" data-open-tab="report">보고서 열기</button>
        </section>
      `)}
    </aside>
  `;
}

function renderIntelDrawer(label, title, content) {
  return `
    <details class="intel-collapsible-card" data-testid="intel-collapsible-card">
      <summary>
        <span>
          <em>${escapeHtml(label)}</em>
          <strong>${escapeHtml(title)}</strong>
        </span>
      </summary>
      <div class="intel-collapsible-body">
        ${content}
      </div>
    </details>
  `;
}

function renderUsableCapabilityMap(run, tab) {
  const groups = visibleCapabilityGroupsForRun(run);
  if (!groups.length) return "";
  const statusLabels = typeof VISIBLE_CAPABILITY_STATUS_LABELS !== "undefined" ? VISIBLE_CAPABILITY_STATUS_LABELS : {};
  const activeLane = workflowLaneForTab(tab);
  const ordered = prioritizeCapabilityGroupsForTab(groups, activeLane, tab);
  const totals = summarizeCapabilityStatuses(groups);
  const statusOrder = ["usable", "partial", "inventory", "validation-required", "external-required"];
  return `
    <section class="capability-map-card" data-testid="usable-capability-map" aria-label="현재 사용 가능한 분석 모듈 현황">
      <div class="capability-map-head">
        <p class="eyebrow">분석 모듈 현황</p>
        <strong>지금 쓸 수 있는 분석 모듈</strong>
        <span>여기 숫자는 발견 항목이 아니라, 해당 분류에 묶인 구현 기능 수입니다.</span>
      </div>
      <div class="capability-status-row" aria-label="Capability status counts">
        ${statusOrder.filter((status) => totals[status]).map((status) => `
          <span class="capability-status-pill status-${safeCssToken(status)}">
            ${escapeHtml(statusLabels[status] || status)}
            <b>${formatNumber(totals[status])}</b>
          </span>
        `).join("")}
      </div>
      <div class="capability-map-list">
        ${ordered.slice(0, 8).map((group) => {
          const capabilities = group.capabilities || [];
          const tabTarget = capabilityGroupTab(group);
          const filterTerm = capabilityGroupFilter(group);
          return `
            <button class="secondary-button capability-map-row ${tabTarget === tab ? "active" : ""}" type="button" data-open-tab="${escapeHtml(tabTarget)}" data-nav-scope="capability-map" data-artifact-filter="${escapeHtml(filterTerm)}">
              <span>
                <strong>${escapeHtml(group.label || group.id || "기능")}</strong>
                <small>${escapeHtml(group.summary || "")}</small>
              </span>
              <em title="구현 기능 ${formatNumber(capabilities.length)}개" aria-label="구현 기능 ${formatNumber(capabilities.length)}개"><span>${formatNumber(capabilities.length)}</span><small>기능</small></em>
            </button>
          `;
        }).join("")}
      </div>
    </section>
  `;
}

function prioritizeCapabilityGroupsForTab(groups, activeLane, tab) {
  const laneTerms = new Set([...(activeLane?.terms || []), tab, activeLane?.id, activeLane?.tab].filter(Boolean).map((item) => String(item).toLowerCase()));
  return [...groups].sort((left, right) => {
    const leftScore = capabilityGroupRelevance(left, laneTerms, tab);
    const rightScore = capabilityGroupRelevance(right, laneTerms, tab);
    if (rightScore !== leftScore) return rightScore - leftScore;
    return String(left.label || left.id || "").localeCompare(String(right.label || right.id || ""));
  });
}

function capabilityGroupRelevance(group, laneTerms, tab) {
  let score = capabilityGroupTab(group) === tab ? 8 : 0;
  const text = [
    group.id,
    group.label,
    group.summary,
    group.catalogId || group.catalog_id,
    group.workflowStage || group.workflow_stage,
    ...(group.capabilities || []).flatMap((capability) => [
      capability.id,
      capability.label,
      capability.viewer,
      ...(capability.terms || []),
      ...(capability.artifactTypes || capability.artifact_types || []),
    ]),
  ].filter(Boolean).join(" ").toLowerCase();
  for (const term of laneTerms) {
    if (term && text.includes(term)) score += 2;
  }
  return score;
}

function summarizeCapabilityStatuses(groups) {
  const totals = {};
  for (const group of groups) {
    for (const capability of group.capabilities || []) {
      const status = capability.status || "partial";
      totals[status] = (totals[status] || 0) + 1;
    }
  }
  return totals;
}

function capabilityGroupTab(group) {
  const direct = group.tab || group.defaultTab || group.default_tab;
  if (direct) return direct;
  const stage = String(group.workflowStage || group.workflow_stage || group.catalogId || group.catalog_id || "").toLowerCase();
  if (stage.includes("document") || stage.includes("docs")) return "docs";
  if (stage.includes("timeline")) return "timeline";
  if (stage.includes("review") || stage.includes("report")) return "review";
  if (stage.includes("search")) return "search";
  if (stage.includes("intake") || stage.includes("evidence")) return "summary";
  return "artifacts";
}

function capabilityGroupFilter(group) {
  const firstCapability = (group.capabilities || [])[0] || {};
  return firstCapability.terms?.[0]
    || firstCapability.id
    || group.id
    || group.label
    || "";
}

function intelligenceKeywordChips(run, tab) {
  const chipDefs = [
    { label: "USB", term: "usb", tab: "artifacts", terms: ["usb", "shellbag", "mount", "device"] },
    { label: "EVTX", term: "evtx", tab: "artifacts", terms: ["evtx", "eventlog", "event id"] },
    { label: "레지스트리", term: "registry", tab: "artifacts", terms: ["registry", "ntuser", "sam", "system"] },
    { label: "브라우저", term: "browser", tab: "artifacts", terms: ["browser", "history", "download", "cookie"] },
    { label: "AI", term: "ai", tab: "artifacts", terms: ["ai", "chatgpt", "claude", "gemini", "perplexity"] },
    { label: "문서", term: "document", tab: "docs", terms: ["document", "pdf", "docx", "xlsx", "pptx", "odt", "ocr"] },
    { label: "메일", term: "email", tab: "docs", terms: ["email", "mail", "eml", "mbox", "pst", "ost"] },
    { label: "시간축", term: "timeline", tab: "timeline", terms: ["timeline", "created", "modified", "accessed"] },
  ];
  const chips = chipDefs.map((item) => ({
    ...item,
    count: artifactGroupCount(run, item.terms),
  }));
  const sorted = chips.sort((a, b) => b.count - a.count);
  const active = sorted.filter((item) => item.tab === tab || item.count > 0).slice(0, 7);
  return active.length ? active : sorted.slice(0, 6);
}

function renderWorkbenchEvidenceViewerSlot() {
  return `
    <section id="evidenceViewer" class="viewer-panel viewer-dock primary-viewer-dock" data-testid="source-viewer" role="region" aria-label="원본 미리보기" aria-live="polite" aria-busy="false">
      ${renderViewerEmptyState("빠른 원본 확인", "중앙 결과에서 행을 선택하면 본문, 메타데이터, 해시, 인용 정보, 리뷰 상태가 표시됩니다.")}
    </section>
  `;
}

function renderViewerEmptyState(title, body) {
  return `
    <div class="viewer-empty-state operator-viewer-empty" data-testid="viewer-empty-state">
      <p class="eyebrow">1-click preview</p>
      <strong>${escapeHtml(title)}</strong>
      <span>${escapeHtml(body)}</span>
      <div class="viewer-empty-checklist" aria-label="원본 검토 순서">
        <em>1 원본</em>
        <em>2 현재 파일 검색</em>
        <em>3 해시/인용</em>
        <em>4 선별</em>
      </div>
      <small>${kbd("Space")} 빠른 확인 · ${kbd("Ctrl F")} 현재 파일 검색 · ${kbd("Alt R")} 관련 있음</small>
    </div>
  `;
}

function renderPreviewDetailCard(run, tab) {
  const tabSignals = artifactGroupCount(run, WORKBENCH_ARTIFACT_TREE_GROUPS.find((group) => group.tab === tab)?.terms || [tab]);
  return `
    <section class="preview-detail-card analyst-preview-card" data-testid="preview-detail-card">
      <p class="eyebrow">선택 항목 상세</p>
      <strong>행 또는 검색 결과를 선택하세요</strong>
      <span>${escapeHtml(tabLabel(tab))} 영역에 ${formatNumber(tabSignals)}개 단서가 있습니다. 선택하면 원본 위치, 인용 정보, 리뷰 상태를 함께 확인합니다.</span>
      <div class="preview-priority-strip" data-testid="preview-analyst-summary">
        <span>1. 출처 확인</span>
        <span>2. 해시/인용</span>
        <span>3. 선별 상태</span>
      </div>
    </section>
  `;
}

function renderSourceLocatorCard(run) {
  const root = run.request?.root || run.summary?.output_dir || "not recorded";
  const outputDir = run.summary?.output_dir || "not recorded";
  return `
    <section class="preview-detail-card source-locator-card" data-testid="preview-source-locator">
      <p class="eyebrow">원본 위치</p>
      <strong>원본 위치 먼저 확인</strong>
      <span>행을 열면 절대 경로, run 기준 상대 경로, Windows 경로를 함께 해석합니다.</span>
      <details class="metadata-disclosure preview-metadata-disclosure" data-testid="preview-metadata-disclosure">
        <summary>기술 메타데이터 보기</summary>
        <dl class="preview-metadata-list">
          <dt>Run ID</dt><dd>${escapeHtml(run.run_id || "unknown")}</dd>
          <dt>Input root</dt><dd><code>${escapeHtml(root)}</code></dd>
          <dt>Output dir</dt><dd><code>${escapeHtml(outputDir)}</code></dd>
        </dl>
      </details>
    </section>
  `;
}

function renderHashVerificationCard(run) {
  const outputs = Object.keys(run.summary?.outputs || {});
  return `
    <section class="preview-detail-card hash-verification-card" data-testid="preview-hash-card">
      <p class="eyebrow">출처 / 인용</p>
      <strong>산출물 포인터 ${formatNumber(outputs.length)}개</strong>
      <span>보고서 후보는 source hash, parser version, offset/index, review state가 붙은 뒤에만 제출 묶음으로 올립니다.</span>
      <button class="secondary-button" type="button" data-open-tab="report">해시 목록 열기</button>
    </section>
  `;
}

function renderLimitationWarningCard(run) {
  const processing = run.summary?.processing || {};
  const warningCount = Number(processing.warning_count || 0);
  const label = warningCount ? `검증 이슈 ${formatNumber(warningCount)}건` : "검증 이슈 없음";
  return `
    <section class="preview-detail-card limitation-warning-card ${warningCount ? "warning" : ""}" data-testid="preview-limitation-warning">
      <p class="eyebrow">제한사항</p>
      <strong>${escapeHtml(label)}</strong>
      <span>상용급/법정 제출 판단은 validation diff, source hash, parser limitation을 같이 확인해야 합니다. 요약 카드만 보고 결론 내리지 않습니다.</span>
    </section>
  `;
}

function renderWorkbenchSmokePanel(run) {
  const validationHref = run?.run_id ? `/api/runs/${encodeURIComponent(run.run_id)}/validation-package` : "";
  return `
    <section class="workbench-smoke-panel" aria-label="브라우저 검증 절차">
      <div>
        <p class="eyebrow">화면 검증</p>
        <h3>반복 확인 가능한 단일 케이스 흐름</h3>
        <p>아래 단계로 접수, 검색, 원본 뷰어, 선별, 보고서 흐름을 반복 검증합니다. 대량 결과 검증 자료에는 DOM 행 수, 응답 시간, 메모리 예산 기준을 함께 기록합니다.</p>
      </div>
      <div class="smoke-checkpoint-row">
        ${WORKBENCH_SMOKE_CHECKPOINTS.map((item, index) => `
          <span title="${escapeHtml(item.selector)}"><strong>${index + 1}</strong>${escapeHtml(item.label)}</span>
        `).join("")}
      </div>
      <div class="smoke-link-row">
        <a class="mini-link" href="/api/workbench/smoke-contract" target="_blank" rel="noreferrer">화면 검증 JSON</a>
        <a class="mini-link" href="/api/workbench/large-result-evidence?record_count=100000" target="_blank" rel="noreferrer" aria-label="e2e performance contract">10만 행 검증 JSON</a>
        ${validationHref ? `<a class="mini-link" href="${validationHref}" target="_blank" rel="noreferrer">실행 검증 패키지</a>` : ""}
      </div>
      <div id="runValidationDiffPanel" class="run-validation-diff-panel" data-testid="run-validation-diff-panel">
        <p class="empty-state">검증 패키지를 불러오면 산출물 차이와 누락 항목이 여기에 표시됩니다.</p>
      </div>
      <div id="commercialReadinessPanel" class="commercial-readiness-panel" data-testid="commercial-readiness-panel">
        <p class="empty-state">상용 준비도 기준이 여기에 표시됩니다. 이 기준을 통과하기 전에는 상용 동등성을 주장하지 않습니다.</p>
      </div>
      <form id="macFirstEvidenceForm" class="mac-first-evidence-form" data-testid="mac-first-evidence-form">
        <label for="macFirstEvidencePath">Mac evidence/QC folder</label>
        <div class="mac-first-evidence-controls">
          <input id="macFirstEvidencePath" name="mac_first_evidence" type="text" placeholder="./qc or ./qc/macos-live-smoke.json" autocomplete="off" />
          <button type="submit">Apply Mac evidence</button>
          <button type="button" id="clearMacFirstEvidence" class="secondary-button">Clear</button>
        </div>
        <p class="help-text">맥에서 만든 <code>macos-live-smoke.json</code>, <code>large-case-readiness.json</code>, <code>email-external-parser.json</code> 또는 그 파일들이 들어있는 QC 폴더를 입력하면 readiness API에 붙여서 다시 계산합니다.</p>
      </form>
    </section>
  `;
}

async function loadRunValidationPackageSummary(runId) {
  const panel = detailPanel.querySelector("#runValidationDiffPanel");
  if (!panel) return;
  panel.innerHTML = '<p class="empty-state">Loading run validation diff inventory...</p>';
  try {
    const payload = await api(`/api/runs/${encodeURIComponent(runId)}/validation-package`);
    panel.innerHTML = renderRunValidationPackageSummary(payload);
  } catch (error) {
    panel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  }
}

async function loadCommercialReadinessSummary() {
  const panel = detailPanel.querySelector("#commercialReadinessPanel");
  if (!panel) return;
  panel.innerHTML = '<p class="empty-state">Loading commercial readiness gate...</p>';
  try {
    const params = new URLSearchParams({
      next_gate: "commercial_grade",
      limit: "8",
      include_internal_validation: "true",
    });
    const macFirstEvidencePath = getStoredMacFirstEvidencePath();
    if (macFirstEvidencePath) {
      params.set("mac_first_evidence", macFirstEvidencePath);
    }
    const payload = await api(`/api/commercial-readiness?${params.toString()}`);
    panel.innerHTML = renderCommercialReadinessSummary(payload);
  } catch (error) {
    panel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  }
}

function getStoredMacFirstEvidencePath() {
  try {
    return localStorage.getItem(MAC_FIRST_EVIDENCE_STORAGE_KEY)?.trim() || "";
  } catch {
    return "";
  }
}

function setStoredMacFirstEvidencePath(value) {
  try {
    const trimmed = String(value || "").trim();
    if (trimmed) {
      localStorage.setItem(MAC_FIRST_EVIDENCE_STORAGE_KEY, trimmed);
    } else {
      localStorage.removeItem(MAC_FIRST_EVIDENCE_STORAGE_KEY);
    }
  } catch {
    // localStorage may be disabled; the form still refreshes the current panel state.
  }
}

function bindMacFirstEvidenceControls() {
  const form = detailPanel.querySelector("#macFirstEvidenceForm");
  const input = detailPanel.querySelector("#macFirstEvidencePath");
  if (!form || !input) return;
  input.value = getStoredMacFirstEvidencePath();
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    setStoredMacFirstEvidencePath(input.value);
    loadCommercialReadinessSummary();
  });
  detailPanel.querySelector("#clearMacFirstEvidence")?.addEventListener("click", () => {
    input.value = "";
    setStoredMacFirstEvidencePath("");
    loadCommercialReadinessSummary();
  });
}

function renderCommercialReadinessSummary(payload) {
  const gates = payload?.gate_counts || {};
  const validated = gates.validated || {};
  const commercial = gates.commercial_grade || {};
  const focused = Array.isArray(payload?.focused_items) ? payload.focused_items : [];
  const validationPackage = payload?.validation_package || {};
  const evidenceSummary = payload?.validation_evidence_summary || {};
  const macFirst = payload?.mac_first_evidence_summary || {};
  const claimClass = payload?.commercial_claim_allowed ? "commercial-ready" : "not-commercial-ready";
  return `
    <div class="commercial-readiness-card ${claimClass}">
      <div>
        <strong>Commercial readiness gate</strong>
        <strong>상용 준비도 기준</strong>
        <span>${escapeHtml(payload?.release_claim || "준비도 기준을 불러오지 못했습니다.")}</span>
      </div>
      <dl class="compact-dl">
        <dt>Validation package</dt>
        <dd>${escapeHtml(validationPackage.attached ? validationPackage.mode || "attached" : "not attached")}</dd>
        <dt>Mapped evidence</dt>
        <dd>${escapeHtml(evidenceSummary.items_with_passed_validation_evidence || 0)} / ${escapeHtml(payload?.item_count || 0)}</dd>
        <dt>점수</dt>
        <dd>${escapeHtml(payload?.readiness_score || 0)}/100</dd>
        <dt>검증 통과</dt>
        <dd>${escapeHtml(validated.passed || 0)} 통과 / ${escapeHtml(validated.failed || 0)} 남음</dd>
        <dt>상용 기준</dt>
        <dd>${escapeHtml(commercial.passed || 0)} 통과 / ${escapeHtml(commercial.failed || 0)} 남음</dd>
        <dt>상용 주장 가능</dt>
        <dd>${escapeHtml(payload?.commercial_claim_allowed ? "가능" : "불가")}</dd>
        <dt>검증 패키지</dt>
        <dd>${escapeHtml(validationPackage.attached ? validationPackage.mode || "첨부됨" : "미첨부")}</dd>
        <dt>매핑된 증거</dt>
        <dd>${escapeHtml(evidenceSummary.items_with_passed_validation_evidence || 0)} / ${escapeHtml(payload?.item_count || 0)}</dd>
        <dt>Mac evidence</dt>
        <dd>${escapeHtml(macFirst.attached ? `${macFirst.evidence_count || 0} attached` : "not attached")}</dd>
      </dl>
      ${macFirst.attached ? `
        <p class="help-text">Mac-first evidence is attached as preparatory proof only: ${escapeHtml(macFirst.claim_effect || "commercial gates still require trusted validation evidence.")}</p>
        ${renderMacFirstEvidenceRows(macFirst)}
      ` : ""}
      ${focused.length ? `
        <ul class="commercial-readiness-list">
          ${focused.slice(0, 5).map((item) => `
            <li>
              <strong>#${escapeHtml(item.number || "?")} ${escapeHtml(item.title || "Readiness item")}</strong>
              <span>${escapeHtml(item.next_required_gate || "next gate")} · ${escapeHtml(item.remaining_gap || item.next_action || "validation evidence required")}</span>
            </li>
          `).join("")}
        </ul>
      ` : `<p class="help-text">No focused gate items returned. Re-run the CLI gate when validation evidence changes.</p>`}
      <p class="help-text">${escapeHtml(validationPackage.warning || "GUI 기능이 보이더라도 trusted diff, known-answer fixture, independent validation이 없으면 상용급 완료로 표시하지 않습니다.")}</p>
      <p class="help-text">현재 패널은 내부 fixture 검증과 commercial-grade gate를 분리해서 보여줍니다. validated가 통과되어도 commercial이 0이면 상용급 완료가 아닙니다.</p>
    </div>
  `;
}

function renderMacFirstEvidenceRows(macFirst) {
  const rows = Array.isArray(macFirst?.rows) ? macFirst.rows : [];
  if (!rows.length) return "";
  return `
    <div class="mac-first-evidence-rows" data-testid="mac-first-evidence-rows">
      <strong>Attached Mac evidence</strong>
      <ul class="commercial-readiness-list mac-first-evidence-list">
        ${rows.slice(0, 6).map((row) => `
          <li>
            <strong>${escapeHtml(row.command || "mac evidence")} · ${escapeHtml(row.status || "observed")}</strong>
            <span>${escapeHtml(macFirstEvidenceSummaryText(row))}</span>
          </li>
        `).join("")}
      </ul>
    </div>
  `;
}

function macFirstEvidenceSummaryText(row) {
  const parts = [];
  if (row.local_smoke_score !== undefined && row.local_smoke_score !== null && row.local_smoke_score !== "") {
    parts.push(`score ${row.local_smoke_score}`);
  }
  if (row.large_case_status) {
    parts.push(`large-case ${row.large_case_status}`);
  }
  if (row.export_file_count !== undefined && row.export_file_count !== null && row.export_file_count !== "") {
    parts.push(`exports ${row.export_file_count}`);
  }
  if (row.ready_for_trusted_diff !== undefined && row.ready_for_trusted_diff !== null && row.ready_for_trusted_diff !== "") {
    parts.push(`trusted diff ${row.ready_for_trusted_diff ? "ready" : "not ready"}`);
  }
  if (row.evidence_manifest_hash) {
    parts.push(`manifest ${String(row.evidence_manifest_hash).slice(0, 12)}`);
  }
  if (row.path_sha256) {
    parts.push(`file ${String(row.path_sha256).slice(0, 12)}`);
  }
  return parts.join(" · ") || "preparatory evidence attached";
}

function renderRunValidationPackageSummary(payload) {
  const diff = payload?.diff_inventory || {};
  const outputs = Array.isArray(diff.outputs) ? diff.outputs : [];
  const stateStatus = diff.usn_state_replay_diff_attached
    ? `${diff.usn_state_replay_diff_pass_count || 0} passed`
    : "not attached";
  const modeSet = new Set();
  for (const output of outputs) {
    const summary = output?.diff_summary || {};
    const modes = Array.isArray(summary.field_diff_modes) ? summary.field_diff_modes : [];
    modes.forEach((mode) => modeSet.add(mode));
  }
  const modes = Array.from(modeSet).sort();
  return `
    <div class="validation-diff-card">
      <div>
        <strong>Run validation diff inventory</strong>
        <span>diff 산출물 ${escapeHtml(outputs.length)}개 · 교차 검증 산출물 ${escapeHtml(diff.cross_tool_output_count || 0)}개</span>
      </div>
      <dl class="compact-dl">
        <dt>USN state replay diff</dt>
        <dd>${escapeHtml(stateStatus)}</dd>
        <dt>Compared modes</dt>
        <dd>${escapeHtml(modes.join(" · ") || "No field diff modes attached")}</dd>
        <dt>Package hash</dt>
        <dd>${escapeHtml(payload?.package_manifest_hash || "pending")}</dd>
      </dl>
      ${outputs.length ? `
        <ul class="validation-diff-list">
          ${outputs.slice(0, 5).map((output) => {
            const summary = output.diff_summary || {};
            return `<li>
              <strong>${escapeHtml(output.name || "diff")}</strong>
              <span>${escapeHtml(summary.command || "unknown")} · ${escapeHtml(summary.status || "unknown")} · state replay ${escapeHtml(summary.usn_state_replay_status || "not-attached")}</span>
            </li>`;
          }).join("")}
        </ul>
      ` : `<p class="help-text">${escapeHtml((diff.limitations || []).join(" · ") || "No trusted diff output is attached to this run yet.")}</p>`}
    </div>
  `;
}

function renderCaseHero(run) {
  const payload = run.summary || {};
  const summary = payload.summary || {};
  const processing = payload.processing || {};
  const outputCount = Object.keys(payload.outputs || {}).length;
  const warningCount = Number(processing.warning_count || 0);
  const artifactSignals = FORENSIC_ARTIFACT_TAXONOMY.reduce((sum, item) => sum + artifactGroupCount(payload, item.terms), 0);
  const source = run.request.root || payload.output_dir || "Evidence source";
  const headline = warningCount ? `검증 이슈 ${formatNumber(warningCount)}건 확인 필요` : "검토 가능한 결과가 준비되었습니다";
  return `
    <section class="case-hero review-first-case-strip" aria-label="Case mission control" data-testid="case-hero">
      <div class="case-hero-main">
        <p class="eyebrow">현재 케이스</p>
        <h2>${escapeHtml(headline)}</h2>
        <p class="case-source-line"><span>입력 증거</span><code>${escapeHtml(source)}</code></p>
      </div>
      <div class="case-hero-metrics">
        ${caseHeroMetric("문서", summary.document_match_count)}
        ${caseHeroMetric("파일", summary.file_candidate_count)}
        ${caseHeroMetric("타임라인", summary.timeline_event_count)}
        ${caseHeroMetric("아티팩트", artifactSignals)}
        ${caseHeroMetric("산출물", outputCount)}
        ${caseHeroMetric("이슈", warningCount)}
      </div>
    </section>
  `;
}

function caseHeroMetric(label, value) {
  return `
    <span class="case-hero-metric">
      <strong>${formatNumber(value || 0)}</strong>
      <em>${escapeHtml(label)}</em>
    </span>
  `;
}

function renderCoreEvidenceWorkflow(run) {
  const payload = run.summary || {};
  const contractStages = Array.isArray(payload.workflow?.stages) ? payload.workflow.stages : [];
  const steps = contractStages.length
    ? contractStages.map((stage, index) => ({
      id: stage.id,
      number: String(index + 1),
      label: stage.label || stage.id,
      title: stage.title || stage.id,
      tab: stage.gui?.primary_tab || "summary",
      action: stage.gui?.next_action || "Open",
    }))
    : (typeof CORE_EVIDENCE_WORKFLOW !== "undefined" ? CORE_EVIDENCE_WORKFLOW : []);
  if (!steps.length) return "";
  const statuses = coreEvidenceWorkflowStatuses(payload);
  return `
    <section class="core-evidence-workflow completed-core-workflow" aria-label="Core evidence workflow" data-testid="core-evidence-workflow">
      ${steps.map((step) => {
        const status = statuses[step.id] || {};
        const stateClass = status.ready ? (status.warning ? "warning" : "done") : (status.blocked ? "blocked" : "pending");
        return `
          <button class="core-workflow-step ${stateClass}" type="button" data-open-tab="${escapeHtml(step.tab || "summary")}" data-core-workflow-step="${escapeHtml(step.id)}" data-testid="core-workflow-step-${escapeHtml(step.id)}">
            <span class="sr-only">${escapeHtml(`${step.label || ""} ${status.state || ""}`)}</span>
            <span class="core-workflow-number">${escapeHtml(step.number || "")}</span>
            <span class="core-workflow-body">
              <span class="core-workflow-topline">
                <em>${escapeHtml(step.label || "")}</em>
                <i>${escapeHtml(status.state || "pending")}</i>
              </span>
              <strong>${escapeHtml(step.title || "")}</strong>
              <small>${escapeHtml(status.detail || step.text || "")}</small>
              <b>${escapeHtml(step.action || "Open")}</b>
            </span>
          </button>
        `;
      }).join("")}
    </section>
  `;
}

function coreEvidenceWorkflowStatuses(payload) {
  const workflowStages = Array.isArray(payload.workflow?.stages) ? payload.workflow.stages : [];
  if (workflowStages.length) {
    return Object.fromEntries(workflowStages.map((stage) => {
      const warnings = Number(stage.warning_count || 0);
      return [stage.id, {
        ready: Boolean(stage.ready),
        warning: stage.status === "warning" || warnings > 0,
        blocked: stage.status === "blocked",
        state: runWorkflowStatusLabel(stage.status || "pending"),
        detail: `${(stage.step_names || []).length}단계 · 산출물 ${(stage.output_keys || []).length}개 · 이슈 ${warnings}건`,
      }];
    }));
  }
  const summary = payload.summary || {};
  const outputs = payload.outputs || {};
  const artifactKinds = Object.keys(payload.artifacts || {});
  const docs = Number(summary.document_match_count || 0);
  const files = Number(summary.file_candidate_count || 0);
  const timeline = Number(summary.timeline_event_count || 0);
  const extracted = Number(summary.docs_extracted_count || 0) + Number(summary.files_extracted_count || 0);
  const outputCount = Object.keys(outputs).length;
  const searchable = docs + files + timeline;
  const extractManifestReady = Boolean(outputs.docs_extract_manifest || outputs.files_extract_manifest);
  const reportReady = Boolean(outputs.report || outputs.summary || summary.report_candidate_count);
  const warningCount = Number(summary.warning_count || 0) + Number(summary.parser_warning_count || 0);
  return {
    ingest: {
      ready: outputCount > 0 || Boolean(payload.source || payload.request || summary.source_kind),
      state: outputCount > 0 ? "입력 확인" : "입력 대기",
      detail: "증거 종류, read-only 전제, dependency, mount/export 필요 여부를 먼저 확인합니다.",
    },
    extract: {
      ready: extracted > 0 || extractManifestReady,
      state: extracted > 0 ? "추출 완료" : (extractManifestReady ? "추출 가능" : "설정 필요"),
      detail: extracted > 0
        ? `${formatNumber(extracted)}개 파일 추출 · manifest/SHA256 기록 있음`
        : "추출 manifest를 보고 필요한 후보만 output 폴더로 꺼냅니다.",
    },
    parse: {
      ready: outputCount > 0 || searchable > 0 || artifactKinds.length > 0,
      state: outputCount > 0 ? "분석 완료" : "확인 필요",
      detail: `${formatNumber(docs)} 문서 · ${formatNumber(files)} 파일 · ${formatNumber(timeline)} 타임라인 · ${formatNumber(artifactKinds.length)} 아티팩트 그룹`,
    },
    index: {
      ready: searchable > 0,
      state: searchable > 0 ? "검색 가능" : "검색 대기",
      detail: `${formatNumber(searchable)}개 문서/파일/타임라인 row를 전체 검색 대상으로 사용`,
    },
    review: {
      ready: searchable > 0 || reportReady,
      warning: warningCount > 0,
      state: warningCount > 0 ? "검토 필요" : "리뷰 준비",
      detail: "검색 결과를 source viewer에서 확인한 뒤 relevant, needs-review, excluded, note, tag를 남깁니다.",
    },
    report: {
      ready: reportReady,
      state: reportReady ? "보고서 가능" : "후보 대기",
      detail: "evidence tray와 citation, limitation, validation 상태를 보고서 후보에 연결합니다.",
    },
  };
}

function runWorkflowStatusLabel(status) {
  if (status === "completed") return "완료";
  if (status === "warning") return "경고";
  if (status === "blocked") return "차단";
  return "대기";
}

function runWorkflowChecklistStatusLabel(status) {
  if (status === "ready") return "확인 준비";
  if (status === "warning") return "주의 필요";
  if (status === "blocked") return "차단";
  return "대기";
}

function normalizeRunPayload(source) {
  if (!source) return {};
  if (source.summary?.summary) return source.summary;
  return source;
}

function artifactGroupsFromPayload(normalized) {
  return normalized.artifacts || normalized.summary?.artifacts || {};
}

function artifactSignalText(payload) {
  const normalized = normalizeRunPayload(payload);
  const summary = normalized.summary || {};
  const steps = Array.isArray(normalized.steps) ? normalized.steps : [];
  const artifacts = artifactGroupsFromPayload(normalized);
  const fragments = [
    Object.keys(artifacts).join(" "),
    steps.map((step) => `${step.name || ""} ${step.label || ""} ${step.status || ""}`).join(" "),
    Object.keys(summary).join(" "),
  ];
  return fragments.join(" ").toLowerCase();
}

function artifactGroupCount(payload, terms) {
  const normalized = normalizeRunPayload(payload);
  const summary = normalized.summary || {};
  const artifacts = artifactGroupsFromPayload(normalized);
  const steps = Array.isArray(normalized.steps) ? normalized.steps : [];
  const lowerTerms = (terms || []).map((term) => String(term).toLowerCase());
  let count = 0;
  for (const [kind, group] of Object.entries(artifacts)) {
    const kindText = String(kind).toLowerCase();
    const rows = Array.isArray(group?.artifacts) ? group.artifacts : [];
    if (lowerTerms.some((term) => kindText.includes(term))) {
      count += Number(group?.pagination?.total || rows.length || 0);
      continue;
    }
    count += rows.filter((artifact) => {
      const text = `${artifact.artifact_type || ""} ${artifact.provider || ""} ${artifact.path || ""}`.toLowerCase();
      return lowerTerms.some((term) => text.includes(term));
    }).length;
  }
  for (const step of steps) {
    const stepText = `${step.name || ""} ${step.label || ""}`.toLowerCase();
    if (!lowerTerms.some((term) => stepText.includes(term))) continue;
    count += Number(step.artifact_count || step.indicator_count || step.row_count || step.count || 0);
  }
  if (lowerTerms.some((term) => ["document", "pdf", "office", "ocr"].includes(term))) {
    count += Number(summary.document_match_count || 0);
  }
  if (lowerTerms.some((term) => ["file", "image", "video", "audio", "media"].includes(term))) {
    count += Number(summary.file_candidate_count || 0);
  }
  if (lowerTerms.some((term) => ["timeline", "event", "evtx"].includes(term))) {
    count += Number(summary.timeline_event_count || 0);
  }
  if (lowerTerms.some((term) => ["report", "case", "custody"].includes(term))) {
    count += Number(summary.report_item_count || 0);
  }
  return count;
}

function artifactRowGroupCount(payload, terms) {
  const normalized = normalizeRunPayload(payload);
  const artifacts = artifactGroupsFromPayload(normalized);
  const lowerTerms = (terms || []).map((term) => String(term).toLowerCase());
  let count = 0;
  for (const [kind, group] of Object.entries(artifacts)) {
    const kindText = String(kind).toLowerCase();
    const rows = Array.isArray(group?.artifacts) ? group.artifacts : [];
    const total = Number(group?.pagination?.total || group?.artifact_count || rows.length || 0);
    if (lowerTerms.some((term) => kindText.includes(term))) {
      count += total;
      continue;
    }
    count += rows.filter((artifact) => {
      const text = `${artifact.artifact_type || ""} ${artifact.provider || ""} ${artifact.path || ""}`.toLowerCase();
      return lowerTerms.some((term) => text.includes(term));
    }).length;
  }
  return count;
}

function artifactViewRowCount(payload) {
  const normalized = normalizeRunPayload(payload);
  const artifacts = artifactGroupsFromPayload(normalized);
  let count = 0;
  for (const group of Object.values(artifacts)) {
    const rows = Array.isArray(group?.artifacts) ? group.artifacts : [];
    count += Number(group?.pagination?.total || group?.artifact_count || rows.length || 0);
  }
  return count;
}

function artifactCategoryCount(payload, category) {
  const normalized = normalizeRunPayload(payload);
  const artifacts = artifactGroupsFromPayload(normalized);
  let count = 0;
  for (const [kind, group] of Object.entries(artifacts)) {
    const rows = Array.isArray(group?.artifacts) ? group.artifacts : [];
    if (rows.length) {
      count += rows.filter((artifact) => artifactSourceCategory(kind, artifact) === category).length;
      continue;
    }
    const total = Number(group?.pagination?.total || group?.artifact_count || 0);
    if (total && artifactSourceCategory(kind, {}) === category) count += total;
  }
  return count;
}

function artifactSourceCategory(kind, artifact = {}) {
  const text = `${kind || ""} ${artifact.artifact_type || ""} ${artifact.provider || ""} ${artifact.path || ""}`.toLowerCase();
  if (/\b(browser|history|download|chatgpt|claude|gemini|perplexity)\b/.test(text) || text.includes("browser-ai") || text.includes("ai-usage")) {
    return "web-ai";
  }
  if (text.includes("media-image") || text.includes("image-unreadable")) {
    return "image";
  }
  if (
    text.includes("windows") ||
    text.includes("eventlog") ||
    text.includes("evtx") ||
    text.includes("registry") ||
    text.includes("shellbag") ||
    text.includes("prefetch") ||
    text.includes("recent-files") ||
    text.includes("jumplist") ||
    text.includes("mft") ||
    text.includes("usn") ||
    text.includes("usb")
  ) {
    return "windows";
  }
  return "other";
}

function renderForensicRibbon(run) {
  const signalText = artifactSignalText(run);
  return `
    <section class="forensic-ribbon" aria-label="Forensic module ribbon">
      ${FORENSIC_RIBBON_GROUPS.map((group) => {
        const count = artifactGroupCount(run, group.terms);
        const active = activeTab === group.tab || group.terms.some((term) => signalText.includes(term));
        return `
          <article class="forensic-ribbon-group ${active ? "active" : ""}">
            <button class="forensic-ribbon-title" type="button" data-open-tab="${escapeHtml(group.tab)}">
              <span>${escapeHtml(group.label)}</span>
              <strong>${formatNumber(count)}</strong>
            </button>
            <div class="forensic-ribbon-modules">
              ${group.modules.map((module) => `<span>${escapeHtml(module)}</span>`).join("")}
            </div>
          </article>
        `;
      }).join("")}
    </section>
  `;
}

function renderCaseCommandBar(run) {
  const summary = run.summary?.summary || {};
  const reviewCount = summary.report_item_count || 0;
  return `
    <section class="case-command-bar" aria-label="Analyst command bar">
      <div class="case-command-main">
        <span class="case-stage-badge">${escapeHtml(viewGroupById(activeViewGroup).label)}</span>
        <strong>${escapeHtml(primaryTaskForTab(activeTab))}</strong>
        <span>${escapeHtml(run.request.root || run.summary?.output_dir || "")}</span>
      </div>
      <form id="globalCaseSearchForm" class="case-command-search" aria-label="Global case search" data-testid="global-case-search">
        <label>
          <span>사건 질문 검색</span>
          <input name="keyword" placeholder="USB, 유출, 삭제, 특정 인물/계정, AI 질문, 파일명..." autocomplete="off" />
        </label>
        <button type="submit">검색</button>
      </form>
      <div class="case-command-actions">
        <button class="secondary-button" type="button" data-open-tab="review">리뷰 ${formatNumber(reviewCount)}</button>
        <button class="secondary-button" type="button" data-open-tab="report">보고서</button>
      </div>
    </section>
  `;
}

function primaryTaskForTab(tab) {
  const copy = {
    summary: "E01/이미지 증거의 분석 가능성과 제한사항을 먼저 고정",
    files: "파일/이미지/hex 후보를 빠르게 미리보고 필요한 항목만 표시",
    docs: "문서·메일·메신저·OCR 히트를 리걸 리뷰 방식으로 선별",
    artifacts: "EVTX·Registry·USB·Browser·AI 사용 흔적을 사건 질문별로 검토",
    timeline: "로그·파일·웹·앱 활동을 시간순으로 재구성",
    indicators: "URL, IP, 도메인, 해시를 관련 파일/시간대 피벗으로 검토",
    search: "전체 케이스에서 키워드를 찾고 원본 뷰어로 즉시 확인",
    review: "관련 있음/재검토/제외/보고서 포함 상태를 정리",
    report: "검토된 증거만 해시·출처·제한사항과 함께 산출물로 정리",
  };
  return copy[tab] || "케이스 작업 진행";
}

function bindTabButtons() {
  for (const button of detailPanel.querySelectorAll(".tab-button, .forensic-view-mode, .workflow-lane-card")) {
    button.addEventListener("click", async () => {
      activeTab = button.dataset.tab;
      activeViewGroup = groupForTab(activeTab);
      activeArtifactFilter = "";
      for (const item of detailPanel.querySelectorAll(".tab-button")) {
        item.classList.toggle("active", item === button);
      }
      for (const item of detailPanel.querySelectorAll(".forensic-view-mode")) {
        item.classList.toggle("active", item.dataset.tab === activeTab);
        item.setAttribute("aria-current", item.dataset.tab === activeTab ? "page" : "false");
      }
      for (const item of detailPanel.querySelectorAll(".workflow-lane-card")) {
        const isActive = item.dataset.tab === activeTab || workflowLaneForTab(activeTab).id === item.dataset.workflowLane;
        item.classList.toggle("active", isActive);
        item.setAttribute("aria-current", isActive ? "step" : "false");
      }
      persistWorkbenchSession();
      await renderActiveTab();
    });
  }
  detailPanel.querySelector("#clearFilter")?.addEventListener("click", () => {
    for (const selector of ["#tableFilter", "#sourceFilterInput", "#timeFilterInput"]) {
      const input = detailPanel.querySelector(selector);
      if (input) input.value = "";
    }
    const preset = detailPanel.querySelector("#columnPresetInput");
    if (preset) preset.value = "analyst";
    applyColumnPreset("analyst");
    applyWorkbenchFilters();
    persistWorkbenchSession();
  });
  for (const selector of ["#tableFilter", "#sourceFilterInput", "#timeFilterInput"]) {
    detailPanel.querySelector(selector)?.addEventListener("input", scheduleWorkbenchFilterUpdate);
  }
  detailPanel.querySelector("#columnPresetInput")?.addEventListener("change", (event) => {
    applyColumnPreset(event.target.value || "analyst");
    persistWorkbenchSession();
  });
  detailPanel.querySelector("#removeRunButton")?.addEventListener("click", removeSelectedRun);
  bindCompareActions();
}

function renderShortcutHelp() {
  return `
    <details id="shortcutHelp" class="shortcut-help">
      <summary>단축키 ${kbd("?")}</summary>
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

function renderCommandPalette(run, tab) {
  const model = typeof LAZYWEB_WORKBENCH_MODEL !== "undefined"
    ? LAZYWEB_WORKBENCH_MODEL
    : { commands: [], quick_actions: [] };
  const workflowCommands = (model.commands || []).map((command) => ({
    id: command.id,
    label: command.label,
    hint: command.hint,
    shortcut: command.shortcut,
    category: "작업",
    tab: command.tab,
    filter: command.filter,
  }));
  const quickActions = (model.quick_actions || []).map((action) => ({
    id: action.id,
    label: action.label,
    hint: action.hint,
    shortcut: action.shortcut,
    category: action.category || "작업",
    action: action.action,
  }));
  const artifactCommands = WORKBENCH_ARTIFACT_TREE_GROUPS.map((group) => ({
    id: `artifact-${group.label}`,
    label: group.label,
    hint: `${group.hint} · 단서 ${formatNumber(artifactGroupCount(run, group.terms))}건`,
    shortcut: "",
    category: "아티팩트",
    tab: group.tab,
    filter: group.terms?.[0] || group.label,
  }));
  const commands = [...workflowCommands, ...quickActions, ...artifactCommands].slice(0, 32);
  return `
    <section id="commandPalette" class="command-palette" role="dialog" aria-modal="true" aria-hidden="true" aria-label="명령 팔레트" data-testid="command-palette" data-active-tab="${escapeHtml(tab)}" hidden>
      <div class="command-palette-backdrop" data-command-palette-close></div>
      <div class="command-palette-shell">
        <div class="command-palette-header">
          <div>
            <p class="eyebrow">빠른 이동</p>
            <strong>명령 팔레트</strong>
            <span>케이스 이동, 아티팩트 필터, 검색, 리뷰, 보고서를 한 번에 호출합니다.</span>
          </div>
          <button class="icon-action" type="button" data-command-palette-close aria-label="명령 팔레트 닫기">Esc</button>
        </div>
        <label class="command-palette-search">
          <span>명령 검색</span>
          <input id="commandPaletteInput" type="search" placeholder="검색, 아티팩트, 보고서, 단축키" autocomplete="off" />
          <kbd>Enter</kbd>
        </label>
        <div class="command-palette-list" role="listbox" aria-label="사용 가능한 포렌식 명령" data-result-limit="${COMMAND_PALETTE_RESULT_LIMIT}">
          ${commands.map((command, index) => `
            <button
              class="command-palette-command ${index === 0 ? "active" : ""}"
              type="button"
              role="option"
              data-command-text="${escapeHtml([command.category, command.label, command.hint, command.shortcut, command.filter].filter(Boolean).join(" ").toLowerCase())}"
              data-command-tab="${escapeHtml(command.tab || "")}"
              data-command-filter="${escapeHtml(command.filter || "")}"
              data-command-action="${escapeHtml(command.action || "")}"
            >
              <span>${escapeHtml(command.category || "명령")}</span>
              <strong>${escapeHtml(command.label || "")}</strong>
              <em>${escapeHtml(command.hint || "")}</em>
              ${command.shortcut ? `<kbd>${escapeHtml(command.shortcut)}</kbd>` : ""}
            </button>
          `).join("")}
        </div>
        <p class="command-palette-footnote">Tip: ${kbd("/")}는 바로 전체 검색, ${kbd("Ctrl/Cmd K")}는 이 팔레트, ${kbd("[")}${kbd("]")}는 대용량 결과 페이지 이동입니다.</p>
      </div>
    </section>
  `;
}

async function renderActiveTab() {
  const body = detailPanel.querySelector("#tabBody");
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
    body.innerHTML = renderTabLoadError(error, activeTab);
  }
  bindPanelActions();
  bindBookmarkButtons();
  bindSearchForm();
  bindSearchResultButtons();
  restoreWorkbenchControls();
  refreshSourceNavigatorState();
}

function renderTabLoadError(error, tab) {
  const detail = error?.detail?.detail || error?.detail || error?.message || "";
  const message = errorMessageFromDetail(detail);
  const outputPath = outputPathFromErrorDetail(detail) || outputPathFromErrorDetail(message);
  const copy = tabRecoveryCopy(tab);
  return `
    <section class="tab-error-card" data-testid="tab-load-error" data-tab-load-error="${escapeHtml(tab)}">
      <div>
        <p class="eyebrow">${escapeHtml(tabLabel(tab))} 로드 실패</p>
        <strong>${outputPath ? "필요한 산출물 파일을 찾을 수 없습니다" : "이 화면을 불러오지 못했습니다"}</strong>
        <span>${escapeHtml(copy)}</span>
      </div>
      ${outputPath ? `<code title="${escapeHtml(outputPath)}">${escapeHtml(outputPath)}</code>` : `<code>${escapeHtml(message)}</code>`}
      <div class="tab-error-actions">
        <button type="button" data-open-tab="summary" data-nav-scope="recovery">증거/산출물 상태 보기</button>
        <button type="button" data-open-tab="search" data-nav-scope="recovery">전체 검색으로 이동</button>
        <button type="button" data-open-tab="artifacts" data-nav-scope="recovery">행위흔적 확인</button>
      </div>
      <p class="help-text">이미 분석 output 폴더를 옮겼거나 임시 샘플 경로가 삭제된 경우, 기존 결과 폴더를 다시 import하거나 같은 증거로 새 run을 생성하세요.</p>
    </section>
  `;
}

function outputPathFromErrorDetail(detail) {
  if (typeof detail !== "string") return "";
  const value = detail.trim();
  if (!value) return "";
  if (/rapidtriage-[\w-]+\.json$/i.test(value) || /[\\/][^\\/]+\.json$/i.test(value)) {
    return value;
  }
  return "";
}

function tabRecoveryCopy(tab) {
  const copy = {
    docs: "문서/메일 검토에는 rapidtriage-docs.json 같은 문서 검색 산출물이 필요합니다.",
    files: "파일/미디어 검토에는 rapidtriage-files.json 같은 파일 후보 산출물이 필요합니다.",
    timeline: "시간축 검토에는 timeline 산출물이 필요합니다. E01/추출 폴더가 바뀌면 다시 생성해야 합니다.",
    artifacts: "행위흔적 검토에는 artifacts 산출물이 필요합니다. EVTX, Registry, Browser 등의 parser 결과를 확인하세요.",
    indicators: "IOC 검토에는 indicators 산출물이 필요합니다. 검색 또는 아티팩트 화면에서 우선 확인할 수 있습니다.",
    report: "보고서 화면은 선별/인용 산출물이 있을 때 가장 유용합니다. 먼저 리뷰 보드에서 증거를 고정하세요.",
    review: "리뷰 보드는 Case DB 산출물이 있을 때 동작합니다. 검색 결과를 먼저 선별하거나 Case DB import를 실행하세요.",
  };
  return copy[tab] || "현재 탭의 결과 산출물이 없거나 접근할 수 없습니다.";
}

function renderSummary(payload) {
  const summary = payload.summary || {};
  const outputs = payload.outputs || {};
  const processing = payload.processing || {};
  const outputCount = Object.keys(outputs).length;
  const warningCount = Number(processing.warning_count || 0);
  const searchableRows = Number(summary.document_match_count || 0)
    + Number(summary.file_candidate_count || 0)
    + Number(summary.timeline_event_count || 0);
  const source = selectedRun?.request?.root || payload.input_root || payload.root || payload.output_dir || "not recorded";
  const legacySummary = `
    ${renderWorkflowGuide(summary)}
    ${renderUserWorkflowMap()}
    ${renderCaseReadinessDashboard(payload)}
    ${renderE01RunWorkflowStatus(payload)}
    ${renderImageStageControlStatus(payload)}
    ${renderForensicArtifactNavigator(payload)}
    ${renderRunActionStrip(payload)}
    ${renderProcessingSummary(payload)}
    ${renderWorkspaceCards(summary)}
    <div class="metric-grid">
      ${metric("문서 히트", summary.document_match_count)}
      ${metric("파일 후보", summary.file_candidate_count)}
      ${metric("시간축 이벤트", summary.timeline_event_count)}
      ${metric("지표", payload.steps?.find((step) => step.name === "indicators")?.indicator_count || 0)}
      ${metric("추출 파일", (summary.docs_extracted_count || 0) + (summary.files_extracted_count || 0))}
    </div>
    ${renderCaseDbPanel(payload)}
    <div class="split-grid">
      <section>
        <h3>핵심 단서</h3>
        ${renderHighlightList(payload.highlights || {})}
      </section>
      <section>
        <h3>산출물</h3>
        <ul class="output-list">
          ${Object.entries(outputs).map(([name, path]) => `
            <li>
              <strong>${escapeHtml(name)}</strong>
              <a href="/api/runs/${encodeURIComponent(selectedRunId)}/outputs/${encodeURIComponent(name)}/file">다운로드</a>
              <br><span>${escapeHtml(path)}</span>
            </li>
          `).join("")}
        </ul>
      </section>
    </div>
  `;
  return `
    <section class="operator-summary-board" aria-label="Operator case summary" data-testid="operator-summary-board">
      <div class="operator-summary-main">
        <p class="eyebrow">요약</p>
        <h3>${warningCount ? `검증 이슈 ${formatNumber(warningCount)}건 확인 필요` : "검토 가능한 결과가 준비되었습니다"}</h3>
        <p class="case-source-line"><span>입력 증거</span><code>${escapeHtml(source)}</code></p>
        <p>요약 화면은 전체 산출물을 나열하는 곳이 아니라, 다음 검토 동선을 결정하는 시작점입니다. 세부 검증 자료는 고급 패널에서 확인합니다.</p>
        <div class="operator-summary-actions">
          <button type="button" data-open-tab="search">전체 검색</button>
          <button class="secondary-button" type="button" data-open-tab="artifacts">아티팩트 보기</button>
          <button class="secondary-button" type="button" data-open-tab="review">선별 보드</button>
          <button class="secondary-button" type="button" data-open-tab="report">보고서</button>
        </div>
      </div>
      <div class="operator-summary-metrics" aria-label="Case totals">
        ${metric("문서", summary.document_match_count)}
        ${metric("파일", summary.file_candidate_count)}
        ${metric("타임라인", summary.timeline_event_count)}
        ${metric("검색 대상", searchableRows)}
        ${metric("산출물", outputCount)}
        ${metric("이슈", warningCount)}
      </div>
      <div class="operator-summary-route">
        <article>
          <strong>1. 키워드 선별</strong>
          <span>키워드, OCR, 문서, 로그, 웹/AI 흔적을 먼저 좁힙니다.</span>
        </article>
        <article>
          <strong>2. 원본 검토</strong>
          <span>테이블 결과를 source viewer, SQLite, hex, document viewer로 확인합니다.</span>
        </article>
        <article>
          <strong>3. 증거 선별</strong>
          <span>관련 있음, 재검토, 제외, 보고서 포함 상태를 남깁니다.</span>
        </article>
      </div>
    </section>
    <details class="operator-advanced-summary">
      <summary>
        <span>검증/산출물 전체 상세</span>
        <strong>필요할 때만 열기</strong>
      </summary>
      ${legacySummary}
    </details>
  `;
}

function renderImageStageControlStatus(payload) {
  const source = payload.source || {};
  const contract = source.stage_control_contract
    || source.workflow_status?.stage_control_contract
    || source.e01_ex01_workflow_manifest?.stage_control_contract
    || source.raw_split_workflow_manifest?.stage_control_contract
    || null;
  if (!contract?.profile_version) return "";
  const checkpoint = contract.checkpoint || {};
  const resume = contract.resume || {};
  const cancelRetry = contract.cancel_retry || {};
  const failure = contract.failure_classification || {};
  const stages = contract.stage_rows || [];
  return `
    <section class="image-stage-control-card" data-testid="image-stage-control-contract" data-qc-prep-item="${escapeHtml(contract.qc_prep_item || 4)}">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">QC-prep #4 stage controls</p>
          <h3>Checkpoint, resume, cancel, retry</h3>
          <p>이미지 처리 단계가 어디까지 갔는지, 재개/취소/재시도 근거가 남았는지 확인합니다.</p>
        </div>
        <span class="status-pill ${contract.status === "failed-stage-present" ? "warning" : "ok"}">${escapeHtml(contract.status || "ready")}</span>
      </div>
      <div class="processing-caps">
        <span>Checkpoint: ${checkpoint.supported ? (checkpoint.exists ? "exists" : "expected") : "not supported"}</span>
        <span>Resume: ${resume.supported ? (checkpoint.resume_ready ? "ready" : "available") : "not supported"}</span>
        <span>Cancel: ${cancelRetry.cancel_supported ? "API" : "n/a"}</span>
        <span>Retry: ${(cancelRetry.retry_supported_for || []).join("/") || "n/a"}</span>
        <span>Failure: ${escapeHtml(failure.category || "none")}</span>
      </div>
      <div class="stage-control-grid">
        ${stages.slice(0, 8).map((stage) => `
          <article>
            <strong>${escapeHtml(stage.label || stage.id || "stage")}</strong>
            <span>${escapeHtml(stage.status || "pending")}</span>
          </article>
        `).join("")}
      </div>
      <details class="match-details">
        <summary>Control routes and evidence</summary>
        <code>${escapeHtml(cancelRetry.cancel_route || "")}</code>
        <code>${escapeHtml(cancelRetry.retry_route || "")}</code>
        <ul>${(contract.validation_evidence_required || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
      </details>
    </section>
  `;
}

function renderE01RunWorkflowStatus(payload) {
  const source = payload.source || {};
  const workflow = source.workflow_status || {};
  if (source.type !== "e01" || !workflow.profile_version) return "";
  const stages = workflow.stages || [];
  return `
    <section class="e01-workflow-panel e01-run-workflow">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">E01 처리 흐름</p>
          <h3>추출부터 분석까지 연결됨</h3>
        </div>
        <span class="status-pill ok">${escapeHtml(runWorkflowStatusLabel(workflow.status || "ready"))}</span>
      </div>
      <div class="metric-grid">
        ${metric("선택 파티션 섹터", workflow.selected_partition_start_sector ?? "n/a")}
        ${metric("실행 명령", workflow.command_history_count ?? 0)}
        ${metric("파티션", workflow.partition_table_count ?? 0)}
        ${metric("복구 항목", workflow.recovered_manifest_entry_count ?? 0)}
      </div>
      ${renderVscWorkflowHandoff(workflow.vsc_workflow_handoff || null)}
      <div class="e01-stage-grid">
        ${stages.map((stage, index) => `
          <article class="e01-stage-card ${escapeHtml(stage.status || "pending")}">
            <span>${index + 1}</span>
            <strong>${escapeHtml(stage.label || stage.id || "단계")}</strong>
            <em>${escapeHtml(runWorkflowStatusLabel(stage.status || "pending"))}</em>
            <p>${escapeHtml(stage.evidence || "")}</p>
          </article>
        `).join("")}
      </div>
      ${(workflow.analyst_next_actions || []).length ? `
        <div class="guidance-actions">
          <button class="secondary-button" type="button" data-open-tab="search">추출 증거 검색</button>
          <button class="secondary-button" type="button" data-open-tab="review">선별 보드</button>
          <button class="secondary-button" type="button" data-open-tab="report">보고서/내보내기</button>
        </div>
      ` : ""}
      <p class="help-text">${escapeHtml(workflow.analysis_root || "")}</p>
    </section>
  `;
}

function renderCaseReadinessDashboard(payload) {
  const summary = payload.summary || {};
  const processing = payload.processing || {};
  const outputs = payload.outputs || {};
  const root = selectedRun?.request?.root || payload.input_root || payload.root || payload.output_dir || "";
  const lowerRoot = String(root).toLowerCase();
  const isE01 = lowerRoot.endsWith(".e01") || lowerRoot.includes(".e01.");
  const warningCount = Number(processing.warning_count || 0);
  const searchableRows = Number(summary.document_match_count || 0) + Number(summary.file_candidate_count || 0) + Number(summary.timeline_event_count || 0);
  const reportCandidates = Number(summary.report_item_count || 0);
  const outputCount = Object.keys(outputs).length;
  const readinessCards = [
    {
      label: "입력",
      title: isE01 ? "E01 처리 흐름 감지" : "폴더 또는 마운트 증거",
      body: isE01
        ? "E01은 의존 도구, 파티션 선택, 추출 provenance를 먼저 확인해야 합니다."
        : "폴더/마운트 증거는 바로 검색과 리뷰로 이동할 수 있습니다.",
      tone: isE01 ? "notice" : "ok",
    },
    {
      label: "규모",
      title: searchableRows ? `검색 대상 ${formatNumber(searchableRows)}행` : "검색 대상 없음",
      body: "대량 결과는 페이지와 가상 행으로 나눠 화면 과부하를 줄입니다.",
      tone: searchableRows ? "ok" : "warning",
    },
    {
      label: "검증",
      title: warningCount ? `검증 이슈 ${formatNumber(warningCount)}건` : "처리 이슈 없음",
      body: warningCount
        ? "보고서 후보로 쓰기 전에 처리 경고와 파서 제한사항을 먼저 확인하세요."
        : "현재 요약 기준으로 즉시 검색/리뷰를 시작할 수 있습니다.",
      tone: warningCount ? "warning" : "ok",
    },
    {
      label: "선별",
      title: reportCandidates ? `보고서 후보 ${formatNumber(reportCandidates)}건` : "선별 보드 준비됨",
      body: "원본 뷰어에서 확인한 항목만 관련 있음/보고서 포함으로 고정합니다.",
      tone: reportCandidates ? "ok" : "notice",
    },
    {
      label: "산출",
      title: outputCount ? `산출물 ${formatNumber(outputCount)}개` : "등록된 산출물 없음",
      body: "보고서, manifest, 검토 묶음을 내보내기 전에 원본 해시와 인용 정보를 확인하세요.",
      tone: outputCount ? "ok" : "warning",
    },
  ];
  return `
    <section class="case-readiness-dashboard" aria-label="Case readiness dashboard">
      <div class="readiness-head">
        <div>
          <p class="eyebrow">케이스 상태</p>
          <h3>분석 전에 볼 핵심 상태</h3>
          <p>E01/대용량/리뷰/제출 준비 상태를 한 번에 확인하고 다음 행동으로 바로 이동합니다.</p>
        </div>
        <div class="readiness-actions">
          <button class="secondary-button" type="button" data-open-tab="search">검색 시작</button>
          <button class="secondary-button" type="button" data-open-tab="review">선별 상태</button>
        </div>
      </div>
      <div class="readiness-grid">
        ${readinessCards.map((card) => `
          <article class="readiness-card ${escapeHtml(card.tone)}">
            <span>${escapeHtml(card.label)}</span>
            <strong>${escapeHtml(card.title)}</strong>
            <p>${escapeHtml(card.body)}</p>
          </article>
        `).join("")}
      </div>
    </section>
  `;
}

function renderForensicArtifactNavigator(payload) {
  const cards = FORENSIC_ARTIFACT_TAXONOMY.map((item) => ({
    ...item,
    count: artifactGroupCount(payload, item.terms),
  }));
  const totalSignals = cards.reduce((sum, item) => sum + item.count, 0);
  return `
    <section class="forensic-artifact-navigator" aria-label="Forensic artifact navigator">
      <div class="navigator-head">
        <div>
          <p class="eyebrow">아티팩트 분류</p>
          <h3>대량 검토용 분류 지도</h3>
          <p>전체 파일트리 대신 사건 판단에 필요한 카테고리를 먼저 보여주고, 필요한 탭으로 바로 이동합니다.</p>
        </div>
        <span class="navigator-total">단서 ${formatNumber(totalSignals)}건</span>
      </div>
      <div class="artifact-tree-grid">
        ${cards.map((card) => `
          <article class="artifact-tree-card">
            <button type="button" data-open-tab="${escapeHtml(card.tab)}">
              <span class="artifact-tree-title">${escapeHtml(card.label)}</span>
              <strong>${formatNumber(card.count)}</strong>
            </button>
            <p>${escapeHtml(card.hint)}</p>
          </article>
        `).join("")}
      </div>
    </section>
  `;
}

function renderUserWorkflowMap() {
  return `
    <section class="analyst-workflow-map" aria-label="Analyst workflow map">
      ${USER_WORKFLOW_STEPS.map((step, index) => `
        <article>
          <span>${index + 1}</span>
          <div>
            <strong>${escapeHtml(step.label)} · ${escapeHtml(step.title)}</strong>
            <p>${escapeHtml(step.text)}</p>
          </div>
        </article>
      `).join("")}
    </section>
  `;
}

function renderRunActionStrip(payload) {
  const outputs = payload.outputs || {};
  const hasReport = Boolean(outputs.report);
  return `
    <section class="run-action-strip" aria-label="Run completion actions">
      <div>
        <p class="eyebrow">후속 작업</p>
        <h3>처리 결과를 증거 검토로 전환</h3>
        <p>완료된 실행에서 Case DB 준비, 전체 검색, 증거 선별, 보고서 산출물로 이동합니다.</p>
      </div>
      <div class="run-action-buttons">
        <button class="secondary-button" type="button" data-focus-case-db="1">Case DB 준비</button>
        <button class="secondary-button" type="button" data-open-tab="search">증거 검색</button>
        <button class="secondary-button" type="button" data-open-tab="review">증거 선별</button>
        <button class="secondary-button" type="button" data-open-tab="report">${hasReport ? "보고서 열기" : "보고서 도구"}</button>
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
          <p class="eyebrow">처리 기록</p>
          <h3>${escapeHtml(processing.profile_label || "처리 프로파일")}</h3>
          <p>완료 표시가 누락을 숨기지 않도록 처리, 제외, 제한, 빈 결과를 함께 보여줍니다.</p>
        </div>
        <span class="warning-badge ${escapeHtml(processing.highest_warning_level || "none")}">
          ${escapeHtml(processing.highest_warning_level || "none")} · ${formatNumber(processing.warning_count || 0)}
        </span>
      </div>
      ${renderParserWarningBadges(payload)}
      <div class="processing-caps">
        <span>${processing.read_only ? "읽기 전용" : "추출 허용"}</span>
        <span>${processing.dry_run ? "예행 실행" : "실행 완료"}</span>
        <span>추출 제한: ${caps.max_extract_size_bytes ? formatBytes(caps.max_extract_size_bytes) : "없음"}</span>
        <span>파일 제한: ${caps.max_file_count ? formatNumber(caps.max_file_count) : "없음"}</span>
      </div>
      ${renderRunWorkflowContract(payload)}
      ${warnings.length ? `
        <div class="processing-warning-list">
          ${warnings.slice(0, 8).map((item) => `
            <div class="processing-warning ${escapeHtml(item.level || "notice")}">
              <strong>${escapeHtml(item.step || "step")}</strong>
              <span>${escapeHtml(item.message || "")}</span>
            </div>
          `).join("")}
        </div>
      ` : '<p class="empty-state">처리 이슈가 기록되지 않았습니다.</p>'}
      <div class="processing-step-grid">
        ${steps.map((step) => renderProcessingStep(step)).join("")}
      </div>
    </section>
  `;
}

function renderRunWorkflowContract(payload) {
  const workflow = payload.workflow || {};
  const stages = Array.isArray(workflow.stages) ? workflow.stages : [];
  if (!stages.length) return "";
  return `
    <section class="run-workflow-contract" data-testid="run-workflow-contract" aria-label="Run workflow contract">
      <div>
        <p class="eyebrow">케이스 처리 계약</p>
        <h3>${escapeHtml(workflow.source_type || "evidence")} · ${formatNumber(workflow.completed_stage_count || 0)}/${formatNumber(workflow.stage_count || stages.length)}단계 준비</h3>
        <p>입력, 추출, 파싱, 인덱싱, 리뷰, 보고서가 같은 산출물 계약으로 연결됩니다.</p>
      </div>
      ${renderRunWorkflowChecklistSummary(workflow.analyst_checklist_summary || {})}
      <div class="run-workflow-stage-grid">
        ${stages.map((stage) => `
          <article class="run-workflow-stage ${escapeHtml(stage.status || "pending")}">
            <button class="run-workflow-stage-main" type="button" data-open-tab="${escapeHtml(stage.gui?.primary_tab || "summary")}" data-workflow-stage="${escapeHtml(stage.id || "")}">
              <strong>${escapeHtml(stage.label || stage.id || "단계")}</strong>
              <span>${escapeHtml(runWorkflowStatusLabel(stage.status || "pending"))}</span>
              <small>${escapeHtml(stage.title || "")}</small>
              <em>단계 ${formatNumber((stage.step_names || []).length)}개 · 산출물 ${formatNumber((stage.output_keys || []).length)}개</em>
            </button>
            ${renderRunWorkflowOutputLinks(stage)}
            ${renderRunWorkflowChecklist(stage)}
          </article>
        `).join("")}
      </div>
    </section>
  `;
}

function renderRunWorkflowChecklistSummary(summary) {
  if (!summary || !summary.profile_version) return "";
  const nextActions = Array.isArray(summary.next_actions) ? summary.next_actions : [];
  const riskCount = Number(summary.warning_count || 0) + Number(summary.blocked_count || 0) + Number(summary.pending_count || 0);
  return `
    <div class="run-workflow-checklist-summary ${riskCount ? "needs-attention" : "ready"}" data-testid="run-workflow-checklist-summary">
      <div>
        <strong>분석관 확인 항목</strong>
        <span>준비 ${formatNumber(summary.ready_count || 0)} · 주의 ${formatNumber(summary.warning_count || 0)} · 차단 ${formatNumber(summary.blocked_count || 0)} · 대기 ${formatNumber(summary.pending_count || 0)}</span>
      </div>
      ${nextActions.length ? `
        <ul>
          ${nextActions.slice(0, 4).map((item) => `
            <li>
              <b>${escapeHtml(item.stage || "단계")} · ${escapeHtml(runWorkflowChecklistStatusLabel(item.status || "pending"))}</b>
              <span>${escapeHtml(item.action || "")}</span>
            </li>
          `).join("")}
        </ul>
      ` : '<p>모든 필수 확인 항목이 분석관 검토 준비 상태입니다.</p>'}
    </div>
  `;
}

function renderRunWorkflowChecklist(stage) {
  const items = Array.isArray(stage.analyst_checklist) ? stage.analyst_checklist : [];
  if (!items.length) return "";
  return `
    <details class="run-workflow-checklist" data-testid="run-workflow-checklist">
      <summary>분석관 체크리스트 · ${formatNumber(items.length)}</summary>
      <div class="run-workflow-checklist-list">
        ${items.map((item) => {
          const matched = Array.isArray(item.matched_outputs) ? item.matched_outputs : [];
          const expected = Array.isArray(item.expected_outputs) ? item.expected_outputs : [];
          const evidenceText = matched.length
            ? `연결됨: ${matched.map((name) => escapeHtml(name)).join(", ")}`
            : `예상 산출물: ${expected.length ? expected.map((name) => escapeHtml(name)).join(", ") : "단계 증거"}`;
          return `
            <div class="run-workflow-checklist-row ${escapeHtml(item.status || "pending")}">
              <div>
                <strong>${escapeHtml(item.label || item.id || "체크 항목")}</strong>
                <span>${escapeHtml(runWorkflowChecklistStatusLabel(item.status || "pending"))} · ${escapeHtml(item.severity || "미분류")}</span>
              </div>
              <p>${escapeHtml(item.action || "")}</p>
              <small>${evidenceText}</small>
            </div>
          `;
        }).join("")}
      </div>
    </details>
  `;
}

function renderRunWorkflowOutputLinks(stage) {
  const rawHandoffs = Array.isArray(stage.handoff_outputs) && stage.handoff_outputs.length
    ? stage.handoff_outputs
    : (Array.isArray(stage.output_keys) ? stage.output_keys.map((name) => ({
      name,
      role: "실행 산출물",
      recommended_viewer: "json-viewer",
      gui_action: "이 단계 산출물을 열어 확인합니다.",
      reportability_note: "보고 전 출처와 provenance 필드를 확인합니다.",
    })) : []);
  const handoffs = rawHandoffs.filter((item) => item?.name);
  if (!handoffs.length) {
    return '<p class="run-workflow-no-output">아직 연결된 산출물이 없습니다.</p>';
  }
  const visible = handoffs.slice(0, 4);
  const moreCount = Math.max(0, handoffs.length - visible.length);
  return `
    <div class="run-workflow-output-links" data-testid="run-workflow-output-links">
      ${visible.map((output) => {
        const name = String(output.name || "");
        const href = selectedRunId
          ? `/api/runs/${encodeURIComponent(selectedRunId)}/outputs/${encodeURIComponent(name)}/file`
          : "#";
        return `
          <div class="run-workflow-output-card">
            <strong>${escapeHtml(name)}</strong>
            <span>${escapeHtml(output.role || "실행 산출물")} · ${escapeHtml(output.recommended_viewer || "뷰어")}</span>
            <div class="run-workflow-output-actions">
              <button type="button" data-preview-output-name="${escapeHtml(name)}" title="${escapeHtml(output.gui_action || output.reportability_note || "")}">미리보기</button>
              <a href="${href}" title="${escapeHtml(output.reportability_note || output.gui_action || "")}">다운로드</a>
            </div>
          </div>
        `;
      }).join("")}
      ${moreCount ? `<small>그 외 산출물 ${formatNumber(moreCount)}개</small>` : ""}
    </div>
  `;
}

async function loadRunOutputPreview(outputName) {
  const viewer = detailPanel.querySelector("#evidenceViewer");
  if (!viewer || !selectedRunId || !outputName) return;
  viewer.setAttribute("aria-busy", "true");
  viewer.innerHTML = '<p class="empty-state">산출물 미리보기를 불러오는 중입니다...</p>';
  try {
    const payload = await api(`/api/runs/${selectedRunId}/outputs/${encodeURIComponent(outputName)}/preview`);
    viewer.innerHTML = renderRunOutputViewer(payload);
    bindViewerButtons();
  } catch (error) {
    viewer.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    viewer.setAttribute("aria-busy", "false");
  }
}

function renderRunOutputViewer(payload) {
  let body = `<p class="empty-state">${escapeHtml(payload.message || "표시할 미리보기가 없습니다.")}</p>`;
  if (payload.preview_type === "text") {
    body = `
      <pre class="viewer-text">${escapeHtml(payload.text || "")}</pre>
      ${payload.truncated ? '<p class="empty-state">성능 보호를 위해 미리보기 일부만 표시했습니다.</p>' : ""}
    `;
  }
  if (payload.preview_type === "json") {
    body = renderJsonPreview(payload.json || {}, payload);
  }
  if (payload.preview_type === "xml") {
    body = renderXmlPreview(payload.xml || {}, payload);
  }
  if (payload.preview_type === "hex") {
    body = renderHexPreview(payload.hex || {}, payload);
  }
  if (payload.preview_type === "sqlite") {
    body = renderSqlitePreview(payload.sqlite || {});
  }
  const profile = payload.output_preview_profile || {};
  return `
    <div class="viewer-header" data-testid="run-output-viewer-header">
      <div>
        <p class="eyebrow">산출물 뷰어</p>
        <h3>${escapeHtml(payload.output_name || payload.name || "output")}</h3>
      </div>
      <div class="detail-actions">
        <a class="mini-link" href="${escapeHtml(payload.download_url || "#")}" target="_blank" rel="noreferrer">다운로드</a>
      </div>
    </div>
    <div class="viewer-meta viewer-meta-compact">
      <span>${escapeHtml(payload.preview_type || "preview")}</span>
      <span>${formatBytes(payload.size || 0)}</span>
      <span>${profile.bounded ? "제한 미리보기" : "미리보기"}</span>
    </div>
    ${body}
    <details class="source-verification">
      <summary>산출물 출처와 보고 가능 여부</summary>
      <dl class="eventlog-fields">
        <dt>산출물 경로</dt><dd>${escapeHtml(payload.path || "")}</dd>
        <dt>판정</dt><dd>${escapeHtml(profile.reportability_decision?.decision || "검토 필요")}</dd>
        <dt>보고 전 확인</dt><dd>${(profile.reportability_decision?.required_before_report || []).map((item) => escapeHtml(item)).join("<br>") || "원본 검증 필요"}</dd>
      </dl>
    </details>
  `;
}

function renderParserWarningBadges(payload) {
  const steps = Array.isArray(payload.steps) ? payload.steps : [];
  const warningSteps = steps.filter((step) => (step.warning_level || "none") !== "none");
  const zeroSteps = steps.filter((step) => stepHasZeroRows(step));
  const reusedSteps = steps.filter((step) => Boolean(step.reused));
  const badges = [
    {
      label: "경고",
      value: warningSteps.length,
      tone: warningSteps.length ? "warning" : "none",
      title: warningSteps.map((step) => step.name).join(", ") || "경고 단계 없음",
    },
    {
      label: "빈 파서",
      value: zeroSteps.length,
      tone: zeroSteps.length ? "notice" : "none",
      title: zeroSteps.map((step) => step.name).join(", ") || "빈 파서 산출물 없음",
    },
    {
      label: "재사용 산출물",
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
      <p class="eyebrow">Case DB</p>
      <h3>검색 결과를 검토 기록으로 고정</h3>
      <p>JSON을 따로 가져오지 않아도 현재 실행 결과를 Case DB로 준비하고, 키워드 검색에서 선별 상태까지 이어갑니다.</p>
      <form id="caseDbImportForm" class="search-form">
        <label>DB 경로 <input name="database" value="${escapeHtml(defaultDb)}" required /></label>
        <label>Case ID <input name="case_id" value="${escapeHtml(defaultCaseId)}" required /></label>
        <label>케이스명 <input name="name" value="${escapeHtml(payload.mode || "rapidtriage run")}" /></label>
        <button id="caseDbImportButton" type="submit">Case DB 준비</button>
      </form>
      <form id="caseDbSearchForm" class="search-form">
        <label>검색어 <input name="keywords" placeholder="password, powershell, download" required /></label>
        <input type="hidden" name="cursor" value="" />
        <label>출처
          <select name="source">
            <option value="">전체 출처</option>
            <option value="documents">문서</option>
            <option value="files">파일</option>
            <option value="artifacts">아티팩트</option>
            <option value="indicators">IOC / 위험</option>
            <option value="timeline">시간축</option>
          </select>
        </label>
        <label>원본 확인
          <select name="verification_status">
            <option value="">전체 상태</option>
            <option value="unverified">미확인</option>
            <option value="source_opened">원본 열람</option>
            <option value="cross_checked">교차 확인</option>
            <option value="verified">확인 완료</option>
            <option value="rejected">제외</option>
          </select>
        </label>
        <label>선별 상태
          <select name="review_status">
            <option value="">전체 선별</option>
            <option value="unreviewed">미검토</option>
            <option value="relevant">관련 있음</option>
            <option value="needs-review">재검토</option>
            <option value="excluded">제외</option>
            <option value="not-relevant">관련 없음</option>
          </select>
        </label>
        <label>검색 저장명 <input name="save_as" placeholder="계정 정보 후보, PowerShell 흔적" /></label>
        <button id="caseDbSearchButton" type="submit">Case DB 검색</button>
        <button class="secondary-button" id="caseDbSavedSearchButton" type="button">저장 검색 불러오기</button>
      </form>
      <section id="caseDbSavedSearches" class="viewer-panel compact">
        <p class="empty-state">Case DB가 준비되면 저장 검색과 최근 검색어가 여기에 표시됩니다.</p>
      </section>
      <section id="caseDbResult" class="viewer-panel">
        <p class="empty-state">검색어를 입력하면 필요한 경우 Case DB를 자동 준비한 뒤 결과를 보여줍니다.</p>
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
      text: "원본을 확인하고 태그, 관련성, 보고서 포함 여부를 결정합니다.",
      metric: `보고서 후보 ${formatNumber(summary.report_item_count || 0)}건`,
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
        <button class="secondary-button" type="button" data-open-tab="search">키워드 검색</button>
        <button class="secondary-button" type="button" data-open-tab="review">선별 보드</button>
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
    ${renderTimelineReviewLanes(payload)}
    <div class="review-list-shell" role="region" aria-label="Timeline result list">
      <table class="data-table">
        <thead><tr><th>Time</th><th>Source</th><th>Type</th><th>Summary</th><th></th></tr></thead>
        <tbody>
          ${rows.map((event, index) => {
            const pointer = `/events/${offset + index}`;
            const context = { source: "timeline", pointer, title: event.summary || "timeline event", note: event.summary || "", path: event.path || "", tags: ["timeline", event.source, event.event_type].filter(Boolean) };
            const inspector = {
              title: event.summary || "Timeline event",
              source: event.source || "timeline",
              kind: event.event_type || "event",
              timestamp: event.timestamp || "",
              path: event.path || "",
              pointer,
              preview: event.summary || "",
              chips: ["timeline", event.source, event.event_type].filter(Boolean),
              reviewContext: context,
            };
            return `
              <tr class="selectable-result-row" data-filter="${rowText(event)}" ${rowInspectorAttributes(inspector)} ${event.path ? `data-viewer-row-path="${escapeHtml(event.path)}" data-review-context="${escapeHtml(JSON.stringify(context))}"` : ""}>
                <td>${escapeHtml(event.timestamp)}</td>
                <td>${escapeHtml(event.source)}</td>
                <td>${escapeHtml(event.event_type)}</td>
                <td><strong>${escapeHtml(event.summary)}</strong><span>${escapeHtml(event.path || "")}</span></td>
                <td>${bookmarkButton("timeline", pointer, event.summary)}</td>
              </tr>
            `;
          }).join("")}
        </tbody>
      </table>
    </div>
    ${renderPaginationControls(payload.pagination, "timeline")}
  `;
}

function renderTimelineReviewLanes(payload) {
  const rows = payload.events || [];
  const lanes = [
    {
      label: "파일 생성/수정",
      filter: "file path modified created",
      terms: ["file", "path", "modified", "created", "mft", "usn"],
      hint: "문서 작성, 복사, 삭제 직전 파일 활동을 먼저 봅니다.",
    },
    {
      label: "웹·AI 활동",
      filter: "browser url ai chatgpt claude gemini perplexity",
      terms: ["browser", "url", "web", "ai", "chatgpt", "claude", "gemini", "perplexity"],
      hint: "검색, 다운로드, AI 프롬프트, 웹 접속 흐름을 모읍니다.",
    },
    {
      label: "윈도우 이벤트",
      filter: "evtx eventlog logon powershell defender",
      terms: ["evtx", "eventlog", "logon", "powershell", "defender", "wmi", "task"],
      hint: "로그온, 실행, 보안 이벤트를 시간순으로 확인합니다.",
    },
    {
      label: "외부장치/반출",
      filter: "usb shellbag mount drive external download",
      terms: ["usb", "shellbag", "mount", "drive", "external", "download"],
      hint: "USB 연결, 다운로드, 외부 저장장치 관련 단서를 봅니다.",
    },
    {
      label: "메신저/메일",
      filter: "chat kakao telegram whatsapp mail email attachment",
      terms: ["chat", "kakao", "telegram", "whatsapp", "mail", "email", "attachment"],
      hint: "대화, 메일, 첨부파일 흐름을 사건 시간에 맞춰 봅니다.",
    },
    {
      label: "삭제/위험",
      filter: "delete removed warning risk validation",
      terms: ["delete", "deleted", "removed", "warning", "risk", "validation"],
      hint: "삭제 흔적과 검증 경고가 있는 타임라인만 좁힙니다.",
    },
  ];
  return `
    <details class="tab-assist-drawer timeline-review-lanes" aria-label="타임라인 사건 재구성 레인" data-testid="timeline-review-lanes">
      <summary>
        <span>
          <em>시간 재구성</em>
          <strong>행위별 필터 ${formatNumber(lanes.length)}개 · 이벤트 ${formatNumber(rows.length)}개</strong>
        </span>
      </summary>
      <div class="tab-assist-body timeline-lane-grid">
        ${lanes.map((lane) => {
          const count = rows.filter((row) => lane.terms.some((term) => compactRowFilterText(row).includes(term))).length;
          return `
            <button class="secondary-button timeline-lane-card" type="button" data-timeline-lane-filter="${escapeHtml(lane.filter)}" title="${escapeHtml(lane.hint)}">
              <span>${escapeHtml(lane.label)}</span>
              <b>${formatNumber(count)}</b>
              <em>${escapeHtml(lane.hint)}</em>
            </button>
          `;
        }).join("")}
      </div>
    </details>
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
      <p>이 목록은 피벗 단서입니다. 매칭 규칙과 위험 플래그는 최종 귀속 판단이 아니므로, 보고 전 원본 행을 반드시 확인하세요.</p>
      <div class="metric-grid">
        ${metric("Indicators", summary.indicator_count)}
        ${metric("Rule hits", summary.matched_indicator_count)}
        ${metric("Types", Object.keys(summary.type_counts || {}).length)}
        ${metric("Sources", Object.keys(summary.source_output_counts || {}).length)}
      </div>
    </section>
    <section class="ti-enrichment-card">
      <div>
        <p class="eyebrow">#63 local ti enrichment</p>
        <h3>Attach an offline IOC feed for review</h3>
        <p>JSON/CSV/TXT feed paths are read locally by the RapidTriage server. No external TI API calls are made; feed provenance and source pointers must still be reviewed before reporting.</p>
      </div>
      <form id="indicatorTiForm" class="search-form">
        <label>Local feed path <input name="ti_feed" placeholder="/cases/feeds/local-ioc-feed.json" /></label>
        <label>Result limit <input name="limit" type="number" min="1" max="1000" value="250" /></label>
        <label class="check-label"><input name="include_unmatched" type="checkbox" /> Include unmatched indicators</label>
        <button type="submit">Run local enrichment</button>
      </form>
      <div id="indicatorTiResult" class="ti-enrichment-result">
        <p class="empty-state">Load a local feed to see matched indicators, severity, feed hashes, and source pointers here.</p>
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

function renderIndicatorTiEnrichment(payload) {
  const rows = payload.indicators || [];
  const summary = payload.summary || {};
  const feedSources = payload.ti_feed_sources || [];
  return `
    <div class="metric-grid">
      ${metric("Feed matches", summary.matched_indicator_count || 0)}
      ${metric("Returned", summary.returned_indicator_count || 0)}
      ${metric("Feeds", summary.ti_feed_count || 0)}
      ${metric("Severities", Object.keys(summary.severity_counts || {}).length)}
    </div>
    <details class="match-details" open>
      <summary>Feed provenance (${feedSources.length})</summary>
      <div class="dense-list">
        ${feedSources.map((feed) => `
          <div class="dense-row">
            <strong>${escapeHtml([feed.name, feed.version].filter(Boolean).join(" · ") || feed.path)}</strong>
            <span>${escapeHtml([feed.format, `${feed.indicator_count || 0} indicators`, `sha256:${feed.sha256 || ""}`].filter(Boolean).join(" · "))}</span>
          </div>
        `).join("") || '<p class="empty-state">No feed provenance.</p>'}
      </div>
    </details>
    ${payload.reportability_decision ? `<p class="help-text">${escapeHtml(payload.reportability_decision.allowed_use || "")} · ${escapeHtml(payload.reportability_decision.decision || "")}</p>` : ""}
    ${rows.length ? `
      <table class="data-table compact-table">
        <thead><tr><th>Indicator</th><th>Enrichment</th><th>Sources</th></tr></thead>
        <tbody>
          ${rows.map((indicator) => {
            const enrichment = indicator.ti_enrichment || {};
            return `
              <tr data-filter="${rowText(indicator)}">
                <td><strong>${escapeHtml(indicator.value)}</strong><span>${escapeHtml([indicator.type, indicator.ti_review_status].filter(Boolean).join(" · "))}</span></td>
                <td>
                  ${renderChipList([enrichment.severity, enrichment.classification, enrichment.source, enrichment.matched_on].filter(Boolean))}
                  <span>${escapeHtml(enrichment.note || "")}</span>
                </td>
                <td>${renderIndicatorSources(indicator.sources || [])}</td>
              </tr>
            `;
          }).join("")}
        </tbody>
      </table>
    ` : '<p class="empty-state">No local feed matches. Check feed values, indicator type, or include unmatched indicators for review.</p>'}
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
  for (const [kind, artifactPayload] of Object.entries(groups)) {
    const offset = artifactPayload.pagination?.offset || 0;
    for (const [index, artifact] of (artifactPayload.artifacts || []).entries()) {
      rows.push({ kind, index: offset + index, artifact });
    }
  }
  const displayRows = activeArtifactFilter
    ? rows.filter(({ kind, artifact }) => artifactSourceCategory(kind, artifact) === activeArtifactFilter)
    : rows;
  const pagination = activeArtifactFilter
    ? filteredPagination(displayRows.length, "artifacts")
    : artifactPaginationSummary(groups, rows.length);
  if (!displayRows.length) return '<p class="empty-state">No artifact rows.</p>';
  return `
    ${renderPaginationNotice(pagination, "artifacts")}
    ${renderArtifactValidationSummary(displayRows)}
    <div class="review-list-shell" role="region" aria-label="Artifact result list">
      <table class="data-table">
        <thead><tr><th>Kind</th><th>Type</th><th>Provider</th><th>Evidence</th><th></th></tr></thead>
        <tbody>
          ${displayRows.map(({ kind, index, artifact }) => {
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
          }).join("")}
        </tbody>
      </table>
    </div>
    ${renderPaginationControls(pagination, "artifacts")}
  `;
}

function filteredPagination(total, collection) {
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

function artifactPaginationSummary(groups, returned) {
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

function renderArtifactValidationSummary(rows) {
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

function summarizeArtifactValidation(rows) {
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

function artifactCommercialBlockers(details) {
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

function renderArtifactValidationBadges(artifact) {
  const details = artifact.details || {};
  const gates = Array.isArray(details.core_accuracy_gates) ? details.core_accuracy_gates : [];
  const firstGate = gates[0] || {};
  const badges = [];
  if (firstGate.gap_id) {
    const missingCount = Array.isArray(firstGate.missing_required_checks) ? firstGate.missing_required_checks.length : 0;
    badges.push(`${firstGate.gap_id} · 미충족 ${missingCount}`);
  }
  if (details.validation_required || firstGate.status === "validation-required") {
    badges.push("검증 필요");
  }
  if (details.reportability) {
    badges.push(`보고: ${details.reportability}`);
  }
  if (details.commercial_grade_ready === false || firstGate.commercial_grade_ready === false) {
    badges.push("상용 검증 전");
  }
  const evtxProfile = details.evtx_commercial_readiness_profile || {};
  if (evtxProfile.allowed_current_use) {
    badges.push(`용도: ${evtxProfile.allowed_current_use}`);
  }
  if (!badges.length) return "";
  return `<div class="artifact-validation-badges">${badges.slice(0, 5).map((badge) => `<span>${escapeHtml(badge)}</span>`).join("")}</div>`;
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
  const ntfsPreview = ntfsArtifactPreviewText(artifact);
  if (ntfsPreview) return ntfsPreview;
  const registryPreview = registryArtifactPreviewText(artifact);
  if (registryPreview) return registryPreview;
  for (const key of ["command_line", "script_block_text", "file_path", "executable_path", "ai_service", "domain", "source_url", "target_path", "entry_name", "service_name", "process_name"]) {
    if (details[key]) return String(details[key]);
  }
  return artifact.artifact_type || "artifact";
}

function ntfsArtifactPreviewText(artifact) {
  const details = artifact.details || {};
  if (artifact.artifact_type === "usn-journal-file" && details.usn_replay_inventory_profile) {
    const replay = details.usn_replay_inventory_profile || {};
    const bounded = replay.bounded_mft_replay_preview || {};
    const rename = replay.rename_pair_preview || {};
    return [
      "USN journal",
      details.native_record_count !== undefined ? `${details.native_record_count} record(s)` : "",
      bounded.correlated_record_count !== undefined ? `${bounded.correlated_record_count} path candidate(s)` : "",
      rename.candidate_pair_count !== undefined ? `${rename.candidate_pair_count} rename pair(s)` : "",
      replay.bounded_state_replay_preview?.transition_count !== undefined ? `${replay.bounded_state_replay_preview.transition_count} state transition(s)` : "",
    ].filter(Boolean).join(" · ");
  }
  if (artifact.artifact_type === "usn-record") {
    const bounded = details.usn_bounded_mft_path || {};
    return [
      "USN record",
      bounded.path_candidate || details.file_name || details.file_path,
      Array.isArray(details.reason_flags) ? details.reason_flags.join("|") : "",
      details.record_cursor !== undefined ? `cursor=${details.record_cursor}` : "",
    ].filter(Boolean).join(" · ");
  }
  if (artifact.artifact_type === "mft-record") {
    const bounded = details.mft_bounded_parent_path || {};
    return [
      "MFT record",
      bounded.path || details.file_path || details.file_name,
      details.record_number !== undefined ? `record=${details.record_number}` : "",
      details.record_offset !== undefined ? `offset=${details.record_offset}` : "",
    ].filter(Boolean).join(" · ");
  }
  return "";
}

function registryArtifactPreviewText(artifact) {
  const details = artifact.details || {};
  if (!details.registry_native_depth_readiness_profile) return "";
  const profile = details.registry_native_depth_readiness_profile || {};
  const primary = details.key_path || details.key_path_candidate || details.parent_key_path_candidate || details.name || artifact.artifact_type;
  const status = [
    profile.family || "registry",
    details.candidate_kind || details.coverage_status,
    details.cell_offset !== undefined ? `cell=${details.cell_offset}` : "",
    profile.validation_summary?.transaction_log_status ? `tx=${profile.validation_summary.transaction_log_status}` : "",
  ].filter(Boolean).join(" · ");
  return [primary, status].filter(Boolean).join(" · ");
}

function renderArtifactDetails(artifact) {
  if (!artifact.details) return "";
  const eventLogCard = renderEventLogArtifactCard(artifact);
  const evtxReadinessCard = renderEvtxReadinessArtifactCard(artifact);
  const ntfsDepthCard = renderNtfsDepthArtifactCard(artifact);
  const ntfsReplayCard = renderNtfsReplayPreviewArtifactCard(artifact);
  const registryDepthCard = renderRegistryDepthArtifactCard(artifact);
  const windowsCoreReadinessCard = renderWindowsCoreReadinessArtifactCard(artifact);
  const accuracyGateCard = renderCoreAccuracyGateCard(artifact);
  const aiUsageCard = renderAiUsageArtifactCard(artifact);
  const aiConversationCard = renderAiConversationArtifactCard(artifact);
  const cloudExportReviewCard = renderCloudExportReviewArtifactCard(artifact);
  return `
    <details class="match-details artifact-inline-details">
      <summary>세부 검증 보기</summary>
      ${eventLogCard}
      ${evtxReadinessCard}
      ${ntfsDepthCard}
      ${ntfsReplayCard}
      ${registryDepthCard}
      ${windowsCoreReadinessCard}
      ${accuracyGateCard}
      ${aiUsageCard}
      ${aiConversationCard}
      ${cloudExportReviewCard}
      <details class="artifact-json-preview">
        <summary>Raw JSON 보기</summary>
        <pre>${escapeHtml(JSON.stringify(artifact.details, null, 2))}</pre>
      </details>
    </details>
  `;
}

function renderCloudExportReviewArtifactCard(artifact) {
  const details = artifact.details || {};
  const cloudProfile = details.cloud_analyst_review_profile || {};
  const providerProfile =
    details.m365_export_review_profile ||
    details.google_takeout_review_profile ||
    details.icloud_export_review_profile ||
    {};
  const manifest =
    details.m365_export_parser_manifest ||
    details.google_takeout_parser_manifest ||
    details.icloud_export_parser_manifest ||
    details.cloud_export_import_manifest ||
    {};
  if (!cloudProfile.profile_version && !providerProfile.profile_version && !manifest.manifest_version) return "";
  const rowPivots = Array.isArray(cloudProfile.row_pivots)
    ? cloudProfile.row_pivots.slice(0, 8)
    : Object.entries(manifest.row_pivots || {}).slice(0, 8).map(([key, value]) => `${key}=${value}`);
  const providerFamily = providerProfile.product_family || providerProfile.workload_family || cloudProfile.cloud_family;
  const teamsProfile = details.teams_message_review_profile || {};
  const filePermissionProfile = details.m365_file_permission_review_profile || {};
  const fileStateProfile = details.m365_file_state_review_profile || {};
  const chips = [
    details.service || cloudProfile.service,
    providerFamily,
    details.commercial_grade_ready === false ? "not commercial-ready" : "",
    providerProfile.provider_native_diff_status || providerProfile.teams_compliance_record_status,
  ].filter(Boolean);
  const rows = [
    ["Summary", cloudProfile.summary || artifact.artifact_type],
    ["Primary pivots", (providerProfile.present_primary_pivots || []).slice(0, 8).join(" · ")],
    ["Row pivots", rowPivots.join(" · ")],
    ["Viewer", manifest.row_citation?.source_viewer_locator?.viewer || manifest.source_viewer_locator?.viewer],
    ["Teams review", [
      teamsProfile.reply_to_message_id ? `reply=${teamsProfile.reply_to_message_id}` : "",
      details.attachment_count !== undefined ? `attachments=${details.attachment_count}` : "",
      details.reaction_count !== undefined ? `reactions=${details.reaction_count}` : "",
      teamsProfile.edited_status,
      teamsProfile.deleted_status,
    ].filter(Boolean).join(" · ")],
    ["File permission/state", [
      filePermissionProfile.permission_count !== undefined ? `permissions=${filePermissionProfile.permission_count}` : "",
      filePermissionProfile.sharing_link_count !== undefined ? `sharing links=${filePermissionProfile.sharing_link_count}` : "",
      fileStateProfile.version_id ? `version=${fileStateProfile.version_id}` : "",
      fileStateProfile.deleted_status,
      fileStateProfile.retention_label ? `retention=${fileStateProfile.retention_label}` : "",
    ].filter(Boolean).join(" · ")],
    ["Questions", (cloudProfile.analyst_questions || []).slice(0, 3).join(" · ")],
    ["Not proof of", (cloudProfile.not_proof_of || []).slice(0, 4).join(" · ")],
  ].filter(([, value]) => value !== undefined && value !== null && String(value).trim());
  return `
    <section class="core-accuracy-card cloud-export-review-card" data-testid="cloud-export-review-card">
      <div class="eventlog-card-header">
        <strong>Cloud export review</strong>
        <span>${escapeHtml([manifest.manifest_version, manifest.manifest_sha256 ? `manifest ${String(manifest.manifest_sha256).slice(0, 12)}` : ""].filter(Boolean).join(" · "))}</span>
      </div>
      <div class="eventlog-chip-row">${chips.map((chip) => `<span>${escapeHtml(chip)}</span>`).join("")}</div>
      <dl class="eventlog-fields">
        ${rows.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(String(value))}</dd>`).join("")}
      </dl>
    </section>
  `;
}

function renderCoreAccuracyGateCard(artifact) {
  const details = artifact.details || {};
  const gates = Array.isArray(details.core_accuracy_gates) ? details.core_accuracy_gates : [];
  if (!gates.length) return "";
  const visibleGates = gates.slice(0, 3);
  return `
    <section class="core-accuracy-card">
      <div class="eventlog-card-header">
        <strong>Core accuracy gates</strong>
        <span>${escapeHtml(`${visibleGates.length}/${gates.length} shown · reportability controls`)}</span>
      </div>
      ${visibleGates.map((gate) => {
        const satisfied = (gate.satisfied_checks || []).slice(0, 5);
        const missing = (gate.missing_required_checks || []).slice(0, 5);
        const refs = (gate.evidence_refs || []).slice(0, 3);
        const missingCount = Array.isArray(gate.missing_required_checks) ? gate.missing_required_checks.length : missing.length;
        const satisfiedCount = Array.isArray(gate.satisfied_checks) ? gate.satisfied_checks.length : satisfied.length;
        const gateTitle = gate.title || "검증 기준";
        return `
          <article class="accuracy-gate-row">
            <div class="accuracy-gate-main">
              <div>
                <strong>${escapeHtml(gate.gap_id || "gap")}</strong>
                <span>${escapeHtml(gateTitle)}</span>
              </div>
              <em>${escapeHtml(`${missingCount} 미충족`)}</em>
            </div>
            <div class="eventlog-chip-row accuracy-gate-chips">
              <span>${escapeHtml(gate.status || "validation-required")}</span>
              <span>${escapeHtml(gate.default_reportability || "reportability unknown")}</span>
              <span>${escapeHtml(gate.commercial_grade_ready ? "commercial-ready" : "not-commercial-ready")}</span>
              <span>${escapeHtml(`${satisfiedCount} 만족`)}</span>
            </div>
            <p class="accuracy-gate-one-line">${escapeHtml(satisfied.slice(0, 2).join(" · ") || "만족된 필수 검증 없음")}</p>
            <details class="accuracy-gate-detail">
              <summary>검증 항목 자세히</summary>
              <dl class="eventlog-fields">
                <dt>만족</dt>
                <dd>${escapeHtml(satisfied.join(" · ") || "No required check satisfied yet")}</dd>
                <dt>미충족</dt>
                <dd>${escapeHtml(missing.join(" · ") || "No missing check listed")}</dd>
                <dt>근거</dt>
                <dd>${escapeHtml(refs.join(" · "))}</dd>
                <dt>다음</dt>
                <dd>${escapeHtml(gate.next_validation_step || "")}</dd>
              </dl>
            </details>
          </article>
        `;
      }).join("")}
    </section>
  `;
}

function windowsCoreReadinessProfile(details) {
  if (details.account_privilege_deep_parse_profile) {
    return {
      title: "SAM/SECURITY/SYSTEM readiness",
      profile: details.account_privilege_deep_parse_profile,
      reportGrade: details.os_account_report_grade_assessment || {},
    };
  }
  if (details.srum_ese_validation_profile) {
    return {
      title: "SRUM ESE readiness",
      profile: details.srum_ese_validation_profile,
      reportGrade: details.execution_report_grade_assessment || {},
    };
  }
  const executionProfiles = [
    ["Amcache readiness", details.amcache_schema_profile?.execution_artifact_validation_profile],
    ["ShimCache readiness", details.shimcache_execution_caveat_profile?.execution_artifact_validation_profile],
    ["BAM/DAM readiness", details.bam_dam_decode_profile?.execution_artifact_validation_profile],
    ["Execution artifact readiness", details.execution_artifact_validation_profile],
  ];
  const match = executionProfiles.find(([, profile]) => profile);
  if (match) {
    return {
      title: match[0],
      profile: match[1],
      reportGrade: details.execution_report_grade_assessment || {},
    };
  }
  return null;
}

function renderWindowsCoreReadinessArtifactCard(artifact) {
  const details = artifact.details || {};
  const readiness = windowsCoreReadinessProfile(details);
  if (!readiness) return "";
  const profile = readiness.profile || {};
  const reportGrade = readiness.reportGrade || {};
  const decoded = profile.decoded_components || {};
  const validationSummary = profile.validation_summary || {};
  const reportability = profile.reportability_decision || {};
  const legal = profile.legal_handling || {};
  const decodedRows = Object.entries(decoded)
    .filter(([, value]) => value)
    .slice(0, 8)
    .map(([key]) => key.replaceAll("_", " "));
  const blockerRows = (profile.commercial_grade_blockers || reportGrade.blockers || []).slice(0, 6);
  const requiredRows = (profile.required_before_report || profile.required_independent_checks || []).slice(0, 4);
  const evidenceKeys = Object.keys(profile.evidence_fields || {}).slice(0, 6);
  const chips = [
    profile.artifact_family || profile.artifact_scope || artifact.artifact_type,
    profile.commercial_gap_id || (Array.isArray(reportGrade.commercial_gap_ids) ? reportGrade.commercial_gap_ids.join(",") : ""),
    reportGrade.status || validationSummary.report_grade_status || reportability.decision,
    profile.commercial_grade_ready ? "commercial-ready" : "not-commercial-ready",
  ].filter(Boolean);
  return `
    <section class="windows-core-readiness-card">
      <div class="eventlog-card-header">
        <strong>${escapeHtml(readiness.title)}</strong>
        <span>${escapeHtml([profile.profile_version, profile.commercial_batch_id].filter(Boolean).join(" · "))}</span>
      </div>
      <div class="eventlog-chip-row">${chips.map((chip) => `<span>${escapeHtml(chip)}</span>`).join("")}</div>
      <dl class="eventlog-fields">
        <dt>디코딩</dt>
        <dd>${escapeHtml(decodedRows.join(" · ") || "검증 프로필만 있음; native row decode는 trusted diff가 더 필요합니다.")}</dd>
        <dt>증거 요건</dt>
        <dd>${escapeHtml(evidenceKeys.join(" · ") || "원본 경로, 해시, 파서 버전이 필요합니다.")}</dd>
        <dt>보고 가능성</dt>
        <dd>${escapeHtml([reportability.allowed_use, reportability.decision, profile.analyst_caveat].filter(Boolean).join(" · "))}</dd>
        <dt>검증</dt>
        <dd>${escapeHtml([validationSummary.report_grade_status, `${validationSummary.passed_check_count || 0}개 점검 통과`, ...(validationSummary.failed_check_names || []).slice(0, 4)].filter(Boolean).join(" · "))}</dd>
        <dt>보고 전 확인</dt>
        <dd>${escapeHtml(requiredRows.join(" · "))}</dd>
        <dt>Blockers</dt>
        <dd>${escapeHtml(blockerRows.join(" · ") || "No blocker listed")}</dd>
        <dt>Legal</dt>
        <dd>${escapeHtml(legal.authority_gate || (legal.security_secret_values_redacted ? "secret values redacted by default" : ""))}</dd>
      </dl>
    </section>
  `;
}

function renderEvtxReadinessArtifactCard(artifact) {
  const details = artifact.details || {};
  const profile = details.evtx_commercial_readiness_profile || null;
  if (!profile) return "";
  const nativeBinxml = profile.native_binxml || {};
  const messageRendering = profile.message_rendering || {};
  const recoveryValidation = profile.recovery_validation || {};
  const trustedEvidence = profile.trusted_evidence || {};
  const blockerRows = (profile.blockers || []).slice(0, 6);
  const actionRows = (profile.next_engineering_actions || []).slice(0, 4);
  const identity = profile.row_identity || {};
  const chips = [
    profile.readiness_status || "validation-required",
    profile.allowed_current_use || "triage-search",
    profile.commercial_grade_ready ? "commercial-ready" : "not-commercial-ready",
    profile.commercial_gap_ids?.join(","),
  ].filter(Boolean);
  return `
    <section class="evtx-readiness-card">
      <div class="eventlog-card-header">
        <strong>EVTX commercial readiness</strong>
        <span>${escapeHtml([identity.record_id ? `record ${identity.record_id}` : "", identity.event_id ? `event ${identity.event_id}` : "", profile.profile_version].filter(Boolean).join(" · "))}</span>
      </div>
      <div class="eventlog-chip-row">${chips.map((chip) => `<span>${escapeHtml(chip)}</span>`).join("")}</div>
      <dl class="eventlog-fields">
        <dt>BinXML</dt>
        <dd>${escapeHtml([nativeBinxml.status, nativeBinxml.field_fidelity, `${nativeBinxml.scalar_value_count || 0} scalar`, `${nativeBinxml.template_substitution_count || 0} template values`].filter(Boolean).join(" · "))}</dd>
        <dt>Message</dt>
        <dd>${escapeHtml([messageRendering.status, messageRendering.renderer, messageRendering.provider_resource_resolved ? "provider resource resolved" : "provider resource missing"].filter(Boolean).join(" · "))}</dd>
        <dt>Recovery</dt>
        <dd>${escapeHtml([recoveryValidation.status, recoveryValidation.allocation_status, `confidence ${recoveryValidation.confidence ?? 0}`].filter(Boolean).join(" · "))}</dd>
        <dt>Trusted diff</dt>
        <dd>${escapeHtml([trustedEvidence.record_diff_status, trustedEvidence.message_diff_status, trustedEvidence.recovery_diff_status].filter(Boolean).join(" · "))}</dd>
        <dt>Blockers</dt>
        <dd>${escapeHtml(blockerRows.join(" · ") || "No blocker listed")}</dd>
        <dt>Next actions</dt>
        <dd>${escapeHtml(actionRows.join(" · "))}</dd>
        <dt>Warning</dt>
        <dd>${escapeHtml(profile.analyst_warning || "")}</dd>
      </dl>
    </section>
  `;
}

function renderRegistryDepthArtifactCard(artifact) {
  const details = artifact.details || {};
  const profile = details.registry_native_depth_readiness_profile || null;
  if (!profile) return "";
  const decoded = profile.decoded_components || {};
  const decodedRows = Object.entries(decoded)
    .filter(([, value]) => value)
    .slice(0, 8)
    .map(([key]) => key.replaceAll("_", " "));
  const blockerRows = (profile.blockers || []).slice(0, 5);
  const citationRows = (profile.source_citation_requirements || []).slice(0, 8);
  return `
    <section class="registry-depth-card">
      <div class="eventlog-card-header">
        <strong>Registry native depth</strong>
        <span>${escapeHtml([profile.family, profile.artifact_scope, profile.status].filter(Boolean).join(" · "))}</span>
      </div>
      <div class="eventlog-chip-row">
        <span>depth ${escapeHtml(String(profile.depth_score ?? "0"))}</span>
        <span>${escapeHtml(profile.decoded_component_count || 0)}/${escapeHtml(profile.total_component_count || 0)} decoded</span>
        <span>${escapeHtml(profile.validation_summary?.transaction_log_status || "transaction unknown")}</span>
        <span>${escapeHtml(profile.report_grade_ready ? "report-ready" : "triage-only")}</span>
      </div>
      <dl class="eventlog-fields">
        <dt>Decoded</dt>
        <dd>${escapeHtml(decodedRows.join(" · ") || "No native components decoded")}</dd>
        <dt>Citation</dt>
        <dd>${escapeHtml(citationRows.join(" · "))}</dd>
        <dt>Blockers</dt>
        <dd>${escapeHtml(blockerRows.join(" · ") || "No blocker listed")}</dd>
        <dt>Warning</dt>
        <dd>${escapeHtml(profile.analyst_warning || "")}</dd>
      </dl>
    </section>
  `;
}

function renderNtfsDepthArtifactCard(artifact) {
  const details = artifact.details || {};
  const profile = details.ntfs_native_depth_readiness_profile || null;
  if (!profile) return "";
  const decoded = profile.decoded_components || {};
  const decodedRows = Object.entries(decoded)
    .filter(([, value]) => value)
    .slice(0, 8)
    .map(([key]) => key.replaceAll("_", " "));
  const blockerRows = (profile.blockers || []).slice(0, 5);
  const citationRows = (profile.source_citation_requirements || []).slice(0, 8);
  return `
    <section class="ntfs-depth-card">
      <div class="eventlog-card-header">
        <strong>${escapeHtml(String(profile.family || "ntfs").toUpperCase())} native depth</strong>
        <span>${escapeHtml(profile.status || "validation required")}</span>
      </div>
      <div class="eventlog-chip-row">
        <span>depth ${escapeHtml(String(profile.depth_score ?? "0"))}</span>
        <span>${escapeHtml(profile.decoded_component_count || 0)}/${escapeHtml(profile.total_component_count || 0)} decoded</span>
        <span>${escapeHtml(profile.validation_summary?.trusted_diff_status || "trusted diff missing")}</span>
        <span>${escapeHtml(profile.report_grade_ready ? "report-ready" : "triage-only")}</span>
      </div>
      <dl class="eventlog-fields">
        <dt>Decoded</dt>
        <dd>${escapeHtml(decodedRows.join(" · ") || "No native components decoded")}</dd>
        <dt>Citation</dt>
        <dd>${escapeHtml(citationRows.join(" · "))}</dd>
        <dt>Blockers</dt>
        <dd>${escapeHtml(blockerRows.join(" · ") || "No blocker listed")}</dd>
        <dt>Warning</dt>
        <dd>${escapeHtml(profile.analyst_warning || "")}</dd>
      </dl>
    </section>
  `;
}

function renderNtfsReplayPreviewArtifactCard(artifact) {
  const details = artifact.details || {};
  const replay = details.usn_replay_inventory_profile || {};
  const boundedReplay = replay.bounded_mft_replay_preview || null;
  const pathCacheProfile = replay.mft_bounded_path_cache_profile || null;
  const pathReliability = replay.usn_path_reliability_profile || null;
  const stateValidation = replay.usn_state_replay_validation_profile || null;
  const renamePreview = replay.rename_pair_preview || null;
  const deletePreview = replay.delete_lifecycle_preview || null;
  const statePreview = replay.bounded_state_replay_preview || null;
  const rowPath = details.usn_bounded_mft_path || null;
  if (!boundedReplay && !renamePreview && !deletePreview && !statePreview && !rowPath) return "";

  const pathSamples = Array.isArray(boundedReplay?.path_samples) ? boundedReplay.path_samples.slice(0, 5) : [];
  const renamePairs = Array.isArray(renamePreview?.pairs) ? renamePreview.pairs.slice(0, 5) : [];
  const deleteCandidates = Array.isArray(deletePreview?.candidates) ? deletePreview.candidates.slice(0, 5) : [];
  const stateTransitions = Array.isArray(statePreview?.transitions) ? statePreview.transitions.slice(0, 8) : [];
  const locatorLinks = renderNtfsSourceLocatorLinks(details, renamePairs, deleteCandidates, stateTransitions);
  const chips = [
    boundedReplay ? `${boundedReplay.correlated_record_count || 0}/${boundedReplay.record_count || 0} path-correlated` : "",
    pathCacheProfile ? `${pathCacheProfile.complete_path_count || 0}/${pathCacheProfile.cache_entry_count || 0} complete MFT paths` : boundedReplay ? `${boundedReplay.cache_entry_count || 0} MFT cache entries` : "",
    renamePreview ? `${renamePreview.candidate_pair_count || 0} rename pair(s)` : "",
    deletePreview ? `${deletePreview.paired_create_delete_count || 0}/${deletePreview.delete_count || 0} delete lifecycle(s)` : "",
    statePreview ? `${statePreview.transition_count || 0} state transition(s)` : "",
    stateValidation?.validation_status ? stateValidation.validation_status : "",
    pathReliability?.reliability ? pathReliability.reliability : "",
    renamePreview ? renamePreview.pair_balance : "",
    rowPath?.path_candidate ? "row path candidate" : "",
  ].filter(Boolean);
  const rows = [
    ["USN path correlation", boundedReplay ? `${boundedReplay.correlated_record_count || 0} correlated · ${boundedReplay.uncorrelated_record_count || 0} uncorrelated` : rowPath?.path_candidate],
    ["MFT cache quality", pathCacheProfile ? `${pathCacheProfile.complete_path_count || 0} complete · ${pathCacheProfile.partial_path_count || 0} partial · warnings=${pathCacheProfile.warning_count || 0}` : ""],
    ["Path reliability", pathReliability ? `${pathReliability.reliability || "unknown"} · ${pathReliability.correlated_record_count || 0}/${pathReliability.record_count || 0} correlated · ${pathReliability.review_priority || ""}` : ""],
    ["Cache hits", boundedReplay ? `file=${boundedReplay.file_reference_cache_hit_count || 0} · parent=${boundedReplay.parent_reference_cache_hit_count || 0}` : rowPath?.path_source],
    ["Correlation status", boundedReplay?.correlation_status_counts ? Object.entries(boundedReplay.correlation_status_counts).map(([key, value]) => `${key}:${value}`).join(" · ") : rowPath?.status],
    ["Rename pairing", renamePreview ? `${renamePreview.candidate_pair_count || 0} paired · old unmatched=${renamePreview.unmatched_old_count || 0} · new unmatched=${renamePreview.unmatched_new_count || 0}` : ""],
    ["Delete lifecycle", deletePreview ? `${deletePreview.paired_create_delete_count || 0} paired · delete-only=${deletePreview.delete_without_prior_create_count || 0}` : ""],
    ["Bounded state replay", statePreview ? `${statePreview.transition_count || 0} transitions · pending rename=${statePreview.pending_rename_count || 0} · final paths=${statePreview.final_path_state_count || 0}` : ""],
    ["State replay validation", stateValidation ? `${stateValidation.validation_status || "unknown"} · record diff=${stateValidation.trusted_diff_status || "not-attached"} · state diff=${stateValidation.state_replay_diff_passed ? "passed" : "required"}` : ""],
  ].filter(([, value]) => value !== undefined && value !== null && String(value).trim());
  return `
    <section class="ntfs-depth-card">
      <div class="eventlog-card-header">
        <strong>USN replay preview</strong>
        <span>${escapeHtml("bounded MFT path correlation · rename candidate review")}</span>
      </div>
      <div class="eventlog-chip-row">${chips.map((chip) => `<span>${escapeHtml(chip)}</span>`).join("")}</div>
      <dl class="eventlog-fields">
        ${rows.map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(String(value))}</dd>`).join("")}
        ${pathSamples.length ? `<dt>Path samples</dt><dd>${pathSamples.map((sample) => escapeHtml([
          sample.path_candidate || sample.file_name,
          sample.transition_class,
          Array.isArray(sample.reason_flags) ? sample.reason_flags.join("|") : "",
          sample.record_cursor !== undefined ? `cursor=${sample.record_cursor}` : "",
        ].filter(Boolean).join(" · "))).join("<br>")}</dd>` : ""}
        ${Array.isArray(pathCacheProfile?.sample_partial_paths) && pathCacheProfile.sample_partial_paths.length ? `<dt>MFT partial path warnings</dt><dd>${pathCacheProfile.sample_partial_paths.slice(0, 5).map((sample) => escapeHtml([
          sample.path || `record=${sample.record_number || ""}`,
          sample.status,
          Array.isArray(sample.warnings) ? sample.warnings.join("|") : "",
        ].filter(Boolean).join(" · "))).join("<br>")}</dd>` : ""}
        ${pathReliability?.safe_report_wording ? `<dt>Reliability wording</dt><dd>${escapeHtml(pathReliability.safe_report_wording)}</dd>` : ""}
        ${renamePairs.length ? `<dt>Rename pairs</dt><dd>${renamePairs.map((pair) => escapeHtml([
          `${pair.old_name || "(old)"} -> ${pair.new_name || "(new)"}`,
          pair.old_path_candidate && pair.new_path_candidate ? `${pair.old_path_candidate} -> ${pair.new_path_candidate}` : "",
          pair.confidence ? `confidence=${pair.confidence}` : "",
          pair.old_record_cursor !== undefined || pair.new_record_cursor !== undefined ? `cursor=${pair.old_record_cursor || "?"}->${pair.new_record_cursor || "?"}` : "",
        ].filter(Boolean).join(" · "))).join("<br>")}</dd>` : ""}
        ${deleteCandidates.length ? `<dt>Delete lifecycle</dt><dd>${deleteCandidates.map((candidate) => escapeHtml([
          candidate.file_name || "(file)",
          candidate.lifecycle_status,
          candidate.delete_path_candidate || candidate.create_path_candidate,
          candidate.confidence ? `confidence=${candidate.confidence}` : "",
          candidate.create_record_cursor || candidate.delete_record_cursor ? `cursor=${candidate.create_record_cursor || "?"}->${candidate.delete_record_cursor || "?"}` : "",
        ].filter(Boolean).join(" · "))).join("<br>")}</dd>` : ""}
        ${stateTransitions.length ? `<dt>State transitions</dt><dd>${stateTransitions.map((transition) => escapeHtml([
          transition.transition || "(transition)",
          transition.previous_path && transition.new_path ? `${transition.previous_path} -> ${transition.new_path}` : transition.previous_path || transition.new_path || transition.file_name,
          transition.state_effect,
          transition.confidence ? `confidence=${transition.confidence}` : "",
          transition.record_cursor !== undefined ? `cursor=${transition.record_cursor}` : "",
        ].filter(Boolean).join(" · "))).join("<br>")}</dd>` : ""}
        ${stateValidation?.safe_report_wording ? `<dt>State validation wording</dt><dd>${escapeHtml(stateValidation.safe_report_wording)}</dd>` : ""}
        ${locatorLinks ? `<dt>Source locators</dt><dd>${locatorLinks}</dd>` : ""}
        ${rowPath?.path_candidate ? `<dt>Current row path</dt><dd>${escapeHtml([rowPath.path_candidate, rowPath.path_source, rowPath.status].filter(Boolean).join(" · "))}</dd>` : ""}
        <dt>Report warning</dt>
        <dd>${escapeHtml("This is a bounded review aid. Court-grade rename/delete replay still requires full-journal ordering, full FRN cache, and trusted-tool diff validation.")}</dd>
      </dl>
    </section>
  `;
}

function renderNtfsSourceLocatorLinks(details, renamePairs = [], deleteCandidates = [], stateTransitions = []) {
  const manifest = details.ntfs_report_citation_manifest || {};
  const sourcePath = details.source_path || manifest.source_path || "";
  const locators = [];
  for (const entry of manifest.viewer_entrypoints || []) {
    if (entry?.viewer === "hex" && entry.byte_offset !== undefined && entry.byte_offset !== "") {
      locators.push({ label: entry.label || "Open raw record", path: entry.source_path || sourcePath, offset: entry.byte_offset, length: details.record_length || 4096 });
    }
  }
  for (const ref of manifest.citation_refs || []) {
    const locator = ref?.viewer_locator || {};
    if (locator.byte_offset !== undefined && locator.byte_offset !== "") {
      locators.push({ label: ref.kind || locator.viewer || "citation locator", path: locator.source_path || sourcePath, offset: locator.byte_offset, length: details.record_length || 4096 });
    }
  }
  for (const pair of renamePairs) {
    if (pair.old_record_cursor !== undefined && pair.old_record_cursor !== "") {
      locators.push({ label: `OLD ${pair.old_name || "rename"}`, path: sourcePath, offset: pair.old_record_cursor, length: 512 });
    }
    if (pair.new_record_cursor !== undefined && pair.new_record_cursor !== "") {
      locators.push({ label: `NEW ${pair.new_name || "rename"}`, path: sourcePath, offset: pair.new_record_cursor, length: 512 });
    }
  }
  for (const candidate of deleteCandidates) {
    if (candidate.create_record_cursor !== undefined && candidate.create_record_cursor !== "") {
      locators.push({ label: `CREATE ${candidate.file_name || "USN"}`, path: sourcePath, offset: candidate.create_record_cursor, length: 512 });
    }
    if (candidate.delete_record_cursor !== undefined && candidate.delete_record_cursor !== "") {
      locators.push({ label: `DELETE ${candidate.file_name || "USN"}`, path: sourcePath, offset: candidate.delete_record_cursor, length: 512 });
    }
  }
  for (const transition of stateTransitions) {
    if (transition.record_cursor !== undefined && transition.record_cursor !== "") {
      locators.push({ label: `STATE ${transition.transition || "USN"}`, path: sourcePath, offset: transition.record_cursor, length: 512 });
    }
    if (transition.paired_old_record_cursor !== undefined && transition.paired_old_record_cursor !== "") {
      locators.push({ label: `STATE paired OLD ${transition.file_name || "USN"}`, path: sourcePath, offset: transition.paired_old_record_cursor, length: 512 });
    }
  }
  const unique = [];
  const seen = new Set();
  for (const locator of locators) {
    if (!locator.path || locator.offset === undefined || locator.offset === "") continue;
    const key = `${locator.path}|${locator.offset}|${locator.label}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(locator);
  }
  if (!unique.length || !selectedRunId) return "";
  return unique.slice(0, 8).map((locator) => {
    const offset = Number(locator.offset) || 0;
    const length = Math.max(1, Math.min(Number(locator.length) || 512, 4096));
    const url = `/api/runs/${encodeURIComponent(selectedRunId)}/source-hex-range?path=${encodeURIComponent(locator.path)}&offset=${encodeURIComponent(offset)}&length=${encodeURIComponent(length)}&include_hashes=true`;
    return `<a class="mini-link" href="${escapeHtml(url)}" target="_blank" rel="noreferrer">${escapeHtml(locator.label)} @ ${escapeHtml(offset)}</a>`;
  }).join("<br>");
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
  return renderRowActionDock(items);
}

function renderFiles(payload) {
  const rows = payload.candidates || [];
  const offset = payload.pagination?.offset || 0;
  const summary = renderFileTriageSummary(payload);
  if (!rows.length) return `${summary}<p class="empty-state">No file candidates.</p>`;
  return `
    ${summary}
    ${renderPaginationNotice(payload.pagination, "files")}
    <div class="review-list-shell" role="region" aria-label="File result list">
      <table class="data-table file-triage-table">
        <thead><tr><th>Name</th><th>Triage</th><th>Categories</th><th>Size</th><th>Modified</th><th></th></tr></thead>
        <tbody>
          ${rows.map((file, index) => {
            const context = { source: "files", pointer: `/candidates/${offset + index}`, title: file.name || fileName(file.path), note: file.name || "", path: file.path || "", tags: ["file", ...(file.categories || [])].filter(Boolean) };
            const match = { source: "files", kind: (file.categories || []).join(", "), path: file.path || "", title: file.name || fileName(file.path), preview: file.name || "", pointer: context.pointer };
            const signature = file.file_signature || {};
            const triageClass = signature.mismatch ? "risk-row" : "";
            const inspector = {
              title: file.name || fileName(file.path) || "File candidate",
              source: "files",
              kind: (file.categories || []).join(", ") || "file",
              timestamp: file.modified_at || "",
              path: file.path || "",
              pointer: context.pointer,
              preview: [formatBytes(file.size), signature.status, signature.mismatch ? "signature mismatch" : ""].filter(Boolean).join(" · "),
              chips: ["file", ...(file.categories || []), signature.mismatch ? "mismatch" : ""].filter(Boolean),
              reviewContext: context,
            };
            return `
              <tr class="selectable-result-row ${triageClass}" data-filter="${rowText(file)}" ${rowInspectorAttributes(inspector)} ${file.path ? `data-viewer-row-path="${escapeHtml(file.path)}" data-review-context="${escapeHtml(JSON.stringify(context))}"` : ""}>
                <td><strong>${escapeHtml(file.name)}</strong><span>${escapeHtml(file.path)}</span></td>
                <td>${renderFileTriageBadges(file)}</td>
                <td>${escapeHtml((file.categories || []).join(", "))}</td>
                <td>${formatBytes(file.size)}</td>
                <td>${escapeHtml(file.modified_at)}</td>
                <td class="action-stack">${renderRowActionDock([
                  file.path ? viewSourceButton(match, context) : "",
                  compareButton(compareItemFromMatch(match, context)),
                  bookmarkButton("files", context.pointer, file.name),
                ])}</td>
              </tr>
            `;
          }).join("")}
        </tbody>
      </table>
    </div>
    ${renderPaginationControls(payload.pagination, "files")}
  `;
}

function renderFileTriageSummary(payload) {
  const summary = payload.summary || {};
  const knownGood = payload.known_good_suppression_profile || {};
  const signature = payload.file_signature_profile || {};
  const suppressed = payload.known_good_suppressed_candidates || [];
  const mismatches = payload.signature_mismatch_candidates || [];
  return `
    <section class="file-triage-summary" data-testid="file-triage-summary">
      <div class="processing-summary-head">
        <div>
          <p class="eyebrow">file triage</p>
          <h3>Known-good suppression and extension spoofing</h3>
          <p class="help-text">정상 파일 숨김 여부와 확장자 위장 의심 파일을 여기서 바로 확인합니다.</p>
        </div>
        <span class="status-pill ${summary.signature_mismatch_count ? "warning" : "ok"}">${summary.signature_mismatch_count || 0} mismatch</span>
      </div>
      <div class="metric-grid compact-metric-grid">
        ${metric(formatNumber(summary.raw_candidate_count || summary.candidate_count || 0), "Raw candidates")}
        ${metric(formatNumber(summary.candidate_count || 0), "Visible candidates")}
        ${metric(formatNumber(summary.known_good_match_count || 0), "Known-good matches")}
        ${metric(formatNumber(summary.signature_mismatch_count || 0), "Signature mismatches")}
      </div>
      <div class="processing-caps file-triage-caps">
        <span>Known-good feed: ${knownGood.configured ? `${formatNumber(knownGood.feed_count || 0)} feed(s)` : "not configured"}</span>
        <span>NSRL RDS: ${formatNumber(knownGood.nsrl_rds_feed_count || 0)} feed(s) / ${formatNumber(knownGood.nsrl_rds_row_count || 0)} row(s)</span>
        <span>Hash count: ${formatNumber(knownGood.known_good_hash_count || 0)}</span>
        <span>Suppression: ${knownGood.hide_known_good ? "hidden from candidate table" : "reviewable in table"}</span>
        <span>Signature checked: ${formatNumber(signature.checked_count || summary.signature_checked_count || 0)}</span>
        <span>Unrecognized header: ${formatNumber(signature.unrecognized_known_extension_count || 0)}</span>
      </div>
      ${suppressed.length ? `
        <details class="dense-list file-triage-details">
          <summary>Hidden known-good rows (${formatNumber(suppressed.length)})</summary>
          ${suppressed.slice(0, 12).map((item) => `
            <div class="dense-row">
              <strong>${escapeHtml(item.name || fileName(item.path))}</strong>
              <span>${escapeHtml(item.path || "")}</span>
              <span>${escapeHtml(item.known_good_match?.algorithm || "hash")} match · ${escapeHtml(item.known_good_match?.value || "")}</span>
              <span>${escapeHtml(item.known_good_match?.feed_format || item.known_good_match?.source_detail?.feed_format || "feed")} · ${escapeHtml(item.known_good_match?.feed_name || item.known_good_match?.source_detail?.feed_name || "")}</span>
            </div>
          `).join("")}
        </details>
      ` : ""}
      ${mismatches.length ? `
        <details class="dense-list file-triage-details" open>
          <summary>Extension/signature mismatch review queue (${formatNumber(mismatches.length)})</summary>
          ${mismatches.slice(0, 12).map((item) => `
            <div class="dense-row warning">
              <strong>${escapeHtml(item.name || fileName(item.path))}</strong>
              <span>${escapeHtml(item.path || "")}</span>
              <span>Detected ${escapeHtml(item.detected || "unknown")} but expected ${(item.expected || []).map(escapeHtml).join(", ")}</span>
            </div>
          `).join("")}
        </details>
      ` : ""}
    </section>
  `;
}

function renderFileTriageBadges(file) {
  const knownStatus = file.known_good_status || "not-configured";
  const knownMatch = file.known_good_match || {};
  const signature = file.file_signature || {};
  const knownLabel = knownStatus === "known-good-feed-match"
    ? `Known-good ${knownMatch.algorithm || ""}`.trim()
    : knownStatus.replace(/-/g, " ");
  const knownSource = knownMatch.feed_format
    ? `${knownMatch.feed_format}${knownMatch.feed_name ? ` · ${knownMatch.feed_name}` : ""}`
    : "";
  const signatureLabel = signature.status
    ? signature.status.replace(/-/g, " ")
    : "signature not checked";
  return `
    <div class="file-triage-badges">
      <span class="file-triage-badge ${knownStatus === "known-good-feed-match" ? "ok" : ""}">${escapeHtml(knownLabel)}</span>
      ${knownSource ? `<span class="file-triage-badge ok">${escapeHtml(knownSource)}</span>` : ""}
      <span class="file-triage-badge ${signature.mismatch ? "warning" : ""}">${escapeHtml(signatureLabel)}</span>
      ${signature.detected ? `<span class="file-triage-badge">detected: ${escapeHtml(signature.detected)}</span>` : ""}
    </div>
  `;
}

function renderDocs(payload) {
  const rows = payload.results || [];
  const offset = payload.pagination?.offset || 0;
  const extractionErrors = payload.extraction_errors || [];
  const extractionNotice = extractionErrors.length
    ? `<div class="search-verification-card warning">
        <strong>${formatNumber(extractionErrors.length)} document(s) skipped during text extraction.</strong>
        <span>Search continued; review the skipped list before concluding that a keyword is absent.</span>
        <details>
          <summary>Show skipped documents</summary>
          <ul>${extractionErrors.slice(0, 20).map((item) => `<li>${escapeHtml(fileName(item.path))} · ${escapeHtml(item.reason || "extraction failed")} · ${formatBytes(item.size || 0)}</li>`).join("")}</ul>
        </details>
      </div>`
    : "";
  if (!rows.length) return `${extractionNotice}<p class="empty-state">No document matches.</p>`;
  return `
    ${extractionNotice}
    ${renderDocumentReviewLanes(payload)}
    ${renderPaginationNotice(payload.pagination, "docs")}
    <div class="review-list-shell" role="region" aria-label="Document result list">
      <table class="data-table">
        <thead><tr><th>Document</th><th>Kind</th><th>Keywords</th><th>Preview</th><th></th></tr></thead>
        <tbody>
          ${rows.map((doc, index) => {
            const context = { source: "docs", pointer: `/results/${offset + index}`, title: fileName(doc.path), note: doc.preview || "", path: doc.path || "", tags: ["document", doc.kind].filter(Boolean) };
            const match = { source: "documents", kind: doc.kind || "", path: doc.path || "", title: fileName(doc.path), preview: doc.preview || "", pointer: context.pointer };
            const inspector = {
              title: fileName(doc.path) || "Document hit",
              source: "documents",
              kind: doc.kind || "document",
              timestamp: doc.modified_at || "",
              path: doc.path || "",
              pointer: context.pointer,
              preview: doc.preview || "",
              chips: ["document", doc.kind, ...(doc.matched_keywords || [])].filter(Boolean),
              reviewContext: context,
            };
            return `
              <tr class="selectable-result-row" data-filter="${rowText(doc)}" ${rowInspectorAttributes(inspector)} ${doc.path ? `data-viewer-row-path="${escapeHtml(doc.path)}" data-review-context="${escapeHtml(JSON.stringify(context))}"` : ""}>
                <td><strong>${escapeHtml(fileName(doc.path))}</strong><span>${escapeHtml(doc.path)}</span></td>
                <td>${escapeHtml(doc.kind)}</td>
                <td>${escapeHtml((doc.matched_keywords || []).join(", "))}</td>
                <td>${escapeHtml(doc.preview || "")}</td>
                <td class="action-stack">${renderRowActionDock([
                  doc.path ? viewSourceButton(match, context) : "",
                  compareButton(compareItemFromMatch(match, context)),
                  bookmarkButton("docs", context.pointer, fileName(doc.path)),
                ])}</td>
              </tr>
            `;
          }).join("")}
        </tbody>
      </table>
    </div>
    ${renderPaginationControls(payload.pagination, "docs")}
  `;
}

function renderDocumentReviewLanes(payload) {
  const rows = payload.results || [];
  const lanes = [
    { label: "문서", filter: "pdf docx xlsx pptx odt ods odp office text", terms: ["pdf", "docx", "xlsx", "pptx", "odt", "ods", "odp", "office", "text"], hint: "계약서, 송장, 보고서, Office/PDF/text 문서를 먼저 봅니다." },
    { label: "메일/첨부", filter: "email mail eml msg pst ost mbox attachment", terms: ["email", "mail", "eml", "msg", "pst", "ost", "mbox", "attachment"], hint: "메일 본문, 첨부, 헤더/송수신자를 검토합니다." },
    { label: "메신저", filter: "kakao whatsapp telegram signal line discord chat", terms: ["kakao", "whatsapp", "telegram", "signal", "line", "discord", "chat"], hint: "대화/메신저 export 또는 DB 파싱 결과를 확인합니다." },
    { label: "OCR/이미지", filter: "ocr image media screenshot scan", terms: ["ocr", "image", "media", "screenshot", "scan"], hint: "이미지 후보와 OCR 텍스트 히트를 따로 봅니다." },
    { label: "보고 후보", filter: "invoice payment transfer fraud contract", terms: ["invoice", "payment", "transfer", "fraud", "contract"], hint: "사건 키워드와 바로 연결될 수 있는 문서를 좁힙니다." },
  ];
  const scored = lanes.map((lane) => ({
    ...lane,
    count: rows.filter((row) => {
      const text = rowText(row);
      return lane.terms.some((term) => text.includes(term));
    }).length,
  }));
  return `
    <details class="tab-assist-drawer document-review-lanes" aria-label="문서 검토 레인" data-testid="document-review-lanes">
      <summary>
        <span>
          <em>Document review</em>
          <strong>문서·메일·대화 검토 레인 · 필터 ${formatNumber(scored.length)}개 · 결과 ${formatNumber(rows.length)}개</strong>
        </span>
      </summary>
      <div class="tab-assist-body document-lane-list">
        ${scored.map((lane) => `
          <button class="secondary-button document-lane-card" type="button" data-doc-lane-filter="${escapeHtml(lane.filter)}" title="${escapeHtml(lane.hint)}">
            <span>${escapeHtml(lane.label)}</span>
            <b>${formatNumber(lane.count)}</b>
            <em>${escapeHtml(lane.hint)}</em>
          </button>
        `).join("")}
      </div>
    </details>
  `;
}

function renderSearch(payload = null) {
  if (payload) currentSearchPayload = payload;
  const rows = payload?.matches || [];
  const draft = payload
    ? {
        keywords: payload.keywords || [],
        ocr: payload.ocr?.enabled !== false,
        source: (payload.options?.sources || [])[0] || "",
        extension: (payload.options?.extensions || [])[0] || "",
        path_contains: payload.options?.path_contains || "",
        search_mode: payload.options?.search_mode || "exact",
        fuzzy_distance: payload.options?.fuzzy_distance ?? 1,
        proximity_window: payload.options?.proximity_window ?? 0,
        hide_known_good: payload.options?.hide_known_good === true,
        keyword_packs: payload.keyword_pack_selection_profile?.selected_pack_names || [],
      }
    : getSearchDraft();
  const draftText = (draft.keywords || []).join(", ");
  const keywordPackLabels = {
    credentials: "계정/인증",
    execution: "실행 흔적",
    network: "네트워크",
    "browser-ai": "브라우저/AI",
    "windows-ir": "윈도우 IR",
    exfiltration: "유출 정황",
  };
  return `
    <section class="search-hero compact-viewer-hero">
      <div>
        <p class="eyebrow">증거 검색</p>
        <h3>검색 → 원본 확인 → 선별</h3>
        <p>결과를 열면 뷰어가 먼저 고정됩니다. 본문 검색, 해시, 리뷰 저장을 같은 패널에서 처리합니다.</p>
      </div>
      <div class="search-hero-tips">
        <span>${kbd("Ctrl K")} 전체 검색</span>
        <span>${kbd("Ctrl F")} 현재 파일/표 필터</span>
        <span>${kbd("Alt R")} 관련 있음 저장</span>
      </div>
    </section>
    <form id="unifiedSearchForm" class="search-form">
      ${renderSearchScopePlanner(draft)}
      <label>
        전체 케이스 검색 ${kbd("Ctrl K")}
        <input id="unifiedSearchInput" value="${escapeHtml(draftText)}" placeholder="문서, 웹 기록, 로그, OCR 검색" required />
      </label>
      <div class="field-grid search-filter-grid">
        <label>
          검색 범위
          <select id="unifiedSearchSource">
            <option value="">전체 출처</option>
            <option value="documents" ${draft.source === "documents" ? "selected" : ""}>문서</option>
            <option value="files" ${draft.source === "files" ? "selected" : ""}>파일 메타데이터</option>
            <option value="web" ${draft.source === "web" ? "selected" : ""}>웹 아티팩트</option>
            <option value="indicators" ${draft.source === "indicators" ? "selected" : ""}>지표</option>
            <option value="artifacts" ${draft.source === "artifacts" ? "selected" : ""}>기타 아티팩트</option>
            <option value="timeline" ${draft.source === "timeline" ? "selected" : ""}>시간축</option>
            <option value="ocr" ${draft.source === "ocr" ? "selected" : ""}>OCR</option>
          </select>
        </label>
        <label>
          확장자
          <input id="unifiedSearchExtension" value="${escapeHtml(draft.extension || "")}" placeholder=".pdf, .log, .sqlite" />
        </label>
      </div>
      <label>
        경로 포함
        <input id="unifiedSearchPath" value="${escapeHtml(draft.path_contains || "")}" placeholder="Users, Downloads, AppData..." />
      </label>
      <div class="field-grid search-filter-grid">
        <label>
          검색 방식
          <select id="unifiedSearchMode">
            <option value="exact" ${draft.search_mode === "exact" ? "selected" : ""}>정확 검색 + 기본 어간</option>
            <option value="fuzzy" ${draft.search_mode === "fuzzy" ? "selected" : ""}>오타 허용 검색</option>
            <option value="regex" ${draft.search_mode === "regex" ? "selected" : ""}>Regex</option>
          </select>
        </label>
        <label>
          오타 허용 거리
          <input id="unifiedSearchFuzzyDistance" type="number" min="0" max="2" value="${escapeHtml(draft.fuzzy_distance ?? 1)}" />
        </label>
        <label>
          근접 검색 범위
          <input id="unifiedSearchProximity" type="number" min="0" max="100" value="${escapeHtml(draft.proximity_window ?? 0)}" />
        </label>
      </div>
      <label class="check-label"><input id="unifiedSearchOcr" type="checkbox" ${draft.ocr === false ? "" : "checked"} /> 이미지 후보에서 OCR 포함</label>
      <label class="check-label"><input id="unifiedSearchHideKnownGood" type="checkbox" ${draft.hide_known_good ? "checked" : ""} /> Known-good / NSRL 파일 숨기기</label>
      <fieldset class="keyword-pack-fieldset">
        <legend>키워드 묶음</legend>
        ${Object.entries(keywordPackLabels).map(([pack, label]) => `
          <label class="check-label compact"><input class="keyword-pack-option" type="checkbox" value="${escapeHtml(pack)}" ${(draft.keyword_packs || []).includes(pack) ? "checked" : ""} /> <span>${escapeHtml(label)}</span></label>
        `).join("")}
      </fieldset>
      <button id="unifiedSearchButton" type="submit">증거 검색</button>
    </form>
    ${renderRecentSearchChips()}
    ${renderDocsIndexSidecarSearch(currentDocsIndexSearchPayload, draft)}
    <div class="preset-row" aria-label="Keyword presets">
      ${SEARCH_PRESETS.map((preset) => `<button class="preset-chip" type="button" data-keywords="${escapeHtml(preset.keywords.join(", "))}">${escapeHtml(preset.label)}</button>`).join("")}
    </div>
    <section class="search-workbench viewer-first-workbench">
      <aside id="evidenceViewer" class="viewer-panel viewer-dock primary-viewer-dock" data-testid="source-viewer" role="region" aria-label="원본 미리보기" aria-live="polite" aria-busy="false">
        ${renderViewerEmptyState("원본 뷰어", "검색 결과의 원본 또는 파일 안 검색을 누르면 원본 내용이 여기에 표시됩니다.")}
      </aside>
      <div class="search-results-pane">
        ${payload ? renderSearchResults(payload, rows) : '<p class="empty-state">키워드를 입력하세요. 여러 단어는 쉼표로 구분합니다.</p>'}
      </div>
    </section>
  `;
}

function renderSearchScopePlanner(draft = {}) {
  const hasTerms = (draft.keywords || []).length > 0;
  return `
    <section class="search-scope-planner" aria-label="검색 범위 선택" data-testid="search-scope-planner">
      <button class="secondary-button search-scope-card active" type="button" data-search-scope-action="case">
        <strong>전체 케이스</strong>
        <span>문서, 웹, 로그, OCR, 아티팩트를 한 번에 검색</span>
        <em>${hasTerms ? "키워드 준비됨" : "Ctrl K"}</em>
      </button>
      <button class="secondary-button search-scope-card" type="button" data-search-scope-action="current-file">
        <strong>현재 파일/뷰어</strong>
        <span>원본 미리보기 안에서 본문, 로그, SQLite, OCR 후보 재검색</span>
        <em>Ctrl F</em>
      </button>
      <button class="secondary-button search-scope-card" type="button" data-search-scope-action="artifact">
        <strong>아티팩트 피벗</strong>
        <span>EVTX, Registry, Browser, AI, USB 같은 행위 흔적으로 이동</span>
        <em>분류 보기</em>
      </button>
    </section>
  `;
}

function renderDocsIndexSidecarSearch(payload = null, draft = {}) {
  const terms = (payload?.query?.terms || draft.keywords || []).join(", ");
  return `
    <section class="docs-index-sidecar-search search-verification-card compact" data-testid="docs-index-sidecar-search">
      <div>
        <p class="eyebrow">문서 인덱스</p>
        <h3>저장된 문서 인덱스에서 빠르게 재검색</h3>
        <p>PDF/Office/메일 텍스트 추출 결과를 다시 열지 않고 <code>rapidtriage-docs-index.json</code> 인덱스 항목을 조회합니다. 본문은 저장하지 않으므로 원본 뷰어로 문맥 검증이 필요합니다.</p>
      </div>
      <div class="mini-stat-row">
        <span>command: docs-index-search</span>
        <span>stores_full_text=false</span>
        <span>limit cap 5000</span>
      </div>
      <button id="docsIndexSearchButton" class="secondary-button" type="button">현재 키워드로 문서 인덱스 검색</button>
      <div id="docsIndexSearchResults" class="docs-index-sidecar-results" aria-live="polite">
        ${payload ? renderDocsIndexSidecarResults(payload) : `<p class="help-text">현재 키워드: ${escapeHtml(terms || "아직 없음")}</p>`}
      </div>
    </section>
  `;
}

function renderDocsIndexSidecarResults(payload) {
  const summary = payload.summary || {};
  const rows = payload.results || [];
  const warning = payload.api_profile?.reportability_warning || "문서 인덱스 히트를 보고서에 넣기 전 원본 뷰어로 확인하세요.";
  if (!rows.length) {
    return `
      <p class="help-text">${escapeHtml(warning)}</p>
      <p class="empty-state">${escapeHtml((payload.query?.terms || []).join(", ") || "현재 키워드")}에 대한 문서 인덱스 히트가 없습니다.</p>
    `;
  }
  return `
    <div class="mini-stat-row docs-index-sidecar-metrics">
      <span>일치 문서 ${formatNumber(summary.matched_document_count || 0)}건</span>
      <span>반환 결과 ${formatNumber(summary.returned_result_count || 0)}건</span>
      <span>${summary.truncated ? "일부만 표시됨; 범위를 좁혀 재검색" : "전체 표시"}</span>
      <span>${summary.stores_full_text === false ? "본문 저장 없음" : "본문 저장 여부 미확인"}</span>
    </div>
    <p class="help-text">${escapeHtml(warning)}</p>
    <table class="data-table compact docs-index-sidecar-table">
      <thead><tr><th>문서</th><th>일치 키워드</th><th>점수</th><th>검증</th></tr></thead>
      <tbody>
        ${rows.slice(0, 50).map((result, index) => {
          const match = {
            path: result.path,
            title: fileName(result.path),
            source: result.source || "docs-index",
            kind: result.kind || "docs-index",
            pointer: result.pointer || result.source_locator || `docs-index:/results/${index}`,
            source_viewer_action_profile: result.source_viewer_action_profile,
            matched_keywords: (result.matched_terms || []).map((item) => item.term),
            preview: result.review_note_citation?.text || `docs-index score ${result.score || 0}; source viewer verification required`,
          };
          return `
            <tr data-viewer-row-path="${escapeHtml(result.path || "")}" data-search-result-index="docs-index-${escapeHtml(index)}">
              <td><strong>${escapeHtml(fileName(result.path) || result.path || "document")}</strong><span>${escapeHtml(result.path || "")}</span><small>${escapeHtml(result.source_locator || "")}</small></td>
              <td>${escapeHtml((result.matched_terms || []).map((item) => `${item.term}:${item.count}`).join(", "))}</td>
              <td>${escapeHtml(result.score || 0)}</td>
              <td class="action-stack">
                ${result.path ? reviewActionButtons(match, `docs-index-${index}`) : ""}
                ${result.review_note_citation?.text ? `<button class="icon-action" type="button" data-copy-path="${escapeHtml(result.review_note_citation.text)}">인용 복사</button>` : ""}
              </td>
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
  `;
}

function renderSearchResults(payload, rows) {
  const summary = payload.summary || {};
  const advancedProfile = payload.advanced_search_profile || {};
  const keywordPackProfile = payload.keyword_pack_selection_profile || {};
  const visibleRows = virtualizedRows(rows, "search");
  const documentErrors = payload.documents?.errors || [];
  if (!rows.length) {
    const ocrErrors = payload.ocr?.errors || [];
    return `
      <div class="metric-grid search-metrics">
        ${metric("Matches", summary.match_count)}
        ${metric("Document errors", summary.document_error_count)}
        ${metric("OCR errors", summary.ocr_error_count)}
      </div>
      ${renderKnownGoodSearchSuppression(payload)}
      <p class="empty-state">No matches found.</p>
      ${renderDocumentErrors(documentErrors)}
      ${renderOcrErrors(ocrErrors)}
    `;
  }
  return `
    <div class="metric-grid search-metrics">
      ${metric("Matches", summary.match_count)}
      ${metric("Sources", Object.keys(summary.source_counts || {}).length)}
      ${metric("Document errors", summary.document_error_count)}
      ${metric("OCR errors", summary.ocr_error_count)}
      ${metric("Keywords", (payload.keywords || []).length)}
    </div>
    ${renderKnownGoodSearchSuppression(payload)}
    ${renderSearchSourceVerification(payload)}
    ${renderSearchFacets(payload, rows)}
    ${renderAdvancedSearchProfile(advancedProfile)}
    ${renderKeywordPackSelectionProfile(keywordPackProfile)}
    ${renderSearchAnalysis(payload.analysis)}
    ${renderVirtualizationNotice(rows, visibleRows, "search matches", "search")}
    <table class="data-table">
      <thead><tr><th>출처</th><th>항목</th><th>키워드</th><th>미리보기 / 근거</th><th></th></tr></thead>
      <tbody>
        ${visibleRows.map((match, index) => {
          const context = bookmarkContextForMatch(match) || {};
          return `
            <tr data-filter="${rowText(match)}" ${match.path ? `data-viewer-row-path="${escapeHtml(match.path)}" data-review-context="${escapeHtml(JSON.stringify(context))}" data-search-result-index="${escapeHtml(index)}"` : ""}>
              <td>${escapeHtml(match.source)}<span>${escapeHtml(match.kind || "")}</span></td>
              <td><strong>${escapeHtml(match.title || fileName(match.path))}</strong><span>${escapeHtml(match.path || "")}</span>${renderSearchResultLocator(match)}</td>
              <td>${escapeHtml((match.matched_keywords || []).join(", "))}</td>
              <td>
                ${escapeHtml(match.preview || "")}
                ${renderSearchMetadata(match)}
              </td>
              <td class="action-stack">
                ${reviewActionButtons(match, index)}
              </td>
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
    ${renderDocumentErrors(documentErrors)}
    ${renderOcrErrors(payload.ocr?.errors || [])}
  `;
}

function renderSearchFacets(payload, rows) {
  const summary = payload.summary || {};
  const sourceCounts = Object.entries(summary.source_counts || {})
    .filter(([, count]) => Number(count) > 0)
    .sort((left, right) => Number(right[1]) - Number(left[1]));
  const kindCounts = rows.reduce((counts, match) => {
    const kind = String(match.kind || match.source || "unknown").trim() || "unknown";
    counts[kind] = (counts[kind] || 0) + 1;
    return counts;
  }, {});
  const topKinds = Object.entries(kindCounts)
    .sort((left, right) => Number(right[1]) - Number(left[1]))
    .slice(0, 10);
  if (!sourceCounts.length && !topKinds.length) return "";
  const facetButton = (label, count) => `
    <button class="search-facet-chip" type="button" data-filter="${escapeHtml(label)}" aria-label="Filter results by ${escapeHtml(label)} (${formatNumber(count)} hits)">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(count)}</strong>
    </button>
  `;
  return `
    <section class="search-facet-panel" aria-label="Search result facets">
      <div>
        <p class="eyebrow">review facets</p>
        <h4>현재 결과를 바로 좁혀보기</h4>
        <p>Source나 artifact kind를 눌러 같은 검색 결과 안에서 빠르게 필터링합니다. 원본 검토 흐름은 유지됩니다.</p>
      </div>
      <div class="search-facet-group" aria-label="Source facets">
        <span>Source</span>
        ${sourceCounts.map(([source, count]) => facetButton(String(source), count)).join("")}
      </div>
      <div class="search-facet-group" aria-label="Kind facets">
        <span>Kind</span>
        ${topKinds.map(([kind, count]) => facetButton(String(kind), count)).join("")}
      </div>
    </section>
  `;
}

function renderSearchSourceVerification(payload) {
  const rows = payload.matches || [];
  const pathReady = rows.filter((match) => Boolean(match.path)).length;
  const reviewReady = rows.filter((match) => Boolean(bookmarkContextForMatch(match))).length;
  const truncated = Boolean(payload.truncated);
  return `
    <section class="search-verification-card ${truncated ? "warning" : ""}" data-testid="search-source-verification" data-search-source-contract="${escapeHtml(SEARCH_SOURCE_VERIFICATION_CONTRACT.profile_version)}">
      <div>
        <p class="eyebrow">원본 검증</p>
        <h3>${formatNumber(pathReady)}/${formatNumber(rows.length)}건은 원본 뷰어로 열 수 있습니다</h3>
        <p>검색 히트는 단서입니다. 보고서 후보로 올리기 전 원본 보기와 선별 저장을 통해 현재 파일 검색 인용과 source hash를 확인하세요.</p>
      </div>
      <div class="mini-stat-row">
        <span>선별 연결 ${formatNumber(reviewReady)}건</span>
        <span>${truncated ? "일부 결과만 표시" : "전체 결과 표시"}</span>
        <span>원칙: 보고 전 원본 확인</span>
      </div>
    </section>
  `;
}

function renderSearchResultLocator(match) {
  const locator = [
    match.pointer ? `pointer ${match.pointer}` : "",
    match.path ? "원본 열기 가능" : "원본 경로 없음",
    match.source_reference?.parser ? `parser ${match.source_reference.parser}` : "",
  ].filter(Boolean).join(" · ");
  if (!locator) return "";
  return `<span class="search-result-locator" data-testid="search-result-locator">${escapeHtml(locator)}</span>`;
}

function renderKeywordPackSelectionProfile(profile) {
  if (!profile?.profile_version || !(profile.selected_pack_names || []).length) return "";
  return `
    <details class="keyword-pack-card">
      <summary>#62 Keyword packs · ${escapeHtml(profile.selected_pack_count || 0)} selected · ${escapeHtml(profile.expanded_keyword_count || 0)} expanded terms</summary>
      <div class="chip-row compact">
        ${(profile.selected_pack_names || []).map((name) => `<span class="filter-chip">${escapeHtml(name)}</span>`).join("")}
      </div>
      <p class="help-text">${escapeHtml(profile.report_use_warning || "Record pack provenance before report use.")}</p>
    </details>
  `;
}

function renderAdvancedSearchProfile(profile) {
  if (!profile?.profile_version) return "";
  const warnings = profile.review_warnings || [];
  return `
    <details class="advanced-search-card">
      <summary>#61 Advanced search · ${escapeHtml(profile.active_mode || "exact")} · ${escapeHtml(profile.query_count || 0)} query item(s)</summary>
      <div class="mini-stat-row">
        <span>fuzzy ${escapeHtml(profile.controls?.fuzzy_distance ?? 0)}</span>
        <span>proximity ${escapeHtml(profile.controls?.proximity_window ?? 0)}</span>
        <span>${escapeHtml(profile.proximity_matched_count || 0)} proximity hit(s)</span>
        <span>${profile.source_verification_required ? "source verification required" : "source verified"}</span>
      </div>
      ${(profile.query_validation || []).length ? `
        <ul class="compact-list">
          ${(profile.query_validation || []).slice(0, 6).map((query) => `
            <li>
              <strong>${escapeHtml(query.query || "")}</strong>
              <span>${query.valid ? "valid" : "invalid"} ${query.error ? `· ${escapeHtml(query.error)}` : ""}</span>
            </li>
          `).join("")}
        </ul>
      ` : ""}
      ${warnings.length ? `<p class="help-text">${escapeHtml(warnings.join(" · "))}</p>` : ""}
    </details>
  `;
}

function renderSearchAnalysis(analysis) {
  if (!analysis) return "";
  const clusters = analysis.clusters?.clusters || [];
  const entities = analysis.entities?.entities || [];
  const hypotheses = analysis.workbook?.hypotheses || [];
  const workbookProfile = analysis.workbook?.workbook_review_profile || {};
  const timelineEvents = analysis.timeline?.events || [];
  const timelineProfile = analysis.timeline?.timeline_correlation_profile || {};
  const graphSummary = analysis.graph?.summary || {};
  const graphProfile = analysis.graph?.graph_interaction_profile || {};
  const graphFilters = graphProfile.available_filters || [];
  const dedupGroups = analysis.deduplication?.groups || [];
  const dedupProfile = analysis.deduplication?.dedup_review_profile || {};
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
        <p class="help-text">
          ${escapeHtml(workbookProfile.review_queue_count || 0)} review item(s);
          ${workbookProfile.version_history_supported ? "version history available." : "version history is still validation-required."}
        </p>
      </article>
      <article class="analysis-card">
        <p class="eyebrow">dedupe</p>
        <h3>Collapse repeated hits</h3>
        <div class="mini-stat-row">
          <span>${escapeHtml(dedupProfile.duplicate_group_count || 0)} groups</span>
          <span>${escapeHtml(dedupProfile.duplicate_match_count || 0)} repeated hits</span>
          <span>${dedupProfile.case_db_suppression_state ? "suppression saved" : "not suppressed"}</span>
        </div>
        ${dedupGroups.length ? dedupGroups.slice(0, 4).map((group) => `
          <details class="dedup-card">
            <summary>${escapeHtml(group.match_count || 0)} duplicate hits · representative #${escapeHtml(group.representative_index ?? "n/a")}</summary>
            <p>${escapeHtml(group.representative_preview || "")}</p>
            <small>${escapeHtml(group.hidden_duplicate_count || 0)} hidden candidate(s); verify before suppression.</small>
          </details>
        `).join("") : '<p class="help-text">No duplicate groups in current hits.</p>'}
        <p class="help-text">
          ${dedupProfile.collapse_preview_supported ? "Representative-first collapse is available." : "Collapse preview unavailable."}
          ${dedupProfile.case_db_suppression_state ? "" : " Persistent suppression still requires Case DB validation."}
        </p>
      </article>
      <article class="analysis-card">
        <p class="eyebrow">graph / timeline</p>
        <h3>Relationship scale</h3>
        <div class="mini-stat-row">
          <span>${escapeHtml(graphSummary.node_count || 0)} nodes</span>
          <span>${escapeHtml(graphSummary.edge_count || 0)} edges</span>
          <span>${escapeHtml(graphSummary.source_citation_edge_count || 0)} cited</span>
          <span>${escapeHtml(timelineEvents.length)} timeline anchors</span>
          <span>${escapeHtml(timelineProfile.event_page_count || 0)} pages</span>
        </div>
        ${graphFilters.length ? `
          <div class="chip-row compact" aria-label="Graph filters">
            ${graphFilters.slice(0, 5).map((filter) => `
              <span class="filter-chip">${escapeHtml(filter.label || filter.filter_id || "Filter")} · ${escapeHtml(filter.count || 0)}</span>
            `).join("")}
          </div>
        ` : ""}
        <p class="help-text">
          ${graphProfile.server_side_paging_supported ? "Server paging available." : "Bounded graph preview; large-case server paging is still validation-required."}
          ${timelineProfile.clock_skew_overlay_supported ? "Clock-skew overlay available." : "Timeline skew validation is still required."}
        </p>
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

function renderDocumentErrors(errors) {
  if (!errors.length) return "";
  return `
    <details class="ocr-errors document-errors search-verification-card warning">
      <summary>Document extraction skipped/failed for ${errors.length} item(s)</summary>
      <p>Search coverage is partial for these documents. Review the skipped list before concluding that a keyword is absent.</p>
      <div class="dense-list">
        ${errors.slice(0, 20).map((item) => `<div class="dense-row"><strong>${escapeHtml(item.path || "Document")}</strong><span>${escapeHtml(item.error || item.message || item.reason || "extraction skipped")}</span></div>`).join("")}
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

function renderKnownGoodSearchSuppression(payload) {
  const profile = payload.known_good_search_suppression_profile || {};
  if (!profile.profile_version) return "";
  const suppressed = Number(profile.suppressed_match_count || 0);
  const known = Number(profile.known_good_match_count || 0);
  if (!known && !profile.hide_known_good) return "";
  return `
    <section class="search-verification-card compact known-good-search-suppression" data-testid="known-good-search-suppression">
      <div>
        <p class="eyebrow">known-good suppression</p>
        <h3>${profile.hide_known_good ? `${formatNumber(suppressed)} hidden` : `${formatNumber(known)} reviewable`} known-good / NSRL hit(s)</h3>
        <p>${escapeHtml(profile.reportability_note || "Known-good hits are triage noise controls, not evidence deletion.")}</p>
      </div>
      <div class="mini-stat-row">
        <span>${profile.hide_known_good ? "hidden from results" : "visible for review"}</span>
        <span>${formatNumber(profile.reviewable_match_count || 0)} reviewable hit(s)</span>
        <span>${escapeHtml((profile.applies_to_sources || []).join(", ") || "no known-good source")}</span>
      </div>
    </section>
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
    const searchMode = detailPanel.querySelector("#unifiedSearchMode")?.value || "exact";
    const fuzzyDistance = detailPanel.querySelector("#unifiedSearchFuzzyDistance")?.value || "1";
    const proximityWindow = detailPanel.querySelector("#unifiedSearchProximity")?.value || "0";
    const hideKnownGood = detailPanel.querySelector("#unifiedSearchHideKnownGood")?.checked ?? false;
    const keywordPacks = Array.from(detailPanel.querySelectorAll(".keyword-pack-option:checked")).map((item) => item.value);
    const keywords = String(input.value || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    if (!keywords.length) return;
    setSearchDraft({
      keywords,
      ocr: includeOcr,
      source,
      extension,
      path_contains: pathContains,
      search_mode: searchMode,
      fuzzy_distance: Number(fuzzyDistance),
      proximity_window: Number(proximityWindow),
      hide_known_good: hideKnownGood,
      keyword_packs: keywordPacks,
    });
    rememberSearchKeywords({ keywords, source, extension, path_contains: pathContains });
    button.disabled = true;
    button.textContent = "검색 중...";
    try {
      const params = new URLSearchParams();
      for (const keyword of keywords) params.append("keyword", keyword);
      params.set("ocr", includeOcr ? "true" : "false");
      if (source) params.append("source", source);
      if (extension) params.append("extension", extension);
      if (pathContains) params.set("path_contains", pathContains);
      params.set("search_mode", searchMode);
      params.set("fuzzy_distance", fuzzyDistance);
      params.set("proximity_window", proximityWindow);
      params.set("hide_known_good", hideKnownGood ? "true" : "false");
      for (const pack of keywordPacks) params.append("keyword_pack", pack);
      const payload = await api(`/api/runs/${selectedRunId}/search?${params.toString()}`);
      virtualWindowOffsets.search = 0;
      currentSearchPayload = payload;
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
  bindSearchResultButtons();
  bindSearchPresetButtons(form);
  bindSearchScopePlanner();
  bindDocsIndexSidecarSearch();
  bindVirtualWindowButtons();
}

function bindSearchScopePlanner() {
  for (const button of detailPanel.querySelectorAll("[data-search-scope-action]")) {
    if (button.dataset.searchScopeBound) continue;
    button.dataset.searchScopeBound = "1";
    button.addEventListener("click", async () => {
      const action = button.dataset.searchScopeAction || "case";
      if (action === "case") {
        detailPanel.querySelector("#unifiedSearchInput")?.focus();
        return;
      }
      if (action === "current-file") {
        focusContextSearch();
        return;
      }
      if (action === "artifact") {
        await switchTab("artifacts", { syncStage: false });
      }
    });
  }
}

function bindDocsIndexSidecarSearch() {
  const button = detailPanel.querySelector("#docsIndexSearchButton");
  const output = detailPanel.querySelector("#docsIndexSearchResults");
  const input = detailPanel.querySelector("#unifiedSearchInput");
  if (!button || !output || !input || button.dataset.docsIndexBound) return;
  button.dataset.docsIndexBound = "1";
  button.addEventListener("click", async () => {
    const keywords = String(input.value || "")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    if (!keywords.length || !selectedRunId) {
      output.innerHTML = '<p class="empty-state">Enter one or more keywords first.</p>';
      return;
    }
    button.disabled = true;
    button.textContent = "Searching docs-index...";
    output.innerHTML = '<p class="help-text">Querying processed-text sidecar...</p>';
    try {
      const params = new URLSearchParams();
      for (const keyword of keywords) params.append("keyword", keyword);
      params.set("limit", "500");
      const payload = await api(`/api/runs/${selectedRunId}/docs-index-search?${params.toString()}`);
      currentDocsIndexSearchPayload = payload;
      output.innerHTML = renderDocsIndexSidecarResults(payload);
      bindCopyButtons();
      bindSearchResultButtons();
    } catch (error) {
      output.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}. If this run has no docs-index sidecar, run a new case scan or use normal search.</p>`;
    } finally {
      button.disabled = false;
      button.textContent = "Search docs-index with current keywords";
    }
  });
}

function bindSearchResultButtons() {
  for (const row of detailPanel.querySelectorAll("[data-viewer-row-path]")) {
    if (row.dataset.viewerRowBound) continue;
    row.dataset.viewerRowBound = "1";
    row.addEventListener("click", async (event) => {
      if (event.target.closest("button, a, input, select, textarea")) return;
      if (row.dataset.inspectorRow) {
        showSelectedRowInspector(row);
        return;
      }
      await loadEvidencePreview(row.dataset.viewerRowPath, parseReviewContext(row.dataset.reviewContext), row.dataset.searchResultIndex);
    });
  }
  bindInspectorRows();
  for (const button of detailPanel.querySelectorAll("[data-view-source-path]")) {
    if (button.dataset.sourcePreviewBound) continue;
    button.dataset.sourcePreviewBound = "1";
    button.addEventListener("click", async () => {
      await loadEvidencePreview(
        button.dataset.viewSourcePath,
        parseReviewContext(button.dataset.reviewContext),
        button.dataset.searchResultIndex,
      );
      if (button.dataset.focusFileSearch === "1") {
        const input = detailPanel.querySelector("#fileSearchForm input[name='keyword']");
        if (input && button.dataset.focusFileSearchKeywords) {
          input.value = button.dataset.focusFileSearchKeywords;
          input.form?.requestSubmit();
        }
        input?.focus();
      }
    });
  }
}

function bindSearchPresetButtons(form) {
  if (!form) return;
  for (const button of detailPanel.querySelectorAll("[data-keywords]")) {
    if (button.dataset.keywordsBound) continue;
    button.dataset.keywordsBound = "1";
    button.addEventListener("click", () => {
      const input = detailPanel.querySelector("#unifiedSearchInput");
      if (!input) return;
      input.value = button.dataset.keywords || "";
      form.requestSubmit();
    });
  }
  for (const button of detailPanel.querySelectorAll(".analysis-chip[data-filter], .entity-pill[data-filter], .search-facet-chip[data-filter]")) {
    if (button.dataset.filterBound) continue;
    button.dataset.filterBound = "1";
    button.addEventListener("click", () => applyFilter(button.dataset.filter || ""));
  }
}

async function loadEvidencePreview(path, reviewContext = null, searchResultIndex = null, options = {}) {
  const viewer = detailPanel.querySelector("#evidenceViewer");
  if (!viewer || !path) return;
  if (searchResultIndex !== null && searchResultIndex !== undefined && searchResultIndex !== "") {
    viewer.dataset.currentSearchResultIndex = String(searchResultIndex);
  }
  viewer.setAttribute("aria-busy", "true");
  viewer.innerHTML = '<p class="empty-state">Loading preview...</p>';
  try {
    const payload = await api(`/api/runs/${selectedRunId}/source-preview?path=${encodeURIComponent(path)}`);
    recordViewerNavigation(payload, reviewContext, searchResultIndex, options);
    viewer.innerHTML = renderEvidenceViewer(payload, reviewContext);
    if (searchResultIndex !== null && searchResultIndex !== undefined && searchResultIndex !== "") {
      viewer.dataset.currentSearchResultIndex = String(searchResultIndex);
    }
    bindViewerButtons();
  } catch (error) {
    viewer.innerHTML = `
      <p class="empty-state">${escapeHtml(error.message)}</p>
      ${renderSourceResolutionDiagnostics(error.detail)}
    `;
  } finally {
    viewer.setAttribute("aria-busy", "false");
  }
}

function renderSourceResolutionDiagnostics(detail) {
  const resolution = detail?.source_path_resolution || detail?.detail?.source_path_resolution;
  if (!resolution?.profile_version) return "";
  const roots = Array.isArray(resolution.allowed_roots) ? resolution.allowed_roots : [];
  const candidates = Array.isArray(resolution.candidates) ? resolution.candidates : [];
  return `
    <details class="source-verification" open>
      <summary>Source path resolution diagnostics · ${escapeHtml(resolution.status || "unresolved")}</summary>
      <dl class="eventlog-fields">
        <dt>Requested path</dt>
        <dd>${escapeHtml(resolution.raw_path || "")}</dd>
        <dt>Allowed roots</dt>
        <dd>${roots.map((root) => escapeHtml(root)).join("<br>") || "none"}</dd>
        <dt>Candidates tried</dt>
        <dd>${candidates.slice(0, 8).map((candidate) => escapeHtml([
          candidate.path,
          candidate.inside_allowed_roots ? "inside-root" : "outside-root",
          candidate.exists ? "exists" : "missing",
          candidate.is_file ? "file" : "",
        ].filter(Boolean).join(" · "))).join("<br>") || "none"}</dd>
      </dl>
      <p class="help-text">E01/Ex01 케이스라면 추출된 분석 루트에 원본 Windows 경로와 같은 상대 경로가 있는지 먼저 확인하세요.</p>
    </details>
  `;
}

function renderEvidenceViewer(payload, reviewContext = null) {
  const openLink = `<a class="mini-link" href="${escapeHtml(payload.download_url)}" target="_blank" rel="noreferrer">원본 열기</a>`;
  const copyButton = `<button class="icon-action" type="button" data-copy-path="${escapeHtml(payload.path)}">경로 복사</button>`;
  const pinButton = `<button class="icon-action" type="button" data-compare-item="${escapeHtml(JSON.stringify(compareItemFromPreview(payload, reviewContext)))}">비교함에 추가</button>`;
  const hashButton = `<button class="icon-action" type="button" data-source-hash-path="${escapeHtml(payload.path)}">해시 계산</button>`;
  let body = `<p class="empty-state">${escapeHtml(payload.message || "표시할 미리보기가 없습니다.")}</p>`;
  if (payload.preview_type === "image") {
    body = renderImagePreview(payload.image || {}, payload);
  }
  if (payload.preview_type === "text") {
    body = `
      <pre class="viewer-text">${escapeHtml(payload.text || "")}</pre>
      ${payload.truncated ? '<p class="empty-state">성능 보호를 위해 미리보기 일부만 표시했습니다.</p>' : ""}
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
    <div class="viewer-header" data-testid="source-viewer-header">
      <div>
        <p class="eyebrow">원본 뷰어</p>
        <h3>${escapeHtml(payload.name)}</h3>
      </div>
      <div class="detail-actions">${openLink}${copyButton}${pinButton}${hashButton}</div>
    </div>
    ${renderViewerNavigationControls(payload)}
    <div class="viewer-meta viewer-meta-compact">
      <span>${escapeHtml(payload.mime_type)}</span>
      <span>${formatBytes(payload.size)}</span>
      <details class="viewer-path-details">
        <summary>원본 경로와 메타데이터</summary>
        <code>${escapeHtml(payload.path)}</code>
      </details>
    </div>
    ${renderViewerEvidenceTrail(payload, reviewContext)}
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

function renderViewerEvidenceTrail(payload, reviewContext = null) {
  const linkedReview = Boolean(reviewContext?.source && reviewContext?.pointer);
  const citation = viewerCitationText(payload, reviewContext);
  const previewState = payload.truncated ? "일부 미리보기" : "미리보기 가능";
  const hashState = payload.hashes?.sha256 ? "해시 확보" : "필요 시 계산";
  const reviewState = linkedReview ? "리뷰 연결됨" : "미선별";
  const cards = [
    {
      title: "1. 원본 확인",
      state: previewState,
      detail: payload.preview_type || "미리보기 없음",
      tone: payload.preview_type ? "ready" : "warning",
    },
    {
      title: "2. 현재 파일 검색",
      state: "Ctrl F / 검색 문맥",
      detail: "본문, 로그, OCR 후보를 같은 뷰어에서 확인",
      tone: "ready",
    },
    {
      title: "3. 해시 · 출처",
      state: hashState,
      detail: payload.path || "원본 경로 없음",
      tone: payload.path ? "ready" : "warning",
    },
    {
      title: "4. 리뷰 · 보고서",
      state: reviewState,
      detail: linkedReview ? `${reviewContext.source}:${reviewContext.pointer}` : "관련성 판정 후 보고서 포함 여부 선택",
      tone: linkedReview ? "ready" : "warning",
    },
  ];
  return `
    <section class="viewer-evidence-trail" aria-label="원본 검증 절차" data-testid="source-verification-trail">
      <div class="viewer-citation-line">
        <span>원본 검증</span>
        <code>${escapeHtml(citation)}</code>
        <button class="mini-inline-button" type="button" data-copy-path="${escapeHtml(citation)}">인용 복사</button>
      </div>
      <div class="viewer-evidence-grid">
        ${cards.map((card) => `
          <article class="viewer-evidence-card ${card.tone}">
            <strong>${escapeHtml(card.title)}</strong>
            <span>${escapeHtml(card.state)}</span>
            <small>${escapeHtml(card.detail)}</small>
          </article>
        `).join("")}
      </div>
    </section>
  `;
}

function viewerCitationText(payload, reviewContext = null) {
  const pointer = [reviewContext?.source, reviewContext?.pointer].filter(Boolean).join(":");
  const fields = [
    pointer || "source-preview",
    payload.name || fileName(payload.path || ""),
    payload.path || "",
    payload.preview_type ? `viewer=${payload.preview_type}` : "",
    payload.size !== undefined ? `size=${payload.size}` : "",
  ];
  return fields.filter(Boolean).join(" | ");
}

function renderViewerActionGuide(payload) {
  const actions = payload.viewer_actions || [];
  const limitations = payload.viewer_limitations || [];
  if (!actions.length && !limitations.length) return "";
  return `
    <section class="source-metadata-panel viewer-action-guide">
      <div>
        <p class="eyebrow">검증 순서</p>
        <h4>미리보기 후 원본을 확인하고 선별하세요</h4>
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
  const badge = action.heavy ? '<span class="status-pill warning">시간 소요</span>' : '<span class="status-pill">즉시</span>';
  let control = "";
  if (action.id === "hash") {
    control = `<button class="mini-inline-button" type="button" data-source-hash-path="${escapeHtml(payload.path)}">실행</button>`;
  } else if (action.id === "search-current-file" || action.id === "search-current-entry") {
    control = `<button class="mini-inline-button" type="button" data-focus-source-search="1">파일 검색</button>`;
  } else if (action.url) {
    control = `<a class="mini-link" href="${escapeHtml(action.url)}" target="_blank" rel="noreferrer">열기</a>`;
  } else if (action.id === "pin-compare") {
    control = `<span>비교함에 추가</span>`;
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
    <details class="source-metadata-panel metadata-disclosure">
      <summary>뷰어 메타데이터</summary>
      <div class="metadata-grid">
        ${metric("뷰어", metadata.parser || "source-viewer")}
        ${metric("전략", metadata.strategy || "unknown")}
        ${metric("상태", metadata.preview_status || "unknown")}
        ${metric("형식", metadata.source_format || "unknown")}
      </div>
    </details>
  `;
}

function renderSqlitePreview(sqlite) {
  const tables = sqlite.tables || [];
  const metadata = sqlite.database_metadata || {};
  const sidecarProfile = sqlite.sidecar_state_profile || metadata.sidecar_state_profile || {};
  if (!tables.length) {
    return `
      ${renderSqliteSidecarState(sidecarProfile)}
      <p class="empty-state">${escapeHtml(sqlite.error || "No user tables were found in this SQLite database.")}</p>
    `;
  }
  const pageProfile = sqlite.table_page_profile || {};
  const pageLinks = pageProfile.table_links || [];
  return `
    <section class="sqlite-preview">
      <div class="file-search-summary">
        ${metric("Tables", sqlite.table_count)}
        ${metric("Previewed", tables.length)}
        ${metric("Rows/table", sqlite.row_limit)}
        ${metric("Page size", metadata.page_size || "n/a")}
      </div>
      <p class="help-text">SQLite viewer is read-only and capped for performance. It shows schema, indexes, bounded rows, API-backed table pages, and restricted contains filters without executing arbitrary SQL.</p>
      ${renderSqliteSidecarState(sidecarProfile)}
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
          ${renderSqliteSchemaPanel(table)}
          ${renderSqliteTablePageLink(pageLinks, table.name)}
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
          ${(table.truncated_rows || table.truncated_columns) ? '<p class="help-text">미리보기 제한: 원본 검색으로 범위를 좁히거나 전용 SQLite 도구로 표를 내보내 전체 검토하세요.</p>' : ""}
        </article>
      `).join("")}
      ${sqlite.truncated ? '<p class="help-text">Additional tables are hidden to keep the viewer responsive.</p>' : ""}
    </section>
  `;
}

function renderSqliteSidecarState(profile) {
  if (!profile || !Object.keys(profile).length) return "";
  const sidecars = profile.sidecars || {};
  const detected = Array.isArray(profile.detected_sidecars) ? profile.detected_sidecars : [];
  const requiresReview = Boolean(profile.requires_wal_review);
  const walHeader = sidecars.wal?.header || {};
  const sidecarRows = [
    ["WAL", sidecars.wal],
    ["SHM", sidecars.shm],
    ["Rollback journal", sidecars.rollback_journal],
  ];
  return `
    <article class="sqlite-sidecar-card ${requiresReview ? "warning" : "ok"}" data-testid="sqlite-sidecar-state">
      <div class="viewer-header compact">
        <div>
          <p class="eyebrow">sqlite sidecar state</p>
          <h3>WAL / SHM / rollback journal review</h3>
        </div>
        <span class="status-pill ${requiresReview ? "warning" : "ok"}">${requiresReview ? "review required" : "none detected"}</span>
      </div>
      <p class="help-text sqlite-sidecar-warning">
        ${escapeHtml(profile.source_viewer_warning || "Check SQLite sidecar files before treating preview rows as complete.")}
      </p>
      <div class="sqlite-sidecar-grid">
        ${sidecarRows.map(([label, info]) => `
          <div class="sqlite-sidecar-chip ${info?.exists ? "detected" : "missing"}">
            <strong>${escapeHtml(label)}</strong>
            <span>${info?.exists ? "detected" : "missing"}</span>
            <small>${info?.exists ? formatBytes(info.size_bytes || 0) : "0 B"}</small>
          </div>
        `).join("")}
      </div>
      ${sidecars.wal?.exists ? `
        <dl class="compact-dl sqlite-wal-header">
          <div><dt>WAL header</dt><dd>${escapeHtml(walHeader.status || "unparsed")}</dd></div>
          <div><dt>Magic</dt><dd>${escapeHtml(walHeader.magic_hex || "n/a")}</dd></div>
          <div><dt>Page size</dt><dd>${escapeHtml(walHeader.page_size || "n/a")}</dd></div>
          <div><dt>Estimated frames</dt><dd>${escapeHtml(walHeader.estimated_frame_count ?? "n/a")}</dd></div>
        </dl>
      ` : ""}
      <div class="sqlite-sidecar-action">
        <strong>Next step</strong>
        <code>${escapeHtml(profile.recommended_cli || "rapidtriage sqlite-wal-preview <database> --json")}</code>
        ${profile.source_path ? `<button class="mini-inline-button" type="button" data-sqlite-wal-preview-path="${escapeHtml(profile.source_path)}">WAL 미리보기</button>` : ""}
        <small>Detected sidecars: ${escapeHtml(detected.length ? detected.join(", ") : "none")}</small>
      </div>
      <div class="sqlite-wal-preview-inline" data-testid="sqlite-wal-preview-inline" aria-live="polite"></div>
    </article>
  `;
}

function renderSqliteSchemaPanel(table) {
  const details = Array.isArray(table.column_details) ? table.column_details : [];
  if (!details.length) return "";
  return `
    <details class="sqlite-schema-panel" data-testid="sqlite-schema-panel" open>
      <summary>Schema visibility · ${escapeHtml(details.length)} column(s)</summary>
      <div class="sqlite-column-grid">
        ${details.map((column) => `
          <span class="sqlite-column-chip" title="${escapeHtml(column.name || "column")}">
            <strong>${escapeHtml(column.name || "column")}</strong>
            <small>${escapeHtml(column.type || "untyped")}${column.notnull ? " · NOT NULL" : ""}${column.pk ? " · PK" : ""}</small>
          </span>
        `).join("")}
      </div>
    </details>
  `;
}

function renderSqliteTablePageLink(pageLinks, tableName) {
  const link = (pageLinks || []).find((item) => item.table === tableName);
  if (!link?.first_page_url) {
    return "";
  }
  return `
    <div class="sqlite-page-card">
      <strong>Table page API</strong>
      <a href="${escapeHtml(link.first_page_url)}" target="_blank" rel="noreferrer">Open first page JSON</a>
      <small>Use the restricted contains filter endpoint for large table review; arbitrary SQL is intentionally blocked.</small>
    </div>
  `;
}

function renderImagePreview(imagePayload, payload) {
  const gallery = imagePayload.gallery_review || {};
  const galleryPage = imagePayload.gallery_page_profile || {};
  const ocrQueue = imagePayload.ocr_queue_profile || {};
  const translationReview = imagePayload.korean_ocr_translation_profile || {};
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
      <div class="image-gallery-card">
        <strong>Folder gallery page</strong>
        <span>Bucket: ${escapeHtml(galleryPage.anchor_similarity_bucket || "n/a")} · limit ${escapeHtml(galleryPage.default_limit || "n/a")}</span>
        ${galleryPage.default_page_url ? `<a href="${escapeHtml(galleryPage.default_page_url)}" target="_blank" rel="noreferrer">Open gallery JSON</a>` : ""}
        ${galleryPage.bucket_page_url ? `<a href="${escapeHtml(galleryPage.bucket_page_url)}" target="_blank" rel="noreferrer">Open similar bucket</a>` : ""}
        <small>${escapeHtml(galleryPage.report_use_warning || "Treat image grouping as triage until validated.")}</small>
      </div>
      <div class="ocr-queue-card">
        <strong>OCR queue</strong>
        <span>Scope: ${escapeHtml(ocrQueue.scope || "image folder")} · max ${escapeHtml(ocrQueue.max_default_items || "n/a")} items</span>
        ${ocrQueue.default_queue_url ? `<a href="${escapeHtml(ocrQueue.default_queue_url)}" target="_blank" rel="noreferrer">Open OCR queue JSON</a>` : ""}
        <small>${escapeHtml(ocrQueue.report_use_warning || "Preserve sidecar hashes and OCR engine logs before report use.")}</small>
      </div>
      <div class="ocr-translation-card">
        <strong>Korean OCR / translation review</strong>
        <span>OCR sidecar: ${translationReview.has_ocr_sidecar ? "yes" : "no"} · translation sidecar: ${translationReview.has_translation_sidecar ? "yes" : "no"}</span>
        ${translationReview.default_review_url ? `<a href="${escapeHtml(translationReview.default_review_url)}" target="_blank" rel="noreferrer">Open side-by-side review JSON</a>` : ""}
        <small>${escapeHtml(translationReview.report_use_warning || "Review OCR and translation sidecars side by side before citing Korean text.")}</small>
      </div>
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
  const attachmentProfile = emailPayload.attachment_package_profile || {};
  const attachmentLinks = attachmentProfile.links || [];
  const parseDiagnostics = emailPayload.parse_diagnostics || {};
  return `
    <section class="structured-preview">
      <div class="file-search-summary">
        ${metric("Messages", emailPayload.message_count ?? messages.length)}
        ${metric("Threads", emailPayload.thread_count ?? threads.length)}
        ${metric("Limit", emailPayload.message_limit ?? "n/a")}
        ${metric("Preview", payload.truncated ? "capped" : "complete")}
      </div>
      <p class="help-text">Email viewer extracts headers, body preview, and attachment names without loading external content.</p>
      ${renderEmailParseDiagnostics(parseDiagnostics)}
      ${attachmentLinks.length ? `
        <div class="email-attachment-card">
          <strong>Attachment citation packages</strong>
          <span>${escapeHtml(attachmentProfile.attachment_count)} attachment(s), max inline content ${escapeHtml(attachmentProfile.max_inline_content_bytes || "n/a")} bytes</span>
          <div class="chip-row compact">
            ${attachmentLinks.slice(0, 6).map((item) => `
              <a class="filter-chip" href="${escapeHtml(item.package_url || "#")}" target="_blank" rel="noreferrer">
                ${escapeHtml(item.filename || item.content_type || `Attachment ${item.attachment_index}`)}
              </a>
            `).join("")}
          </div>
          <small>${escapeHtml(attachmentProfile.report_use_warning || "Validate attachments before report use.")}</small>
        </div>
      ` : ""}
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

function renderEmailParseDiagnostics(diagnostics) {
  if (!diagnostics || !Object.keys(diagnostics).length) return "";
  const truncated = Boolean(
    diagnostics.source_truncated
    || diagnostics.message_limit_reached
    || Number(diagnostics.message_size_truncated_count || 0) > 0
  );
  return `
    <div class="email-diagnostics-card ${truncated ? "warning" : "ok"}" data-testid="email-parse-diagnostics">
      <div>
        <strong>Email parse window</strong>
        <span>${truncated ? "bounded / partial" : "bounded / complete in preview window"}</span>
      </div>
      <dl class="compact-dl">
        <div><dt>Mode</dt><dd>${escapeHtml(diagnostics.parse_mode || "unknown")}</dd></div>
        <div><dt>Bytes read</dt><dd>${formatBytes(diagnostics.bytes_read || 0)}</dd></div>
        <div><dt>Max input</dt><dd>${formatBytes(diagnostics.max_input_bytes || 0)}</dd></div>
        <div><dt>Truncated messages</dt><dd>${escapeHtml(diagnostics.message_size_truncated_count ?? 0)}</dd></div>
      </dl>
      <small>${truncated ? "메일함 전용 페이지/내보내기 검증이 끝나기 전에는 전체 메일함으로 단정하지 마세요." : "현재 파싱 구간에서는 잘림 진단이 보고되지 않았습니다."}</small>
    </div>
  `;
}

function renderHexPreview(hexPayload, payload) {
  const rows = hexPayload.rows || [];
  const rangeProfile = hexPayload.range_citation_profile || {};
  const exportUrl = rangeProfile.default_export_url;
  return `
    <section class="structured-preview">
      <div class="file-search-summary">
        ${metric("Bytes", hexPayload.bytes_read ?? 0)}
        ${metric("Max", hexPayload.max_bytes ?? "n/a")}
        ${metric("Rows", rows.length)}
        ${metric("Range", `${hexPayload.first_offset_hex || "0x0"}-${hexPayload.last_offset_hex || "n/a"}`)}
      </div>
      <p class="help-text">Hex 뷰어는 읽기 전용이며 범위가 제한됩니다. 미리보기 SHA256: ${escapeHtml(hexPayload.preview_sha256 || "n/a")}. 바이트 오프셋을 보고하기 전 전체 파일 해시는 원본 메타데이터로 확인하세요.</p>
      <div class="hex-citation-card">
        <strong>Byte range citation</strong>
        <span>Default range: ${escapeHtml(rangeProfile.default_offset_hex || "0x0")} / ${escapeHtml(String(rangeProfile.default_length ?? 0))} bytes</span>
        ${exportUrl ? `<a href="${escapeHtml(exportUrl)}" target="_blank" rel="noreferrer">Open citation package JSON</a>` : ""}
        <small>${escapeHtml(rangeProfile.report_use_warning || "Attach hashes and validation before report use.")}</small>
      </div>
      <div class="hex-table" role="table" aria-label="Hex preview for ${escapeHtml(payload.name || "source")}">
        ${rows.map((row) => `
          <div class="hex-row" role="row">
            <code class="hex-offset">${escapeHtml(row.offset_hex)}</code>
            <code class="hex-bytes">${escapeHtml(row.hex)}</code>
            <code class="hex-ascii">${escapeHtml(row.ascii)}</code>
          </div>
        `).join("")}
      </div>
      ${hexPayload.truncated ? '<p class="help-text">성능 보호를 위해 Hex 미리보기를 일부만 표시했습니다. 전체 바이트 검토가 필요하면 원본을 여세요.</p>' : ""}
    </section>
  `;
}

function renderMediaPreview(mediaPayload, payload) {
  const metadata = mediaPayload.metadata || {};
  const sidecars = mediaPayload.transcript_sidecars || [];
  const review = mediaPayload.review || {};
  const sourceHashes = mediaPayload.source_hashes || {};
  const cueProfile = mediaPayload.cue_package_profile || {};
  const cueLinks = cueProfile.links || [];
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
      ${cueLinks.length ? `
        <div class="media-cue-card">
          <strong>Transcript cue citations</strong>
          <span>${escapeHtml(cueProfile.cue_count)} cue(s), max ${escapeHtml(cueProfile.max_cue_export_chars || "n/a")} chars</span>
          <div class="chip-row compact">
            ${cueLinks.slice(0, 6).map((item) => `
              <a class="filter-chip" href="${escapeHtml(item.package_url || "#")}" target="_blank" rel="noreferrer">
                ${escapeHtml(`${item.start}-${item.end}`)}
              </a>
            `).join("")}
          </div>
          <small>${escapeHtml(cueProfile.report_use_warning || "Verify cue alignment before report use.")}</small>
        </div>
      ` : ""}
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
        이 파일 안에서 검색 ${kbd("Ctrl F")}
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
    return '<p class="empty-state">이 원본은 미리볼 수 있지만, 저장된 결과 포인터와 연결되어 있지 않아 선별 상태를 남길 수 없습니다.</p>';
  }
  const suggestedTags = Array.from(new Set([...(reviewContext.tags || []), payload.extension?.replace(".", "")].filter(Boolean))).join(", ");
  return `
    <form id="viewerReviewForm" class="review-capture" data-review-context="${escapeHtml(JSON.stringify(reviewContext))}" data-testid="viewer-review-form">
      <div>
        <p class="eyebrow">선별 판정</p>
        <h3>이 단서의 관련성과 보고 포함 여부를 기록합니다</h3>
      </div>
      <div class="review-decision-rail" aria-label="빠른 선별 판정">
        <button class="review-decision-chip relevant" type="button" data-review-quick-status="relevant" data-review-quick-report="true">관련 있음 + 보고서</button>
        <button class="review-decision-chip needs-review" type="button" data-review-quick-status="needs-review" data-review-quick-report="false">재검토</button>
        <button class="review-decision-chip reject" type="button" data-review-quick-status="not-relevant" data-review-quick-report="false">관련 없음</button>
      </div>
      <div class="review-grid">
        <label>
          판정
          <select name="status">
            <option value="needs-review">재검토</option>
            <option value="relevant">관련 있음</option>
            <option value="not-relevant">관련 없음</option>
            <option value="unreviewed">미검토</option>
          </select>
        </label>
        <label>
          태그
          <input name="tags" value="${escapeHtml(suggestedTags)}" placeholder="credential, browser, suspicious-login" />
        </label>
      </div>
      <label>
        Analyst note
        <textarea name="note" rows="3" placeholder="Why this matters, what to verify next, or why it is noise.">${escapeHtml(reviewContext.note || "")}</textarea>
      </label>
      <div class="review-actions">
        <label class="check-label"><input name="include_in_report" type="checkbox" /> 보고서 후보에 포함</label>
        <button type="submit">선별 결과 저장</button>
        <span id="viewerReviewStatus" class="review-save-status"></span>
      </div>
    </form>
  `;
}

function bindViewerButtons() {
  bindCopyButtons();
  bindCompareActions();
  for (const button of detailPanel.querySelectorAll("[data-viewer-history-delta]")) {
    if (button.dataset.viewerHistoryBound) continue;
    button.dataset.viewerHistoryBound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      await goViewerNavigation(Number(button.dataset.viewerHistoryDelta || 0));
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-source-hash-path]")) {
    if (button.dataset.hashBound) continue;
    button.dataset.hashBound = "1";
    button.addEventListener("click", async () => {
      await loadSourceMetadata(button.dataset.sourceHashPath, button);
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-sqlite-wal-preview-path]")) {
    if (button.dataset.sqliteWalBound) continue;
    button.dataset.sqliteWalBound = "1";
    button.addEventListener("click", async () => {
      await loadSqliteWalPreview(button);
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-focus-source-search]")) {
    if (button.dataset.focusSourceSearchBound) continue;
    button.dataset.focusSourceSearchBound = "1";
    button.addEventListener("click", () => focusContextSearch());
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
    for (const button of reviewForm.querySelectorAll("[data-review-quick-status]")) {
      button.addEventListener("click", async () => {
        const status = reviewForm.querySelector("[name='status']");
        const includeInput = reviewForm.querySelector("[name='include_in_report']");
        if (status) status.value = button.dataset.reviewQuickStatus || "needs-review";
        if (includeInput) includeInput.checked = button.dataset.reviewQuickReport === "true";
        await saveViewerReview({ preventDefault() {}, currentTarget: reviewForm });
      });
    }
  }
}

async function loadSourceMetadata(path, button) {
  const panel = detailPanel.querySelector("#sourceMetadataPanel");
  if (!panel || !path) return;
  button.disabled = true;
  button.textContent = "해시 계산 중...";
  panel.innerHTML = '<p class="empty-state">이 원본 파일의 MD5/SHA1/SHA256을 계산하고 있습니다.</p>';
  try {
    const payload = await api(`/api/runs/${selectedRunId}/source-metadata?path=${encodeURIComponent(path)}&hash=true`);
    panel.innerHTML = renderSourceMetadata(payload);
    bindCopyButtons();
  } catch (error) {
    panel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "해시 계산";
  }
}

async function loadSqliteWalPreview(button) {
  const card = button.closest("[data-testid='sqlite-sidecar-state']");
  const output = card?.querySelector("[data-testid='sqlite-wal-preview-inline']");
  if (!output || !button.dataset.sqliteWalPreviewPath) return;
  button.disabled = true;
  button.textContent = "확인 중...";
  output.innerHTML = '<p class="help-text">WAL/SHM/journal sidecar 메타데이터를 제한 미리보기로 확인하고 있습니다.</p>';
  try {
    const params = new URLSearchParams();
    params.set("path", button.dataset.sqliteWalPreviewPath);
    params.set("max_frames", "20");
    const payload = await api(`/api/runs/${selectedRunId}/source-sqlite-wal-preview?${params.toString()}`);
    output.innerHTML = renderSqliteWalPreviewInline(payload);
    bindCopyButtons();
  } catch (error) {
    output.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    button.disabled = false;
    button.textContent = "WAL 미리보기";
  }
}

function renderSqliteWalPreviewInline(payload) {
  const recovery = payload.recovery_scope || {};
  const wal = payload.wal || {};
  const header = wal.header || {};
  const frames = Array.isArray(wal.frames) ? wal.frames : [];
  const warning = payload.api_profile?.reportability_warning || "Validate WAL recovery candidates before reporting.";
  return `
    <section class="sqlite-wal-preview-panel" data-testid="sqlite-wal-preview-panel">
      <div class="mini-stat-row">
        <span>WAL ${wal.exists ? "detected" : "missing"}</span>
        <span>${formatNumber(recovery.frame_preview_count || frames.length)} frame(s)</span>
        <span>${formatNumber(recovery.schema_mapped_record_count || 0)} schema-mapped</span>
        <span>${formatNumber(recovery.deleted_record_candidate_count || 0)} deleted candidate(s)</span>
      </div>
      <p class="help-text">${escapeHtml(warning)}</p>
      ${wal.exists ? `
        <dl class="compact-dl">
          <div><dt>Header</dt><dd>${escapeHtml(wal.status || "unknown")}</dd></div>
          <div><dt>Page size</dt><dd>${escapeHtml(header.page_size || "n/a")}</dd></div>
          <div><dt>Manifest</dt><dd><code>${escapeHtml(payload.manifest_sha256 || "n/a")}</code></dd></div>
        </dl>
      ` : ""}
      ${frames.length ? `
        <table class="data-table compact">
          <thead><tr><th>#</th><th>Page</th><th>Commit</th><th>Hash</th></tr></thead>
          <tbody>
            ${frames.slice(0, 10).map((frame) => `
              <tr>
                <td>${escapeHtml(frame.frame_index ?? "")}</td>
                <td>${escapeHtml(frame.page_number ?? "")}</td>
                <td>${escapeHtml(frame.commit_db_size_pages ?? "")}</td>
                <td><code>${escapeHtml(frame.page_sha256 || "")}</code></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      ` : ""}
    </section>
  `;
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

async function resumeCurrentFileSearch(button) {
  const output = detailPanel.querySelector("#fileSearchResults");
  const status = detailPanel.querySelector("#fileSearchStatus");
  const path = button.dataset.fileSearchPath || "";
  const token = button.dataset.fileSearchResume || "";
  const kind = button.dataset.fileSearchResumeKind || "sqlite";
  const keywords = String(button.dataset.fileSearchKeywords || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (!path || !token || !keywords.length || !output) return;
  button.disabled = true;
  if (status) status.textContent = kind === "file" ? "Continuing large file search from byte cursor..." : "Continuing SQLite search from cursor...";
  try {
    const params = new URLSearchParams();
    params.set("path", path);
    params.set(kind === "file" ? "file_resume_token" : "sqlite_resume_token", token);
    for (const keyword of keywords) params.append("keyword", keyword);
    const payload = await api(`/api/runs/${selectedRunId}/source-search?${params.toString()}`);
    output.innerHTML = renderFileSearchResults(payload);
    bindCopyButtons();
    bindCompareActions();
    bindFileSearchHitActions();
  } catch (error) {
    output.insertAdjacentHTML("afterbegin", `<p class="empty-state">${escapeHtml(error.message)}</p>`);
  } finally {
    if (status) status.textContent = "";
    button.disabled = false;
  }
}

function renderFileSearchResults(payload) {
  const rows = payload.matches || [];
  const controls = payload.source_search_profile?.large_data_controls || {};
  const sqliteResumeToken = payload.summary?.sqlite_resume_token || controls.sqlite_resume_token || "";
  const fileResumeToken = payload.summary?.file_resume_token || controls.file_resume_token || "";
  const resumeKind = sqliteResumeToken ? "sqlite" : fileResumeToken ? "file" : "";
  const resumeToken = sqliteResumeToken || fileResumeToken;
  const resumeLabel = resumeKind === "file" ? "Continue large file search" : "Continue SQLite search";
  const resumeAction = resumeToken ? `
    <button
      class="secondary-button"
      type="button"
      data-file-search-resume="${escapeHtml(resumeToken)}"
      data-file-search-resume-kind="${escapeHtml(resumeKind)}"
      data-file-search-path="${escapeHtml(payload.path || "")}"
      data-file-search-keywords="${escapeHtml((payload.keywords || []).join(","))}"
    >
      ${resumeLabel}
    </button>
  ` : "";
  if (!payload.searchable) {
    return `<p class="empty-state">${escapeHtml(payload.message || "This file is not searchable.")}</p>`;
  }
  if (!rows.length) {
    const noMatchMessage = payload.truncated
      ? "No matches in the searched window yet. Continue from the cursor before concluding the keyword is absent."
      : "No matches in this file.";
    return `
      <div class="file-search-summary">
        ${metric("File matches", 0)}
        ${metric("Keywords", (payload.keywords || []).length)}
      </div>
      ${renderCurrentFileSearchProfile(payload)}
      <p class="empty-state ${payload.truncated ? "warning" : ""}">${escapeHtml(noMatchMessage)}</p>
      ${resumeAction}
    `;
  }
  return `
    <div class="file-search-summary">
      ${metric("File matches", payload.summary?.match_count)}
      ${metric("Keywords", (payload.keywords || []).length)}
    </div>
    ${renderCurrentFileSearchProfile(payload)}
    <div class="dense-list">
      ${rows.map((match) => `
        <article class="dense-row">
          <strong>줄 ${escapeHtml(match.line)} · ${escapeHtml(match.keyword)}</strong>
          <span>${highlightSnippet(match.snippet || "", payload.keywords || [])}</span>
          <small>${escapeHtml(match.citation || "")}</small>
          <div class="review-actions">
            ${compareButton(compareItemFromFileSearchMatch(payload, match))}
            <button class="icon-action" type="button" data-copy-path="${escapeHtml(match.citation || match.snippet || "")}">인용 복사</button>
            <button class="icon-action" type="button" data-copy-path="${escapeHtml(match.compare_preview || match.snippet || "")}">본문 복사</button>
            <button class="icon-action" type="button" data-review-note-text="${escapeHtml(reviewNoteFromFileSearchMatch(match))}">검토 메모에 추가</button>
          </div>
        </article>
      `).join("")}
    </div>
    ${payload.truncated ? '<p class="help-text">Results were capped for performance. Continue from the available cursor or narrow the keyword if needed.</p>' : ""}
    ${resumeAction}
  `;
}

function renderCurrentFileSearchProfile(payload) {
  const profile = payload.source_search_profile || {};
  const controls = profile.large_data_controls || {};
  const extractionLimits = controls.document_extraction_limits || {};
  if (!profile.profile_version) return "";
  return `
    <section class="current-file-search-profile ${controls.truncated ? "warning" : ""}" data-testid="current-file-search-profile" data-current-file-search-contract="${escapeHtml(CURRENT_FILE_SEARCH_CONTRACT.profile_version)}">
      <div>
        <p class="eyebrow">current-file search</p>
        <strong>${escapeHtml(profile.searchable ? "Searchable source" : "Search limited or blocked")}</strong>
        <span>${escapeHtml(profile.reportability_decision?.allowed_use || "verification pivot")}</span>
      </div>
      <div class="mini-stat-row">
        <span>limit ${escapeHtml(controls.result_limit ?? payload.summary?.limit ?? "n/a")}</span>
        <span>${controls.truncated ? "truncated" : "not truncated"}</span>
        <span>SQLite rows ${escapeHtml(controls.sqlite_scanned_row_count ?? "n/a")}</span>
        <span>${controls.sqlite_scan_truncated ? "SQLite scan capped" : "SQLite scan not capped"}</span>
        ${controls.sqlite_resume_requested ? "<span>resumed from cursor</span>" : ""}
        ${controls.sqlite_resume_token ? "<span>resume token ready</span>" : ""}
        ${controls.file_scan_truncated ? "<span>large file scan capped</span>" : ""}
        ${controls.file_resume_requested ? "<span>file cursor resumed</span>" : ""}
        ${controls.file_resume_token ? "<span>file resume token ready</span>" : ""}
        ${extractionLimits.limits_visible_to_gui ? `<span>doc cap ${escapeHtml(formatBytes(extractionLimits.max_plain_text_bytes || 0))}</span>` : ""}
        ${extractionLimits.max_pdf_stream_decompressed_bytes ? `<span>PDF stream cap ${escapeHtml(formatBytes(extractionLimits.max_pdf_stream_decompressed_bytes))}</span>` : ""}
      </div>
      <p class="help-text">${escapeHtml((profile.reportability_decision?.required_before_report || []).join(" · ") || "Copy locator/citation and verify hashes before report use.")}</p>
    </section>
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
  const reviewCitation = match.review_note_citation || match.citation_profile?.review_note_citation || {};
  const locator = match.source_viewer_locator || match.citation_profile?.source_viewer_locator || {};
  return [
    `Current-file hit: ${match.citation || match.match_id || "source-search hit"}`,
    reviewCitation.text ? `Structured citation: ${reviewCitation.text}` : "",
    locator.locator_sha256 ? `Source locator: ${locator.locator_sha256}` : "",
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
  for (const button of detailPanel.querySelectorAll("[data-file-search-resume]")) {
    if (button.dataset.fileSearchResumeBound) continue;
    button.dataset.fileSearchResumeBound = "1";
    button.addEventListener("click", () => resumeCurrentFileSearch(button));
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
    status.innerHTML = '선별 보드에 저장됨 <button class="mini-inline-button" type="button" data-open-tab="review">열기</button>';
    bindPanelActions();
  } catch (error) {
    status.textContent = `실패: ${error.message}`;
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
    status.textContent = `실패: ${error.message}`;
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
      `<a class="mini-link" href="${archiveUrl}" target="_blank" rel="noreferrer">ZIP 다운로드</a>`,
      payload.outputs?.selected_evidence ? `<span>Selected JSON: ${escapeHtml(payload.outputs.selected_evidence)}</span>` : "",
      payload.outputs?.bundle_manifest ? `<span>Bundle manifest: ${escapeHtml(payload.outputs.bundle_manifest)}</span>` : "",
      payload.outputs?.reviewer ? `<span>${escapeHtml(payload.outputs.reviewer)}</span>` : "",
    ].filter(Boolean).join(" ");
  } catch (error) {
    status.textContent = `실패: ${error.message}`;
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

function rowInspectorAttributes(payload) {
  return `data-inspector-row="${escapeHtml(JSON.stringify(payload || {}))}"`;
}

function parseInspectorRow(value) {
  if (!value) return null;
  try {
    const payload = JSON.parse(value);
    return payload && typeof payload === "object" ? payload : null;
  } catch {
    return null;
  }
}

function bindInspectorRows() {
  for (const row of detailPanel.querySelectorAll("[data-inspector-row]")) {
    if (row.dataset.inspectorBound) continue;
    row.dataset.inspectorBound = "1";
    row.addEventListener("click", (event) => {
      if (event.target.closest("button, a, input, select, textarea")) return;
      showSelectedRowInspector(row);
    });
  }
}

function showSelectedRowInspector(row) {
  const payload = parseInspectorRow(row?.dataset.inspectorRow);
  const viewer = detailPanel.querySelector("#evidenceViewer");
  if (!payload || !viewer) return;
  for (const item of detailPanel.querySelectorAll(".selectable-result-row.selected-row")) {
    item.classList.remove("selected-row");
  }
  row.classList.add("selected-row");
  viewer.removeAttribute("aria-busy");
  viewer.innerHTML = renderSelectedRowInspector(payload);
  bindSearchResultButtons();
  bindBookmarkButtons();
  bindCompareActions();
}

function renderSelectedRowInspector(payload) {
  const reviewContext = payload.reviewContext || {};
  const match = {
    source: reviewContext.source || payload.source || activeTab,
    kind: payload.kind || "",
    path: payload.path || reviewContext.path || "",
    title: payload.title || fileName(payload.path) || "selected row",
    preview: payload.preview || "",
    pointer: payload.pointer || reviewContext.pointer || "",
  };
  const chips = Array.from(new Set((payload.chips || []).filter(Boolean))).slice(0, 8);
  return `
    <section class="selected-row-inspector" data-testid="selected-row-inspector">
      <p class="eyebrow">selected evidence</p>
      <strong>${escapeHtml(payload.title || "선택된 결과")}</strong>
      <span>${escapeHtml(payload.preview || "행을 선택했습니다. 아래 원본 경로와 리뷰 동작을 확인하세요.")}</span>
      <dl>
        ${payload.timestamp ? `<dt>Time</dt><dd>${escapeHtml(payload.timestamp)}</dd>` : ""}
        ${payload.source ? `<dt>Source</dt><dd>${escapeHtml(payload.source)}</dd>` : ""}
        ${payload.kind ? `<dt>Type</dt><dd>${escapeHtml(payload.kind)}</dd>` : ""}
        ${payload.provider ? `<dt>Provider</dt><dd>${escapeHtml(payload.provider)}</dd>` : ""}
        ${payload.path ? `<dt>Path</dt><dd><code>${escapeHtml(payload.path)}</code></dd>` : ""}
        ${payload.pointer ? `<dt>Pointer</dt><dd><code>${escapeHtml(payload.pointer)}</code></dd>` : ""}
      </dl>
      ${chips.length ? `<div class="viewer-chip-row">${chips.map((chip) => `<span>${escapeHtml(chip)}</span>`).join("")}</div>` : ""}
      <div class="preview-action-row">
        ${match.path ? viewSourceButton(match, reviewContext) : ""}
        ${match.path ? sourceFileLink(match) : ""}
        ${match.path ? compareButton(compareItemFromMatch(match, reviewContext)) : ""}
        ${reviewContext.source && reviewContext.pointer ? bookmarkButton(reviewContext.source, reviewContext.pointer, reviewContext.note || payload.title || "") : ""}
      </div>
      <p class="help-text">행 클릭은 이 패널에 상세를 고정합니다. 원문 내용이 필요할 때만 원본 보기를 눌러 원본 뷰어를 여세요.</p>
    </section>
  `;
}

function parseTags(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function renderReport(markdown) {
  return `
    ${renderReportReadinessGate()}
    <section class="guidance-card">
      <div>
        <p class="eyebrow">보고서</p>
        <h3>검토된 증거만 산출물로 정리</h3>
      </div>
      <p>이 화면은 실행 보고서와 증거 선별 결과를 분리합니다. 선별 보드에서 확인된 항목만 해시 목록과 케이스 보고서 초안에 반영하세요.</p>
      <div class="guidance-actions">
        <button class="secondary-button" type="button" data-open-tab="review">선별 보드</button>
        <a class="link-button" href="/api/runs/${encodeURIComponent(selectedRunId)}/outputs/report/file">실행 보고서 다운로드</a>
      </div>
      <p class="help-text">권장 순서: 증거 선별, 해시 목록 생성, 확인된 증거만 케이스 보고서 또는 reviewer bundle에 포함.</p>
    </section>
    <pre class="report-view">${escapeHtml(markdown)}</pre>
  `;
}

function renderReportReadinessGate() {
  const summary = selectedRun?.summary?.summary || {};
  const outputs = selectedRun?.summary?.outputs || {};
  const checks = [
    {
      label: "선별 증거",
      count: Number(summary.report_item_count || 0),
      ready: Number(summary.report_item_count || 0) > 0,
      action: "review",
      detail: "관련 있음 + 보고서 포함으로 표시된 항목",
    },
    {
      label: "해시/manifest",
      count: Number(summary.scanned_file_count || 0),
      ready: Boolean(outputs.manifest || outputs.fingerprint),
      action: "summary",
      detail: "원본 경로, 크기, SHA256 근거",
    },
    {
      label: "인용 근거",
      count: Number(summary.report_item_count || 0),
      ready: Number(summary.report_item_count || 0) > 0,
      action: "review",
      detail: "source, pointer, parser, offset/index",
    },
    {
      label: "제한사항",
      count: Number(summary.warning_count || summary.validation_issue_count || 0),
      ready: true,
      action: "summary",
      detail: "검증 경고와 parser limitation 명시",
    },
    {
      label: "제출 묶음",
      count: outputs.report ? 1 : 0,
      ready: Boolean(outputs.report),
      action: "report",
      detail: "보고서 파일 또는 reviewer bundle",
    },
  ];
  const missing = checks.filter((check) => !check.ready).length;
  return `
    <section class="report-readiness-gate" aria-label="보고서 제출 준비 게이트" data-testid="report-readiness-gate">
      <div class="lane-section-header">
        <div>
          <p class="eyebrow">제출 전 점검</p>
          <strong>보고서에 넣기 전에 빠진 근거 확인</strong>
        </div>
        <span>${missing ? `${formatNumber(missing)}개 보강 필요` : "제출 준비됨"}</span>
      </div>
      <div class="report-gate-grid">
        ${checks.map((check) => `
          <button class="secondary-button report-gate-card ${check.ready ? "ready" : "blocked"}" type="button" data-open-tab="${escapeHtml(check.action)}">
            <span>${escapeHtml(check.label)}</span>
            <b>${formatNumber(check.count)}</b>
            <em>${escapeHtml(check.detail)}</em>
          </button>
        `).join("")}
      </div>
    </section>
  `;
}

function renderReviewBoard(payload) {
  if (!payload.exists || !payload.case) {
    return `
      ${renderReviewStateDashboard([], {})}
      <section class="guidance-card">
        <p class="eyebrow">review board</p>
        <h3>No reviewed evidence yet</h3>
        <p>검색 결과를 원본 뷰어에서 확인한 뒤 선별 상태를 저장하면 이 보드에 누적됩니다.</p>
        <div class="guidance-actions">
          <button class="secondary-button" type="button" data-open-tab="search">Go to search</button>
        </div>
      </section>
    `;
  }
  const bookmarks = payload.case.bookmarks || [];
  if (!bookmarks.length) {
    return `
      ${renderReviewStateDashboard([], summary)}
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
    ${renderReviewStateDashboard(bookmarks, summary)}
    ${renderReviewCockpit(summary)}
    <div class="metric-grid">
      ${metric("검토 항목", summary.bookmark_count)}
      ${metric("보고서 후보", summary.report_item_count)}
      ${metric("관련 있음", summary.review_status_counts?.relevant)}
      ${metric("재검토", summary.review_status_counts?.["needs-review"])}
    </div>
    ${renderSubmissionManifestPanel(summary)}
    ${renderCaseReportPanel(summary, payload.case)}
    ${renderReviewerBundlePanel(summary, payload.case)}
    ${renderReviewSelectionTray(bookmarks)}
    <p class="empty-state">이 화면에서 보고서에 올릴 근거와 노이즈를 분리합니다. 저장된 선별 구조는 rapidtriage-case.json에 남습니다.</p>
    ${["relevant", "needs-review", "not-relevant", "unreviewed"].map((status) => renderReviewGroup(status, groups[status] || [])).join("")}
  `;
}

function renderReviewStateDashboard(bookmarks = [], summary = {}) {
  const counts = summary.review_status_counts || {};
  const statuses = [
    ["all", "전체", bookmarks.length],
    ["relevant", "관련 있음", counts.relevant || 0],
    ["needs-review", "재검토", counts["needs-review"] || 0],
    ["not-relevant", "제외", counts["not-relevant"] || 0],
    ["unreviewed", "미검토", counts.unreviewed || 0],
    ["report", "보고 포함", summary.report_item_count || 0],
  ];
  return `
    <section class="review-state-dashboard" aria-label="증거 선별 상태판" data-testid="review-state-dashboard">
      <div class="lane-section-header">
        <div>
          <p class="eyebrow">선별 작업대</p>
          <strong>검토 상태별로 바로 좁혀보기</strong>
        </div>
        <span>보고 후보 ${formatNumber(summary.report_item_count || 0)}</span>
      </div>
      <div class="review-state-grid">
        ${statuses.map(([status, label, count]) => `
          <button class="secondary-button review-state-chip ${status === "all" ? "active" : ""}" type="button" data-review-status-filter="${escapeHtml(status)}">
            <span>${escapeHtml(label)}</span>
            <b>${formatNumber(count)}</b>
          </button>
        `).join("")}
      </div>
      <p class="help-text">검토자는 원본 확인 후 관련 있음, 재검토, 제외, 보고 포함을 나눕니다. 이 상태가 보고서와 검토자 패키지의 기준이 됩니다.</p>
    </section>
  `;
}

function renderReviewCockpit(summary) {
  const relevant = Number(summary.review_status_counts?.relevant || 0);
  const needsReview = Number(summary.review_status_counts?.["needs-review"] || 0);
  const reportCount = Number(summary.report_item_count || 0);
  const unreviewed = Number(summary.review_status_counts?.unreviewed || 0);
  return `
    <section class="review-cockpit" aria-label="증거 선별 현황">
      <div>
        <p class="eyebrow">선별 현황</p>
        <h3>보고서 후보와 노이즈를 분리하는 화면</h3>
        <p>카드를 선택해 비교 묶음을 만들고, 관련 있음 중 보고서 포함 항목만 제출 패키지로 보냅니다.</p>
      </div>
      <div class="review-cockpit-stats">
        <span>관련 있음 ${formatNumber(relevant)}</span>
        <span>재검토 ${formatNumber(needsReview)}</span>
        <span>보고서 포함 ${formatNumber(reportCount)}</span>
        <span>미검토 ${formatNumber(unreviewed)}</span>
      </div>
    </section>
  `;
}

function renderReviewSelectionTray(bookmarks) {
  const selectedIds = getReviewSelection();
  const selectedBookmarks = bookmarks.filter((bookmark) => selectedIds.includes(String(bookmark.bookmark_id || "")));
  const reportSelectedCount = selectedBookmarks.filter((bookmark) => Boolean(bookmark.review?.include_in_report)).length;
  const selectedStatusCounts = selectedBookmarks.reduce((counts, bookmark) => {
    const status = bookmark.review?.status || "unreviewed";
    counts[status] = (counts[status] || 0) + 1;
    return counts;
  }, {});
  const selectedQueueText = ["relevant", "needs-review", "not-relevant", "unreviewed"]
    .map((status) => `${status} ${formatNumber(selectedStatusCounts[status] || 0)}`)
    .join(" · ");
  return `
    <section id="reviewSelectionTray" class="review-selection-tray ${selectedBookmarks.length ? "" : "empty"}" data-testid="review-bulk-queue">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">선택 묶음</p>
          <h3>현재 검토 묶음</h3>
          <p class="help-text">선택 묶음은 브라우저에 유지됩니다. 관련 증거를 모은 뒤 원본 경로와 보고서 포함 여부를 한 화면에서 대조하세요.</p>
        </div>
        <div class="detail-actions">
          <span class="status-pill">${selectedBookmarks.length}</span>
          <span class="status-pill">보고서 포함 ${reportSelectedCount}</span>
          <button class="secondary-button" type="button" data-clear-review-selection ${selectedBookmarks.length ? "" : "disabled"}>선택 해제</button>
        </div>
      </div>
      <div class="review-bulk-toolbar" aria-label="Selected evidence workflow">
        <span>${escapeHtml(selectedQueueText)}</span>
        <button class="secondary-button" type="button" data-open-tab="search">관련 결과 찾기</button>
        <button class="secondary-button" type="button" data-open-tab="report">보고서 준비</button>
      </div>
      ${selectedBookmarks.length ? `
        <div class="dense-list">
          ${selectedBookmarks.map((bookmark) => {
            const review = bookmark.review || {};
            const snapshot = bookmark.snapshot || {};
            return `
              <div class="dense-row">
                <strong>${escapeHtml(bookmark.summary || bookmark.bookmark_id)}</strong>
                <span>${escapeHtml(review.status || "unreviewed")} · ${review.include_in_report ? "보고서 포함" : "보고서 제외"} · ${escapeHtml(snapshot.path || "")}</span>
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
        <p class="eyebrow">제출 해시</p>
        <h3>제출용 해시 목록 준비</h3>
      </div>
      <p>보고서 후보 증거에 대해서만 MD5, SHA1, SHA256을 계산하고 run output에 rapidtriage-submission-manifest.json을 저장합니다.</p>
      <div class="guidance-actions">
        <a class="link-button ${disabled}" href="${reportCount ? fileUrl : "#"}" target="_blank" rel="noreferrer">해시 목록 다운로드</a>
        <a class="link-button ${disabled}" href="${reportCount ? jsonUrl : "#"}" target="_blank" rel="noreferrer">JSON 미리보기</a>
      </div>
      <p class="help-text">보고서나 bundle을 내보내기 전에 사용하세요. 선택 증거의 무결성 기준점입니다.</p>
      ${reportCount ? "" : '<p class="help-text">해시 목록을 만들기 전에 증거를 “보고서 후보에 포함”으로 표시하세요.</p>'}
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
            케이스 번호
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
          <label class="check-label"><input name="include_all" type="checkbox" /> 보고서 후보 외 검토 완료 항목도 포함</label>
          <button type="submit" ${reportCount ? "" : "disabled"}>보고서 초안 생성</button>
          <span id="caseReportStatus" class="review-save-status"></span>
        </div>
      </form>
      ${reportCount ? "" : '<p class="help-text">보고서 초안을 만들기 전에 증거를 “보고서 후보에 포함”으로 표시하세요.</p>'}
    </section>
  `;
}

function renderReviewerBundlePanel(summary, casePayload) {
  const reportCount = Number(summary.report_item_count || 0);
  return `
    <section class="guidance-card">
      <div>
        <p class="eyebrow">검토자 패키지</p>
        <h3>원본 이미지 없이 선별 자료 공유</h3>
      </div>
      <p>보고서 후보, 리뷰 메모, 해시를 기반으로 HTML/JSON/DOCX/PDF/ZIP 검토자 패키지를 생성합니다. 원본 증거 이미지는 복사하지 않습니다.</p>
      <p class="help-text">ZIP에는 검토자 HTML, 선택 증거 JSON, 보고서 산출물, 해시 목록, 감사 JSON, bundle manifest가 포함됩니다. archive SHA256 확인 후 공유하세요.</p>
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
          <label class="check-label"><input name="include_all" type="checkbox" /> 보고서 후보 외 검토 완료 항목도 포함</label>
          <button type="submit" ${reportCount ? "" : "disabled"}>검토자 패키지 생성</button>
          <span id="reviewerBundleStatus" class="review-save-status"></span>
        </div>
      </form>
      ${reportCount ? "" : '<p class="help-text">검토자 패키지를 만들기 전에 증거를 “보고서 후보에 포함”으로 표시하세요.</p>'}
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
    relevant: "관련 있는 증거",
    "needs-review": "재검토 필요",
    "not-relevant": "관련 없음 / 노이즈",
    unreviewed: "미검토 북마크",
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
  const reportBadge = review.include_in_report ? '<span class="review-badge report">보고서 포함</span>' : '<span class="review-badge">보고서 제외</span>';
  const compareButton = snapshot.path ? `<button class="icon-action" type="button" data-compare-item="${escapeHtml(JSON.stringify(compareItemFromBookmark(bookmark)))}">비교함에 추가</button>` : "";
  const bookmarkId = String(bookmark.bookmark_id || "");
  const selected = getReviewSelection().includes(bookmarkId);
  const reviewStatus = review.status || "unreviewed";
  return `
    <article class="review-card ${selected ? "selected" : ""}" data-filter="${rowText(bookmark)}" data-review-card-id="${escapeHtml(bookmarkId)}" data-review-card-status="${escapeHtml(reviewStatus)}" data-review-card-report="${review.include_in_report ? "1" : "0"}">
      <div class="review-card-top">
        <strong>${escapeHtml(bookmark.summary || bookmark.bookmark_id)}</strong>
        <div class="detail-actions">
          ${reportBadge}
          <button class="icon-action" type="button" data-toggle-review-selection="${escapeHtml(bookmarkId)}">${selected ? "선택됨" : "선택"}</button>
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
  return `<button class="icon-action" type="button" title="검토 대상으로 선별" data-bookmark-source="${escapeHtml(source)}" data-bookmark-pointer="${escapeHtml(pointer)}" data-bookmark-note="${escapeHtml(note || "")}">선별</button>`;
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
  if (match.source_viewer_action_profile?.profile_version) {
    return renderSearchResultSourceActionStrip(match, searchResultIndex);
  }
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
  return renderRowActionDock(items);
}

function renderRowActionDock(items, label = "검토") {
  const controls = (items || []).filter(Boolean);
  if (!controls.length) return "";
  return `
    <div class="row-action-dock" data-testid="row-action-dock" data-row-action-count="${escapeHtml(controls.length)}">
      <span>${escapeHtml(label)}</span>
      <div>${controls.join("")}</div>
    </div>
  `;
}

function renderSearchResultSourceActionStrip(match, searchResultIndex = null) {
  const profile = match.source_viewer_action_profile || {};
  const context = bookmarkContextForMatch(match);
  const enabledCount = (profile.actions || []).filter((action) => action.enabled !== false).length;
  return `
    <div
      class="search-result-source-actions"
      data-testid="search-result-source-actions"
      data-source-action-contract="${escapeHtml(profile.profile_version || SEARCH_RESULT_SOURCE_ACTION_CONTRACT.profile_version)}"
      data-qc-prep-item="${escapeHtml(profile.qc_prep_item || SEARCH_RESULT_SOURCE_ACTION_CONTRACT.qc_prep_item)}"
    >
      ${(profile.actions || []).map((action) => renderSearchResultSourceActionControl(action, match, context, searchResultIndex)).join("")}
      <small>가능 작업 ${escapeHtml(enabledCount)}개 · ${profile.ready_for_report_workflow ? "보고 가능" : "원본 위치 확인 필요"}</small>
    </div>
  `;
}

function renderSearchResultSourceActionControl(action, match, context, searchResultIndex = null) {
  if (!action?.id || action.enabled === false) {
    return "";
  }
  if (action.id === "open-source-viewer") {
    return viewSourceButton(match, context, searchResultIndex);
  }
  if (action.id === "open-source-file") {
    return sourceFileLink(match);
  }
  if (action.id === "search-inside-source") {
    const keywords = (action.keywords || match.matched_keywords || []).join(", ");
    return `<button class="icon-action subtle" type="button" data-view-source-path="${escapeHtml(match.path || "")}" data-review-context="${escapeHtml(JSON.stringify(context || {}))}" data-search-result-index="${escapeHtml(searchResultIndex ?? "")}" data-focus-file-search="1" data-focus-file-search-keywords="${escapeHtml(keywords)}">파일 안 검색</button>`;
  }
  if (action.id === "pin-compare") {
    return compareButton(compareItemFromMatch(match, context));
  }
  if (action.id === "save-review" && context) {
    return bookmarkButton(context.source, context.pointer, context.note || context.title);
  }
  return "";
}

function compareButton(item) {
  if (!item?.path) return "";
  return `<button class="icon-action" type="button" title="비교 트레이에 고정" data-compare-item="${escapeHtml(JSON.stringify(item))}">비교</button>`;
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
  return `<button class="icon-action primary-viewer-action" type="button" title="원본 미리보기" data-view-source-path="${escapeHtml(match.path)}" data-review-context="${escapeHtml(JSON.stringify(context || {}))}"${indexAttribute}>원본</button>`;
}

function sourceFileLink(match) {
  if (!match.path) return "";
  const url = `/api/runs/${encodeURIComponent(selectedRunId)}/source-file?path=${encodeURIComponent(match.path)}`;
  return `<a class="mini-link" href="${url}" target="_blank" rel="noreferrer" title="원본 파일 새 창으로 열기">새창</a>`;
}

function applyFilter(value) {
  const needle = value.trim().toLowerCase();
  for (const row of detailPanel.querySelectorAll("[data-filter]")) {
    row.hidden = needle && !row.dataset.filter.includes(needle);
  }
}

function clientFilteredRows() {
  return Array.from(detailPanel.querySelectorAll(".selectable-result-row[data-filter], .workspace-card[data-filter], tbody tr[data-filter]"));
}

function updateClientFilterSummary() {
  const rows = clientFilteredRows();
  const summaryAnchor = detailPanel.querySelector(".pagination-bar:not(.pagination-actions)");
  let summary = detailPanel.querySelector("[data-client-filter-summary]");
  if (!rows.length || !summaryAnchor) {
    detailPanel.classList.remove("client-filter-empty");
    if (summary) summary.hidden = true;
    return;
  }
  const visibleNeedle = detailPanel.querySelector("#tableFilter")?.value.trim() || "";
  const sourceNeedle = detailPanel.querySelector("#sourceFilterInput")?.value.trim() || "";
  const timeNeedle = detailPanel.querySelector("#timeFilterInput")?.value.trim() || "";
  const filterActive = Boolean(activeArtifactFilter || visibleNeedle || sourceNeedle || timeNeedle);
  if (!summary) {
    summary = document.createElement("div");
    summary.className = "client-filter-summary";
    summary.dataset.clientFilterSummary = "true";
    summaryAnchor.insertAdjacentElement("afterend", summary);
  }
  const visibleCount = rows.filter((row) => !row.hidden).length;
  detailPanel.classList.toggle("client-filter-empty", filterActive && visibleCount === 0 && rows.length > 0);
  summary.hidden = !filterActive;
  summary.classList.toggle("empty", filterActive && visibleCount === 0);
  summary.textContent = filterActive
    ? `현재 화면 필터 결과 ${formatNumber(visibleCount)}건 / 로드된 행 ${formatNumber(rows.length)}건`
    : "";
}

function applyWorkbenchFilters() {
  const visibleNeedle = detailPanel.querySelector("#tableFilter")?.value.trim().toLowerCase() || "";
  const sourceNeedle = detailPanel.querySelector("#sourceFilterInput")?.value.trim().toLowerCase() || "";
  const timeNeedle = detailPanel.querySelector("#timeFilterInput")?.value.trim().toLowerCase() || "";
  for (const row of detailPanel.querySelectorAll("[data-filter]")) {
    const haystack = row.dataset.filter || "";
    const rowSourceCategory = row.dataset.sourceCategory || "";
    row.hidden = Boolean(
      (activeTab === "artifacts" && activeArtifactFilter && rowSourceCategory !== activeArtifactFilter) ||
      (visibleNeedle && !haystack.includes(visibleNeedle)) ||
      (sourceNeedle && !haystack.includes(sourceNeedle)) ||
      (timeNeedle && !haystack.includes(timeNeedle))
    );
  }
  updateClientFilterSummary();
}

function scheduleWorkbenchFilterUpdate() {
  if (workbenchFilterTimer) window.clearTimeout(workbenchFilterTimer);
  workbenchFilterTimer = window.setTimeout(() => {
    applyWorkbenchFilters();
    persistWorkbenchSession();
    workbenchFilterTimer = null;
  }, 120);
}

function applyColumnPreset(preset) {
  detailPanel.classList.remove("table-columns-compact", "table-columns-source");
  if (preset === "compact") detailPanel.classList.add("table-columns-compact");
  if (preset === "source") detailPanel.classList.add("table-columns-source");
}

function currentWorkbenchControls() {
  return {
    visible_filter: detailPanel.querySelector("#tableFilter")?.value || "",
    source_filter: detailPanel.querySelector("#sourceFilterInput")?.value || "",
    time_filter: detailPanel.querySelector("#timeFilterInput")?.value || "",
    column_preset: detailPanel.querySelector("#columnPresetInput")?.value || "analyst",
  };
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

function safeCssToken(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "unknown";
}

const ROW_FILTER_TEXT_LIMIT = 900;
const ROW_FILTER_KEYS = [
  "title",
  "name",
  "path",
  "source",
  "kind",
  "type",
  "status",
  "review_status",
  "verification_status",
  "priority",
  "summary",
  "preview",
  "matched_keywords",
  "tags",
  "note",
  "pointer",
  "target_id",
  "target_type",
  "timestamp",
  "created_at",
  "modified_at",
  "accessed_at",
  "url",
  "domain",
  "value",
];

function rowText(value) {
  return escapeHtml(compactRowFilterText(value));
}

function compactRowFilterText(value) {
  const fragments = [];
  appendRowFilterFragments(fragments, value, 0);
  return fragments.join(" ").toLowerCase().slice(0, ROW_FILTER_TEXT_LIMIT);
}

function appendRowFilterFragments(fragments, value, depth) {
  if (fragments.join(" ").length >= ROW_FILTER_TEXT_LIMIT) return;
  if (value === null || value === undefined) return;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    const text = String(value).trim();
    if (text) fragments.push(text.slice(0, 220));
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value.slice(0, 8)) appendRowFilterFragments(fragments, item, depth + 1);
    return;
  }
  if (typeof value !== "object" || depth > 1) return;
  for (const key of ROW_FILTER_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
    appendRowFilterFragments(fragments, value[key], depth + 1);
  }
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

function storageAvailable() {
  try {
    const key = "rapidtriage.storage.check";
    window.localStorage.setItem(key, "1");
    window.localStorage.removeItem(key);
    return true;
  } catch {
    return false;
  }
}

function searchStorageKey() {
  return `${SEARCH_STORAGE_PREFIX}${selectedRunId || "default"}`;
}

function searchHistoryStorageKey() {
  return `${SEARCH_HISTORY_PREFIX}${selectedRunId || "default"}`;
}

function getSearchDraft() {
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

function setSearchDraft(payload) {
  if (!storageAvailable()) return;
  try {
    window.localStorage.setItem(searchStorageKey(), JSON.stringify(payload || {}));
  } catch {
    // Search drafts are convenience state only; failure should not block review.
  }
}

function getSearchHistory() {
  if (!storageAvailable()) return [];
  try {
    const payload = JSON.parse(window.localStorage.getItem(searchHistoryStorageKey()) || "[]");
    return Array.isArray(payload) ? payload : [];
  } catch {
    return [];
  }
}

function rememberSearchKeywords(entry) {
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

function compareStorageKey() {
  return `${COMPARE_STORAGE_PREFIX}${selectedRunId || "default"}`;
}

function viewerNavigationStorageKey() {
  return `${VIEWER_NAVIGATION_STORAGE_PREFIX}${selectedRunId || "default"}`;
}

function getViewerNavigation() {
  if (!storageAvailable()) return { items: [], index: -1 };
  try {
    const payload = JSON.parse(window.localStorage.getItem(viewerNavigationStorageKey()) || "{}");
    const items = Array.isArray(payload.items)
      ? payload.items.filter((item) => item?.path).slice(-VIEWER_NAVIGATION_LIMIT)
      : [];
    const index = Math.max(-1, Math.min(items.length - 1, Number(payload.index ?? items.length - 1)));
    return { items, index };
  } catch {
    return { items: [], index: -1 };
  }
}

function setViewerNavigation(state) {
  if (!storageAvailable()) return;
  const items = Array.isArray(state.items)
    ? state.items.filter((item) => item?.path).slice(-VIEWER_NAVIGATION_LIMIT)
    : [];
  const index = Math.max(-1, Math.min(items.length - 1, Number(state.index ?? items.length - 1)));
  window.localStorage.setItem(viewerNavigationStorageKey(), JSON.stringify({ items, index }));
}

function recordViewerNavigation(payload, reviewContext = null, searchResultIndex = null, options = {}) {
  if (options.fromHistory || !payload?.path) return getViewerNavigation();
  const state = getViewerNavigation();
  const current = state.items[state.index] || null;
  const pointer = reviewContext?.pointer || "";
  if (current?.path === payload.path && (current.reviewContext?.pointer || "") === pointer) {
    return state;
  }
  const nextItem = {
    path: payload.path,
    title: payload.name || fileName(payload.path),
    preview_type: payload.preview_type || "source",
    reviewContext: reviewContext || null,
    searchResultIndex: searchResultIndex === null || searchResultIndex === undefined ? null : String(searchResultIndex),
    opened_at: new Date().toISOString(),
  };
  const prefix = state.index >= 0 ? state.items.slice(0, state.index + 1) : state.items;
  const items = [...prefix, nextItem].slice(-VIEWER_NAVIGATION_LIMIT);
  const nextState = { items, index: items.length - 1 };
  setViewerNavigation(nextState);
  return nextState;
}

function renderViewerNavigationControls(payload) {
  const state = getViewerNavigation();
  const canBack = state.index > 0;
  const canForward = state.index >= 0 && state.index < state.items.length - 1;
  const current = state.index >= 0 ? `${state.index + 1}/${state.items.length}` : "0/0";
  return `
    <nav class="viewer-navigation-bar" aria-label="Opened source navigation" data-testid="viewer-navigation-bar" data-navigation-contract="${escapeHtml(VIEWER_NAVIGATION_CONTRACT.profile_version)}">
      <button class="secondary-button" type="button" data-viewer-history-delta="-1" ${canBack ? "" : "disabled"}>Back</button>
      <button class="secondary-button" type="button" data-viewer-history-delta="1" ${canForward ? "" : "disabled"}>Forward</button>
      <span>${escapeHtml(current)} opened source(s)</span>
      <small>${escapeHtml(payload.path || "")}</small>
    </nav>
  `;
}

async function goViewerNavigation(delta) {
  const state = getViewerNavigation();
  const nextIndex = state.index + Number(delta || 0);
  if (nextIndex < 0 || nextIndex >= state.items.length) return false;
  const nextState = { items: state.items, index: nextIndex };
  setViewerNavigation(nextState);
  const item = nextState.items[nextIndex];
  await loadEvidencePreview(item.path, item.reviewContext || null, item.searchResultIndex, { fromHistory: true });
  return true;
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

function renderCompareCitationBundle(items) {
  const citationText = items.map((item, index) => compareCitationLine(item, index)).join("\n");
  return `
    <section class="compare-citation-bundle" aria-label="report-citation-bundle">
      <div>
        <p class="eyebrow">인용 근거 묶음</p>
        <h4>보고서 후보 근거 묶음</h4>
        <p class="help-text">비교함에 모은 자료는 보고서에 넣을 인용 후보입니다. 원본 경로와 source/pointer를 같이 보존합니다.</p>
      </div>
      <button class="secondary-button" type="button" data-copy-path="${escapeHtml(citationText)}">인용 묶음 복사</button>
    </section>
  `;
}

function compareCitationLine(item, index) {
  const label = String.fromCharCode(65 + index);
  const fields = [
    `${label}. ${item.title || fileName(item.path) || "evidence"}`,
    item.source ? `source=${item.source}` : "",
    item.pointer ? `pointer=${item.pointer}` : "",
    item.kind ? `kind=${item.kind}` : "",
    item.path ? `path=${item.path}` : "",
  ];
  return fields.filter(Boolean).join(" | ");
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

async function openCompareDiff() {
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

function renderCompareDiff(left, right) {
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
  bindCommandPaletteActions();
  const globalSearchForm = detailPanel.querySelector("#globalCaseSearchForm");
  if (globalSearchForm && !globalSearchForm.dataset.bound) {
    globalSearchForm.dataset.bound = "1";
    globalSearchForm.addEventListener("submit", runGlobalCommandSearch);
  }
  for (const button of detailPanel.querySelectorAll("[data-open-tab]")) {
    button.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      const capability = event.target.closest("[data-capability-filter]");
      const targetTab = capability?.dataset.capabilityTab || button.dataset.openTab;
      const sourceCategoryFilter = button.dataset.sourceCategoryFilter || "";
      const filter = capability?.dataset.capabilityFilter || button.dataset.artifactFilter || "";
      activeArtifactFilter = targetTab === "artifacts" ? sourceCategoryFilter : "";
      await switchTab(targetTab, { syncStage: false });
      if (button.classList.contains("source-card")) {
        setWorkbenchVisibleFilter("");
      } else {
        applyArtifactTreeFilter(filter);
      }
      refreshSourceNavigatorState();
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-doc-lane-filter]")) {
    if (button.dataset.docLaneBound) continue;
    button.dataset.docLaneBound = "1";
    button.addEventListener("click", () => {
      setWorkbenchVisibleFilter(button.dataset.docLaneFilter || "");
      detailPanel.querySelector("#tableFilter")?.focus();
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-timeline-lane-filter]")) {
    if (button.dataset.timelineLaneBound) continue;
    button.dataset.timelineLaneBound = "1";
    button.addEventListener("click", () => {
      setWorkbenchVisibleFilter(button.dataset.timelineLaneFilter || "");
      detailPanel.querySelector("#tableFilter")?.focus();
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-review-status-filter]")) {
    if (button.dataset.reviewStatusBound) continue;
    button.dataset.reviewStatusBound = "1";
    button.addEventListener("click", () => applyReviewStatusFilter(button.dataset.reviewStatusFilter || "all"));
  }
  for (const button of detailPanel.querySelectorAll("[data-keyboard-action]")) {
    if (button.dataset.keyboardActionBound) continue;
    button.dataset.keyboardActionBound = "1";
    button.addEventListener("click", async () => {
      await executeKeyboardStripAction(button.dataset.keyboardAction || "");
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-preview-output-name]")) {
    if (button.dataset.outputPreviewBound) continue;
    button.dataset.outputPreviewBound = "1";
    button.addEventListener("click", async () => {
      await loadRunOutputPreview(button.dataset.previewOutputName || "");
    });
  }
  for (const button of detailPanel.querySelectorAll("[data-start-configured-e01-run]")) {
    if (button.dataset.e01StartBound) continue;
    button.dataset.e01StartBound = "1";
    button.addEventListener("click", () => {
      const inputKindInput = document.querySelector("#inputKindInput");
      if (inputKindInput) inputKindInput.value = "e01-derived";
      updateRunSubmissionCta(document.querySelector("#rootInput")?.value || "", document.querySelector("#processingProfileInput")?.value || "fast");
      runForm?.requestSubmit();
    });
  }
  bindE01PartitionControls(detailPanel);
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
  bindIndicatorTiForm();
  bindCompareActions();
  bindReviewSelectionActions();
  bindVirtualWindowButtons();
}

function bindCommandPaletteActions() {
  const palette = detailPanel.querySelector("#commandPalette");
  if (!palette || palette.dataset.paletteBound) return;
  palette.dataset.paletteBound = "1";
  for (const trigger of detailPanel.querySelectorAll("[data-command-palette-open]")) {
    trigger.addEventListener("click", () => openCommandPalette());
  }
  for (const closer of palette.querySelectorAll("[data-command-palette-close]")) {
    closer.addEventListener("click", closeCommandPalette);
  }
  const input = palette.querySelector("#commandPaletteInput");
  input?.addEventListener("input", () => filterCommandPalette(input.value));
  input?.addEventListener("keydown", async (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      const command = firstVisibleCommandPaletteButton();
      if (command) await executeCommandPaletteButton(command);
    }
    if (event.key === "Escape") {
      event.preventDefault();
      closeCommandPalette();
    }
  });
  for (const command of palette.querySelectorAll(".command-palette-command")) {
    command.addEventListener("click", async () => executeCommandPaletteButton(command));
  }
}

function commandPaletteElement() {
  return detailPanel.querySelector("#commandPalette");
}

function commandPaletteIsOpen() {
  const palette = commandPaletteElement();
  return Boolean(palette && !palette.hidden);
}

function openCommandPalette(prefill = "") {
  if (!selectedRunId) return false;
  const palette = commandPaletteElement();
  if (!palette) return false;
  palette.hidden = false;
  palette.classList.add("open");
  palette.setAttribute("aria-hidden", "false");
  const input = palette.querySelector("#commandPaletteInput");
  if (input) {
    input.value = prefill;
    filterCommandPalette(prefill);
    requestAnimationFrame(() => {
      input.focus();
      input.select();
    });
  }
  return true;
}

function closeCommandPalette() {
  const palette = commandPaletteElement();
  if (!palette) return;
  palette.classList.remove("open");
  palette.setAttribute("aria-hidden", "true");
  palette.hidden = true;
}

function filterCommandPalette(query) {
  const palette = commandPaletteElement();
  if (!palette) return;
  const terms = String(query || "").trim().toLowerCase().split(/\s+/).filter(Boolean);
  let visibleCount = 0;
  for (const command of palette.querySelectorAll(".command-palette-command")) {
    const haystack = command.dataset.commandText || "";
    const visible = !terms.length || terms.every((term) => haystack.includes(term));
    command.hidden = !visible || visibleCount >= COMMAND_PALETTE_RESULT_LIMIT;
    command.classList.remove("active");
    if (!command.hidden) visibleCount += 1;
  }
  firstVisibleCommandPaletteButton()?.classList.add("active");
  palette.classList.toggle("empty", visibleCount === 0);
}

function firstVisibleCommandPaletteButton() {
  return Array.from(detailPanel.querySelectorAll(".command-palette-command")).find((button) => !button.hidden);
}

async function executeCommandPaletteButton(button) {
  const tab = button.dataset.commandTab || "";
  const filter = button.dataset.commandFilter || "";
  const action = button.dataset.commandAction || "";
  closeCommandPalette();
  if (tab) {
    await switchTab(tab, { syncStage: false });
    applyArtifactTreeFilter(filter);
    return;
  }
  if (action === "focus-visible-filter") {
    detailPanel.querySelector("#tableFilter")?.focus();
    return;
  }
  if (action === "focus-current-file-search") {
    focusContextSearch();
    return;
  }
  if (action === "page-next") {
    await pageCurrentTable("next");
    return;
  }
  if (action === "toggle-shortcuts") {
    toggleShortcutHelp(true);
  }
}

function applyArtifactTreeFilter(filterTerm) {
  const term = String(filterTerm || "").trim();
  if (!term) return;
  const input = detailPanel.querySelector("#tableFilter");
  if (!input) return;
  input.value = term;
  applyWorkbenchFilters();
  persistWorkbenchSession();
}

function setWorkbenchVisibleFilter(filterTerm) {
  const input = detailPanel.querySelector("#tableFilter");
  if (!input) return;
  input.value = String(filterTerm || "");
  applyWorkbenchFilters();
  persistWorkbenchSession();
}

function applyReviewStatusFilter(status) {
  const normalized = String(status || "all");
  for (const button of detailPanel.querySelectorAll("[data-review-status-filter]")) {
    const active = (button.dataset.reviewStatusFilter || "all") === normalized;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  }
  for (const card of detailPanel.querySelectorAll(".review-card[data-review-card-status]")) {
    const cardStatus = card.dataset.reviewCardStatus || "unreviewed";
    const report = card.dataset.reviewCardReport === "1";
    card.hidden = !(
      normalized === "all" ||
      normalized === cardStatus ||
      (normalized === "report" && report)
    );
  }
}

async function executeKeyboardStripAction(action) {
  if (action === "palette") {
    openCommandPalette();
    return true;
  }
  if (action === "focus-context-search") {
    focusContextSearch();
    return true;
  }
  if (action === "preview-first-visible-row") {
    return previewFirstVisibleRow();
  }
  if (action === "mark-relevant") {
    return applyViewerReviewShortcut("relevant", true);
  }
  if (action === "open-review") {
    await switchTab("review", { syncStage: false });
    return true;
  }
  return false;
}

async function previewFirstVisibleRow() {
  const row = Array.from(detailPanel.querySelectorAll(".selectable-result-row[data-viewer-row-path], tr[data-viewer-row-path]"))
    .find((candidate) => !candidate.hidden);
  if (!row) return false;
  if (row.dataset.inspectorRow && !row.dataset.viewerRowPath) {
    showSelectedRowInspector(row);
    return true;
  }
  if (!row.dataset.viewerRowPath) return false;
  await loadEvidencePreview(row.dataset.viewerRowPath, parseReviewContext(row.dataset.reviewContext), row.dataset.searchResultIndex);
  row.classList.add("selected-row");
  return true;
}

function refreshSourceNavigatorState() {
  for (const button of detailPanel.querySelectorAll(".source-card[data-open-tab]")) {
    const tab = button.dataset.openTab || "";
    const category = button.dataset.sourceCategoryFilter || "";
    const active = tab === activeTab && (tab !== "artifacts" || category === activeArtifactFilter);
    button.classList.toggle("active", active);
    button.setAttribute("aria-current", active ? "page" : "false");
  }
}

async function runGlobalCommandSearch(event) {
  event.preventDefault();
  const keyword = String(new FormData(event.currentTarget).get("keyword") || "").trim();
  if (!keyword) {
    await openCaseSearch();
    return;
  }
  await switchTab("search", { syncStage: false });
  const input = detailPanel.querySelector("#unifiedSearchInput");
  if (input) input.value = keyword;
  detailPanel.querySelector("#unifiedSearchForm")?.requestSubmit();
}

function bindIndicatorTiForm() {
  const form = detailPanel.querySelector("#indicatorTiForm");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const result = detailPanel.querySelector("#indicatorTiResult");
    const button = form.querySelector("button[type='submit']");
    const formData = new FormData(form);
    const feedPath = String(formData.get("ti_feed") || "").trim();
    if (!feedPath) {
      result.innerHTML = '<p class="empty-state">Enter a local JSON/CSV/TXT feed path first.</p>';
      return;
    }
    const params = new URLSearchParams();
    params.append("ti_feed", feedPath);
    params.set("limit", String(formData.get("limit") || "250"));
    if (formData.get("include_unmatched")) params.set("include_unmatched", "true");
    button.disabled = true;
    button.textContent = "Enriching...";
    result.innerHTML = '<p class="empty-state">Applying local feed without external network calls...</p>';
    try {
      const payload = await api(`/api/runs/${selectedRunId}/indicators/ti-enrichment?${params.toString()}`);
      result.innerHTML = renderIndicatorTiEnrichment(payload);
    } catch (error) {
      result.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
    } finally {
      button.disabled = false;
      button.textContent = "Run local enrichment";
    }
  });
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
        button.textContent = "Case DB 준비";
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
      const cursorOverride = Object.prototype.hasOwnProperty.call(searchForm.dataset, "caseDbCursorOverride")
        ? String(searchForm.dataset.caseDbCursorOverride || "")
        : null;
      if (cursorOverride !== null) delete searchForm.dataset.caseDbCursorOverride;
      const submittedCursor = cursorOverride !== null
        ? cursorOverride
        : event.submitter?.hasAttribute("data-case-db-cursor") ? String(event.submitter.dataset.caseDbCursor || "") : "";
      const request = {
        database: String(importData.get("database") || ""),
        case_id: String(importData.get("case_id") || ""),
        keywords,
        cursor: submittedCursor,
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
        button.textContent = "검색 중...";
        const payload = await api("/api/case-db/search", { method: "POST", body: JSON.stringify(request) });
        virtualWindowOffsets.caseDb = 0;
        currentCaseDbSearchPayload = payload;
        output.innerHTML = renderCaseDbSearchResult(payload);
        searchForm.elements.cursor.value = payload.summary?.next_cursor || "";
        rememberCaseDbKeywords(request);
        await loadCaseDbSavedSearches(request.database, request.case_id);
        bindCaseDbCursorButtons();
        bindCaseDbReviewButtons(request.database, request.case_id);
        bindCaseDbBatchButtons(request.database, request.case_id);
        bindCaseDbReportExportButton(request.database, request.case_id);
      } catch (error) {
        output.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
      } finally {
        button.disabled = false;
        button.textContent = "Case DB 검색";
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

function bindCaseDbCursorButtons() {
  const searchForm = detailPanel.querySelector("#caseDbSearchForm");
  if (!searchForm) return;
  for (const button of detailPanel.querySelectorAll("[data-case-db-cursor]")) {
    if (button.dataset.cursorBound) continue;
    button.dataset.cursorBound = "1";
    button.addEventListener("click", () => {
      searchForm.elements.cursor.value = button.dataset.caseDbCursor || "";
      searchForm.dataset.caseDbCursorOverride = button.dataset.caseDbCursor || "";
      searchForm.requestSubmit();
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
    return '<p class="empty-state">저장된 검색이 없습니다. 한 번 검색한 뒤 “검색 저장명”을 입력해 보관하세요.</p>';
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
  form.elements.cursor.value = "";
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
  currentCaseDbSearchPayload = payload;
  const rows = payload.matches || [];
  const visibleRows = virtualizedRows(rows, "caseDb");
  const saved = payload.saved_search;
  const reviewWorkflow = payload.review_workflow_summary || {};
  const documentErrors = payload.documents?.errors || [];
  const cursorApi = payload.summary?.cursor_api || {};
  const pagination = renderCaseDbPagination(payload);
  if (!rows.length) {
    return `
      ${saved ? `<p class="help-text">Saved search: ${escapeHtml(saved.name)} (${escapeHtml(saved.citation_id)})</p>` : ""}
      <div class="metric-grid">
        ${metric("DB 일치", payload.summary?.match_count)}
        ${metric("표시", payload.summary?.returned_count)}
        ${metric("문서 오류", payload.summary?.document_error_count)}
      </div>
      ${pagination}
      <p class="empty-state">Case DB에서 일치 결과를 찾지 못했습니다.</p>
      ${renderDocumentErrors(documentErrors)}
    `;
  }
  return `
    ${saved ? `<p class="help-text">Saved search: ${escapeHtml(saved.name)} (${escapeHtml(saved.citation_id)})</p>` : ""}
    <div class="metric-grid">
      ${metric("DB 일치", payload.summary?.match_count)}
      ${metric("표시", payload.summary?.returned_count)}
      ${metric("페이지 위치", cursorApi.offset)}
      ${metric("출처", Object.keys(payload.summary?.source_counts || {}).length)}
      ${metric("문서 오류", payload.summary?.document_error_count)}
      ${metric("검색어", (payload.keywords || []).length)}
      ${metric("우선 검토", payload.summary?.priority_counts?.high)}
    </div>
    ${pagination}
    ${renderDocumentErrors(documentErrors)}
    ${renderCaseDbReviewWorkflowSummary(reviewWorkflow)}
    <section class="review-selection-tray">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">일괄 선별</p>
          <h3>반복 결과를 한 번에 정리</h3>
        </div>
        <div class="detail-actions">
          <button class="secondary-button" type="button" data-case-db-select="visible">현재 결과 선택</button>
          <button class="secondary-button" type="button" data-case-db-select="low">낮은 우선순위 선택</button>
          <button class="secondary-button" type="button" data-case-db-batch="verify">선택 항목 확인</button>
          <button class="secondary-button" type="button" data-case-db-batch="reject">선택 항목 제외</button>
          <button class="secondary-button" type="button" data-case-db-export-report>보고서 후보 내보내기</button>
        </div>
      </div>
      <p class="help-text">관련성이 같은 행을 선택한 뒤 동일한 선별 상태를 한 번에 적용합니다.</p>
      <span id="caseDbBatchStatus" class="review-save-status"></span>
    </section>
    ${renderVirtualizationNotice(rows, visibleRows, "Case DB 결과", "caseDb")}
    <table class="data-table">
      <thead><tr><th>선택</th><th>인용</th><th>우선도</th><th>출처</th><th>항목</th><th>선별</th><th></th></tr></thead>
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
                }))}">확인</button>
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
                }))}">제외</button>
              </td>
            </tr>
          `;
        }).join("")}
      </tbody>
    </table>
  `;
}

function renderCaseDbPagination(payload) {
  const summary = payload.summary || {};
  const cursorApi = summary.cursor_api || {};
  const nextCursor = summary.next_cursor || cursorApi.next_cursor || "";
  const offset = Number(cursorApi.offset || summary.page_offset || 0);
  const pageSize = Number(cursorApi.page_size || summary.page_size || 0);
  if (!nextCursor && offset <= 0) return "";
  return `
    <section class="review-selection-tray compact" data-testid="case-db-cursor-pagination">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">대량 결과 페이지</p>
          <h3>${escapeHtml(offset + 1)}-${escapeHtml(offset + (summary.returned_count || 0))}${pageSize ? ` / 페이지 ${escapeHtml(pageSize)}건` : ""}</h3>
        </div>
        <div class="detail-actions">
          ${offset > 0 ? `<button class="secondary-button" type="button" data-case-db-cursor="">처음으로</button>` : ""}
          ${nextCursor ? `<button class="secondary-button" type="button" data-case-db-cursor="${escapeHtml(nextCursor)}" aria-label="Next results">다음 결과</button>` : ""}
        </div>
      </div>
      <p class="help-text">커서 토큰은 현재 케이스, 검색어, 출처, 메타데이터, 선별 필터에 묶여 검색 조건이 흔들리지 않도록 합니다.</p>
    </section>
  `;
}

function renderCaseDbReviewWorkflowSummary(summary) {
  if (!summary || !summary.profile_version) return "";
  const statusCounts = summary.status_counts || {};
  const verificationCounts = summary.verification_status_counts || {};
  return `
    <section class="review-selection-tray compact">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">선별 흐름</p>
          <h3>담당자와 상태 큐</h3>
        </div>
        <div class="mini-stat-row">
          <span>배정 ${escapeHtml(summary.assigned_count || 0)}</span>
          <span>미배정 ${escapeHtml(summary.unassigned_count || 0)}</span>
          <span>보고서 후보 ${escapeHtml(summary.report_candidate_count || 0)}</span>
        </div>
      </div>
      <div class="chip-row compact">
        ${Object.entries(statusCounts).slice(0, 5).map(([key, count]) => `<span class="filter-chip">${escapeHtml(key)} · ${escapeHtml(count)}</span>`).join("")}
        ${Object.entries(verificationCounts).slice(0, 5).map(([key, count]) => `<span class="filter-chip">${escapeHtml(key)} · ${escapeHtml(count)}</span>`).join("")}
      </div>
      <p class="help-text">현재는 단일 사용자 검토 큐입니다. 역할 기반 배정, 알림, 다중 사용자 충돌 처리는 추가 검증이 필요합니다.</p>
    </section>
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
    button.textContent = "내보내는 중...";
    try {
      const payload = await api("/api/case-db/report-export", {
        method: "POST",
        body: JSON.stringify({ database, case_id: caseId, include_all: false, max_items: 500 }),
      });
      if (status) status.textContent = `Case DB에서 보고서 후보 ${payload.summary?.exported_item_count || 0}건을 내보냈습니다.`;
    } catch (error) {
      if (status) status.textContent = `실패: ${error.message}`;
    } finally {
      button.disabled = false;
      button.textContent = "보고서 후보 내보내기";
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
        if (status) status.textContent = `실패: ${error.message}`;
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
    if (commandPaletteIsOpen() && event.key === "Escape") {
      event.preventDefault();
      closeCommandPalette();
      return;
    }
    if (isTypingTarget(event.target) && !commandShortcut) return;
    if (event.key === "?") {
      event.preventDefault();
      toggleShortcutHelp();
      return;
    }
    if (commandShortcut && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openCommandPalette();
      return;
    }
    if (commandShortcut && event.key.toLowerCase() === "f") {
      event.preventDefault();
      focusContextSearch();
      return;
    }
    if (!event.metaKey && !event.ctrlKey && !event.altKey && event.key === "/") {
      event.preventDefault();
      await openCaseSearch();
      return;
    }
    if (!event.metaKey && !event.ctrlKey && !event.altKey && event.key === " ") {
      if (await previewFirstVisibleRow()) event.preventDefault();
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
    if (!event.metaKey && !event.ctrlKey && !event.altKey && /^[1-5]$/.test(event.key)) {
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

function toggleShortcutHelp(forceOpen = null) {
  const help = detailPanel.querySelector("#shortcutHelp");
  if (!help) return;
  help.open = forceOpen === null ? !help.open : Boolean(forceOpen);
}

async function openCaseSearch() {
  if (!selectedRunId) return;
  await switchTab("search", { syncStage: false });
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
  if (status) status.textContent = includeInput.checked ? "보고서 포함으로 표시했습니다. 저장하면 반영됩니다." : "보고서 포함을 해제했습니다. 저장하면 반영됩니다.";
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
  if (activeTab === "search" && pageVirtualWindow("search", direction)) return true;
  if (activeTab === "review" && pageVirtualWindow("caseDb", direction)) return true;
  if (!["timeline", "artifacts", "files", "docs"].includes(activeTab)) return false;
  const selector = `[data-page-tab="${CSS.escape(activeTab)}"]`;
  const buttons = Array.from(detailPanel.querySelectorAll(selector));
  const button = buttons.find((item) => item.textContent.toLowerCase().includes(direction));
  if (!button || button.disabled) return false;
  button.click();
  return true;
}

function pageVirtualWindow(windowKey, direction) {
  const selector = `[data-virtual-window-key="${CSS.escape(windowKey)}"]`;
  const buttons = Array.from(detailPanel.querySelectorAll(selector));
  const button = buttons.find((item) => item.textContent.toLowerCase().includes(direction === "previous" ? "previous" : "next"));
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

async function switchTab(tab, options = {}) {
  if (!tab) return;
  activeTab = tab;
  if (tab !== "artifacts") activeArtifactFilter = "";
  if (options.stageId) {
    activeStageId = options.stageId;
  } else if (options.syncStage) {
    activeStageId = stageIdForTab(caseStageFlow(selectedRun, tab, ""), tab);
  }
  activeStageSubactionId = options.stageSubactionId || "";
  const nextGroup = groupForTab(tab);
  const tabIsVisible = Array.from(detailPanel.querySelectorAll(".tab-button")).some((item) => item.dataset.tab === tab);
  if (activeViewGroup !== nextGroup || !tabIsVisible) {
    activeViewGroup = nextGroup;
    detailPanel.innerHTML = renderDetailShell(selectedRun, activeTab);
    updateSideStagePanel();
    bindTabButtons();
    restoreWorkbenchControls();
    persistWorkbenchSession();
    await renderActiveTab();
    return;
  }
  for (const item of detailPanel.querySelectorAll(".tab-button")) {
    item.classList.toggle("active", item.dataset.tab === tab);
  }
  await renderActiveTab();
  refreshSourceNavigatorState();
  updateSideStagePanel();
  persistWorkbenchSession();
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
    ["#e01PartitionStartSectorInput", "e01PartitionStartSector"],
    ["#knownGoodHashFeedInput", "knownGoodHashFeeds"],
    ["#knownGoodMaxHashMbInput", "knownGoodMaxHashMb"],
    ["#importOutputInput", "importOutputDir"],
  ]) {
    const element = document.querySelector(selector);
    if (element && saved[key] !== undefined) element.value = saved[key];
  }
  for (const [selector, key] of [
    ["#readOnlyInput", "readOnly"],
    ["#dryRunInput", "dryRun"],
    ["#overwriteInput", "overwrite"],
    ["#hideKnownGoodInput", "hideKnownGood"],
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
    e01PartitionStartSector: document.querySelector("#e01PartitionStartSectorInput")?.value || "",
    knownGoodHashFeeds: document.querySelector("#knownGoodHashFeedInput")?.value || "",
    knownGoodMaxHashMb: document.querySelector("#knownGoodMaxHashMbInput")?.value || "64",
    importOutputDir: document.querySelector("#importOutputInput")?.value || "",
    readOnly: document.querySelector("#readOnlyInput")?.checked ?? true,
    dryRun: document.querySelector("#dryRunInput")?.checked ?? false,
    overwrite: document.querySelector("#overwriteInput")?.checked ?? false,
    hideKnownGood: document.querySelector("#hideKnownGoodInput")?.checked ?? false,
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
    "#e01PartitionStartSectorInput",
    "#knownGoodHashFeedInput",
    "#knownGoodMaxHashMbInput",
    "#importOutputInput",
    "#readOnlyInput",
    "#dryRunInput",
    "#overwriteInput",
    "#hideKnownGoodInput",
  ]) {
    document.querySelector(selector)?.addEventListener("input", persistRunForm);
    document.querySelector(selector)?.addEventListener("change", persistRunForm);
    document.querySelector(selector)?.addEventListener("input", refreshRunPlanPreview);
    document.querySelector(selector)?.addEventListener("change", refreshRunPlanPreview);
  }
  document.querySelector("#processingProfileInput")?.addEventListener("change", applyProcessingProfile);
  document.querySelector("#rootInput")?.addEventListener("input", applyRootEvidenceHints);
  document.querySelector("#rootInput")?.addEventListener("change", applyRootEvidenceHints);
  collectPlanButton?.addEventListener("click", previewCollectPlan);
  bindStartChoiceCards();
}

function bindStartChoiceCards() {
  for (const button of document.querySelectorAll("[data-intake-action]")) {
    button.addEventListener("click", () => applyStartChoice(button.dataset.intakeAction || ""));
  }
}

function applyStartChoice(action) {
  const rootInput = document.querySelector("#rootInput");
  const inputKindInput = document.querySelector("#inputKindInput");
  const processingProfileInput = document.querySelector("#processingProfileInput");
  const modeInput = document.querySelector("#modeInput");
  if (action === "e01") {
    if (inputKindInput) inputKindInput.value = "e01-derived";
    if (processingProfileInput) processingProfileInput.value = "fast";
    if (modeInput) modeInput.value = "fraud";
    rootInput?.focus();
    evidenceCheckStatus.textContent = "E01/Ex01 또는 이미지 경로를 넣고 이미지 지원 확인을 누르면 도구, 파티션, 마운트/추출 필요 여부를 먼저 확인합니다.";
  } else if (action === "folder") {
    if (inputKindInput) inputKindInput.value = "folder";
    if (processingProfileInput) processingProfileInput.value = "fast";
    if (modeInput) modeInput.value = "fraud";
    rootInput?.focus();
    evidenceCheckStatus.textContent = "이미지를 이미 마운트/추출한 폴더나 벤더 Export 폴더 경로를 넣고 분석 실행을 누르면 됩니다.";
  } else if (action === "recent") {
    document.querySelector("#importOutputInput")?.focus();
  } else if (action === "sample") {
    sampleRunButton?.click();
  } else if (action === "qc") {
    doctorButton?.click();
  }
  persistRunForm();
  refreshRunPlanPreview();
}

function detectEvidenceImageKind(root) {
  const value = String(root || "").trim();
  if (!value) return { isImage: false, family: "", label: "", inputKind: "" };
  for (const format of IMAGE_EVIDENCE_FORMATS) {
    if (format.pattern.test(value)) {
      return {
        isImage: true,
        family: format.family,
        label: format.label,
        inputKind: format.inputKind,
      };
    }
  }
  return { isImage: false, family: "", label: "", inputKind: "" };
}

function applyRootEvidenceHints() {
  const root = document.querySelector("#rootInput")?.value || "";
  const rootError = document.querySelector("#rootInputError");
  if (root.trim() && rootError) rootError.hidden = true;
  const inputKindInput = document.querySelector("#inputKindInput");
  const detected = detectEvidenceImageKind(root);
  if (detected.isImage && detected.inputKind && inputKindInput && ["", "e01-derived", "disk-image-derived", "archive-image-derived"].includes(inputKindInput.value)) {
    inputKindInput.value = detected.inputKind;
  }
  if (evidenceCheckStatus && evidenceCheckStatus.dataset.checkedRoot !== root) {
    delete evidenceCheckStatus.dataset.checkedRoot;
    evidenceCheckStatus.textContent = detected.isImage
      ? `${detected.label} 이미지로 보입니다. 먼저 이미지 지원 확인으로 필요한 도구, 파티션/마운트/추출 가능 여부를 확인하세요.`
      : "E01/Ex01/RAW/VHDX/DMG는 먼저 도구와 파티션 처리 가능 여부를 확인합니다.";
  }
  persistRunForm();
  refreshRunPlanPreview();
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
  const root = document.querySelector("#rootInput")?.value || "";
  const profileKey = document.querySelector("#processingProfileInput")?.value || "fast";
  const profile = PROCESSING_PROFILES[profileKey] || PROCESSING_PROFILES.fast;
  const readOnly = document.querySelector("#readOnlyInput")?.checked ?? true;
  const dryRun = document.querySelector("#dryRunInput")?.checked ?? false;
  const maxExtractBytes = extractLimitBytes();
  const maxFiles = Number(document.querySelector("#maxFileCountInput")?.value || 0);
  const e01PartitionStartSector = optionalInteger(document.querySelector("#e01PartitionStartSectorInput")?.value);
  const knownGoodFeeds = parseKnownGoodHashFeeds();
  const hideKnownGood = document.querySelector("#hideKnownGoodInput")?.checked ?? false;
  const knownGoodMaxBytes = knownGoodMaxHashBytes();
  const mode = document.querySelector("#modeInput")?.value || "fraud";
  const collectors = RUN_MODE_COLLECTORS[mode] || RUN_MODE_COLLECTORS.fraud;
  const badges = [
    ...profile.badges,
    readOnly ? "read-only" : "extract allowed",
    dryRun ? "dry-run" : "writes output",
    knownGoodFeeds.length ? `${knownGoodFeeds.length} known-good feed(s)` : "no known-good feed",
    hideKnownGood ? "hide known-good" : "known-good reviewable",
  ];
  target.innerHTML = `
    <p class="eyebrow">run plan preview</p>
    <h3>${escapeHtml(profile.title)} · ${escapeHtml(titleCase(mode))}</h3>
    <p>${escapeHtml(profile.summary)}</p>
    <p>Collectors: ${collectors.map((collector) => `<code>${escapeHtml(collector)}</code>`).join(" ")}</p>
    ${renderRunPlanE01Readiness(root, e01PartitionStartSector, profileKey)}
    <div class="processing-caps">
      ${badges.map((badge) => `<span>${escapeHtml(badge)}</span>`).join("")}
      <span>Max extract: ${maxExtractBytes ? formatBytes(maxExtractBytes) : "uncapped/none"}</span>
      <span>Max files: ${Number.isFinite(maxFiles) && maxFiles > 0 ? formatNumber(maxFiles) : "uncapped/none"}</span>
      <span>E01 partition: ${e01PartitionStartSector === null ? "auto largest supported" : `sector ${formatNumber(e01PartitionStartSector)}`}</span>
      <span>Known-good hash cap: ${formatBytes(knownGoodMaxBytes)}</span>
      <span>Signature mismatch: always on</span>
    </div>
  `;
  updateRunSubmissionCta(root, profileKey);
}

function isLikelyE01Path(root) {
  return detectEvidenceImageKind(root).family === "ewf";
}

function isLikelyImageEvidencePath(root) {
  return detectEvidenceImageKind(root).isImage;
}

function updateRunSubmissionCta(root, profileKey = "fast") {
  if (!runButton) return;
  if (runButton.disabled) return;
  const detected = detectEvidenceImageKind(root);
  if (isLikelyE01Path(root)) {
    runButton.dataset.e01Detected = "true";
    delete runButton.dataset.evidenceImageDetected;
    runButton.textContent = profileKey === "fast"
      ? "E01 사전 점검 + 빠른 분석"
      : "E01 인입 + 분석 실행";
    return;
  }
  if (detected.isImage) {
    runButton.dataset.evidenceImageDetected = "true";
    delete runButton.dataset.e01Detected;
    runButton.textContent = profileKey === "fast"
      ? "이미지 빠른 분석 실행"
      : "이미지 인입 + 분석 실행";
    return;
  }
  delete runButton.dataset.e01Detected;
  delete runButton.dataset.evidenceImageDetected;
  runButton.textContent = "분석 실행";
}

function runStartingLabel(root) {
  if (isLikelyE01Path(root)) return "E01 분석 준비 중...";
  if (isLikelyImageEvidencePath(root)) return "이미지 증거 분석 준비 중...";
  return "분석 시작 중...";
}

function renderRunPlanE01Readiness(root, partitionStartSector, profileKey) {
  const detected = detectEvidenceImageKind(root);
  if (!detected.isImage) return "";
  if (!isLikelyE01Path(root)) {
    const imageWarning = profileKey === "deep"
      ? "대용량 이미지에서 심층 추출은 오래 걸릴 수 있습니다. 빠른 1차 분석 후 필요한 범위만 깊게 보세요."
      : "이미지 증거는 먼저 지원 확인으로 도구와 추출 방식을 확인한 뒤 빠른 1차 분석을 권장합니다.";
    const strategyText = detected.family === "forensic-container"
      ? "벤더 도구로 Export/마운트 후 폴더 분석"
      : "지원 확인 후 마운트/추출 또는 직접 분석";
    return `
      <section class="run-plan-e01-readiness" aria-label="Image evidence pre-run readiness">
        <div class="review-group-header">
          <div>
            <p class="eyebrow">image evidence pre-run</p>
            <h4>${escapeHtml(detected.label)} 이미지 증거로 보입니다</h4>
          </div>
          <span class="status-pill warning">support check recommended</span>
        </div>
        <p>${escapeHtml(imageWarning)}</p>
        <div class="processing-caps">
          <span>Recommended input kind: ${escapeHtml(detected.inputKind || "vendor-export-first")}</span>
          <span>${escapeHtml(strategyText)}</span>
          <span>해시/출처/도구 버전 보존 필요</span>
        </div>
      </section>
    `;
  }
  const sectorText = partitionStartSector === null
    ? "auto select largest supported filesystem"
    : `use sector ${formatNumber(partitionStartSector)}`;
  const profileWarning = profileKey === "deep"
    ? "Deep extraction can be very slow on E01. Start fast unless you already narrowed the target."
    : "Good start: run fast/standard first, then deepen after search results point to useful evidence.";
  return `
    <section class="run-plan-e01-readiness" aria-label="E01 pre-run readiness">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">windows 11 e01 pre-run</p>
          <h4>E01 single-case workflow will run before artifact analysis</h4>
        </div>
        <span class="status-pill warning">preflight required</span>
      </div>
      <p>${escapeHtml(profileWarning)}</p>
      <div class="processing-caps">
        <span>Recommended input kind: e01-derived</span>
        <span>Partition: ${escapeHtml(sectorText)}</span>
        <span>Evidence support check recommended</span>
      </div>
      <div class="e01-pre-run-grid">
        ${E01_PRE_RUN_STEPS.map((step, index) => `
          <article>
            <strong>${index + 1}. ${escapeHtml(step.label)}</strong>
            <span>${escapeHtml(step.text)}</span>
          </article>
        `).join("")}
      </div>
    </section>
  `;
}

function optionalInteger(value) {
  const text = String(value ?? "").trim();
  if (!text) return null;
  const number = Number(text);
  if (!Number.isInteger(number) || number < 0) return null;
  return number;
}

function extractLimitBytes() {
  const mb = Number(document.querySelector("#maxExtractMbInput")?.value || 0);
  if (!Number.isFinite(mb) || mb <= 0) return 0;
  return Math.floor(mb * 1024 * 1024);
}

function parseKnownGoodHashFeeds() {
  const raw = document.querySelector("#knownGoodHashFeedInput")?.value || "";
  return raw
    .split(/[\n,;]+/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function knownGoodMaxHashBytes() {
  const raw = document.querySelector("#knownGoodMaxHashMbInput")?.value;
  if (raw === undefined || String(raw).trim() === "") return 64 * 1024 * 1024;
  const mb = Number(raw);
  if (!Number.isFinite(mb) || mb < 0) return 64 * 1024 * 1024;
  return Math.floor(mb * 1024 * 1024);
}

async function previewCollectPlan() {
  const target = document.querySelector("#collectPlanPreview");
  const root = document.querySelector("#rootInput")?.value || "";
  const profile = document.querySelector("#collectProfileInput")?.value || "intrusion";
  const inputKind = document.querySelector("#inputKindInput")?.value || null;
  if (!target) return;
  if (!root.trim()) {
    target.innerHTML = '<p class="empty-state">먼저 마운트/Export된 증거 경로를 넣어주세요.</p>';
    return;
  }
  collectPlanButton.disabled = true;
  collectPlanButton.textContent = "확인 중...";
  target.innerHTML = '<p class="empty-state">중요 아티팩트 경로를 확인하는 중입니다...</p>';
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
    collectPlanButton.textContent = "수집 대상 보기";
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

runForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const rootInput = document.querySelector("#rootInput");
  const rootError = document.querySelector("#rootInputError");
  const root = rootInput.value.trim();
  if (!root) {
    if (rootError) rootError.hidden = false;
    rootInput.focus();
    return;
  }
  if (rootError) rootError.hidden = true;
  runButton.disabled = true;
  runButton.textContent = runStartingLabel(root);
  const request = {
    root,
    mode: document.querySelector("#modeInput").value,
    output_dir: document.querySelector("#outputInput").value || null,
    input_kind: document.querySelector("#inputKindInput").value || null,
    read_only: document.querySelector("#readOnlyInput").checked,
    dry_run: document.querySelector("#dryRunInput").checked,
    overwrite: document.querySelector("#overwriteInput").checked,
    max_extract_size_bytes: extractLimitBytes(),
    max_file_count: Number(document.querySelector("#maxFileCountInput")?.value || 0),
    e01_partition_start_sector: optionalInteger(document.querySelector("#e01PartitionStartSectorInput")?.value),
    known_good_hash_feeds: parseKnownGoodHashFeeds(),
    hide_known_good: document.querySelector("#hideKnownGoodInput")?.checked ?? false,
    known_good_max_hash_bytes: knownGoodMaxHashBytes(),
  };
  try {
    const run = await api("/api/runs", { method: "POST", body: JSON.stringify(request) });
    selectedRunId = run.run_id;
    activeTab = "summary";
    activeViewGroup = groupForTab(activeTab);
    persistWorkbenchSession({ tableControls: { visible_filter: "", source_filter: "", time_filter: "", column_preset: "analyst" } });
    await loadRuns();
    await loadRunDetail(run.run_id, activeTab);
  } catch (error) {
    detailPanel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    runButton.disabled = false;
    updateRunSubmissionCta(root, document.querySelector("#processingProfileInput")?.value || "fast");
  }
});

refreshButton.addEventListener("click", loadRuns);

importForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const outputDir = document.querySelector("#importOutputInput").value.trim();
  if (!outputDir) return;
  importButton.disabled = true;
  importButton.textContent = "불러오는 중...";
  try {
    const run = await api("/api/runs/import", {
      method: "POST",
      body: JSON.stringify({ output_dir: outputDir }),
    });
    selectedRunId = run.run_id;
    activeTab = "summary";
    activeViewGroup = groupForTab(activeTab);
    persistWorkbenchSession({ tableControls: { visible_filter: "", source_filter: "", time_filter: "", column_preset: "analyst" } });
    await loadRuns();
    await loadRunDetail(run.run_id, activeTab);
  } catch (error) {
    detailPanel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    importButton.disabled = false;
    importButton.textContent = "결과 불러오기";
  }
});

sampleRunButton?.addEventListener("click", async () => {
  sampleRunButton.disabled = true;
  sampleRunButton.textContent = "샘플 생성 중...";
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
    activeViewGroup = groupForTab(activeTab);
    persistWorkbenchSession({ tableControls: { visible_filter: "", source_filter: "", time_filter: "", column_preset: "analyst" } });
    await loadRuns();
    await loadRunDetail(payload.run.run_id, activeTab);
  } catch (error) {
    detailPanel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    sampleRunButton.disabled = false;
    sampleRunButton.textContent = "샘플 실행";
  }
});

doctorButton?.addEventListener("click", async () => {
  doctorButton.disabled = true;
  doctorButton.textContent = "점검 중...";
  try {
    const payload = await api("/api/doctor");
    detailPanel.innerHTML = renderDoctorPanel(payload);
  } catch (error) {
    detailPanel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    doctorButton.disabled = false;
    doctorButton.textContent = "환경 점검";
  }
});

crashReportsButton?.addEventListener("click", async () => {
  crashReportsButton.disabled = true;
  crashReportsButton.textContent = "크래시 불러오는 중...";
  try {
    const payload = await api("/api/crash-reports?limit=100");
    detailPanel.innerHTML = renderCrashReportsPanel(payload);
    bindCrashReportActions();
  } catch (error) {
    detailPanel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  } finally {
    crashReportsButton.disabled = false;
    crashReportsButton.textContent = "크래시 로그";
  }
});

function renderCrashReportsPanel(payload) {
  const reports = payload.reports || [];
  const dashboard = payload.crash_trend_dashboard || payload.summary || {};
  return `
    <section class="guidance-card crash-dashboard" data-testid="crash-dashboard">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">local-only crash reporting</p>
          <h3>Crash export dashboard</h3>
          <p>자동 업로드 없이 로컬 JSON만 읽습니다. 필요한 항목은 ZIP export로 묶어 운영자가 직접 전달합니다.</p>
        </div>
        <span class="status-pill ok">no upload</span>
      </div>
      <div class="metric-grid">
        ${metric("Reports", dashboard.report_count || 0)}
        ${metric("Local-only", dashboard.local_only_count || 0)}
        ${metric("Redacted keys", dashboard.redacted_key_total || 0)}
        ${metric("Exception types", Object.keys(dashboard.exception_type_counts || {}).length)}
      </div>
      <p class="help-text">Dashboard hash: ${escapeHtml(dashboard.dashboard_hash || "")}</p>
      ${reports.length ? `
        <div class="dense-list">
          ${reports.map((report) => `
            <div class="dense-row crash-report-row">
              <strong>${escapeHtml(report.crash_id || "")} · ${escapeHtml(report.exception_type || "unknown")}</strong>
              <span>${escapeHtml(report.exception_message || "")}</span>
              <small>${escapeHtml(report.generated_at || "")} · ${escapeHtml(report.api_path || report.component || "local")}</small>
              <div class="mini-actions">
                <button class="secondary-button" type="button" data-crash-detail="${escapeHtml(report.crash_id || "")}">Details</button>
                <button class="secondary-button" type="button" data-crash-export="${escapeHtml(report.crash_id || "")}">Export ZIP</button>
              </div>
            </div>
          `).join("")}
        </div>
      ` : '<p class="empty-state">No local crash reports found.</p>'}
      <div id="crashReportDetail" class="source-verification"></div>
    </section>
  `;
}

function bindCrashReportActions() {
  detailPanel.querySelectorAll("[data-crash-detail]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = detailPanel.querySelector("#crashReportDetail");
      try {
        const payload = await api(`/api/crash-reports/${encodeURIComponent(button.dataset.crashDetail || "")}`);
        const report = payload.payload || {};
        target.innerHTML = `
          <h4>${escapeHtml(payload.summary?.crash_id || "")}</h4>
          <p>${escapeHtml(report.privacy_note || "")}</p>
          <code>${escapeHtml(payload.path || "")}</code>
          <pre>${escapeHtml(JSON.stringify({
            exception: report.exception,
            context: report.context,
            redaction_matrix_hash: report.crash_redaction_matrix_hash,
            no_upload_manifest_hash: report.crash_no_upload_manifest_hash,
          }, null, 2))}</pre>
        `;
      } catch (error) {
        target.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
      }
    });
  });
  detailPanel.querySelectorAll("[data-crash-export]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = detailPanel.querySelector("#crashReportDetail");
      try {
        const payload = await api(`/api/crash-reports/${encodeURIComponent(button.dataset.crashExport || "")}/export`, {
          method: "POST",
          body: JSON.stringify({}),
        });
        target.innerHTML = `
          <h4>Crash export bundle created</h4>
          <p>Bundle SHA256: ${escapeHtml(payload.bundle_sha256 || "")}</p>
          <code>${escapeHtml(payload.bundle_path || "")}</code>
          <p class="help-text">이 ZIP은 로컬에만 생성됩니다. 업로드나 외부 전송은 하지 않습니다.</p>
        `;
      } catch (error) {
        target.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
      }
    });
  });
}

evidenceCheckButton?.addEventListener("click", checkEvidenceSupport);

async function checkEvidenceSupport() {
  const root = document.querySelector("#rootInput")?.value?.trim();
  if (!root) {
    evidenceCheckStatus.textContent = "먼저 E01/Ex01/RAW/VHDX/DMG 이미지나 마운트/Export 폴더 경로를 넣어주세요.";
    return;
  }
  evidenceCheckButton.disabled = true;
  evidenceCheckButton.textContent = "확인 중...";
  evidenceCheckStatus.textContent = "이미지 형식, 필요한 도구, 파티션/마운트 처리 가능 여부를 확인하는 중입니다...";
  try {
    const payload = await api("/api/evidence/identify", {
      method: "POST",
      body: JSON.stringify({ path: root }),
    });
    const result = payload.result || {};
    applyEvidenceCheckRecommendation(result);
    evidenceCheckStatus.innerHTML = renderEvidenceCheckStatus(result);
    evidenceCheckStatus.dataset.checkedRoot = root;
    bindEvidenceCheckActions();
  } catch (error) {
    evidenceCheckStatus.textContent = error.message;
  } finally {
    evidenceCheckButton.disabled = false;
    evidenceCheckButton.textContent = "이미지 지원 확인";
  }
}

function bindEvidenceCheckActions() {
  if (!evidenceCheckStatus) return;
  for (const button of evidenceCheckStatus.querySelectorAll("[data-open-tab]")) {
    if (button.dataset.evidenceOpenTabBound) continue;
    button.dataset.evidenceOpenTabBound = "1";
    button.addEventListener("click", async () => {
      await switchTab(button.dataset.openTab);
    });
  }
  for (const button of evidenceCheckStatus.querySelectorAll("[data-start-configured-e01-run]")) {
    if (button.dataset.e01StartBound) continue;
    button.dataset.e01StartBound = "1";
    button.addEventListener("click", () => {
      const inputKindInput = document.querySelector("#inputKindInput");
      if (inputKindInput) inputKindInput.value = "e01-derived";
      updateRunSubmissionCta(document.querySelector("#rootInput")?.value || "", document.querySelector("#processingProfileInput")?.value || "fast");
      runForm?.requestSubmit();
    });
  }
  bindE01PartitionControls(evidenceCheckStatus);
}

function bindE01PartitionControls(rootElement) {
  if (!rootElement) return;
  for (const button of rootElement.querySelectorAll("[data-e01-partition-sector]")) {
    if (button.dataset.e01PartitionBound) continue;
    button.dataset.e01PartitionBound = "1";
    button.addEventListener("click", () => {
      const sectorInput = document.querySelector("#e01PartitionStartSectorInput");
      if (sectorInput) {
        sectorInput.value = button.dataset.e01PartitionSector || "";
        sectorInput.focus();
      }
      persistRunForm();
      refreshRunPlanPreview();
    });
  }
  for (const button of rootElement.querySelectorAll("[data-e01-partition-focus]")) {
    if (button.dataset.e01PartitionFocusBound) continue;
    button.dataset.e01PartitionFocusBound = "1";
    button.addEventListener("click", () => {
      const sectorInput = document.querySelector("#e01PartitionStartSectorInput");
      sectorInput?.scrollIntoView({ behavior: "smooth", block: "center" });
      sectorInput?.focus();
    });
  }
}

function applyEvidenceCheckRecommendation(result) {
  const workflow = result.ingest_workflow || {};
  const recommendedInputKind = workflow.recommended_input_kind || "";
  const inputKind = document.querySelector("#inputKindInput");
  if (inputKind && !inputKind.value && recommendedInputKind) {
    inputKind.value = recommendedInputKind;
  }
  persistRunForm();
  refreshRunPlanPreview();
}

function renderEvidenceCheckStatus(result) {
  const support = result.supported ? "supported" : "not supported";
  const action = result.can_extract || result.can_mount ? "direct handling available" : "mount/export first";
  const missing = (result.missing_tools || []).length ? ` Missing tools: ${(result.missing_tools || []).join(", ")}.` : "";
  return `
    <div class="evidence-status-card ${result.supported ? "ready" : "blocked"}">
      <div>
        <strong>${escapeHtml((result.detected_format || "unknown").toUpperCase())}</strong>
        <span>${escapeHtml(result.adapter || "adapter")} · ${escapeHtml(support)} · ${escapeHtml(action)}</span>
      </div>
      <p>${escapeHtml(result.message || "")}${escapeHtml(missing)}</p>
      ${renderE01IngestWorkflow(result.ingest_workflow || null)}
      ${renderEvidencePreflightSummary(result.preflight_summary || null)}
      ${renderEvidenceFailureGuidance(result.failure_guidance || null)}
      ${renderEvidenceToolPreflight(result.tool_preflight || [])}
    </div>
  `;
}

function renderE01IngestWorkflow(workflow) {
  if (!workflow) return "";
  const e01WorkflowLabel = "Starting E01 workflow";
  const stages = workflow.stages || [];
  return `
    <section class="e01-workflow-panel">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">Windows 11 E01 처리 · ${escapeHtml(e01WorkflowLabel)}</p>
          <h3>${escapeHtml(workflow.direct_extract_ready ? "Ready for single-case ingest" : "Preflight blocked")}</h3>
        </div>
        <span class="status-pill ${workflow.direct_extract_ready ? "ok" : "warning"}">${escapeHtml(workflow.ui_primary_action || "review")}</span>
      </div>
      <p>${escapeHtml(workflow.workflow_goal || "")}</p>
      ${workflow.blocked_reason ? `<p class="help-text">${escapeHtml(workflow.blocked_reason)}</p>` : ""}
      ${renderE01PartitionBrowser(workflow.partition_browser || workflow.partition_selection || null)}
      ${renderVscWorkflowHandoff(workflow.vsc_workflow_handoff || workflow.vsc_handoff || null)}
      ${renderE01HandoffContract(workflow.handoff_contract || null)}
      <div class="e01-stage-grid">
        ${stages.map((stage, index) => `
          <article class="e01-stage-card ${escapeHtml(stage.status || "pending")}">
            <span>${index + 1}</span>
            <strong>${escapeHtml(stage.label || stage.id || "stage")}</strong>
            <em>${escapeHtml(stage.status || "pending")}</em>
            <p>${escapeHtml(stage.operator_action || "")}</p>
            ${(stage.evidence || []).length ? `<small>${escapeHtml((stage.evidence || []).join(" · "))}</small>` : ""}
          </article>
        `).join("")}
      </div>
      ${(workflow.large_case_controls || []).length ? `
        <details class="match-details">
          <summary>Large-case safety controls</summary>
          <ul>${(workflow.large_case_controls || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
        </details>
      ` : ""}
    </section>
  `;
}

function renderVscWorkflowHandoff(handoff) {
  if (!handoff?.profile_version) return "";
  const commands = handoff.commands || {};
  const steps = handoff.workflow_steps || [];
  return `
    <section class="vsc-handoff-card" data-testid="vsc-workflow-handoff" data-qc-prep-item="${escapeHtml(handoff.qc_prep_item || 3)}">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">QC-prep #3 VSC handoff</p>
          <strong>Shadow copy discovery → compare → extract</strong>
          <span>${escapeHtml(handoff.goal || "")}</span>
        </div>
        <span class="status-pill ${handoff.status === "blocked" ? "warning" : "ok"}">${escapeHtml(handoff.status || "pending")}</span>
      </div>
      <div class="processing-caps">
        <span>Source: ${escapeHtml(handoff.source_kind || "image")}</span>
        <span>Snapshots: ${formatNumber(handoff.snapshot_count || 0)}</span>
        <span>Direct image VSC mount: ${handoff.direct_image_level_mount_supported ? "yes" : "external"}</span>
      </div>
      <p class="help-text">${escapeHtml(handoff.operator_warning || "")}</p>
      <div class="vsc-step-grid">
        ${steps.map((step, index) => `
          <article>
            <span>${index + 1}</span>
            <strong>${escapeHtml(step.label || step.id || "step")}</strong>
            <em>${escapeHtml(step.status || "pending")}</em>
          </article>
        `).join("")}
      </div>
      <details class="match-details">
        <summary>VSC commands</summary>
        <code>${escapeHtml(commands.discover || "")}</code>
        <code>${escapeHtml(commands.compare || "")}</code>
        <code>${escapeHtml(commands.extract || "")}</code>
        <code>${escapeHtml(commands.case_db_import || "")}</code>
      </details>
    </section>
  `;
}

function renderE01PartitionBrowser(browser) {
  if (!browser?.profile_version) return "";
  const rows = browser.partitions || browser.partition_browser_rows || [];
  const recommendedSector = browser.recommended_start_sector ?? "";
  const selectedSector = browser.selected_start_sector ?? "";
  return `
    <section class="e01-partition-browser" data-testid="e01-partition-browser" data-qc-prep-item="${escapeHtml(browser.qc_prep_item || 2)}">
      <div class="review-group-header">
        <div>
          <p class="eyebrow">QC-prep #2 partition browser</p>
          <strong>E01 partition choice</strong>
          <span>${escapeHtml(browser.goal || "Review mmls partitions before extraction.")}</span>
        </div>
        <span class="status-pill ${rows.length ? "ok" : "warning"}">${escapeHtml(browser.status || "pending")}</span>
      </div>
      <div class="processing-caps">
        <span>Partitions: ${formatNumber(browser.partition_count ?? rows.length)}</span>
        <span>Supported: ${formatNumber(browser.supported_partition_count ?? rows.filter((row) => row.supported_filesystem_hint).length)}</span>
        <span>Recommended: ${recommendedSector === "" ? "pending" : formatNumber(recommendedSector)}</span>
        <span>Selected: ${selectedSector === "" ? "auto" : formatNumber(selectedSector)}</span>
      </div>
      ${rows.length ? `
        <div class="table-scroll">
          <table class="data-table e01-partition-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Start sector</th>
                <th>Size</th>
                <th>Filesystem</th>
                <th>Recommendation</th>
                <th>Manual override</th>
              </tr>
            </thead>
            <tbody>
              ${rows.map((row) => `
                <tr class="${row.selected_for_recovery ? "selected-row" : ""}">
                  <td>${escapeHtml(row.partition_number ?? row.slot ?? "")}</td>
                  <td>${row.start_sector === null || row.start_sector === undefined ? "n/a" : formatNumber(row.start_sector)}</td>
                  <td>${row.size_bytes ? formatBytes(row.size_bytes) : "n/a"}</td>
                  <td><strong>${escapeHtml(row.filesystem_guess || "unknown")}</strong><span>${escapeHtml(row.description || "")}</span></td>
                  <td>${escapeHtml(row.recommendation || (row.recommended_for_recovery ? "recommended" : "review"))}</td>
                  <td>
                    <button class="mini-inline-button" type="button" data-e01-partition-sector="${escapeHtml(row.start_sector ?? "")}" ${row.start_sector === null || row.start_sector === undefined ? "disabled" : ""}>
                      Use sector
                    </button>
                  </td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      ` : `
        <p class="empty-state">${escapeHtml(browser.empty_state || "Partition table is not available yet.")}</p>
      `}
      <div class="e01-partition-actions">
        <button class="secondary-button" type="button" data-e01-partition-focus>Manual start-sector override</button>
        ${recommendedSector === "" ? "" : `<button class="secondary-button" type="button" data-e01-partition-sector="${escapeHtml(recommendedSector)}">Use recommended sector</button>`}
      </div>
      <p class="help-text">${escapeHtml(browser.manual_override?.warning || "Preserve the mmls/trusted-tool evidence for any manual partition choice.")}</p>
    </section>
  `;
}

function renderE01HandoffContract(contract) {
  if (!contract?.profile_version) return "";
  const entrypoints = contract.gui_entrypoints || [];
  return `
    <section class="e01-handoff-card" data-testid="e01-end-to-end-handoff" data-qc-prep-item="${escapeHtml(contract.qc_prep_item || 1)}">
      <div>
        <p class="eyebrow">QC-prep #1 handoff</p>
        <strong>Evidence → run → search → review → report</strong>
        <span>${escapeHtml(contract.goal || "")}</span>
      </div>
      <div class="e01-handoff-actions">
        <button class="secondary-button" type="button" data-start-configured-e01-run ${entrypoints.some((item) => item.id === "start-configured-run" && item.status === "ready") ? "" : "disabled"}>Start configured run</button>
        <button class="secondary-button" type="button" data-open-tab="search">검색</button>
        <button class="secondary-button" type="button" data-open-tab="review">Review</button>
        <button class="secondary-button" type="button" data-open-tab="report">Report</button>
      </div>
      <div class="e01-handoff-chain">
        ${entrypoints.map((item) => `
          <span title="${escapeHtml(item.required_before || "")}">${escapeHtml(item.label || item.id)} · ${escapeHtml(item.status || "pending")}</span>
        `).join("")}
      </div>
      <details class="match-details">
        <summary>Expected output chain</summary>
        <ul>${(contract.required_output_chain || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
        <code>${escapeHtml(contract.run_command || "")}</code>
      </details>
    </section>
  `;
}

function renderEvidenceFailureGuidance(guidance) {
  if (!guidance) return "";
  return `
    <section class="evidence-preflight-summary warning">
      <div class="processing-caps">
        <span>Failure class: ${escapeHtml(guidance.category || "unknown")}</span>
      </div>
      <strong>${escapeHtml(guidance.title || "Evidence handling issue")}</strong>
      <p>${escapeHtml(guidance.analyst_message || "")}</p>
      ${(guidance.next_actions || []).length ? `
        <ul>${(guidance.next_actions || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
      ` : ""}
    </section>
  `;
}

function renderEvidencePreflightSummary(summary) {
  if (!summary) return "";
  return `
    <section class="evidence-preflight-summary">
      <div class="processing-caps">
        <span>Status: ${escapeHtml(summary.status || "unknown")}</span>
        <span>Available: ${formatNumber(summary.available_count || 0)}</span>
        <span>Missing: ${formatNumber(summary.missing_count || 0)}</span>
      </div>
      <p>${escapeHtml(summary.operator_message || "")}</p>
      ${(summary.remediation_steps || []).length ? `
        <details class="match-details">
          <summary>How to fix missing E01 tools</summary>
          <ul>${(summary.remediation_steps || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
        </details>
      ` : ""}
    </section>
  `;
}

function renderEvidenceToolPreflight(rows) {
  if (!rows.length) return "";
  return `
    <details class="match-details evidence-tool-details">
      <summary>Tool preflight details</summary>
      <div class="dense-list">
        ${rows.map((row) => `
          <div class="dense-row">
            <strong>${escapeHtml(row.tool || "")} · ${row.available ? "available" : "missing"}</strong>
            <span>${escapeHtml(row.version || row.path || row.remediation || "No version/path available")}</span>
            <small>${escapeHtml(row.purpose || "")}</small>
            ${row.install_hint ? `<small>${escapeHtml(row.install_hint)}</small>` : ""}
          </div>
        `).join("")}
      </div>
    </details>
  `;
}

function renderDoctorPanel(payload) {
  const checks = payload.checks || [];
  return `
    <section class="guidance-card">
      <p class="eyebrow">환경 점검</p>
      <h3>RapidTriage 상태: ${escapeHtml(payload.status || "unknown")}</h3>
      <div class="metric-grid">
        ${metric("OK", payload.summary?.ok)}
        ${metric("경고", payload.summary?.warn)}
        ${metric("오류", payload.summary?.error)}
        ${metric("점검 항목", payload.summary?.check_count)}
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
    activeStageId = "";
    activeStageSubactionId = "";
    document.body.classList.remove("analysis-active");
    updateSideStagePanel();
    persistWorkbenchSession({ selectedRunId: null, activeTab: "summary", activeViewGroup: "triage" });
    detailPanel.innerHTML = '<p class="empty-state">Run removed from the local catalog. Output files were not deleted.</p>';
    await loadRuns();
  } catch (error) {
    detailPanel.innerHTML = `<p class="empty-state">${escapeHtml(error.message)}</p>`;
  }
}

hydrateRunForm();
restoreWorkbenchSession();
bindRunFormPersistence();
refreshRunPlanPreview();
bindKeyboardShortcuts();
checkHealth();
loadRuns();
pollTimer = setInterval(loadRuns, 4000);
