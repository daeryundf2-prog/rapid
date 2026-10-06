// DetailPanel screen module (R3-2). Workbench shell: command deck, layout
// frame, and diagnostics drawer. All heavy sub-renderers stay in app.js and are
// injected once via initDetailPanel.
import { devModeEnabled, escapeHtml, metric, tabLabel } from "./app_utils.js";
import { workbenchState } from "./app_store.js";
import { FEATURE_PLACEMENT_CONTRACT, FORENSIC_WORKFLOW_LANES } from "./app_workbench_config.js";
import { renderCaseHero } from "./app_case_header.js";

let groupForTab, renderAdaptiveViewerHeader, renderArtifactTreeRows,
  renderEvidenceSourceNavigator, renderForensicFeatureCatalog,
  renderForensicQuestionBar, renderForensicRibbon, renderIntelligencePanel,
  renderLazywebCommandCenter, renderSecondaryWorkbenchControls,
  renderTableControlBar, renderValidationReadinessBanner,
  renderWorkbenchSmokePanel, runCounts, setActiveViewGroup, tabsForGroup;

export function initDetailPanel(deps) {
  ({
    groupForTab, renderAdaptiveViewerHeader, renderArtifactTreeRows,
    renderEvidenceSourceNavigator, renderForensicFeatureCatalog,
    renderForensicQuestionBar, renderForensicRibbon, renderIntelligencePanel,
    renderLazywebCommandCenter, renderSecondaryWorkbenchControls,
    renderTableControlBar, renderValidationReadinessBanner,
    renderWorkbenchSmokePanel, runCounts, setActiveViewGroup, tabsForGroup,
  } = deps);
}

export function workflowLanes() {
  return Array.isArray(FORENSIC_WORKFLOW_LANES) ? FORENSIC_WORKFLOW_LANES : [];
}

export function workflowLaneForTab(tab) {
  const lanes = workflowLanes();
  const groupId = groupForTab(tab);
  return lanes.find((lane) => lane.tab === tab || lane.id === groupId || (lane.id === "documents" && groupId === "documents"))
    || lanes[0]
    || { id: "triage", label: tabLabel(tab), tab, terms: [tab], modules: [] };
}

export function renderWorkbenchLayoutFrame(run, tab) {
  const reportCandidates = runCounts(run).reviewItems;
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
        ${renderAdaptiveViewerHeader(run, tab)}
        <p id="tabStatus" class="sr-only" role="status" aria-live="polite"></p>
        <div id="tabBody" class="tab-body" role="tabpanel" data-testid="tab-body"></div>
      </main>
      ${renderIntelligencePanel(run, tab, reportCandidates)}
    </section>
  `;
}

export function renderAdvancedDiagnosticsPanel(run, tab) {
  const counts = runCounts(run);
  return `
    <section class="advanced-diagnostics-panel" data-testid="advanced-diagnostics-panel" aria-label="개발 및 검증 진단">
      <div class="advanced-diagnostics-copy">
        <p class="eyebrow">진단 전용</p>
        <h3>분석 흐름에 필요 없는 기능 상태는 여기로 분리했습니다</h3>
        <p>아래 정보는 구현 범위, 검증 상태, 성능 스모크 확인용입니다. 실제 증거 검토는 왼쪽 영역과 가운데 리뷰 화면에서 진행하세요.</p>
      </div>
      <div class="advanced-diagnostics-grid">
        ${metric("문서", counts.docs)}
        ${metric("파일", counts.files)}
        ${metric("타임라인", counts.timelineEvents)}
        ${metric("검증 이슈", counts.validationIssues)}
        ${metric("산출물", counts.outputs)}
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

export function renderDetailShell(run, tab) {
  setActiveViewGroup(groupForTab(tab));
  const tabs = tabsForGroup(workbenchState.activeViewGroup);
  const devMode = devModeEnabled();
  return `
    <section class="workbench-command-deck" aria-label="Case command deck">
      ${renderCaseHero(run)}
    </section>
    <div class="tab-row redundant-tab-row" role="tablist" aria-label="보조 탭 전환">
      ${tabs.map((item) => `<button class="tab-button ${item === tab ? "active" : ""}" role="tab" aria-selected="${item === tab ? "true" : "false"}" aria-controls="tabBody" data-tab="${escapeHtml(item)}" data-testid="tab-${escapeHtml(item)}" type="button">${escapeHtml(tabLabel(item))}</button>`).join("")}
    </div>
    ${renderWorkbenchLayoutFrame(run, tab)}
    <div class="dev-mode-strip" data-testid="dev-mode-strip">
      <button type="button" class="mini-inline-button" data-dev-mode-toggle="${devMode ? "off" : "on"}">
        ${devMode ? "개발자 도구 끄기" : "개발자 도구"}
      </button>
      <small>${devMode ? "검증·진단 패널 표시 중" : "검증·진단 패널은 개발자 모드에서만 표시됩니다."}</small>
    </div>
    ${devMode ? `
      <details class="workbench-intel-drawer">
        <summary>
          <span>개발/QC 진단</span>
          <strong>일반 분석에는 접어두기</strong>
        </summary>
        ${renderAdvancedDiagnosticsPanel(run, tab)}
      </details>
    ` : ""}
  `;
}
