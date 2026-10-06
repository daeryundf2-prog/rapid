// CaseHeader screen module (R3-2). Header strip, core-evidence workflow, and
// workflow status labels. Render helpers live here; app.js wires dependencies
// once via initCaseHeader so this module never imports the monolith.
import { escapeHtml, formatNumber } from "./app_utils.js";
import { CORE_EVIDENCE_WORKFLOW, FORENSIC_ARTIFACT_TAXONOMY } from "./app_workbench_config.js";

let artifactGroupCount, runCounts;
export function initCaseHeader({ artifactGroupCount: a, runCounts: r }) {
  artifactGroupCount = a;
  runCounts = r;
}

export function renderCaseHero(run) {
  const payload = run.summary || {};
  const counts = runCounts(payload);
  const warningCount = counts.validationIssues;
  const artifactSignals = FORENSIC_ARTIFACT_TAXONOMY.reduce((sum, item) => sum + artifactGroupCount(payload, item.terms), 0);
  const recoveredCount = (payload.source?.recovered_root_manifest?.files || []).length;
  const keywordHits = (payload.highlights?.document_hits || []).length;
  const source = run.request.root || payload.output_dir || "Evidence source";
  const foundBits = [
    recoveredCount ? `복구 파일 ${formatNumber(recoveredCount)}개` : "",
    keywordHits ? `키워드 매치 ${formatNumber(keywordHits)}건` : "",
    artifactSignals ? `수집 흔적 ${formatNumber(artifactSignals)}건` : "",
  ].filter(Boolean);
  const headline = foundBits.length
    ? foundBits.join(" · ")
    : (warningCount ? `검증 이슈 ${formatNumber(warningCount)}건 확인 필요` : "검토 가능한 결과가 준비되었습니다");
  return `
    <section class="case-hero review-first-case-strip" aria-label="Case mission control" data-testid="case-hero">
      <div class="case-hero-main">
        <p class="eyebrow">현재 케이스</p>
        <h2>${escapeHtml(headline)}</h2>
        <p class="case-source-line"><span>입력 증거</span><code>${escapeHtml(source)}</code></p>
        ${warningCount ? `<p class="case-hero-warning">검증 이슈 ${formatNumber(warningCount)}건 — 원본 확인 후 판단하세요.</p>` : ""}
      </div>
      <div class="case-hero-metrics">
        ${caseHeroMetric("문서", counts.docs)}
        ${caseHeroMetric("파일", counts.files)}
        ${caseHeroMetric("타임라인", counts.timelineEvents)}
        ${caseHeroMetric("아티팩트", artifactSignals)}
        ${caseHeroMetric("산출물", counts.outputs)}
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

export function renderCoreEvidenceWorkflow(run) {
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

export function coreEvidenceWorkflowStatuses(payload) {
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
  const counts = runCounts(payload);
  const artifactKinds = Object.keys(payload.artifacts || {});
  const docs = counts.docs;
  const files = counts.files;
  const timeline = counts.timelineEvents;
  const extracted = Number(summary.docs_extracted_count || 0) + Number(summary.files_extracted_count || 0);
  const outputCount = counts.outputs;
  const searchable = docs + files + timeline;
  const extractManifestReady = Boolean(outputs.docs_extract_manifest || outputs.files_extract_manifest);
  const reportReady = Boolean(outputs.report || outputs.summary || summary.report_candidate_count);
  const warningCount = counts.validationIssues;
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

export function runWorkflowStatusLabel(status) {
  if (status === "completed") return "완료";
  if (status === "warning") return "경고";
  if (status === "blocked") return "차단";
  return "대기";
}
