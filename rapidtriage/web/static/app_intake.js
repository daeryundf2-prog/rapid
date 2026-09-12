// ES module extracted from app.js — RapidForensic analyst console.
import { api } from "./app_api.js";
import {
  escapeHtml,
  formatBytes,
  formatNumber,
  metric,
  storageAvailable,
  titleCase,
} from "./app_utils.js";
import {
  E01_PRE_RUN_STEPS,
  IMAGE_EVIDENCE_FORMATS,
  PROCESSING_PROFILES,
  RUN_FORM_STORAGE_KEY,
  RUN_MODE_COLLECTORS,
  collectPlanButton,
  detailPanel,
  doctorButton,
  evidenceCheckButton,
  evidenceCheckStatus,
  renderEvidenceCheckStatus,
  runButton,
  runForm,
  sampleRunButton,
  switchTab,
} from "./app.js";

export function hydrateRunForm() {
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

export function persistRunForm() {
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

export function bindRunFormPersistence() {
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

export function bindStartChoiceCards() {
  for (const button of document.querySelectorAll("[data-intake-action]")) {
    button.addEventListener("click", () => applyStartChoice(button.dataset.intakeAction || ""));
  }
}

export function applyStartChoice(action) {
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

export function detectEvidenceImageKind(root) {
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

export function applyRootEvidenceHints() {
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

export function applyProcessingProfile() {
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

export function refreshRunPlanPreview() {
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

export function isLikelyE01Path(root) {
  return detectEvidenceImageKind(root).family === "ewf";
}

export function isLikelyImageEvidencePath(root) {
  return detectEvidenceImageKind(root).isImage;
}

export function updateRunSubmissionCta(root, profileKey = "fast") {
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

export function runStartingLabel(root) {
  if (isLikelyE01Path(root)) return "E01 분석 준비 중...";
  if (isLikelyImageEvidencePath(root)) return "이미지 증거 분석 준비 중...";
  return "분석 시작 중...";
}

export function renderRunPlanE01Readiness(root, partitionStartSector, profileKey) {
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

export function optionalInteger(value) {
  const text = String(value ?? "").trim();
  if (!text) return null;
  const number = Number(text);
  if (!Number.isInteger(number) || number < 0) return null;
  return number;
}

export function extractLimitBytes() {
  const mb = Number(document.querySelector("#maxExtractMbInput")?.value || 0);
  if (!Number.isFinite(mb) || mb <= 0) return 0;
  return Math.floor(mb * 1024 * 1024);
}

export function parseKnownGoodHashFeeds() {
  const raw = document.querySelector("#knownGoodHashFeedInput")?.value || "";
  return raw
    .split(/[\n,;]+/)
    .map((value) => value.trim())
    .filter(Boolean);
}

export function knownGoodMaxHashBytes() {
  const raw = document.querySelector("#knownGoodMaxHashMbInput")?.value;
  if (raw === undefined || String(raw).trim() === "") return 64 * 1024 * 1024;
  const mb = Number(raw);
  if (!Number.isFinite(mb) || mb < 0) return 64 * 1024 * 1024;
  return Math.floor(mb * 1024 * 1024);
}

export async function previewCollectPlan() {
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

export function renderCollectPlanPreview(payload) {
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

export function shellQuote(value) {
  const text = String(value || "");
  if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(text)) return text;
  return `'${text.replace(/'/g, "'\\''")}'`;
}

export function bindCrashReportActions() {
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

export async function checkEvidenceSupport() {
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

export function bindEvidenceCheckActions() {
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

export function bindE01PartitionControls(rootElement) {
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

export function applyEvidenceCheckRecommendation(result) {
  const workflow = result.ingest_workflow || {};
  const recommendedInputKind = workflow.recommended_input_kind || "";
  const inputKind = document.querySelector("#inputKindInput");
  if (inputKind && !inputKind.value && recommendedInputKind) {
    inputKind.value = recommendedInputKind;
  }
  persistRunForm();
  refreshRunPlanPreview();
}

export function renderEvidenceFailureGuidance(guidance) {
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

export function renderEvidencePreflightSummary(summary) {
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

export function renderEvidenceToolPreflight(rows) {
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

export function renderDoctorPanel(payload) {
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
