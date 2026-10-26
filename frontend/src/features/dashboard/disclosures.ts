/**
 * 처리 제한 사항 (parser-quality r1 §2; formerly "공개 사항"): the run summary's `disclosures` block
 * and `warnings[]` as short Korean lines — missing tools, caps/truncation, timezone,
 * acquisition-copy times, timeline exclusions, document text states. Shown on the 접수 dashboard
 * "처리 경고·제한 사항" card and in the 처리 plan header. Raw step / kind / flag ids never reach the
 * visible text: they are mapped to Korean (stepLabelKo, kindLabel) and kept in `detail` (tooltip).
 * Pure data shaping; no React.
 */

import type {
  DocsSizeCaps,
  IndicatorCapPolicy,
  RowTruncation,
  RunDisclosures,
  RunSummary,
  RunWarning,
} from "../../api/runs";
import { kindLabel } from "../derived/tables";
import { stepNameLabel } from "../stages/stepLabels";

export type DisclosureTone = "warn" | "info";

export interface DisclosureItem {
  id: string;
  label: string;
  text: string;
  tone: DisclosureTone;
  /** Raw ids behind the line (step names, flag keys) for a tooltip; never the visible text. */
  detail?: string;
}

/**
 * Korean name of a run step: `artifacts-<kind>` reads "아티팩트 수집: <수집기 이름>" (kindLabel),
 * every other id goes through the shared stepNameLabel.
 */
export function stepLabelKo(name: string): string {
  if (name.startsWith("artifacts-")) return `아티팩트 수집: ${kindLabel(name.slice("artifacts-".length))}`;
  return stepNameLabel(name);
}

/** Windows time zone names (registry `TimeZoneKeyName`) → Korean; unknown names stay as sent. */
const TIMEZONE_KO: Record<string, string> = {
  "Korea Standard Time": "한국 표준시",
  "Tokyo Standard Time": "일본 표준시",
  "China Standard Time": "중국 표준시",
  "Taipei Standard Time": "타이베이 표준시",
  "Singapore Standard Time": "싱가포르 표준시",
  UTC: "협정 세계시",
  "Coordinated Universal Time": "협정 세계시",
  "GMT Standard Time": "영국 표준시",
  "W. Europe Standard Time": "서유럽 표준시",
  "Central Europe Standard Time": "중부 유럽 표준시",
  "Eastern Standard Time": "미국 동부 표준시",
  "Central Standard Time": "미국 중부 표준시",
  "Mountain Standard Time": "미국 산지 표준시",
  "Pacific Standard Time": "미국 태평양 표준시",
};

/** "UTC+09:00" from an ISO offset ("+09:00") or a Windows bias (minutes, UTC − local: -540 → +09:00). */
export function utcOffsetText(offset: string | undefined, biasMinutes: number | undefined): string {
  if (offset) {
    const trimmed = offset.trim().replace(/^UTC\s*/i, "");
    return `UTC${trimmed.startsWith("+") || trimmed.startsWith("-") ? trimmed : `+${trimmed}`}`;
  }
  if (typeof biasMinutes !== "number" || !Number.isFinite(biasMinutes)) return "";
  const total = -biasMinutes;
  const sign = total < 0 ? "-" : "+";
  const abs = Math.abs(total);
  return `UTC${sign}${String(Math.floor(abs / 60)).padStart(2, "0")}:${String(abs % 60).padStart(2, "0")}`;
}

/** File-candidate exclusion reasons (core files step) → Korean; unknown reasons stay as sent. */
const FILE_EXCLUSION_LABEL: Record<string, string> = {
  "category-not-selected": "선택 안 된 범주",
};

const TEXT_STATUS: Record<string, string> = {
  ok: "본문 있음",
  "no-text": "본문 없음",
  encrypted: "암호화",
  "binary-rejected": "이진 본문 제외",
  unsupported: "지원 안 함",
  "too-large": "크기 초과",
  error: "추출 오류",
};

const n = (value: number) => value.toLocaleString("ko-KR");

function num(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

/** Processing profile labels (core/run/summary.py infer_processing_profile_label) → Korean. */
const PROFILE_LABELS: Record<string, { text: string; tone: DisclosureTone }> = {
  "Dry run - no extraction": { text: "시험 실행 — 추출 없음", tone: "info" },
  "Fast first pass - read-only": { text: "빠른 1차 처리 — 읽기 전용", tone: "info" },
  "Standard - bounded extraction": { text: "표준 — 추출 크기·개수 상한 적용", tone: "warn" },
  "Deep - extraction without size limits": { text: "정밀 — 크기 상한 없이 추출", tone: "info" },
  // parser-quality r2: a run whose parser / stage / row caps were hit is never "without limits".
  "Deep - parser/stage caps applied (disclosed)": {
    text: "정밀 — 파서·단계 상한 적용(처리 제한 사항 참조)",
    tone: "warn",
  },
  // r1 wording of the same case.
  "Deep - extraction without size limits (parser caps disclosed)": {
    text: "정밀 — 파서·단계 상한 적용(처리 제한 사항 참조)",
    tone: "warn",
  },
};

/** Korean line of `processing.profile_label` (unknown labels are shown as sent). */
export function profileLine(label: string): { text: string; tone: DisclosureTone } {
  return PROFILE_LABELS[label] ?? { text: label, tone: "info" };
}

/** 지표 상한 line from the indicators `cap_policy` ("상한 없음" / "상한 N개"). */
export function capPolicyLine(policy: IndicatorCapPolicy): { text: string; tone: DisclosureTone } | null {
  if (policy.mode === "uncapped" || (policy.mode !== "capped" && !policy.max_indicators)) {
    const kept = typeof policy.kept === "number" ? ` — 지표 후보 ${n(policy.kept)}건 모두 기록` : "";
    return { text: `상한 없음${kept}`, tone: "info" };
  }
  const max = num(policy.max_indicators);
  if (!max) return null;
  const kept = num(policy.kept);
  const total = num(policy.total_before_cap);
  if (total > kept) {
    return { text: `상한 ${n(max)}개 — 전체 ${n(total)}건 중 ${n(kept)}건만 기록`, tone: "warn" };
  }
  return { text: `상한 ${n(max)}개 (도달하지 않음)`, tone: "info" };
}

const mb = (bytes: unknown) => `${Math.round(num(bytes) / 1_000_000).toLocaleString("ko-KR")} MB`;

/** 문서 크기 상한 line from the docs `size_caps` (byte caps of text extraction). */
export function sizeCapsLine(caps: DocsSizeCaps): { text: string; tone: DisclosureTone } {
  const limits = [
    num(caps.max_input_bytes) ? `파일 ${mb(caps.max_input_bytes)}` : "",
    num(caps.max_archive_member_bytes) ? `압축 멤버 ${mb(caps.max_archive_member_bytes)}` : "",
    num(caps.max_archive_total_bytes) ? `압축 합계 ${mb(caps.max_archive_total_bytes)}` : "",
  ].filter(Boolean);
  const tooLarge = num(caps.too_large_count);
  const binary = num(caps.binary_rejected_count);
  const effects = [
    tooLarge ? `초과 ${n(tooLarge)}건 본문 미추출` : "초과 문서 없음",
    binary ? `비인쇄 문자 비율 초과 ${n(binary)}건 미색인` : "",
  ].filter(Boolean);
  return {
    text: `${limits.length ? `${limits.join(" · ")} — ` : ""}${effects.join(" · ")}`,
    tone: tooLarge || binary ? "warn" : "info",
  };
}

/**
 * Row-level truncation per artifact kind: `disclosures.input_row_truncation` when the server sends
 * it, else the steps' `row_truncation` (`artifacts-<kind>` steps, core/run/steps.py).
 */
export function rowTruncationOf(summary: RunSummary | undefined): Record<string, RowTruncation> {
  const direct = summary?.disclosures?.input_row_truncation;
  if (direct && typeof direct === "object" && direct.by_step && typeof direct.by_step === "object") {
    const byKind: Record<string, RowTruncation> = {};
    for (const [name, value] of Object.entries(direct.by_step)) {
      if (!name || !value || typeof value !== "object" || Array.isArray(value)) continue;
      byKind[name.replace(/^artifacts-/, "")] = value;
    }
    return byKind;
  }
  const out: Record<string, RowTruncation> = {};
  for (const step of summary?.steps ?? []) {
    const value = step?.row_truncation;
    const name = typeof step?.name === "string" ? step.name : "";
    if (!name || !value || typeof value !== "object" || Array.isArray(value)) continue;
    out[name.replace(/^artifacts-/, "")] = value as RowTruncation;
  }
  return out;
}

/** Run-level totals of `input_row_truncation` (headline counts + level), null when absent. */
export function rowTruncationTotalsOf(
  summary: RunSummary | undefined,
): { payload: number; preview: number; level: string } | null {
  const d = summary?.disclosures?.input_row_truncation;
  if (!d || typeof d !== "object" || typeof d.by_step !== "object" || !d.by_step) return null;
  return {
    payload: num(d.payload_truncated_rows),
    preview: num(d.preview_truncated_rows),
    level: String(d.level ?? ""),
  };
}

const sumValues = (record: Record<string, number> | undefined) =>
  Object.values(record ?? {}).reduce((total, value) => total + num(value), 0);

/**
 * 행 절단 lines: payload cuts (`rows_with_truncation` / `count_fields`, the record keeps only part
 * of the original value) are a warning; display-preview cuts (`preview_only_rows`, record value
 * kept) are a notice (info).
 */
export function rowTruncationItems(
  truncation: Record<string, RowTruncation>,
  totals?: { payload: number; preview: number; level: string } | null,
): DisclosureItem[] {
  const payload: string[] = [];
  const preview: string[] = [];
  for (const [kind, entry] of Object.entries(truncation)) {
    if (!entry || typeof entry !== "object") continue;
    const rows = num(entry.rows_with_truncation);
    const counted = sumValues(entry.count_fields);
    const name = kindLabel(kind);
    if (rows || counted) payload.push(rows ? `${name} ${n(rows)}행` : `${name} ${n(counted)}건`);
    const previewRows = num(entry.preview_only_rows);
    const previewCounted = sumValues(entry.preview_count_fields);
    if (previewRows || previewCounted) {
      preview.push(previewRows ? `${name} ${n(previewRows)}행` : `${name} ${n(previewCounted)}건`);
    }
  }
  const out: DisclosureItem[] = [];
  const kinds = Object.keys(truncation).join(", ") || undefined;
  const showPayload = totals ? totals.level === "warning" || totals.payload > 0 : payload.length > 0;
  const showPreview = totals ? totals.preview > 0 : preview.length > 0;
  if (showPayload) {
    const head = totals ? `원문 값 일부만 보존된 행 총 ${n(totals.payload)}건` : "원문 값 일부만 보존된 행";
    out.push({
      id: "row-truncation",
      label: "행 절단(원문 일부)",
      text: totals
        ? `${head}${payload.length ? ` — ${payload.join(" · ")}` : ""}`
        : `${head}: ${payload.join(" · ")}`,
      tone: "warn",
      detail: kinds,
    });
  }
  if (showPreview) {
    const head = totals
      ? `표시용 미리보기만 잘림 총 ${n(totals.preview)}건(원본 레코드 값은 보존)`
      : "표시용 미리보기만 잘림(원본 레코드 값은 보존)";
    out.push({
      id: "row-preview-truncation",
      label: "미리보기 절단",
      text: totals
        ? `${head}${preview.length ? ` — ${preview.join(" · ")}` : ""}`
        : `${head}: ${preview.join(" · ")}`,
      tone: "info",
      detail: kinds,
    });
  }
  return out;
}

/** "저장 UTC · 증거 시스템 한국 표준시 (UTC+09:00)". */
function timezoneText(name: string, offset: string | undefined, bias: number | undefined): string {
  const text = utcOffsetText(offset, bias);
  return `저장 UTC · 증거 시스템 ${TIMEZONE_KO[name] ?? name}${text ? ` (${text})` : ""}`;
}

/** Disclosure lines of a run (empty when the summary predates them). */
export function disclosureItems(summary: RunSummary | undefined): DisclosureItem[] {
  const d: RunDisclosures | undefined = summary?.disclosures;
  if (!d || typeof d !== "object") return [];
  const out: DisclosureItem[] = [];

  const missing = Object.entries(d.missing_tools ?? {}).filter(
    ([, info]) => info && info.available === false,
  );
  out.push(
    missing.length
      ? {
          id: "missing-tools",
          label: "누락 도구",
          text: missing.map(([name, info]) => (info.note ? info.note : name)).join("; "),
          tone: "warn",
        }
      : { id: "missing-tools", label: "누락 도구", text: "없음", tone: "info" },
  );

  const caps = Object.entries(d.caps ?? {}).filter(([, flags]) => Array.isArray(flags) && flags.length);
  out.push(
    caps.length
      ? {
          id: "caps",
          label: "상한·절단",
          text: `${caps.length}단계 결과가 전수가 아닙니다: ${caps.map(([step]) => stepLabelKo(step)).join(", ")}`,
          tone: "warn",
          detail: caps
            .map(([step, flags]) => `${step}: ${flags.slice(0, 3).join(", ")}${flags.length > 3 ? " …" : ""}`)
            .join("; "),
        }
      : { id: "caps", label: "상한·절단", text: "적용된 단계 없음", tone: "info" },
  );

  const tz = d.timezone?.evidence_timezone;
  out.push(
    tz && (tz.name || tz.label)
      ? {
          id: "timezone",
          label: "시간대",
          text: timezoneText(String(tz.name || tz.label), tz.utc_offset, tz.bias_minutes),
          tone: "info",
          detail: String(tz.name || tz.label),
        }
      : {
          id: "timezone",
          label: "시간대",
          text: "저장 UTC · 증거 시스템 시간대가 레지스트리에서 확인되지 않았습니다",
          tone: "warn",
        },
  );

  if (d.acquisition_copy_note) {
    out.push({
      id: "copy-time",
      label: "취득 사본 시각",
      // The server names the record fields (`source_file_*`); the examiner reads the field family.
      text: d.acquisition_copy_note.replace(/source_file_\*\s*/g, "'취득 사본 시각' 필드"),
      tone: "warn",
    });
  }

  const excluded = d.timeline_excluded;
  const excludedTotal =
    num(excluded?.out_of_range) + num(excluded?.duplicates) + num(excluded?.copy_time_candidates);
  if (excluded && excludedTotal > 0) {
    out.push({
      id: "timeline-excluded",
      label: "타임라인 제외",
      text: `범위 밖 시각 ${n(num(excluded.out_of_range))}건 · 중복 ${n(num(excluded.duplicates))}건 · 사본 시각만 있는 파일 ${n(num(excluded.copy_time_candidates))}건`,
      tone: "info",
    });
  }

  const profile = summary?.processing?.profile_label;
  if (typeof profile === "string" && profile) {
    out.push({ id: "profile", label: "처리 프로필", ...profileLine(profile) });
  }

  const indicators = d.indicators;
  const capPolicy = indicators?.cap_policy ? capPolicyLine(indicators.cap_policy) : null;
  if (capPolicy) out.push({ id: "indicator-cap", label: "지표 상한", ...capPolicy });
  if (indicators && (indicators.rule_status_message || indicators.truncated)) {
    out.push({
      id: "indicators",
      label: indicators.display_label || "지표",
      text: [
        indicators.rule_status_message ?? "",
        indicators.truncated ? `상한으로 절단(상한 전 ${n(num(indicators.total_before_cap))}건)` : "",
      ]
        .filter(Boolean)
        .join(" · "),
      tone: indicators.truncated || !indicators.rule_count ? "warn" : "info",
    });
  }

  const statuses = Object.entries(d.documents?.text_status_counts ?? {}).filter(
    ([, count]) => num(count) > 0,
  );
  if (statuses.length) {
    out.push({
      id: "documents",
      label: "문서 본문",
      text: statuses
        .map(([status, count]) => `${TEXT_STATUS[status] ?? status} ${n(num(count))}`)
        .join(" · "),
      tone: "info",
    });
  }

  if (d.documents?.size_caps && typeof d.documents.size_caps === "object") {
    out.push({ id: "docs-size-caps", label: "문서 크기 상한", ...sizeCapsLine(d.documents.size_caps) });
  }

  out.push(...rowTruncationItems(rowTruncationOf(summary), rowTruncationTotalsOf(summary)));

  if (num(d.files?.excluded_file_count) > 0) {
    out.push({
      id: "files-excluded",
      label: "파일 후보 제외",
      text: `${n(num(d.files?.excluded_file_count))}건 (${Object.entries(
        d.files?.exclusion_reason_counts ?? {},
      )
        .map(([reason, count]) => `${FILE_EXCLUSION_LABEL[reason] ?? reason} ${n(num(count))}`)
        .join(", ")})`,
      tone: "info",
      detail: Object.keys(d.files?.exclusion_reason_counts ?? {}).join(", ") || undefined,
    });
  }

  for (const [kind, notes] of Object.entries(d.collection_notes ?? {})) {
    if (!Array.isArray(notes) || !notes.length) continue;
    out.push({
      id: `notes:${kind}`,
      label: `${kindLabel(kind)} 수집 메모`,
      text: notes.join("; "),
      tone: "info",
      detail: kind,
    });
  }
  return out;
}

/** Step warnings of the run summary (`warnings[]`), each "단계: 메시지". */
export function runWarnings(summary: RunSummary | undefined): RunWarning[] {
  const list = summary?.warnings;
  return Array.isArray(list) ? list.filter((w) => w && typeof w === "object" && w.message) : [];
}

/** A `level: "notice"` step message (preview-only truncation): disclosed, not a warning. */
export function isNotice(warning: RunWarning): boolean {
  return warning.level === "notice";
}

/** One-line digest for the 처리 plan header ("처리 제한 사항 — 확인 필요: 누락 도구, … · 경고 4건"). */
export function disclosureDigest(summary: RunSummary | undefined): string {
  const items = disclosureItems(summary);
  const warnings = runWarnings(summary);
  if (!items.length && !warnings.length) return "";
  const warn = items.filter((item) => item.tone === "warn").map((item) => item.label);
  const parts = [
    warn.length ? `확인 필요: ${warn.join(", ")}` : "제한 사항 없음",
    warnings.some((w) => !isNotice(w)) ? `경고 ${n(warnings.filter((w) => !isNotice(w)).length)}건` : "",
    warnings.some(isNotice) ? `알림 ${n(warnings.filter(isNotice).length)}건` : "",
  ].filter(Boolean);
  return `처리 제한 사항 — ${parts.join(" · ")}`;
}
