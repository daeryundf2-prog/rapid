/**
 * 공개 사항 (parser-quality r1 §2): the run summary's `disclosures` block and `warnings[]` as
 * short Korean lines — missing tools, caps/truncation, timezone, acquisition-copy times,
 * timeline exclusions, document text states. Shown on the 접수 dashboard card and in the 처리
 * plan header. Pure data shaping; no React.
 */

import type { RunDisclosures, RunSummary, RunWarning } from "../../api/runs";

export type DisclosureTone = "warn" | "info";

export interface DisclosureItem {
  id: string;
  label: string;
  text: string;
  tone: DisclosureTone;
}

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
          text: `${caps.length}단계 결과가 전수가 아닙니다 (${caps
            .map(([step, flags]) => `${step}: ${flags.slice(0, 3).join(", ")}${flags.length > 3 ? " …" : ""}`)
            .join("; ")})`,
          tone: "warn",
        }
      : { id: "caps", label: "상한·절단", text: "적용된 단계 없음", tone: "info" },
  );

  const tz = d.timezone?.evidence_timezone;
  out.push(
    tz && (tz.name || tz.label)
      ? {
          id: "timezone",
          label: "시간대",
          text: `저장 UTC · 증거 시스템 ${tz.name || tz.label}${
            tz.utc_offset
              ? ` (UTC ${tz.utc_offset})`
              : typeof tz.bias_minutes === "number"
                ? ` (bias ${tz.bias_minutes}분)`
                : ""
          }`,
          tone: "info",
        }
      : {
          id: "timezone",
          label: "시간대",
          text: "저장 UTC · 증거 시스템 시간대가 레지스트리에서 확인되지 않았습니다",
          tone: "warn",
        },
  );

  if (d.acquisition_copy_note) {
    out.push({ id: "copy-time", label: "취득 사본 시각", text: d.acquisition_copy_note, tone: "warn" });
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

  const indicators = d.indicators;
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

  if (num(d.files?.excluded_file_count) > 0) {
    out.push({
      id: "files-excluded",
      label: "파일 후보 제외",
      text: `${n(num(d.files?.excluded_file_count))}건 (${Object.entries(
        d.files?.exclusion_reason_counts ?? {},
      )
        .map(([reason, count]) => `${reason} ${n(num(count))}`)
        .join(", ")})`,
      tone: "info",
    });
  }

  for (const [kind, notes] of Object.entries(d.collection_notes ?? {})) {
    if (!Array.isArray(notes) || !notes.length) continue;
    out.push({ id: `notes:${kind}`, label: `${kind} 수집 메모`, text: notes.join("; "), tone: "info" });
  }
  return out;
}

/** Step warnings of the run summary (`warnings[]`), each "단계: 메시지". */
export function runWarnings(summary: RunSummary | undefined): RunWarning[] {
  const list = summary?.warnings;
  return Array.isArray(list) ? list.filter((w) => w && typeof w === "object" && w.message) : [];
}

/** One-line digest for the 처리 plan header ("공개 사항: 누락 도구 2 · 상한 3단계 · 경고 4건"). */
export function disclosureDigest(summary: RunSummary | undefined): string {
  const items = disclosureItems(summary);
  const warnings = runWarnings(summary);
  if (!items.length && !warnings.length) return "";
  const warn = items.filter((item) => item.tone === "warn").map((item) => item.label);
  const parts = [
    warn.length ? `확인 필요: ${warn.join(", ")}` : "제한 사항 없음",
    warnings.length ? `경고 ${n(warnings.length)}건` : "",
  ].filter(Boolean);
  return `공개 사항 — ${parts.join(" · ")}`;
}
