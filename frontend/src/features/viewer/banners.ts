/**
 * Record warnings (viewer redesign §3): what an examiner must read BEFORE the fields — a row
 * that is not evidence (string candidate, invalid content, synthetic-media score), a record in
 * slack / below the first record / with undecoded template names, lists cut by a cap, times that
 * are acquisition-copy times, the parser's own caution labels, and two confidence values that
 * disagree. Pure: computed from the row, rendered at the top of the 메타 view.
 */

import type { GridRow } from "../../contracts/collection";
import { flatValue } from "../../utils/flatValue";
import { layoutFields } from "./fieldSheets";
import { metaValueLabel } from "./views/metaLabels";

export type BannerTone = "danger" | "warning" | "info";

export interface RecordBanner {
  id: string;
  tone: BannerTone;
  title: string;
  /** One sentence of detail; may be empty. */
  detail: string;
  /** Record keys the banner reads (tooltip / tests). */
  keys: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown): string {
  return flatValue(value).trim();
}

/** Truncation flags: boolean `*_truncated` / `truncated` / `limit_reached` / `scan_capped`. */
const TRUNCATION_KEY = /(^|_)truncated$|^limit_reached$|^scan_capped$|_capped$/;

/** Human name of a truncated list ("events_truncated" → "events"). */
const TRUNCATION_NAMES: Record<string, string> = {
  payload_truncated: "원본 페이로드",
  events_truncated: "세션 이벤트 목록",
  destinations_truncated: "점프 목록 대상",
  ole_streams_truncated: "OLE 스트림 목록",
  text_truncated: "텍스트",
  preview_truncated: "미리보기",
  scan_capped: "스캔 대상",
  limit_reached: "목록",
  truncated: "목록",
};

/** EVTX record state (`evtx_record_state`: live · slack-recovered · inactive-chunk · outside-chunk) and
 * record-number position (`evtx_record_id_position`: stale-below-first …). */
const RECORD_STATE_KEYS = [
  "evtx_record_state",
  "evtx_record_id_position",
  "record_state",
  "evtx_recovery_status",
];

const STATE_READINGS: Record<string, { title: string; detail: string; tone: BannerTone }> = {
  "slack-recovered": {
    tone: "warning",
    title: "슬랙 영역에서 복구한 레코드",
    detail: "할당된 레코드가 아닙니다 — 같은 레코드 ID의 할당 레코드와 비교하세요.",
  },
  "inactive-chunk": {
    tone: "warning",
    title: "비활성 청크의 레코드",
    detail: "파일 헤더가 가리키는 범위 밖의 청크에서 읽었습니다 — 잔존 데이터일 수 있습니다.",
  },
  "outside-chunk": {
    tone: "warning",
    title: "청크 밖에서 찾은 레코드",
    detail: "청크 구조 밖에서 복구했습니다 — 원본 위치를 헥스로 확인하세요.",
  },
  slack: {
    tone: "warning",
    title: "슬랙 영역에서 복구한 레코드",
    detail: "할당된 레코드가 아닙니다 — 같은 레코드 ID의 할당 레코드와 비교하세요.",
  },
  "slack-duplicate": {
    tone: "warning",
    title: "슬랙 영역의 중복 레코드",
    detail: "할당된 레코드와 같은 내용이 슬랙에 남은 사본입니다.",
  },
  "stale-below-first": {
    tone: "warning",
    title: "첫 레코드 번호보다 오래된 잔존 레코드",
    detail: "청크 헤더의 첫 레코드보다 앞선 레코드입니다 — 덮어쓰기 이전 잔존 데이터일 수 있습니다.",
  },
  carved: {
    tone: "warning",
    title: "카빙으로 복구한 레코드",
    detail: "파일 시스템 구조 없이 바이트 패턴으로 찾은 레코드입니다.",
  },
};

export function recordBanners(row: GridRow | null): RecordBanner[] {
  if (!row) return [];
  const fields = layoutFields(row);
  const type = row.artifactType ?? "";
  const out: RecordBanner[] = [];

  // Not evidence at all.
  if (type.endsWith("-string-candidate") || /string-candidate/.test(text(fields.coverage_status))) {
    out.push({
      id: "string-candidate",
      tone: "danger",
      title: "문자열 후보 — 증거 아님",
      detail: "구조 해석 없이 바이트에서 찾은 문자열입니다. 원본 구조로 확인하기 전에는 보고에 쓰지 마세요.",
      keys: ["artifact_type", "coverage_status"],
    });
  }
  if (type.endsWith("-invalid-content")) {
    const label = text(fields.detected_content_label) || text(fields.detected_content_kind);
    out.push({
      id: "invalid-content",
      tone: "danger",
      title: "내용 불일치 — 아티팩트로 해석되지 않음",
      detail: [
        label ? `이 파일의 내용은 ${label}입니다.` : "파일 내용이 이 아티팩트 형식이 아닙니다.",
        text(fields.note),
      ]
        .filter(Boolean)
        .join(" "),
      keys: ["artifact_type", "detected_content_label", "note"],
    });
  }
  if (type.startsWith("synthetic-media") || row.ref.kind === "synthetic-media") {
    out.push({
      id: "synthetic-media",
      tone: "warning",
      title: "진위 판정 아님",
      detail: "합성·조작 미디어 선별 점수입니다. 진위는 전문 도구와 감정으로 확인해야 합니다.",
      keys: ["score_semantics", "score_guidance"],
    });
  }

  // Record state (EVTX slack / stale / template names / decode errors).
  for (const key of RECORD_STATE_KEYS) {
    const state = text(fields[key]).toLowerCase();
    const reading = STATE_READINGS[state];
    if (reading && !out.some((b) => b.id === `state-${state}`)) {
      out.push({ id: `state-${state}`, ...reading, keys: [key] });
    }
  }
  if (fields.duplicate_of_live_record === true) {
    out.push({
      id: "duplicate-of-live",
      tone: "info",
      title: "할당 레코드의 중복 사본",
      detail: "같은 내용의 할당(live) 레코드가 있습니다 — 그 레코드를 인용하세요.",
      keys: ["duplicate_of_live_record"],
    });
  }
  const tsStatus = text(fields.timestamp_status);
  if (tsStatus && tsStatus !== "ok") {
    out.push({
      id: "timestamp-status",
      tone: "warning",
      title: "시각 확인 필요",
      detail: `시각 상태: ${tsStatus}${text(fields.timestamp_raw_iso) ? ` (원문 ${text(fields.timestamp_raw_iso)})` : ""}`,
      keys: ["timestamp_status", "timestamp_raw_iso"],
    });
  }
  if (text(fields.event_data_key_status) === "template-undecoded") {
    out.push({
      id: "template-undecoded",
      tone: "warning",
      title: "EventData 이름 미해석(template-undecoded)",
      detail:
        "템플릿의 이름을 읽지 못해 data_N 이름으로 표시합니다 — 값의 의미는 원본 템플릿으로 확인하세요.",
      keys: ["event_data_key_status"],
    });
  }
  const decodeError = fields.evtx_decode_error ?? fields.decode_error ?? fields.binxml_error;
  if (text(decodeError)) {
    out.push({
      id: "decode-error",
      tone: "warning",
      title: "레코드 해석 오류",
      detail: text(decodeError),
      keys: ["evtx_decode_error"],
    });
  }

  // Truncated lists / payloads.
  const truncated = Object.entries(fields)
    .filter(([key, value]) => TRUNCATION_KEY.test(key) && (value === true || value === "true"))
    .map(([key]) => key);
  if (truncated.length) {
    const names = truncated.map((key) => TRUNCATION_NAMES[key] ?? key.replace(/_truncated$/, ""));
    // `cap_list_field` writes `<list>_truncated` + `<list>_total` next to the capped `<list>`.
    const pairs: Array<[string, string]> = truncated.map((key) => {
      const list = key.replace(/_truncated$/, "");
      return [`${list}_total`, list];
    });
    pairs.push(["event_count", "events"]);
    const totals = pairs
      .map(([total, list]) => {
        const n = fields[total];
        const items = fields[list];
        return typeof n === "number" && Array.isArray(items) && items.length < n
          ? `${n.toLocaleString("ko-KR")}개 중 ${items.length.toLocaleString("ko-KR")}개`
          : "";
      })
      .filter(Boolean);
    out.push({
      id: "truncated",
      tone: "warning",
      title: "목록·값 일부만 포함(상한)",
      detail: `${names.join(", ")}이(가) 상한에서 잘렸습니다${totals.length ? ` — ${totals.join(", ")}` : ""}. 전체는 원본에서 확인하세요.`,
      keys: truncated,
    });
  }
  if (isRecord(fields.cap_disclosure) || text(fields.scan_cap_note)) {
    out.push({
      id: "cap",
      tone: "info",
      title: "수집 상한 안내",
      detail: text(fields.scan_cap_note) || "요약 목록에 상한이 적용되었습니다(cap_disclosure).",
      keys: ["cap_disclosure", "scan_cap_note"],
    });
  }

  // Acquisition-copy times.
  const origin = text(fields.modified_at_origin) || text(fields.time_origin);
  if (origin === "host-copy" || origin === "acquisition-copy" || fields.source_file_mtime !== undefined) {
    out.push({
      id: "acquisition-copy",
      tone: "info",
      title: "파일 시각은 취득 사본 시각",
      detail:
        "source_file_mtime·수정 시각은 증거를 복사한 시점일 수 있습니다(원본 파일 시스템 시각 아님). 레코드 안의 시각을 기준으로 보세요.",
      keys: ["source_file_mtime", "modified_at_origin", "time_origin"],
    });
  }

  // The parser's own caution labels.
  const cautions = Array.isArray(fields.caution_labels)
    ? fields.caution_labels.map(text).filter(Boolean)
    : [];
  if (cautions.length) {
    out.push({
      id: "caution",
      tone: "warning",
      title: "파서 주의 표시",
      detail: cautions.map((label) => metaValueLabel(label) ?? label).join(", "),
      keys: ["caution_labels"],
    });
  }

  // Two confidence values that disagree (row confidence vs parser_confidence): show one note.
  const contradiction = confidenceContradiction(row, fields);
  if (contradiction) out.push(contradiction);
  return out;
}

const CONFIDENCE_WORDS: Record<string, number> = { low: 0.3, medium: 0.6, high: 0.9 };

function confidenceLevel(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value > 1 ? value / 100 : value;
  const t = text(value).toLowerCase();
  if (!t) return null;
  if (t in CONFIDENCE_WORDS) return CONFIDENCE_WORDS[t] as number;
  const n = Number(t);
  return Number.isFinite(n) ? (n > 1 ? n / 100 : n) : null;
}

function bucket(level: number): string {
  return level < 0.45 ? "low" : level < 0.75 ? "medium" : "high";
}

const CONFIDENCE_KO: Record<string, string> = { low: "낮음", medium: "중간", high: "높음" };

function confidenceText(value: unknown): string {
  const raw = text(value);
  return CONFIDENCE_KO[raw.trim().toLowerCase()] ?? raw;
}

function confidenceContradiction(row: GridRow, fields: Record<string, unknown>): RecordBanner | null {
  const record = isRecord(row.fields.artifact_record) ? row.fields.artifact_record : {};
  const rowConfidence = record.confidence ?? row.fields.confidence;
  const parserConfidence = fields.parser_confidence;
  const a = confidenceLevel(rowConfidence);
  const b = confidenceLevel(parserConfidence);
  if (a === null || b === null || bucket(a) === bucket(b)) return null;
  return {
    id: "confidence",
    tone: "info",
    title: "신뢰도 값이 서로 다릅니다",
    // Confidence words read Korean (R7 L3: never "medium"); numbers as written.
    detail: `레코드 신뢰도 ${confidenceText(rowConfidence)} · 파서 신뢰도 ${confidenceText(parserConfidence)} — 출처의 파서 신뢰도를 기준으로 보세요.`,
    keys: ["confidence", "parser_confidence"],
  };
}
