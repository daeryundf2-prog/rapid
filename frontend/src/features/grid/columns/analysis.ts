/**
 * Analysis job result rows (plan analysis-workbench-p1 §3.2 / §4): one column set per API
 * kind, every details column server-sorted on `details.<key>` (the rows endpoint applies the
 * artifact sort index to rows.jsonl). Rows address `/rows/<record_index>` with the job id
 * as the RowRef kind, so review marks resolve as `{collection:"analysis", kind:<id>, locator}`.
 */

import { fetchAnalysisRowsPage, locateAnalysisRow } from "../../../api/analyses";
import { parseFlags } from "../../flags/flags";
import { serverPathFilter } from "../gridUtils";
import type { CollectionDef, ColumnSpec } from "../types";
import { type KindColumnDef, kindColumn } from "./artifacts";
import { crossCaseCasesCell } from "./CrossCaseCell";
import { baseName, col, isRecord, makeRef, makeRow, sha256Of, str, strOrNull } from "./common";

const VSC_STATUS: Record<string, string> = { deleted: "삭제됨", modified: "수정됨", added: "추가됨" };
const OCR_STATUS: Record<string, string> = { ok: "성공", empty: "텍스트 없음", failed: "실패" };
const RECOVERY_METHOD: Record<string, string> = {
  carved: "카빙",
  parsed: "파싱됨",
  rejected: "거부됨(오탐)",
};

const label = (map: Record<string, string>) => (value: unknown) => {
  const text = str(value);
  return map[text] ?? text;
};

export function hexOffset(value: unknown): string {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return str(value);
  return `0x${Math.floor(value).toString(16).toUpperCase()}`;
}

/** §3.2 result row details → columns (header / keys). */
export const ANALYSIS_COLUMNS: Record<string, KindColumnDef[]> = {
  carve: [
    { header: "서명 종류", keys: ["signature_kind"], width: 110 },
    { header: "소스 경로", keys: ["source_path"], width: 320 },
    {
      header: "오프셋",
      keys: ["offset"],
      width: 120,
      number: true,
      mono: true,
      display: (v) => hexOffset(v),
      tooltip: (d) => `${str(d.offset)} 바이트`,
    },
    { header: "길이", keys: ["length"], width: 100, bytes: true },
    { header: "신뢰도", keys: ["confidence"], width: 80, number: true },
    { header: "SHA-256", keys: ["sha256"], width: 200, mono: true },
    // R3 §3.3: the family a carved file belongs to and how it was recovered.
    { header: "계열", keys: ["family_label"], width: 90 },
    { header: "복구 방법", keys: ["recovery_method"], width: 90, display: label(RECOVERY_METHOD) },
    { header: "추출 경로", keys: ["extracted_path"], width: 260 },
    { header: "비고", keys: ["notes"], width: 200 },
  ],
  "vsc-discover": [
    { header: "스냅샷 루트", keys: ["snapshot_root"], width: 360 },
    { header: "점수", keys: ["score"], width: 80, number: true },
    { header: "근거", keys: ["reason"], width: 260 },
    { header: "파일 수(상한)", keys: ["file_count_bounded"], width: 110, number: true },
  ],
  "vsc-compare": [
    { header: "상태", keys: ["status"], width: 90, display: label(VSC_STATUS) },
    { header: "경로", keys: ["path"], width: 360 },
    { header: "크기", keys: ["size"], width: 100, bytes: true },
    { header: "SHA-256", keys: ["sha256"], width: 200, mono: true },
    { header: "스냅샷 루트", keys: ["snapshot_root"], width: 260 },
  ],
  "vsc-extract": [
    { header: "경로", keys: ["path"], width: 320 },
    { header: "저장 위치", keys: ["destination"], width: 320 },
    { header: "크기", keys: ["size"], width: 100, bytes: true },
    { header: "SHA-256", keys: ["sha256"], width: 200, mono: true },
    { header: "상태", keys: ["status"], width: 90, display: label(VSC_STATUS) },
  ],
  "ntfs-meta": [
    { header: "MFT 엔트리", keys: ["entry_number"], width: 100, number: true, mono: true },
    {
      header: "사용 중",
      keys: ["in_use"],
      width: 80,
      display: (v) => (v === true ? "예" : v === false ? "아니오" : str(v)),
    },
    { header: "이름", keys: ["name"], width: 200 },
    { header: "상위 경로", keys: ["parent_path"], width: 260 },
    { header: "경로", keys: ["path"], width: 320 },
    { header: "크기", keys: ["size"], width: 100, bytes: true },
    { header: "생성", keys: ["created_at"], width: 170, time: true },
    { header: "수정", keys: ["modified_at"], width: 170, time: true },
    { header: "MFT 수정", keys: ["mft_modified_at"], width: 170, time: true },
    { header: "접근", keys: ["accessed_at"], width: 170, time: true },
    {
      header: "레코드 오프셋",
      keys: ["record_offset"],
      width: 120,
      number: true,
      mono: true,
      display: (v) => hexOffset(v),
    },
    { header: "플래그", keys: ["flags"], width: 120 },
    { header: "USN", keys: ["usn"], width: 110, number: true, mono: true, presets: ["source"] },
    { header: "USN 사유", keys: ["reason"], width: 200, presets: ["source"] },
    { header: "USN 파일 이름", keys: ["file_name"], width: 200, presets: ["source"] },
    { header: "USN 시각", keys: ["timestamp"], width: 170, time: true, presets: ["source"] },
  ],
  "ocr-batch": [
    { header: "이미지", keys: ["source_path"], width: 300 },
    { header: "상태", keys: ["status"], width: 90, display: label(OCR_STATUS) },
    { header: "텍스트", keys: ["text"], width: 360 },
    { header: "글자 수", keys: ["text_length"], width: 80, number: true },
    { header: "신뢰도", keys: ["confidence"], width: 80, number: true },
    { header: "언어", keys: ["language"], width: 80 },
    { header: "소요(ms)", keys: ["elapsed_ms"], width: 90, number: true },
    { header: "오류", keys: ["error"], width: 220 },
  ],
  "cross-case": [
    { header: "지표", keys: ["indicator"], width: 280, mono: true },
    { header: "지표 종류", keys: ["kind"], width: 110 },
    {
      header: "케이스",
      keys: ["cases"],
      width: 240,
      list: true,
      display: (v) => (Array.isArray(v) ? v.map(str).join(", ") : str(v)),
    },
    { header: "처음 본 시각", keys: ["first_seen"], width: 170, time: true },
    { header: "마지막 본 시각", keys: ["last_seen"], width: 170, time: true },
  ],
};

const TIME_KEYS = ["timestamp", "modified_at", "created_at", "last_seen", "first_seen", "finished_at"];
const TITLE_KEYS = [
  "name",
  "file_name",
  "indicator",
  "snapshot_root",
  "path",
  "source_path",
  "plugin",
  "title",
];

function details(raw: Record<string, unknown>): Record<string, unknown> {
  return isRecord(raw.details) ? raw.details : {};
}

function firstText(record: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" || typeof value === "number") {
      const text = strOrNull(value);
      if (text) return text;
    }
  }
  return null;
}

function titleOf(kind: string, d: Record<string, unknown>, path: string | null, index: number): string {
  if (kind === "carve") {
    const sig = strOrNull(d.signature_kind) ?? "서명";
    return `${sig} @ ${hexOffset(d.offset)} · ${baseName(strOrNull(d.source_path) ?? path ?? "")}`;
  }
  if (kind === "ocr-batch") return baseName(strOrNull(d.source_path) ?? path ?? "") || `이미지 ${index + 1}`;
  if (kind === "vsc-compare" || kind === "vsc-extract") {
    // The changed file (relative path), never the snapshot folder every row shares.
    const file = strOrNull(d.path) ?? strOrNull(d.source_path) ?? path;
    if (file) return baseName(file) || file;
  }
  if (kind === "ntfs-meta") {
    const named = firstText(d, ["name", "file_name"]) ?? strOrNull(d.path);
    if (named) return baseName(named) || named;
    const entry = typeof d.entry_number === "number" ? d.entry_number : null;
    if (entry !== null) {
      const state = d.in_use === false ? "삭제됨" : d.directory === true ? "폴더" : "";
      return `MFT 엔트리 ${entry} (이름 없음${state ? `, ${state}` : ""})`;
    }
  }
  const text = firstText(d, TITLE_KEYS) ?? path;
  if (!text) return `결과 ${index + 1}`;
  return kind === "cross-case" || kind === "vsc-discover" ? text : baseName(text) || text;
}

const typeColumn = col.field("type", "유형", 140, ["source"], (r) => r.artifactType);

/** Column set of one analysis kind; kinds without a table (memory-import) keep generic columns. */
export function analysisColumnsForKind(kind: string | undefined): ColumnSpec[] {
  const defs = kind ? ANALYSIS_COLUMNS[kind] : undefined;
  const head = [col.title("항목", 280), col.review()];
  if (!defs) {
    return [
      ...head,
      typeColumn,
      { ...col.timestamp(170), sortKey: "timestamp", filterKind: "time" },
      col.path(420, ["analysis", "source"]),
      col.sha256(),
    ];
  }
  const hasSha = defs.some((d) => d.keys[0] === "sha256");
  return [
    ...head,
    ...defs.map((def) =>
      kind === "cross-case" && def.keys[0] === "cases"
        ? { ...kindColumn(def), render: crossCaseCasesCell }
        : kindColumn(def),
    ),
    typeColumn,
    col.path(360, ["source"]),
    ...(hasSha ? [] : [col.sha256()]),
  ];
}

export const analysisCollection: CollectionDef = {
  id: "analysis",
  label: "분석 결과",
  source: "paged",
  fetch: async (runId, query, signal) => {
    const id = query.ref.analysisId;
    if (!id)
      return { rows: [], total: 0, offset: query.offset, backend: "file", truncated: false, elapsedMs: 0 };
    return fetchAnalysisRowsPage(
      runId,
      id,
      {
        offset: query.offset,
        limit: query.limit,
        sort: query.sort,
        pathContains: query.pathContains?.trim() || serverPathFilter(query.text),
        ...(query.flags?.length ? { flags: query.flags } : {}),
        ...(query.flagGrade ? { flagGrade: query.flagGrade } : {}),
        ...(query.detailFilters ? { detailFilters: query.detailFilters } : {}),
      },
      signal,
    );
  },
  locate: (runId, ref, sort, recordIndex, signal) =>
    ref.analysisId
      ? locateAnalysisRow(runId, ref.analysisId, sort, recordIndex, signal)
      : Promise.resolve({ status: "ready", position: null }),
  mapRow: (raw, index, ctx) => {
    const d = details(raw);
    const kind = ctx.ref.kind ?? "";
    const analysisId = strOrNull(raw._analysis) ?? ctx.ref.analysisId ?? "";
    const rowIndex = typeof raw._index === "number" ? raw._index : index;
    // Rows with `path` open in the viewer; carve rows open their source file in hex at `offset`.
    const carveSource = kind === "carve" ? strOrNull(d.source_path) : null;
    // ntfs-meta rows: `path` is a path inside the NTFS volume (`\Users\…`), not a file the
    // viewer can open — those rows show their record (meta) only.
    const volumePath = kind === "ntfs-meta" ? strOrNull(raw.path) : null;
    const path = kind === "ntfs-meta" ? null : (strOrNull(raw.path) ?? carveSource);
    const offset = typeof d.offset === "number" && d.offset >= 0 ? d.offset : null;
    const length = typeof d.length === "number" && d.length > 0 ? d.length : undefined;
    const isCarveHit = kind === "carve" && offset !== null && path !== null;
    const carvedRow =
      kind === "carve" && d.status !== "false-positive-rejected" && d.recovery_method !== "rejected";
    return makeRow(
      makeRef("analysis", `/rows/${rowIndex}`, analysisId || undefined),
      {
        title: titleOf(kind, d, path, rowIndex),
        sourcePath: path,
        timestamp: firstText(d, TIME_KEYS),
        artifactType: strOrNull(raw.artifact_type) ?? (kind ? `${kind}-row` : null),
        sha256: sha256Of(d.sha256),
      },
      {
        kind,
        analysisId,
        ...(path && (d.is_directory === true || d.directory === true || /[\\/]$/.test(path))
          ? { isDirectory: true }
          : {}),
        details: volumePath && d.path === undefined ? { ...d, path: volumePath } : d,
        ...(volumePath ? { volumePath } : {}),
        ...(Array.isArray(raw.flags) ? { flags: raw.flags, flagList: parseFlags(raw.flags) } : {}),
        ...(isCarveHit
          ? { highlight: { offset, ...(length ? { length } : {}) }, viewerMode: "hex", sourceOffset: offset }
          : {}),
        // 증거 정보 "복구 방법 카빙 · 오프셋" (rows written before R3 have no recovery_method).
        ...(carvedRow ? { recovery: "carved" } : {}),
      },
    );
  },
  columns: analysisColumnsForKind(undefined),
  columnsFor: (ref) => analysisColumnsForKind(ref.kind),
};
