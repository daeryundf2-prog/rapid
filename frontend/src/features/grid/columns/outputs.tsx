import { fetchOutputRows } from "../../../api/collections";
import { ToneChip } from "../../../components/ToneChip";
import type { CollectionDef } from "../types";
import { col, formatBytes, makeRef, makeRow, strOrNull } from "./common";

const LIST_OUTPUTS = new Set(["manifest", "docs", "docs_index", "files", "timeline", "indicators"]);
const REPORT_OUTPUTS = new Set(["report", "summary", "timeline_report"]);

/**
 * Kind of a run output (the 보고 toolbar's 종류, visual-polish S2), from its summary `outputs`
 * key: artifacts_<kind> → 아티팩트, report/summary → 보고서, item lists and indexes → 목록·색인,
 * extraction manifests → 추출, the case DB → 케이스 DB, everything else → 처리 기록.
 */
export function outputKindLabel(name: string): string {
  if (name.startsWith("artifacts_")) return "아티팩트";
  if (REPORT_OUTPUTS.has(name)) return "보고서";
  if (LIST_OUTPUTS.has(name)) return "목록·색인";
  if (name.endsWith("_extract_manifest")) return "추출";
  if (name === "case_db") return "케이스 DB";
  return "처리 기록";
}

/** Korean names of the fixed run outputs (the raw summary key stays the tooltip). */
const OUTPUT_NAMES: Record<string, string> = {
  manifest: "매니페스트",
  docs: "문서 목록",
  docs_index: "문서 색인",
  files: "파일 목록",
  timeline: "타임라인",
  indicators: "IOC 목록",
  report: "보고서",
  summary: "요약",
  timeline_report: "타임라인 보고서",
  case_db: "케이스 DB",
};

/**
 * 보고 table 이름 (review #9): "artifacts_android-apk" → "아티팩트: android-apk",
 * "carve_extract_manifest" → "추출 매니페스트: carve", known keys by name, else the raw key.
 */
export function outputDisplayName(name: string): string {
  if (name.startsWith("artifacts_") && name.length > "artifacts_".length)
    return `아티팩트: ${name.slice("artifacts_".length)}`;
  if (name.endsWith("_extract_manifest") && name.length > "_extract_manifest".length)
    return `추출 매니페스트: ${name.slice(0, -"_extract_manifest".length)}`;
  return OUTPUT_NAMES[name] ?? name;
}

export const outputsCollection: CollectionDef = {
  id: "outputs",
  label: "산출물",
  source: "whole",
  fetch: (runId, _query, signal) => fetchOutputRows(runId, signal),
  mapRow: (raw, index) => {
    const name = strOrNull(raw.name);
    return makeRow(
      makeRef("outputs", `output:${name ?? index}`),
      {
        title: name ?? `산출물 ${index + 1}`,
        sourcePath: strOrNull(raw.path),
        // The 종류 filter reuses the type filter (URL `types=`, applied to the loaded rows).
        artifactType: name ? outputKindLabel(name) : null,
      },
      {
        size: typeof raw.size === "number" ? raw.size : null,
        exists: raw.exists !== false,
        downloadUrl: strOrNull(raw.download_url),
      },
    );
  },
  columns: [
    {
      ...col.title("이름", 260),
      format: (r) => outputDisplayName(r.title),
      tooltip: (r) => r.title,
    },
    col.field("kind", "종류", 100, ["analysis", "compact"], (r) => r.artifactType),
    // 상태 as the shared dot + text chip (review #24).
    col.field("exists", "상태", 90, ["analysis", "compact"], (r) => (r.fields.exists ? "있음" : "없음"), {
      render: (r) =>
        r.fields.exists ? <ToneChip tone="ok">있음</ToneChip> : <ToneChip tone="danger">없음</ToneChip>,
    }),
    col.field("size", "크기", 100, ["analysis", "compact"], (r) => (r.fields.size as number | null) ?? null, {
      align: "right",
      format: (r) => formatBytes(r.fields.size),
    }),
    col.path(520, ["analysis", "source"]),
  ],
};
