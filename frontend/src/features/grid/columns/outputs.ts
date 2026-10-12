import { fetchOutputRows } from "../../../api/collections";
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
    col.title("이름", 260),
    col.field("kind", "종류", 100, ["analysis", "compact"], (r) => r.artifactType),
    col.field("exists", "상태", 90, ["analysis", "compact"], (r) => (r.fields.exists ? "있음" : "없음")),
    col.field("size", "크기", 100, ["analysis", "compact"], (r) => (r.fields.size as number | null) ?? null, {
      align: "right",
      format: (r) => formatBytes(r.fields.size),
    }),
    col.path(520, ["analysis", "source"]),
  ],
};
