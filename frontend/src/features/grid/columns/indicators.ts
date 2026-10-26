import { fetchIndicatorsPage } from "../../../api/collections";
import type { CollectionDef } from "../types";
import { col, fieldStr, isRecord, joinList, makeRef, makeRow, str, strOrNull } from "./common";

function firstSourcePath(sources: unknown): string | null {
  if (!Array.isArray(sources)) return null;
  for (const source of sources) {
    if (!isRecord(source)) continue;
    const path = strOrNull(source.path) ?? strOrNull(source.file) ?? strOrNull(source.source_path);
    if (path) return path;
  }
  return null;
}

export const indicatorsCollection: CollectionDef = {
  id: "indicators",
  label: "IOC",
  source: "paged",
  fetch: (runId, query, signal) => fetchIndicatorsPage(runId, query.offset, query.limit, signal),
  mapRow: (raw, index) =>
    makeRow(
      makeRef("indicators", `/indicators/${index}`),
      {
        title: strOrNull(raw.value) ?? `지표 ${index + 1}`,
        sourcePath: firstSourcePath(raw.sources),
        artifactType: strOrNull(raw.type),
      },
      {
        count: typeof raw.count === "number" ? raw.count : null,
        classification: str(raw.classification),
        riskFlags: joinList(raw.risk_flags),
        sourceCount: Array.isArray(raw.sources) ? raw.sources.length : 0,
      },
    ),
  columns: [
    col.field("type", "유형", 80, ["analysis", "compact"], (r) => r.artifactType),
    col.title("값", 380),
    col.review(),
    col.field("classification", "범위", 120, ["analysis", "compact"], (r) => fieldStr(r, "classification")),
    col.field(
      "count",
      "건수",
      70,
      ["analysis", "compact"],
      (r) => (r.fields.count as number | null) ?? null,
      {
        align: "right",
      },
    ),
    col.field("riskFlags", "위험 표지", 180, ["analysis"], (r) => fieldStr(r, "riskFlags")),
    col.path(360, ["source"]),
  ],
};
