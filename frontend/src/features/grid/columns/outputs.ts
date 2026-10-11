import { fetchOutputRows } from "../../../api/collections";
import type { CollectionDef } from "../types";
import { col, formatBytes, makeRef, makeRow, strOrNull } from "./common";

export const outputsCollection: CollectionDef = {
  id: "outputs",
  label: "산출물",
  source: "whole",
  fetch: (runId, _query, signal) => fetchOutputRows(runId, signal),
  mapRow: (raw, index) =>
    makeRow(
      makeRef("outputs", `output:${strOrNull(raw.name) ?? index}`),
      {
        title: strOrNull(raw.name) ?? `산출물 ${index + 1}`,
        sourcePath: strOrNull(raw.path),
      },
      {
        size: typeof raw.size === "number" ? raw.size : null,
        exists: raw.exists !== false,
        downloadUrl: strOrNull(raw.download_url),
      },
    ),
  columns: [
    col.title("이름", 260),
    col.field("exists", "상태", 90, ["analysis", "compact"], (r) => (r.fields.exists ? "있음" : "없음")),
    col.field("size", "크기", 100, ["analysis", "compact"], (r) => (r.fields.size as number | null) ?? null, {
      align: "right",
      format: (r) => formatBytes(r.fields.size),
    }),
    col.path(520, ["analysis", "source"]),
  ],
};
