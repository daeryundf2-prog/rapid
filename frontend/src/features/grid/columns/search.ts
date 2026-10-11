import { fetchSearchRows } from "../../../api/collections";
import type { CollectionDef } from "../types";
import {
  baseName,
  col,
  fieldStr,
  isRecord,
  joinList,
  makeRef,
  makeRow,
  sha256Of,
  str,
  strOrNull,
} from "./common";

export const searchCollection: CollectionDef = {
  id: "search",
  label: "검색 결과",
  source: "whole",
  fetch: (runId, query, signal) => fetchSearchRows(runId, query, 1000, signal),
  mapRow: (raw, index) => {
    const source = str(raw.source);
    const kind = strOrNull(raw.kind);
    const pointer = str(raw.pointer);
    const path = strOrNull(raw.path);
    const metadata = isRecord(raw.metadata) ? raw.metadata : {};
    const hashes = isRecord(metadata.source_hashes) ? metadata.source_hashes : {};
    // ref.locator is the API pointer (mark-able by S2/the bookmark API); a scheme prefix such as
    // "docs-index:/results/3" is dropped. rowKey stays unique by adding source and kind.
    const locator = pointer.includes(":/")
      ? pointer.slice(pointer.indexOf(":/") + 1)
      : pointer || `/search/${index}`;
    const ref = { ...makeRef("search", locator, kind ?? undefined), source };
    const row = makeRow(
      ref,
      {
        title: strOrNull(raw.title) ?? (baseName(path) || `결과 ${index + 1}`),
        sourcePath: path,
        timestamp: strOrNull(raw.timestamp) ?? strOrNull(metadata.timestamp),
        artifactType: kind,
        provider: strOrNull(source),
        sha256: sha256Of(metadata.sha256, hashes.sha256),
      },
      {
        pointer,
        source,
        keywords: joinList(raw.matched_keywords),
        preview: str(raw.preview),
      },
    );
    row.rowKey = `search:${[source, kind, locator].filter(Boolean).join(":")}`;
    return row;
  },
  columns: [
    col.title("항목", 260),
    col.review(),
    col.field("source", "출처", 90, ["analysis", "compact", "source"], (r) => r.provider),
    col.field("kind", "유형", 120, ["analysis", "compact"], (r) => r.artifactType),
    col.field("keywords", "일치", 140, ["analysis"], (r) => fieldStr(r, "keywords")),
    col.field("preview", "미리보기", 420, ["analysis"], (r) => fieldStr(r, "preview")),
    col.timestamp(170, ["analysis"]),
    col.path(420, ["analysis", "source"]),
    col.sha256(),
  ],
};
