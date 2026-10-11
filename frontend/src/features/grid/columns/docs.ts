import { fetchDocsPage } from "../../../api/collections";
import type { CollectionDef } from "../types";
import { baseName, col, fieldStr, formatBytes, joinList, makeRef, makeRow, str, strOrNull } from "./common";

export const docsCollection: CollectionDef = {
  id: "docs",
  label: "문서",
  source: "paged",
  fetch: (runId, query, signal) => fetchDocsPage(runId, query.offset, query.limit, signal),
  mapRow: (raw, index) => {
    const path = strOrNull(raw.path);
    return makeRow(
      makeRef("docs", `/results/${index}`),
      {
        title: baseName(path) || `문서 ${index + 1}`,
        sourcePath: path,
        artifactType: strOrNull(raw.kind),
      },
      {
        kind: str(raw.kind),
        keywords: joinList(raw.matched_keywords),
        keywordCount: Array.isArray(raw.matched_keywords) ? raw.matched_keywords.length : 0,
        preview: str(raw.preview),
        size: typeof raw.size === "number" ? raw.size : null,
      },
    );
  },
  columns: [
    col.title("이름", 260),
    col.review(),
    col.field("kind", "형식", 80, ["analysis", "compact"], (r) => fieldStr(r, "kind")),
    col.field("keywords", "일치 키워드", 180, ["analysis"], (r) => fieldStr(r, "keywords")),
    col.field("preview", "미리보기", 360, ["analysis"], (r) => fieldStr(r, "preview")),
    col.field("size", "크기", 90, ["analysis", "compact"], (r) => (r.fields.size as number | null) ?? null, {
      align: "right",
      format: (r) => formatBytes(r.fields.size),
    }),
    col.path(420),
  ],
};
