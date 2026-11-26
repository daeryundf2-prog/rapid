import type { RawRow } from "../../../api/collections";
import type { GridRow } from "../../../contracts/collection";
import { domainLabel } from "../../search/domainLabel";
import { fetchSearchPage } from "../../search/rows";
import { highlight, keywordPattern } from "../../viewer/views/Highlight";
import type { CollectionDef } from "../types";
import { artifactsCollection } from "./artifacts";
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

/** Collections an index hit can belong to. */
const HIT_COLLECTIONS = ["files", "docs", "artifacts", "indicators", "analysis"] as const;

/** What the viewer names as still loading for an artifact hit (the index keeps a few fields). */
const INDEX_OMITTED = "색인에 없는 필드";

/**
 * An index hit (`POST /search/query`). The row keeps the address of the record it found
 * (`{collection, kind, locator}`), so review marks and the viewer treat it as that record; an
 * artifact hit also takes the artifact row shape and lets the viewer load the full record.
 * `ref.source` marks it as a hit: its locator is no position in the search results.
 */
function indexRow(raw: RawRow): GridRow {
  const collection = HIT_COLLECTIONS.find((id) => id === raw.collection) ?? "search";
  const kind = strOrNull(raw.kind) ?? undefined;
  const locator = str(raw.locator);
  const path = strOrNull(raw.path);
  const hashes = isRecord(raw.hashes) ? raw.hashes : {};
  const matched = Array.isArray(raw.matched) ? raw.matched.map((m) => (isRecord(m) ? str(m.term) : "")) : [];
  const hit = {
    pointer: locator,
    source: collection,
    keywords: matched.filter(Boolean).join(", "),
    preview: isRecord(raw.snippet) ? str(raw.snippet.text) : "",
  };
  const title = strOrNull(raw.title) ?? (baseName(path) || locator);
  const timestamp = strOrNull(raw.ts);
  const provider = domainLabel(str(raw.domain) || collection);
  const recordIndex = /^\/artifacts\/(\d+)$/.exec(locator)?.[1];
  if (collection === "artifacts" && kind && recordIndex !== undefined) {
    const record = {
      artifact_type: raw.artifact_type,
      path,
      details: raw.fields,
      details_omitted: [INDEX_OMITTED],
      _kind: kind,
      _index: Number(recordIndex),
    };
    const row = artifactsCollection.mapRow(record, Number(recordIndex), { ref: { id: "artifacts", kind } });
    return {
      ...row,
      ref: { ...row.ref, source: collection },
      title,
      timestamp: timestamp ?? row.timestamp,
      provider,
      fields: { ...row.fields, ...hit },
    };
  }
  return makeRow(
    { ...makeRef(collection, locator, kind), source: collection },
    {
      title,
      sourcePath: path,
      timestamp,
      artifactType: strOrNull(raw.artifact_type),
      provider,
      sha256: sha256Of(hashes.sha256),
    },
    hit,
  );
}

/** A scan match (`GET /search`): addressed by its pointer inside the search collection. */
function scanRow(raw: RawRow, index: number): GridRow {
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
}

export const searchCollection: CollectionDef = {
  id: "search",
  label: "검색 결과",
  // True for a search without hits and for one the analyst cancelled (the status line says which).
  emptyText: "표시할 검색 결과가 없습니다.",
  source: "paged",
  fetch: fetchSearchPage,
  mapRow: (raw, index) => (typeof raw.doc_id === "number" ? indexRow(raw) : scanRow(raw, index)),
  columns: [
    col.title("항목", 260),
    col.review(),
    col.field("source", "출처", 110, ["analysis", "compact", "source"], (r) => r.provider),
    col.field("kind", "유형", 120, ["analysis", "compact"], (r) => r.artifactType),
    col.field("keywords", "일치", 140, ["analysis"], (r) => fieldStr(r, "keywords")),
    col.field("preview", "미리보기", 420, ["analysis"], (r) => fieldStr(r, "preview"), {
      // The matched words stand out in the excerpt.
      render: (r) => highlight(fieldStr(r, "preview"), keywordPattern(fieldStr(r, "keywords").split(", "))),
    }),
    col.timestamp(170, ["analysis"]),
    col.path(420, ["analysis", "source"]),
    col.sha256(),
  ],
};
