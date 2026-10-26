import { fetchSearchRows } from "../../../api/collections";
import { kindLabel } from "../../derived/tables";
import { artifactTypeLabel, timelineEventTypeLabel } from "../../filters/typeLabels";
import { familyForType } from "../../flags/catalog";
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
import { fileCategoryLabel } from "./files";
import { searchPathCell, snippetCell, snippetSpans } from "./SearchCells";

/** Korean names of the unified-search sources (core/search.py `source`). */
export const SEARCH_SOURCE_LABELS: Readonly<Record<string, string>> = {
  documents: "문서 본문",
  files: "파일",
  web: "웹·브라우저",
  artifacts: "아티팩트",
  timeline: "타임라인",
  indicators: "지표(IOC)",
  ocr: "OCR",
  "docs-index": "문서 색인",
};

const INDICATOR_LABELS: Readonly<Record<string, string>> = {
  "ioc-scanner-hit": "IOC 스캐너 적중",
  url: "URL",
  domain: "도메인",
  ip: "IP 주소",
  ipv4: "IP 주소",
  ipv6: "IP 주소",
  email: "이메일 주소",
  hash: "해시",
  md5: "해시(MD5)",
  sha1: "해시(SHA-1)",
  sha256: "해시(SHA-256)",
  path: "경로",
};

/** 유형 of a hit in Korean: artifact type, file category, document format, event type, IOC type. */
export function searchKindLabel(source: string, kind: string, artifactType: string): string {
  if (source === "artifacts" || source === "web") {
    const type = artifactType || kind;
    const named = artifactTypeLabel(type) ?? familyForType(type)?.label;
    if (named) return named;
    const kindName = kindLabel(kind);
    return kindName !== kind ? kindName : type;
  }
  if (source === "files" || source === "ocr") {
    const categories = kind
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    if (source === "ocr") return "OCR 텍스트";
    return categories.length ? categories.map(fileCategoryLabel).join("·") : "파일";
  }
  if (source === "documents" || source === "docs-index") {
    return kind ? `${kind.toUpperCase()} 문서` : "문서";
  }
  if (source === "timeline") return timelineEventTypeLabel(kind) ?? artifactTypeLabel(kind) ?? kind;
  if (source === "indicators") return INDICATOR_LABELS[kind] ?? (kind ? `지표(${kind})` : "지표");
  return kind;
}

/**
 * Review locator of a hit (`locator` from the API: `{collection, kind, pointer, record_index, ...}`):
 * the run-output row the case DB resolves for review marks (reviewActions.reviewLocatorTarget).
 */
function reviewFields(raw: Record<string, unknown>): Record<string, unknown> {
  const locator = isRecord(raw.locator) ? raw.locator : null;
  const collection = locator ? strOrNull(locator.collection) : null;
  const pointer = locator ? strOrNull(locator.pointer) : null;
  if (!collection || !pointer?.startsWith("/")) return {};
  return { reviewCollection: collection, reviewKind: str(locator?.kind), reviewPointer: pointer };
}

export const searchCollection: CollectionDef = {
  id: "search",
  label: "검색 결과",
  // Server pages (R7): `limit`/`offset` per page, the grid asks for the next one on scroll.
  source: "paged",
  fetch: (runId, query, signal) => fetchSearchRows(runId, query, query.limit, signal),
  mapRow: (raw, index) => {
    const source = str(raw.source);
    const kind = strOrNull(raw.kind);
    const pointer = str(raw.pointer);
    const path = strOrNull(raw.path);
    const metadata = isRecord(raw.metadata) ? raw.metadata : {};
    const hashes = isRecord(metadata.source_hashes) ? metadata.source_hashes : {};
    const review = reviewFields(raw);
    // ref.locator is the API pointer (mark-able by S2/the bookmark API); a scheme prefix such as
    // "docs-index:/results/3" is dropped.
    const locator = pointer.includes(":/")
      ? pointer.slice(pointer.indexOf(":/") + 1)
      : pointer || `/search/${index}`;
    const ref = { ...makeRef("search", locator, kind ?? undefined), source };
    const artifactType = str(raw.artifact_type);
    // The snippet is the match context (<= 200 chars); `preview` is the older field name.
    const snippet = str(raw.snippet) || str(raw.preview);
    const row = makeRow(
      ref,
      {
        title: strOrNull(raw.title) ?? (baseName(path) || `결과 ${index + 1}`),
        sourcePath: path,
        timestamp: strOrNull(raw.timestamp) ?? strOrNull(metadata.timestamp),
        artifactType: artifactType || kind,
        provider: strOrNull(source),
        sha256: sha256Of(metadata.sha256, hashes.sha256),
      },
      {
        pointer,
        source,
        sourceLabel: SEARCH_SOURCE_LABELS[source] ?? source,
        kindLabel: searchKindLabel(source, kind ?? "", artifactType),
        keywords: joinList(raw.matched_keywords),
        preview: snippet,
        snippetHighlights: snippetSpans(raw.snippet_highlights, snippet.length),
        displayPath: strOrNull(raw.display_path) ?? path,
        ...review,
      },
    );
    // Stable identity across refetches: the source row the hit names (else its position).
    row.rowKey = review.reviewPointer
      ? `search:${str(review.reviewCollection)}:${str(review.reviewKind)}:${str(review.reviewPointer)}`
      : `search:${[source, kind, locator].filter(Boolean).join(":")}`;
    return row;
  },
  columns: [
    col.title("항목", 260),
    col.review(),
    col.field("source", "출처", 90, ["analysis", "compact", "source"], (r) => fieldStr(r, "sourceLabel"), {
      tooltip: (r) => r.provider ?? "",
    }),
    col.field("kind", "유형", 140, ["analysis", "compact"], (r) => fieldStr(r, "kindLabel"), {
      tooltip: (r) => r.artifactType ?? "",
    }),
    col.field("keywords", "일치", 120, ["analysis"], (r) => fieldStr(r, "keywords")),
    col.field("preview", "미리보기", 420, ["analysis"], (r) => fieldStr(r, "preview"), {
      render: (r) =>
        snippetCell(fieldStr(r, "preview"), (r.fields.snippetHighlights as [number, number][]) ?? []),
    }),
    col.timestamp(170, ["analysis", "compact"]),
    {
      ...col.path(360, ["analysis", "source"]),
      // Under the acquisition root (same as the timeline 출처 행); the full path on hover.
      value: (r) => fieldStr(r, "displayPath") || r.sourcePath,
      tooltip: (r) => r.sourcePath ?? "",
      render: (r) => searchPathCell(fieldStr(r, "displayPath"), r.sourcePath),
    },
    col.sha256(),
  ],
};
