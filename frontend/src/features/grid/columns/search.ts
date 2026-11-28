import { fetchSearchRows } from "../../../api/collections";
import { artifactTypeLabel } from "../../filters/typeLabels";
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
import { matchContextCell } from "./SearchCells";
import {
  contextText,
  MATCH_FIELD_LABELS,
  type MatchContext,
  searchHitTexts,
  searchMatch,
} from "./searchMatch";
import { targetCell } from "./TargetCell";
import { eventTypeLabel, TIMELINE_SOURCE_LABELS } from "./timeline";
import { type TimelineTarget, timelineTarget } from "./timelineTarget";

/**
 * Korean names of the search sources (core/search.py): the timeline's 파일 / 문서 / 아티팩트 plus
 * the sources only search has. The raw id stays the tooltip and the filter value.
 */
export const SEARCH_SOURCE_LABELS: Readonly<Record<string, string>> = {
  ...TIMELINE_SOURCE_LABELS,
  documents: "문서",
  web: "웹 기록",
  timeline: "타임라인",
  indicators: "지표",
  ocr: "OCR",
};

/**
 * 유형 of a hit in Korean (F11): a timeline hit by its event (the timeline's 이벤트 text), an
 * artifact by its type (falling back to its family), a document by its format, a file by its
 * category. An unnamed id is shown whole (the tooltip has it too).
 */
export function searchTypeLabel(raw: Record<string, unknown>): string {
  const source = str(raw.source);
  const kind = str(raw.kind);
  const metadata = isRecord(raw.metadata) ? raw.metadata : {};
  if (source === "timeline") {
    const details = isRecord(metadata.details) ? metadata.details : {};
    return eventTypeLabel(kind, strOrNull(details.artifact_type));
  }
  if (source === "artifacts" || source === "web") {
    return artifactTypeLabel(str(raw.title)) ?? artifactTypeLabel(kind) ?? (str(raw.title) || kind);
  }
  if (source === "documents") return kind ? `${kind.toUpperCase()} 문서` : "문서";
  if (source === "files") return fileCategoryLabel(kind);
  if (source === "ocr") return "OCR 텍스트";
  return kind;
}

/** 항목 of a hit: a timeline event's target (F10, whole), an artifact's file, else the server title. */
function searchTitle(
  raw: Record<string, unknown>,
  index: number,
): Pick<TimelineTarget, "text" | "display" | "kind"> {
  const source = str(raw.source);
  const metadata = isRecord(raw.metadata) ? raw.metadata : {};
  const path = strOrNull(raw.path);
  if (source === "timeline") {
    const target = timelineTarget({ ...metadata, summary: metadata.summary ?? raw.title });
    if (target.text) return target;
  }
  const plain = (text: string) => ({ text, display: text, kind: "text" as const });
  if ((source === "artifacts" || source === "web") && path) return plain(baseName(path));
  return plain(strOrNull(raw.title) ?? (baseName(path) || `결과 ${index + 1}`));
}

/** Search columns, highest priority first (narrow panes keep the hit's name and its context). */
export const SEARCH_PRIORITY = [
  "title",
  "preview",
  "matchField",
  "source",
  "kind",
  "review",
  "timestamp",
  "keywords",
  "path",
] as const;

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
    const match = searchMatch(raw);
    // A hit with no readable context (a fuzzy match) reads its own text, never the JSON preview.
    const fallback = searchHitTexts(raw).body[0] ?? "";
    const title = searchTitle(raw, index);
    const row = makeRow(
      ref,
      {
        title: title.text,
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
        typeLabel: searchTypeLabel(raw),
        matchField: match.fields.map((field) => MATCH_FIELD_LABELS[field]).join(", "),
        matchContext: match.context,
        preview: contextText(match.context) || fallback.slice(0, 120),
        serverTitle: str(raw.title),
        targetDisplay: title.display,
        targetKind: title.kind,
      },
    );
    row.rowKey = `search:${[source, kind, locator].filter(Boolean).join(":")}`;
    return row;
  },
  columns: [
    { ...col.title("항목", 260), render: targetCell, tooltip: (r) => fieldStr(r, "serverTitle") || r.title },
    col.review(),
    col.field("source", "출처", 90, ["analysis", "compact", "source"], (r) => r.provider, {
      format: (r) => SEARCH_SOURCE_LABELS[r.provider ?? ""] ?? r.provider ?? "",
      tooltip: (r) => r.provider ?? "",
    }),
    col.field("kind", "유형", 160, ["analysis", "compact"], (r) => r.artifactType, {
      format: (r) => fieldStr(r, "typeLabel") || (r.artifactType ?? ""),
      tooltip: (r) => r.artifactType ?? "",
    }),
    col.field("keywords", "일치", 140, ["analysis"], (r) => fieldStr(r, "keywords")),
    col.field("matchField", "일치 위치", 120, ["analysis"], (r) => fieldStr(r, "matchField")),
    col.field("preview", "일치 문맥", 420, ["analysis"], (r) => fieldStr(r, "preview"), {
      minWidth: 200,
      render: matchContextCell,
      tooltip: (r) => {
        const context = r.fields.matchContext as MatchContext | null | undefined;
        return context
          ? `${MATCH_FIELD_LABELS[context.field]}: ${contextText(context)}`
          : fieldStr(r, "preview");
      },
    }),
    col.timestamp(170, ["analysis"]),
    col.path(420, ["analysis", "source"]),
    col.sha256(),
  ],
  widthPriority: () => SEARCH_PRIORITY,
};
