import { DOCS_MATCHED, DOCS_UNMATCHED, fetchDocsPage } from "../../../api/collections";
import type { CollectionDef } from "../types";
import { baseName, col, fieldStr, formatBytes, joinList, makeRef, makeRow, str, strOrNull } from "./common";

/** `text_status` of a document (core/doc_text.py) → Korean. */
export const TEXT_STATUS_LABELS: Readonly<Record<string, string>> = {
  ok: "본문 있음",
  "no-text": "본문 없음",
  encrypted: "암호화",
  "image-only": "이미지만",
  "binary-rejected": "본문 아님(이진)",
  unsupported: "지원 안 함",
  "too-large": "크기 초과",
  error: "추출 오류",
};

/**
 * Korean text state of a docs row. A `no-text` PDF whose reason names image-only pages
 * ("이미지 전용 페이지 …: OCR 필요") reads "이미지만".
 */
export function textStatusLabel(status: string, reason = ""): string {
  if (!status) return "";
  if (status === "no-text" && /이미지|image/i.test(reason)) return TEXT_STATUS_LABELS["image-only"] as string;
  return TEXT_STATUS_LABELS[status] ?? status;
}

export const docsCollection: CollectionDef = {
  id: "docs",
  label: "문서",
  source: "paged",
  fetch: (runId, query, signal) =>
    fetchDocsPage(
      runId,
      query.offset,
      query.limit,
      signal,
      query.ref.category === DOCS_MATCHED
        ? "matched"
        : query.ref.category === DOCS_UNMATCHED
          ? "unmatched"
          : "all",
    ),
  mapRow: (raw, position, ctx) => {
    const path = strOrNull(raw.path);
    // `candidates` rows (every document) vs the older `results` list (matches only).
    const list = ctx?.page?.meta?.docs_rows === "candidates" ? "candidates" : "results";
    const own = typeof raw.record_index === "number" ? raw.record_index : raw.candidate_index;
    const index = typeof own === "number" && Number.isInteger(own) && own >= 0 ? own : position;
    const keywords = Array.isArray(raw.matched_keywords) ? raw.matched_keywords : [];
    const matched =
      typeof raw.matched === "boolean" ? raw.matched : list === "results" || keywords.length > 0;
    return makeRow(
      makeRef("docs", `/${list}/${index}`),
      {
        title: baseName(path) || `문서 ${index + 1}`,
        sourcePath: path,
        artifactType: strOrNull(raw.kind),
      },
      {
        kind: str(raw.kind),
        keywords: joinList(raw.matched_keywords),
        keywordCount: keywords.length,
        preview: str(raw.preview),
        size: typeof raw.size === "number" ? raw.size : null,
        matched,
        textStatus: str(raw.text_status),
        textReason: str(raw.text_reason),
        encrypted: raw.encrypted === true,
      },
    );
  },
  columns: [
    col.title("이름", 260),
    col.review(),
    col.field("kind", "형식", 80, ["analysis", "compact"], (r) => fieldStr(r, "kind")),
    col.field("matched", "일치", 70, ["analysis", "compact"], (r) => r.fields.matched === true, {
      format: (r) => (r.fields.matched === true ? "일치" : "—"),
      tooltip: (r) =>
        r.fields.matched === true ? `키워드 일치: ${fieldStr(r, "keywords")}` : "키워드 일치 없음",
    }),
    col.field("textStatus", "본문", 100, ["analysis", "source"], (r) => fieldStr(r, "textStatus") || null, {
      format: (r) =>
        r.fields.encrypted === true && !fieldStr(r, "textStatus")
          ? (TEXT_STATUS_LABELS.encrypted as string)
          : textStatusLabel(fieldStr(r, "textStatus"), fieldStr(r, "textReason")),
      tooltip: (r) =>
        [textStatusLabel(fieldStr(r, "textStatus"), fieldStr(r, "textReason")), fieldStr(r, "textReason")]
          .filter(Boolean)
          .join(" — "),
    }),
    col.field("keywords", "일치 키워드", 180, ["analysis"], (r) => fieldStr(r, "keywords")),
    col.field("preview", "미리보기", 360, ["analysis"], (r) => fieldStr(r, "preview")),
    col.field("size", "크기", 90, ["analysis", "compact"], (r) => (r.fields.size as number | null) ?? null, {
      align: "right",
      format: (r) => formatBytes(r.fields.size),
    }),
    col.path(420),
  ],
};
