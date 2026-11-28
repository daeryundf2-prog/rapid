/** F11: search hits read as match context (never JSON), the matched field, Korean labels. */
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { matchContextCell } from "./SearchCells";
import { searchCollection, searchTypeLabel } from "./search";
import { contextAround, contextText, keywordFinder, looksLikeJson, searchMatch } from "./searchMatch";

const docText =
  "RapidTriage sample evidence. Invoice INV-2026-0424 shows a wire transfer, account review, password reset, credential";

/** Hit shapes of the synthetic run (`GET /search?keyword=invoice`, core/search.py). */
const documentHit = {
  source: "documents",
  kind: "docx",
  path: "/tmp/rd-data/evidence/Users/alice/Documents/breach-summary.docx",
  title: "breach-summary.docx",
  matched_keywords: ["invoice"],
  search_match: { mode: "exact" },
  pointer: "/results/2",
  preview: docText,
  metadata: {
    path: "/tmp/rd-data/evidence/Users/alice/Documents/breach-summary.docx",
    matched_keywords: ["invoice"],
  },
};
const fileHit = {
  source: "files",
  kind: "documents",
  path: "/tmp/rd-data/evidence/Users/alice/Documents/invoice-wire-transfer.txt",
  title: "invoice-wire-transfer.txt",
  matched_keywords: ["invoice"],
  search_match: { mode: "exact" },
  pointer: "/candidates/8",
  preview: "/tmp/rd-data/evidence/Users/alice/Documents/invoice-wire-transfer.txt",
  metadata: { name: "invoice-wire-transfer.txt", extension: ".txt" },
};
const artifactHit = {
  source: "artifacts",
  kind: "recent-files",
  path: "/tmp/rd-data/evidence/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/Invoice Review.lnk",
  title: "recent-shortcut-invalid-content",
  matched_keywords: ["invoice"],
  search_match: { mode: "exact" },
  pointer: "/artifacts/0",
  preview: '{"artifact_record": {"artifact_family": "recent-files", "artifact_id": "artifact-7828"...',
  metadata: { artifact_type: "recent-shortcut-invalid-content", details: { note: "header failed" } },
};
const timelineHit = {
  source: "timeline",
  kind: "artifact-bam-entry-run",
  path: "/tmp/rd-data/evidence/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/Invoice Review.lnk",
  title: "Artifact event: bam-entry invoice-wire-transfer.txt (합성 30)",
  matched_keywords: ["invoice"],
  search_match: { mode: "exact" },
  pointer: "/events/30",
  preview: '{"event_type": "artifact-bam-entry-run", "path": "/tmp/rd-data/..."}',
  metadata: {
    event_type: "artifact-bam-entry-run",
    source: "artifacts",
    summary: "Artifact event: bam-entry invoice-wire-transfer.txt (합성 30)",
    timestamp: "2026-10-18T06:10:00+00:00",
  },
};

describe("searchMatch", () => {
  it("a document hit: 본문 context ±40 characters around the hit, case-insensitive", () => {
    const match = searchMatch(documentHit);
    expect(match.fields).toEqual(["body"]);
    expect(match.context?.field).toBe("body");
    expect(match.context?.hit).toBe("Invoice");
    expect(match.context?.before).toBe("RapidTriage sample evidence. ");
    expect(match.context?.after.length).toBe(40);
    expect(match.context?.cutEnd).toBe(true);
  });

  it("a file hit: 이름 and 경로, context from the path (folders around the name)", () => {
    const match = searchMatch(fileHit);
    expect(match.fields).toEqual(["name", "path"]);
    expect(match.context?.field).toBe("path");
    expect(contextText(match.context)).toContain("Documents/invoice-wire-transfer.txt");
  });

  it("an artifact hit never shows its JSON preview: the path matched", () => {
    const match = searchMatch(artifactHit);
    expect(match.fields).toEqual(["name", "path"]);
    expect(contextText(match.context)).not.toContain("{");
    expect(match.context?.hit).toBe("Invoice");
  });

  it("a timeline hit reads its event summary as 본문", () => {
    const match = searchMatch(timelineHit);
    expect(match.fields).toEqual(["body", "path"]);
    expect(match.context?.field).toBe("body");
    expect(contextText(match.context)).toBe("Artifact event: bam-entry invoice-wire-transfer.txt (합성 30)");
  });

  it("a hit only in other record fields is a 메타 hit (query bookkeeping excluded)", () => {
    const match = searchMatch({
      source: "artifacts",
      path: "/x/y.db",
      matched_keywords: ["alice"],
      metadata: { matched_keywords: ["alice"], details: { user: "alice" } },
    });
    expect(match.fields).toEqual(["meta"]);
    expect(match.context?.hit).toBe("alice");
  });

  it("regex mode matches the expression; an invalid one is matched as text", () => {
    const find = keywordFinder(["inv-\\d+"], "regex");
    expect(contextAround("see INV-2026 here", find, "body")?.hit).toBe("INV-2026");
    const bad = keywordFinder(["a(b"], "regex");
    expect(contextAround("xx a(b yy", bad, "body")?.hit).toBe("a(b");
  });

  it("a fuzzy hit that is not literally present has no context", () => {
    expect(
      searchMatch({ ...documentHit, matched_keywords: ["invoyce"], search_match: { mode: "fuzzy" } }).context,
    ).toBe(null);
  });

  it("looksLikeJson", () => {
    expect(looksLikeJson('{"a": 1}')).toBe(true);
    expect(looksLikeJson(" [1]")).toBe(true);
    expect(looksLikeJson("Invoice {x}")).toBe(false);
  });
});

describe("search collection columns", () => {
  const ctx = { ref: { id: "search" as const } };
  it("Korean source and type labels; raw ids stay the tooltip", () => {
    const source = searchCollection.columns.find((c) => c.id === "source");
    const kind = searchCollection.columns.find((c) => c.id === "kind");
    const rows = [documentHit, fileHit, artifactHit, timelineHit].map((hit, i) =>
      searchCollection.mapRow(hit, i, ctx),
    );
    expect(rows.map((row) => source?.format?.(row))).toEqual(["문서", "파일", "아티팩트", "타임라인"]);
    expect(source?.tooltip?.(rows[0] as never)).toBe("documents");
    expect(kind?.format?.(rows[0] as never)).toBe("DOCX 문서");
    expect(kind?.format?.(rows[1] as never)).toBe("문서");
    expect(kind?.format?.(rows[3] as never)).toBe("BAM 실행 기록 · 실행");
    expect(kind?.tooltip?.(rows[3] as never)).toBe("artifact-bam-entry-run");
    expect(searchTypeLabel({ source: "ocr", kind: "png" })).toBe("OCR 텍스트");
  });

  it("항목: a timeline hit's target, an artifact hit's file name", () => {
    expect(searchCollection.mapRow(timelineHit, 0, ctx).title).toBe("invoice-wire-transfer.txt (합성 30)");
    expect(searchCollection.mapRow(artifactHit, 0, ctx).title).toBe("Invoice Review.lnk");
  });

  it("일치 위치 + 일치 문맥 columns; the cell marks the hit", () => {
    const row = searchCollection.mapRow(documentHit, 0, ctx);
    const headers = searchCollection.columns.map((c) => c.header);
    expect(headers).toContain("일치 위치");
    expect(headers).toContain("일치 문맥");
    expect(headers).toContain("판정");
    expect(row.fields.matchField).toBe("본문");
    const { container } = render(<>{matchContextCell(row)}</>);
    expect(container.querySelector("mark")?.textContent).toBe("Invoice");
    expect(container.textContent).not.toContain("{");
  });

  it("an artifact hit without a readable context falls back to text, never JSON", () => {
    const row = searchCollection.mapRow({ ...artifactHit, matched_keywords: ["zzz"] }, 0, ctx);
    expect(String(row.fields.preview)).not.toContain("{");
  });
});
