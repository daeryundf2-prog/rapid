/**
 * T-176 (GAP-090·130, IS-021·096): the 검토 목록 summary carries no internal type-id prefix, the
 * list is named 검토 (not 리뷰), and 보고서 포함 is a marker of its own, not the verdict chip.
 */
import { isValidElement } from "react";
import { describe, expect, it } from "vitest";
import type { GridRow } from "../../../contracts/collection";
import { inReport, REPORT_MARKER, reviewCollection, reviewSummary } from "./review";

const mapRow = (raw: Record<string, unknown>, index = 0): GridRow =>
  reviewCollection.mapRow(raw, index, { ref: { id: "review" } } as never) as GridRow;

const caseDbMark = (extra: Record<string, unknown>) => ({
  _store: "case-db",
  target_type: "artifact",
  target_id: "7",
  status: "relevant",
  include_in_report: false,
  ...extra,
});

describe("검토 목록 요약 (T-176)", () => {
  it("drops an internal type-id prefix", () => {
    expect(reviewSummary("prefetch-file: CHROME.EXE", "prefetch-file")).toBe("CHROME.EXE");
    // No kind on the row: an id the artifact type catalogue knows is still dropped.
    expect(reviewSummary("prefetch-file: CHROME.EXE")).toBe("CHROME.EXE");
    expect(reviewSummary("browser-history:  방문 기록")).toBe("방문 기록");
  });

  it("keeps a leading time, address, host or file name that only looks like an id (P1-6)", () => {
    for (const text of [
      "2026-01-01T10:23:45 logon",
      "192.168.0.5:445 SMB",
      "mail.example.com:443 session",
      "setup.exe: 3 runs",
      "report_final.docx: opened",
      "windows_prefetch: CHROME.EXE",
    ]) {
      expect(reviewSummary(text)).toBe(text);
      expect(reviewSummary(text, "prefetch-file")).toBe(text);
    }
    const row = mapRow(caseDbMark({ title: "192.168.0.5:445 SMB", target_kind: "network-connection" }));
    expect(row.title).toBe("192.168.0.5:445 SMB");
  });

  it("keeps drive letters, URLs and plain sentences", () => {
    expect(reviewSummary("C:\\Users\\kim\\a.txt")).toBe("C:\\Users\\kim\\a.txt");
    expect(reviewSummary("https://example.test/a")).toBe("https://example.test/a");
    expect(reviewSummary("메모: 확인 필요")).toBe("메모: 확인 필요");
  });

  it("a summary that is only the type id is not shown as the id", () => {
    const summary = reviewSummary("prefetch-file", "prefetch-file");
    expect(summary).not.toBe("prefetch-file");
    expect(reviewSummary(null)).toBeNull();
  });

  it("case-DB and bookmark rows use the cleaned summary", () => {
    const row = mapRow(caseDbMark({ title: "prefetch-file: CHROME.EXE", target_kind: "prefetch-file" }));
    expect(row.title).toBe("CHROME.EXE");
    const bare = mapRow(caseDbMark({ title: "prefetch-file", target_kind: "prefetch-file" }));
    expect(bare.title).not.toMatch(/^prefetch-file/);
    const bookmark = mapRow({
      _store: "bookmarks",
      bookmark_id: "b1",
      summary: "browser-history: 방문 기록",
    });
    expect(bookmark.title).toBe("방문 기록");
  });
});

describe("검토 용어와 보고서 포함 표식 (T-176)", () => {
  it("the collection is named 검토 목록, never 리뷰", () => {
    expect(reviewCollection.label).toBe("검토 목록");
    for (const column of reviewCollection.columns) expect(column.header).not.toMatch(/리뷰/);
  });

  const column = (id: string) => reviewCollection.columns.find((c) => c.id === id);

  it("보고서 포함 shows in the 보고서 column, not in the verdict chip slot", () => {
    const includeOnly = mapRow(caseDbMark({ status: "unreviewed", include_in_report: true }));
    expect(includeOnly.reviewStatus).toBe("include-in-report");
    expect(inReport(includeOnly)).toBe(true);
    expect(column("review")?.format?.(includeOnly)).toBe("");
    expect(column("review")?.render?.(includeOnly)).toBeNull();
    expect(column("report")?.format?.(includeOnly)).toBe(REPORT_MARKER);
    const marker = column("report")?.render?.(includeOnly);
    expect(isValidElement(marker)).toBe(true);
  });

  it("a judged row keeps its verdict and also carries the report marker", () => {
    const both = mapRow(caseDbMark({ status: "relevant", include_in_report: true }));
    expect(column("review")?.format?.(both)).toBe("관련 있음");
    expect(column("report")?.format?.(both)).toBe(REPORT_MARKER);
    const judged = mapRow(caseDbMark({ status: "excluded" }));
    expect(column("report")?.format?.(judged)).toBe("");
    expect(column("report")?.render?.(judged)).toBeNull();
  });
});
