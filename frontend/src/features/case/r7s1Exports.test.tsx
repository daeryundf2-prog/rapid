// R7 stage 1 re-review R-4 (dialog half): every file the case report writes is named before
// and after the export; the submission manifest downloads the saved file (`/saved`).
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useToastStore } from "../../components/toastStore";
import { CASE_REPORT_FILES, caseReportWritten, exportWrites, performExport, writtenDetail } from "./exports";
import { ReportDialog } from "./ReportDialog";
import { mockFetch, renderWithQuery } from "./testUtils";

const review = (runId: string) => ({
  run_id: runId,
  database: "/o/case.db",
  case_id: `run-${runId}`,
  exists: true,
  by_status: {},
  include_in_report: 2,
  case_json: { bookmarks: 0, include_in_report: 0 },
  report_candidates: 2,
});

const file = (name: string) =>
  new Response("x", { status: 200, headers: { "content-disposition": `attachment; filename="${name}"` } });

beforeEach(() => {
  useToastStore.getState().clear();
  URL.createObjectURL = vi.fn(() => "blob:x");
  URL.revokeObjectURL = vi.fn();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("R-4: case report writes", () => {
  it("the static list names md, html, docx, pdf, the exports manifest and the audit record", () => {
    const writes = exportWrites("case-report", "D:\\out\\run", "pdf");
    expect(writes.map((w) => w.where)).toEqual([
      "D:\\out\\run\\rapidtriage-case-report.md",
      "D:\\out\\run\\rapidtriage-case-report.html",
      "D:\\out\\run\\rapidtriage-case-report.docx",
      "D:\\out\\run\\rapidtriage-case-report.pdf",
      "D:\\out\\run\\rapidtriage-case-report.exports.json",
      "D:\\out\\run\\rapidtriage-case-report.audit.md",
    ]);
    // Only the chosen format is the one also saved to the download folder.
    expect(writes.filter((w) => w.what.includes("다운로드 폴더")).map((w) => w.where)).toEqual([
      "D:\\out\\run\\rapidtriage-case-report.pdf",
    ]);
    expect(writes.some((w) => w.what.includes("원본(Markdown)·감사 기록"))).toBe(false);
  });

  it("the submission manifest lists its audit record too", () => {
    expect(exportWrites("submission-manifest", "/o").map((w) => w.where)).toEqual([
      "/o/rapidtriage-submission-manifest.json",
      "/o/rapidtriage-submission-manifest.audit.json",
    ]);
  });

  it("reads the server's own list first, else report_path + exports + audit", () => {
    expect(caseReportWritten({ written: ["/o/a.md", "/o/b.pdf"], report_path: "/o/a.md" })).toEqual([
      "/o/a.md",
      "/o/b.pdf",
    ]);
    expect(
      caseReportWritten({
        report_path: "/o/r.md",
        exports: { md: "/o/r.md", html: "/o/r.html", manifest: "/o/r.exports.json" },
        audit: "/o/r.audit.md",
      }),
    ).toEqual(["/o/r.md", "/o/r.html", "/o/r.exports.json", "/o/r.audit.md"]);
    expect(caseReportWritten({})).toEqual([]);
    expect(writtenDetail(["D:\\o\\r.md", "D:\\o\\r.pdf"])).toBe("D:\\o — 2개 파일: r.md, r.pdf");
    expect(writtenDetail([])).toBeNull();
  });

  it("the dialog lists all six files and the completion toast names every written file", async () => {
    mockFetch({
      "GET /api/runs/r4a/review-counts": review("r4a"),
      "GET /api/runs/r4a": { run_id: "r4a", summary: { output_dir: "D:\\out\\r4a" } },
      "POST /api/runs/r4a/case-report": {
        report_path: "D:\\out\\r4a\\rapidtriage-case-report.md",
        exports: {
          md: "D:\\out\\r4a\\rapidtriage-case-report.md",
          html: "D:\\out\\r4a\\rapidtriage-case-report.html",
          docx: "D:\\out\\r4a\\rapidtriage-case-report.docx",
          pdf: "D:\\out\\r4a\\rapidtriage-case-report.pdf",
          manifest: "D:\\out\\r4a\\rapidtriage-case-report.exports.json",
        },
        audit: "D:\\out\\r4a\\rapidtriage-case-report.audit.md",
      },
      "GET /api/runs/r4a/case-report/file/html": file("rapidtriage-case-report.html"),
    });
    renderWithQuery(<ReportDialog runId="r4a" runIsActive={false} onClose={() => undefined} />);
    await screen.findByText("보고 후보 2건");
    const items = () => [...screen.getByTestId("export-writes").querySelectorAll("li")];
    await waitFor(() =>
      expect(items()[0]?.textContent).toContain("D:\\out\\r4a\\rapidtriage-case-report.md"),
    );
    expect(items()).toHaveLength(CASE_REPORT_FILES.length);
    fireEvent.click(screen.getByRole("button", { name: "내보내기" }));
    await waitFor(() => expect(useToastStore.getState().toasts).toHaveLength(1));
    const toast = useToastStore.getState().toasts[0];
    expect(toast?.text).toBe(
      "보고서: 6개 파일을 썼습니다 (rapidtriage-case-report.html은(는) 다운로드 폴더에도 저장).",
    );
    expect(toast?.detail).toBe(
      "D:\\out\\r4a — 6개 파일: rapidtriage-case-report.md, rapidtriage-case-report.html, " +
        "rapidtriage-case-report.docx, rapidtriage-case-report.pdf, rapidtriage-case-report.exports.json, " +
        "rapidtriage-case-report.audit.md",
    );
  });

  it("falls back to the static list when the response names no files", async () => {
    mockFetch({
      "POST /api/runs/r4b/case-report": {},
      "GET /api/runs/r4b/case-report/file/md": file("r.md"),
    });
    const result = await performExport("case-report", "r4b", { format: "md" });
    expect(result.written).toHaveLength(6);
    expect(result.written?.[5]).toContain("rapidtriage-case-report.audit.md");
  });
});

describe("R-4: submission manifest re-reads the saved file", () => {
  it("downloads /saved after the one GET (no second write)", async () => {
    const { calls } = mockFetch({
      "GET /api/runs/r4c/submission-manifest": { files: [] },
      "GET /api/runs/r4c/submission-manifest/saved": file("rapidtriage-submission-manifest.json"),
    });
    const result = await performExport("submission-manifest", "r4c");
    expect(result.fileName).toBe("rapidtriage-submission-manifest.json");
    expect(calls.map((c) => c.url.split("?")[0])).toEqual([
      "/api/runs/r4c/submission-manifest",
      "/api/runs/r4c/submission-manifest/saved",
    ]);
  });

  it("an older server without /saved falls back to /file", async () => {
    const { calls } = mockFetch({
      "GET /api/runs/r4d/submission-manifest": { files: [] },
      "GET /api/runs/r4d/submission-manifest/file": file("m.json"),
    });
    const result = await performExport("submission-manifest", "r4d");
    expect(result.fileName).toBe("m.json");
    expect(calls.at(-1)?.url).toBe("/api/runs/r4d/submission-manifest/file");
  });
});
