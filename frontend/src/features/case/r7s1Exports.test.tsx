// R7 stage 1 re-review R-4 (dialog half): every file the case report writes is named before
// and after the export; the submission manifest downloads the saved file (`/saved`).
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../../api/client";
import { isExportNotWritten } from "../../api/reports";
import { useToastStore } from "../../components/toastStore";
import {
  CASE_REPORT_FILES,
  caseReportWritten,
  downloadSavedExport,
  exportWrites,
  NOT_EXPORTED_MESSAGE,
  openSavedExport,
  performExport,
  writtenDetail,
} from "./exports";
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

describe("R-4: submission manifest is written once (POST) and re-read (/saved)", () => {
  it("POSTs once, then downloads /saved; the result names both written files", async () => {
    const { calls } = mockFetch({
      "POST /api/runs/r4c/submission-manifest": {
        written: [
          "D:o\rapidtriage-submission-manifest.json",
          "D:o\rapidtriage-submission-manifest.audit.json",
        ],
        download_url: "/api/runs/r4c/submission-manifest/saved",
      },
      "GET /api/runs/r4c/submission-manifest/saved": file("rapidtriage-submission-manifest.json"),
    });
    const result = await performExport("submission-manifest", "r4c");
    expect(result.fileName).toBe("rapidtriage-submission-manifest.json");
    expect(result.written).toHaveLength(2);
    expect(calls.map((c) => `${c.method} ${c.url.split("?")[0]}`)).toEqual([
      "POST /api/runs/r4c/submission-manifest",
      "GET /api/runs/r4c/submission-manifest/saved",
    ]);
    // Never the legacy write-on-read GETs.
    expect(
      calls.some(
        (c) => c.method === "GET" && /submission-manifest(\/file)?$/.test(c.url.split("?")[0] ?? ""),
      ),
    ).toBe(false);
  });
});

describe("R8 T-030: a saved export that was never written (404 EXPORT_NOT_WRITTEN)", () => {
  const notWritten = () =>
    new Response(
      JSON.stringify({
        detail: {
          code: "EXPORT_NOT_WRITTEN",
          message: "저장된 검증 패키지이(가) 없습니다. 먼저 내보내기를 실행하세요",
        },
      }),
      { status: 404, headers: { "content-type": "application/json" } },
    );

  it("the download rejects with the one 'not exported yet' state, code kept", async () => {
    mockFetch({ "GET /api/runs/r8a/submission-manifest/saved": notWritten() });
    const failure = await downloadSavedExport("/api/runs/r8a/submission-manifest/saved", "m.json").catch(
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(ApiError);
    expect((failure as ApiError).message).toBe(NOT_EXPORTED_MESSAGE);
    expect((failure as ApiError).code).toBe("EXPORT_NOT_WRITTEN");
    expect(isExportNotWritten(failure)).toBe(true);
  });

  it("other download errors pass through unchanged", async () => {
    mockFetch({});
    const failure = await downloadSavedExport("/api/runs/r8a/case-report/file/md", "r.md").catch(
      (error: unknown) => error,
    );
    expect(isExportNotWritten(failure)).toBe(false);
    expect((failure as ApiError).message).not.toBe(NOT_EXPORTED_MESSAGE);
  });

  it("열기 on a missing package shows the state with a 내보내기 action that POSTs, then downloads", async () => {
    let saved = false;
    const { calls } = mockFetch({
      "GET /api/runs/r8b/validation-package/saved": () =>
        saved ? file("rapidforensic-run-validation-package.json") : notWritten(),
      "POST /api/runs/r8b/validation-package": () => {
        saved = true;
        return {
          package_path: "D:\\o\\rapidforensic-run-validation-package.json",
          audit: "D:\\o\\rapidforensic-run-validation-package.audit.json",
          written: [],
          download_url: "/api/runs/r8b/validation-package/saved",
        };
      },
    });
    const opened = await openSavedExport(
      "validation-package",
      "r8b",
      "/api/runs/r8b/validation-package/saved",
      "rapidforensic-run-validation-package.json",
    );
    expect(opened).toBeUndefined();
    const toast = useToastStore.getState().toasts.at(-1);
    expect(toast?.text).toBe(`검증 패키지: ${NOT_EXPORTED_MESSAGE}`);
    expect(toast?.tone).toBe("warn");
    expect(toast?.action?.label).toBe("내보내기");
    toast?.action?.run?.();
    await waitFor(() =>
      expect(useToastStore.getState().toasts.at(-1)?.text).toBe(
        "검증 패키지: rapidforensic-run-validation-package.json을(를) 저장했습니다.",
      ),
    );
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "GET /api/runs/r8b/validation-package/saved",
      "POST /api/runs/r8b/validation-package",
    ]);
    // The new package's own 열기 then reads the saved file.
    expect(
      await openSavedExport(
        "validation-package",
        "r8b",
        "/api/runs/r8b/validation-package/saved",
        "rapidforensic-run-validation-package.json",
      ),
    ).toBe("rapidforensic-run-validation-package.json");
  });
});
