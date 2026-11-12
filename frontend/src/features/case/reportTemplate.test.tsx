// WB-10 (verify T-027): the 보고서 내보내기 dialog offers the report templates, 감정서 included.
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ReportDialog } from "./ReportDialog";
import { mockFetch, renderWithQuery } from "./testUtils";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const review = (candidates: number) => ({
  run_id: "r1",
  database: "/o/case.db",
  case_id: "run-r1",
  exists: true,
  by_status: {},
  include_in_report: candidates,
  case_json: { bookmarks: 0, include_in_report: 0 },
  report_candidates: candidates,
});

describe("ReportDialog report template", () => {
  it("sends the chosen report template (감정서 = korean-expert)", async () => {
    const { calls } = mockFetch({
      "GET /api/runs/r1/review-counts": review(3),
      "POST /api/runs/r1/case-report": { report_path: "/o/r.md", exports: {} },
      "GET /api/runs/r1/case-report/file/html": new Response("x", {
        status: 200,
        headers: { "content-disposition": 'attachment; filename="r.html"' },
      }),
    });
    URL.createObjectURL = vi.fn(() => "blob:x");
    URL.revokeObjectURL = vi.fn();
    renderWithQuery(<ReportDialog runId="r1" runIsActive={false} onClose={() => undefined} />);
    await screen.findByText("보고 후보 3건");
    const select = screen.getByLabelText("보고서 양식") as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.text)).toEqual([
      "법률 인계용",
      "의사결정자 요약",
      "기술 부록 포함",
      "감정서",
    ]);
    fireEvent.change(select, { target: { value: "korean-expert" } });
    expect(screen.getByLabelText("감정인 (선택)")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "내보내기" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({ template: "korean-expert" });
  });
});
