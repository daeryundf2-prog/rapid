// R7 AI 사용 (갈래 D, plan r7-ai-usage §3.5): the report dialog's "AI 사용 절 포함" — offered for a
// run with AI usage rows (on by default), sent as `sections` (["ai-usage"] / []); a run without AI
// rows sends no `sections` (the server default).

import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useToastStore } from "../../components/toastStore";
import { ReportDialog } from "./ReportDialog";
import { mockFetch, renderWithQuery } from "./testUtils";

const review = { run_id: "r1", exists: true, by_status: {}, report_candidates: 2 };
const file = () =>
  new Response("x", { status: 200, headers: { "content-disposition": 'attachment; filename="r.html"' } });

function tree(ai: boolean) {
  return {
    run_id: "r1",
    root: {},
    nodes: [
      {
        id: ai ? "artifacts:ai-agent" : "artifacts:browser",
        label: "k",
        collection: "artifacts",
        kind: ai ? "ai-agent" : "browser",
        count: 5,
        artifact_type_counts: ai ? { "ai-agent-session": 5 } : { "browser-history": 5 },
      },
    ],
  };
}

function routes(ai: boolean) {
  return {
    "GET /api/runs/r1/review-counts": review,
    "GET /api/runs/r1": { run_id: "r1", summary: { output_dir: "D:\\out" } },
    "GET /api/runs/r1/tree": tree(ai),
    "POST /api/runs/r1/case-report": { report_path: "D:\\out\\rapidtriage-case-report.md", exports: {} },
    "GET /api/runs/r1/case-report/file/html": file(),
  };
}

beforeEach(() => {
  useToastStore.getState().clear();
  URL.createObjectURL = vi.fn(() => "blob:x");
  URL.revokeObjectURL = vi.fn();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const reportBody = (calls: Array<{ method: string; url: string; body?: unknown }>) =>
  calls.find((call) => call.method === "POST" && call.url.endsWith("/case-report"))?.body as
    | Record<string, unknown>
    | undefined;

describe("report dialog › AI 사용 절", () => {
  it("is offered (checked) for a run with AI rows and sent as sections", async () => {
    const { calls } = mockFetch(routes(true));
    renderWithQuery(<ReportDialog runId="r1" runIsActive={false} onClose={() => undefined} />);
    const box = (await screen.findByLabelText(/AI 사용 절 포함/)) as HTMLInputElement;
    expect(box.checked).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "내보내기" }));
    await waitFor(() => expect(reportBody(calls)).toBeDefined());
    expect(reportBody(calls)?.sections).toEqual(["ai-usage"]);
  });

  it("unchecked: sections []", async () => {
    const { calls } = mockFetch(routes(true));
    renderWithQuery(<ReportDialog runId="r1" runIsActive={false} onClose={() => undefined} />);
    fireEvent.click(await screen.findByLabelText(/AI 사용 절 포함/));
    fireEvent.click(screen.getByRole("button", { name: "내보내기" }));
    await waitFor(() => expect(reportBody(calls)).toBeDefined());
    expect(reportBody(calls)?.sections).toEqual([]);
  });

  it("a run without AI rows: no checkbox, no sections", async () => {
    const { calls } = mockFetch(routes(false));
    renderWithQuery(<ReportDialog runId="r1" runIsActive={false} onClose={() => undefined} />);
    await screen.findByText("보고 후보 2건");
    await waitFor(() => expect(calls.some((call) => call.url.endsWith("/tree"))).toBe(true));
    expect(screen.queryByTestId("report-ai-section")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "내보내기" }));
    await waitFor(() => expect(reportBody(calls)).toBeDefined());
    expect(reportBody(calls)).not.toHaveProperty("sections");
  });
});
