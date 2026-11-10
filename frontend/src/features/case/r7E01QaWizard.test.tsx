// E01 QA S2 (fix/r7-e01-qa-s2): D4 — no output beside evidence, the wizard's output folder becomes the
// case folder; D5 — the output folder is pre-checked so a refused path leaves no orphan case.

import { cleanup, configure, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AddRunDialog } from "./CaseDialogs";
import { CaseWizard, wizardOutputSpec, wizardPlan } from "./CaseWizard";
import { DEFAULT_RUN_FORM } from "./runForm";
import { mockFetch, type RecordedCall, renderWithQuery } from "./testUtils";
import { EMPTY_CASE_INFO } from "./wizardModel";

configure({ asyncUtilTimeout: 5000 });

beforeEach(() => {
  window.location.hash = "";
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function fill(label: string, value: string, scope: HTMLElement = document.body) {
  fireEvent.change(within(scope).getByLabelText(label, { exact: false }), { target: { value } });
}

const RUNNABLE = { ok: true, problem: "", runnable: true, run_blocked_reason: "" };

async function toOptions(caseNumber: string, evidencePath: string) {
  fill("사건 번호", caseNumber);
  fireEvent.click(screen.getByTestId("wizard-next"));
  await screen.findByTestId("wizard-step-evidence");
  fill("증거 경로", evidencePath);
  fireEvent.click(screen.getByTestId("wizard-next"));
  await screen.findByTestId("wizard-step-options");
}

describe("wizard output folder (D4)", () => {
  it("model: without a case folder the output folder becomes the case folder", () => {
    expect(wizardOutputSpec("", 1).required).toBe(true);
    expect(wizardOutputSpec("", 0).required).toBe(false);
    expect(wizardOutputSpec("D:\\cases\\c", 1).required).toBe(false);
    const plan = wizardPlan(EMPTY_CASE_INFO, { ...DEFAULT_RUN_FORM, outputDir: " D:\\out\\c1 " });
    expect(plan.caseInfo.caseRoot).toBe("D:\\out\\c1");
    expect(plan.runForm.outputDir).toBe("");
    const kept = wizardPlan(
      { ...EMPTY_CASE_INFO, caseRoot: "D:\\cases\\c" },
      { ...DEFAULT_RUN_FORM, outputDir: "D:\\o" },
    );
    expect(kept.caseInfo.caseRoot).toBe("D:\\cases\\c");
    expect(kept.runForm.outputDir).toBe("D:\\o");
  });

  it("requires an output folder when no case folder is set and links it to the case folder", async () => {
    const { calls } = mockFetch({
      "POST /api/cases/evidence-check": RUNNABLE,
      "POST /api/cases/output-check": { ok: true, problem: "" },
      "POST /api/cases": (call: RecordedCall) => ({
        case: { case_id: "case-1", case_number: "1", ...(call.body as object), evidence: [] },
      }),
      "POST /api/cases/case-1/evidence": { evidence: { citation_id: "1-EVID-000001", runs: [] } },
      "POST /api/cases/case-1/runs": { run: { run_id: "run-1" }, snapshot: {} },
    });
    renderWithQuery(<CaseWizard runIsActive={false} onClose={vi.fn()} />);
    await toOptions("1", "D:\\ev\\disk.E01");
    // Required and visible without opening 고급 옵션; no "파일 옆" wording anywhere.
    const output = screen.getByLabelText("출력 폴더", { exact: false }) as HTMLInputElement;
    expect(output.getAttribute("aria-required")).toBe("true");
    expect(document.body.textContent).not.toContain("파일 옆");
    const submit = screen.getByTestId("wizard-submit");
    expect(submit.getAttribute("aria-disabled")).toBe("true");
    expect(screen.getAllByText(/출력 폴더를 지정하세요/).length).toBeGreaterThan(0);
    fill("출력 폴더", "D:\\out\\case1");
    expect(screen.getByTestId("wizard-case-root").textContent).toBe("D:\\out\\case1");
    expect(screen.getByTestId("wizard-submit").getAttribute("aria-disabled")).toBeNull();
    fireEvent.click(screen.getByTestId("wizard-submit"));
    await waitFor(() => expect(window.location.hash).toBe("#/case/run-1/intake"));
    const posts = calls.filter((call) => call.method === "POST").map((call) => call.url);
    expect(posts.indexOf("/api/cases/output-check")).toBeLessThan(posts.indexOf("/api/cases"));
    expect(calls.find((call) => call.url === "/api/cases")?.body).toMatchObject({
      case_root: "D:\\out\\case1",
    });
    // The run goes into a run folder under the case folder (server side): no explicit output.
    const runBody = calls.find((call) => call.url === "/api/cases/case-1/runs")?.body as
      | { output_dir?: unknown }
      | undefined;
    expect(runBody?.output_dir).toBeNull();
  });
});

describe("wizard output pre-check (D5)", () => {
  it("a refused output folder creates no case and the error clears when the folder is edited", async () => {
    const { calls } = mockFetch({
      "POST /api/cases/evidence-check": RUNNABLE,
      "POST /api/cases/output-check": { ok: false, problem: "출력 폴더 경로를 허용하지 않습니다: UNC 경로" },
      "POST /api/cases": { case: { case_id: "case-x", case_number: "x", evidence: [] } },
    });
    renderWithQuery(<CaseWizard runIsActive={false} onClose={vi.fn()} />);
    await toOptions("x", "D:\\ev\\disk.E01");
    fill("출력 폴더", "D:\\bad");
    fireEvent.click(screen.getByTestId("wizard-submit"));
    await screen.findByText(/출력 폴더 확인 실패: 출력 폴더 경로를 허용하지 않습니다/);
    expect(calls.some((call) => call.url === "/api/cases")).toBe(false);
    fill("출력 폴더", "D:\\better");
    await waitFor(() => expect(screen.queryByText(/출력 폴더 확인 실패/)).toBeNull());
  });
});

describe("런 추가 output folder (D4)", () => {
  it("requires an output folder for a case without a case folder", async () => {
    mockFetch({
      "GET /api/cases/case-1": {
        case: {
          case_id: "case-1",
          case_number: "1",
          case_root: "",
          evidence: [
            {
              citation_id: "1-EVID-000001",
              evidence_number: "E-01",
              display_name: "disk",
              source_type: "e01",
              path: "D:\\ev\\disk.E01",
              runnable: true,
              runs: [],
            },
          ],
        },
      },
    });
    renderWithQuery(
      <AddRunDialog
        caseId="case-1"
        evidenceCitationId="1-EVID-000001"
        runIsActive={false}
        onClose={vi.fn()}
      />,
    );
    const hint = await screen.findByTestId("output-dir-hint");
    expect(hint.textContent).toContain("직접 지정");
    await waitFor(() => expect(screen.getAllByText(/출력 폴더를 지정하세요/).length).toBeGreaterThan(0));
  });
});
