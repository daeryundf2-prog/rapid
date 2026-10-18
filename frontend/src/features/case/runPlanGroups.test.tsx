// 처리 그룹 checklist (R4 V1 U-P2-3): defaults from `GET /run-plan/preview`, required groups
// disabled with the reason, 전부 선택 / 전부 해제, defaults re-applied on a mode change, and the
// unchecked skippable groups sent as `skip_groups` by the quick-run dialog and the case wizard.

import { cleanup, configure, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RunPlanPreview } from "../../api/runPlan";
import { CaseWizard } from "./CaseWizard";
import { RunDialog } from "./RunDialog";
import { CARVE_GATED_REASON, EXTRACT_GATED_REASON, REQUIRED_GROUP_REASON } from "./RunPlanGroupsField";
import { buildRunBody, DEFAULT_RUN_FORM } from "./runForm";
import { summarizeRunRequest } from "./runSummary";
import { mockFetch, type RecordedCall, renderWithQuery } from "./testUtils";

configure({ asyncUtilTimeout: 5000 });

const PREVIEWS: Record<string, RunPlanPreview> = {
  fraud: {
    mode: "fraud",
    groups: [
      {
        id: "prepare",
        label: "준비",
        default_on: true,
        skippable: false,
        tasks: [{ id: "prepare", label: "준비" }],
      },
      {
        id: "docs",
        label: "문서",
        default_on: true,
        skippable: true,
        tasks: [{ id: "docs", label: "문서" }],
      },
      {
        id: "email",
        label: "메일",
        default_on: false,
        skippable: true,
        tasks: [{ id: "email", label: "메일" }],
      },
      {
        id: "report",
        label: "보고서",
        default_on: true,
        skippable: false,
        tasks: [{ id: "report", label: "보고서" }],
      },
    ],
  },
  hacking: {
    mode: "hacking",
    groups: [
      {
        id: "prepare",
        label: "준비",
        default_on: true,
        skippable: false,
        tasks: [{ id: "prepare", label: "준비" }],
      },
      {
        id: "eventlog",
        label: "이벤트 로그",
        default_on: true,
        skippable: true,
        tasks: [
          { id: "eventlog", label: "이벤트 로그" },
          { id: "sysmon", label: "Sysmon" },
        ],
      },
      {
        id: "browser",
        label: "웹 브라우저",
        default_on: true,
        skippable: true,
        tasks: [{ id: "browser", label: "웹" }],
      },
      {
        id: "carve",
        label: "카빙",
        default_on: false,
        skippable: true,
        tasks: [{ id: "carve", label: "카빙" }],
      },
      {
        id: "report",
        label: "보고서",
        default_on: true,
        skippable: false,
        tasks: [{ id: "report", label: "보고서" }],
      },
    ],
  },
};

function previewRoute(call: RecordedCall) {
  const mode = new URL(call.url, "http://x").searchParams.get("mode") ?? "";
  return (
    PREVIEWS[mode] ??
    new Response(JSON.stringify({ detail: `지원하지 않는 모드입니다: ${mode}` }), { status: 400 })
  );
}

const checkbox = (name: string) =>
  screen.getByRole("checkbox", { name: new RegExp(`^${name}`) }) as HTMLInputElement;

beforeEach(() => {
  window.location.hash = "";
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("run form skip_groups", () => {
  it("sends skip_groups only when a group is unchecked (default body unchanged)", () => {
    expect(buildRunBody({ ...DEFAULT_RUN_FORM, root: "D:/e" })).not.toHaveProperty("skip_groups");
    expect(
      buildRunBody({ ...DEFAULT_RUN_FORM, root: "D:/e", skipGroups: ["carve", "carve", "email"] })
        .skip_groups,
    ).toEqual(["carve", "email"]);
    const rows = summarizeRunRequest({ mode: "fraud", skip_groups: ["email"] });
    expect(rows.find((row) => row.key === "skip_groups")).toEqual({
      key: "skip_groups",
      label: "건너뛸 처리 그룹",
      value: "email",
    });
  });
});

describe("RunDialog 처리 그룹", () => {
  it("checks the mode defaults, keeps required groups on, re-applies defaults on a mode change and posts skip_groups", async () => {
    const { calls } = mockFetch({
      "GET /api/run-plan/preview": previewRoute,
      "POST /api/runs": { run_id: "new1", status: "queued" },
    });
    const onClose = vi.fn();
    renderWithQuery(<RunDialog runIsActive={false} onClose={onClose} />);
    const fieldset = await screen.findByRole("group", { name: "처리 그룹" });
    await waitFor(() => expect(within(fieldset).getAllByRole("checkbox")).toHaveLength(4));
    expect(calls[0]?.url).toBe("/api/run-plan/preview?mode=fraud&carve=false&extract=false");
    // fraud defaults: 메일 off; 준비 / 보고서 required (checked, disabled, with the reason).
    await waitFor(() => expect(checkbox("메일").checked).toBe(false));
    expect(checkbox("문서").checked).toBe(true);
    const prepare = checkbox("준비");
    expect(prepare.checked).toBe(true);
    expect(prepare.disabled).toBe(true);
    expect(document.getElementById(prepare.getAttribute("aria-describedby") as string)?.textContent).toBe(
      REQUIRED_GROUP_REASON,
    );
    expect(screen.getByTestId("run-plan-groups-count").textContent).toBe("4개 그룹 중 3개 실행");

    // Mode change: hacking defaults replace the fraud choice; 카빙 has no run option here, so it
    // stays off and disabled with the reason and never counts as running.
    fireEvent.change(screen.getByLabelText("모드"), { target: { value: "hacking" } });
    await waitFor(() => expect(within(fieldset).getAllByRole("checkbox")).toHaveLength(5));
    await waitFor(() => expect(checkbox("카빙").checked).toBe(false));
    expect(checkbox("카빙").disabled).toBe(true);
    expect(
      document.getElementById(checkbox("카빙").getAttribute("aria-describedby") as string)?.textContent,
    ).toContain(CARVE_GATED_REASON);
    expect(checkbox("이벤트 로그").checked).toBe(true);
    expect(fieldset.textContent).toContain("(태스크 2)");
    expect(screen.getByTestId("run-plan-groups-count").textContent).toBe("5개 그룹 중 4개 실행");

    // 전부 해제 → every choosable group off; 전부 선택 → all on (gated 카빙 stays off); then a choice.
    fireEvent.click(within(fieldset).getByRole("button", { name: "전부 해제" }));
    expect(checkbox("이벤트 로그").checked).toBe(false);
    expect(checkbox("웹 브라우저").checked).toBe(false);
    expect(checkbox("보고서").checked).toBe(true);
    fireEvent.click(within(fieldset).getByRole("button", { name: "전부 선택" }));
    expect(checkbox("카빙").checked).toBe(false);
    expect(screen.getByTestId("run-plan-groups-count").textContent).toBe("5개 그룹 중 4개 실행");
    fireEvent.click(checkbox("카빙")); // gated: no effect
    fireEvent.click(checkbox("이벤트 로그"));
    fireEvent.click(checkbox("보고서")); // disabled: no effect

    fireEvent.change(screen.getByLabelText(/증거 경로/), { target: { value: "D:/case/img.E01" } });
    fireEvent.click(screen.getByRole("button", { name: "실행" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    const post = calls.find((c) => c.method === "POST");
    expect(post?.body).toMatchObject({
      root: "D:/case/img.E01",
      mode: "hacking",
      skip_groups: ["eventlog"],
    });
  });

  it("추출(선택) follows the 파일 추출 option: disabled with the reason while off, its default re-applied when on", async () => {
    const extractPreview = (call: RecordedCall): RunPlanPreview => {
      const extract = new URL(call.url, "http://x").searchParams.get("extract") === "true";
      return {
        mode: "fraud",
        groups: [
          {
            id: "prepare",
            label: "준비",
            default_on: true,
            skippable: false,
            tasks: [{ id: "prepare", label: "준비" }],
          },
          {
            id: "docs",
            label: "문서",
            default_on: true,
            skippable: true,
            tasks: [{ id: "docs", label: "문서" }],
          },
          {
            id: "extract",
            label: "추출(선택)",
            default_on: extract,
            skippable: true,
            tasks: [
              { id: "docs-extract", label: "문서 추출" },
              { id: "files-extract", label: "파일 추출" },
            ],
          },
        ],
      };
    };
    const { calls } = mockFetch({
      "GET /api/run-plan/preview": extractPreview,
      "POST /api/runs": { run_id: "new1", status: "queued" },
    });
    const onClose = vi.fn();
    renderWithQuery(<RunDialog runIsActive={false} onClose={onClose} />);
    const fieldset = await screen.findByRole("group", { name: "처리 그룹" });
    await waitFor(() => expect(within(fieldset).getAllByRole("checkbox")).toHaveLength(3));
    const extract = () => checkbox("추출\\(선택\\)");
    expect(extract().checked).toBe(false);
    expect(extract().disabled).toBe(true);
    expect(
      document.getElementById(extract().getAttribute("aria-describedby") as string)?.textContent,
    ).toContain(EXTRACT_GATED_REASON);
    expect(screen.getByTestId("run-plan-groups-count").textContent).toBe("3개 그룹 중 2개 실행");

    // 파일 추출 on: the preview's default_on flips to true and is applied (checked, enabled).
    fireEvent.click(screen.getByRole("button", { name: "고급 옵션 펼치기" }));
    fireEvent.click(screen.getByLabelText("파일 추출"));
    await waitFor(() => expect(extract().disabled).toBe(false));
    await waitFor(() => expect(extract().checked).toBe(true));
    expect(screen.getByTestId("run-plan-groups-count").textContent).toBe("3개 그룹 중 3개 실행");
    expect(calls.some((call) => call.url.includes("extract=true"))).toBe(true);

    // Unchecked by the examiner → skipped; 파일 추출 off again → gated, not counted, not sent.
    fireEvent.click(extract());
    expect(extract().checked).toBe(false);
    fireEvent.click(screen.getByLabelText("파일 추출"));
    await waitFor(() => expect(extract().disabled).toBe(true));
    expect(screen.getByTestId("run-plan-groups-count").textContent).toBe("3개 그룹 중 2개 실행");
    fireEvent.change(screen.getByLabelText(/증거 경로/), { target: { value: "D:/case/img.E01" } });
    fireEvent.click(screen.getByRole("button", { name: "실행" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(calls.find((c) => c.method === "POST")?.body).not.toHaveProperty("skip_groups");
  });

  it("says so when the preview is unavailable and posts without skip_groups", async () => {
    const { calls } = mockFetch({ "POST /api/runs": { run_id: "new1", status: "queued" } });
    const onClose = vi.fn();
    renderWithQuery(<RunDialog runIsActive={false} onClose={onClose} />);
    expect(await screen.findByTestId("run-plan-groups-error")).toBeTruthy();
    fireEvent.change(screen.getByLabelText(/증거 경로/), { target: { value: "D:/case/img.E01" } });
    fireEvent.click(screen.getByRole("button", { name: "실행" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(calls.find((c) => c.method === "POST")?.body).not.toHaveProperty("skip_groups");
  });
});

describe("CaseWizard step 3 처리 그룹", () => {
  it("lists the groups for the run options and posts skip_groups with the case run", async () => {
    const { calls } = mockFetch({
      "GET /api/run-plan/preview": previewRoute,
      "POST /api/cases": (call: RecordedCall) => ({
        case: { case_id: "case-1", ...(call.body as object), evidence: [] },
      }),
      "POST /api/cases/case-1/evidence": (call: RecordedCall) => ({
        evidence: { citation_id: "C-EVID-000001", ...(call.body as object), runs: [] },
      }),
      "POST /api/cases/case-1/runs": { run: { run_id: "run-new01", status: "queued" }, snapshot: {} },
      "POST /api/cases/evidence-check": { ok: true, problem: "", runnable: true, run_blocked_reason: "" },
    });
    const onClose = vi.fn();
    renderWithQuery(<CaseWizard runIsActive={false} onClose={onClose} />);
    fireEvent.change(screen.getByLabelText("사건 번호", { exact: false }), { target: { value: "2026-1" } });
    fireEvent.click(screen.getByTestId("wizard-next"));
    await screen.findByTestId("wizard-step-evidence");
    fireEvent.change(screen.getByLabelText("증거 경로", { exact: false }), {
      target: { value: "D:\\ev\\a.E01" },
    });
    fireEvent.click(screen.getByTestId("wizard-next"));
    const step3 = await screen.findByTestId("wizard-step-options");
    const fieldset = within(step3).getByRole("group", { name: "처리 그룹" });
    await waitFor(() => expect(within(fieldset).getAllByRole("checkbox")).toHaveLength(4));
    await waitFor(() => expect(checkbox("메일").checked).toBe(false));
    fireEvent.click(checkbox("문서"));
    // The summary lists the choice exactly as the request carries it.
    const summary = screen.getByTestId("wizard-summary");
    await waitFor(() =>
      expect(summary.querySelector('tr[data-key="skip_groups"]')?.textContent).toContain("email, docs"),
    );
    fireEvent.click(screen.getByTestId("wizard-submit"));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    const run = calls.find((c) => c.url === "/api/cases/case-1/runs");
    expect(run?.body).toMatchObject({
      mode: "fraud",
      skip_groups: ["email", "docs"],
      evidence_citation_id: "C-EVID-000001",
    });
  });
});
