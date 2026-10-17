// Case intake (AXIOM adoption E1): wizard validation and submit, run-option summary 1:1 with the
// request, case switcher tree, citation prefix, commands' disabled reasons.

import { cleanup, configure, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildCitation } from "../viewer/citation";
import { CasePicker } from "./CasePicker";
import { CaseWizard, caseRunBody } from "./CaseWizard";
import { caseCitationParts, linkFromSnapshot, useCaseLinks } from "./caseLink";
import { buildCaseCommands } from "./commands";
import { DEFAULT_RUN_FORM } from "./runForm";
import { summarizeRunRequest } from "./runSummary";
import { mockFetch, type RecordedCall, renderWithQuery } from "./testUtils";
import {
  EMPTY_CASE_INFO,
  evidenceBody,
  evidenceListReason,
  newEvidenceDraft,
  pathProblem,
  validateCaseInfo,
  validateEvidenceDraft,
} from "./wizardModel";

// The full suite runs many files in parallel: give async queries room beyond the 1 s default.
configure({ asyncUtilTimeout: 5000 });

const ctx = {
  runId: "r1",
  collection: null,
  selectedRowKeys: [],
  focusedRowKey: null,
  viewerHasTarget: false,
  runIsActive: false,
};

beforeEach(() => {
  window.location.hash = "";
  useCaseLinks.setState({ byRun: {} });
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("wizard model", () => {
  it("requires 사건 번호 with a Korean message", () => {
    expect(validateCaseInfo(EMPTY_CASE_INFO).caseNumber).toBe("사건 번호를 입력하세요.");
    expect(validateCaseInfo({ ...EMPTY_CASE_INFO, caseNumber: "  " }).caseNumber).toBe(
      "사건 번호를 입력하세요.",
    );
    expect(validateCaseInfo({ ...EMPTY_CASE_INFO, caseNumber: "2026-1" })).toEqual({});
    expect(validateCaseInfo({ ...EMPTY_CASE_INFO, caseNumber: "1", caseRoot: "rel" }).caseRoot).toContain(
      "절대 경로",
    );
  });

  it("mirrors the server path policy", () => {
    expect(pathProblem("D:\\ev\\a.E01")).toBeUndefined();
    expect(pathProblem("/mnt/ev")).toBeUndefined();
    expect(pathProblem("~/ev")).toContain("홈 디렉터리");
    expect(pathProblem("\\\\server\\share")).toContain("UNC");
    expect(pathProblem("\\\\?\\C:\\x")).toContain("UNC");
    expect(pathProblem("ev\\a")).toContain("절대 경로");
  });

  it("validates evidence numbers, paths, E01 suffix and expected hashes", () => {
    const a = { ...newEvidenceDraft([]), path: "D:\\ev\\a.E01" };
    const b = { ...newEvidenceDraft([a]), path: "D:\\ev\\b.E01" };
    expect(a.evidenceNumber).toBe("E-01");
    expect(b.evidenceNumber).toBe("E-02");
    expect(validateEvidenceDraft(a, [a, b])).toEqual({});
    const dup = { ...b, evidenceNumber: "E-01" };
    expect(validateEvidenceDraft(dup, [a, dup]).evidenceNumber).toBe("증거 번호가 중복됩니다.");
    expect(validateEvidenceDraft({ ...a, path: "D:\\ev\\a.txt" }, [a]).path).toContain(".E01");
    expect(validateEvidenceDraft({ ...a, sourceType: "folder", path: "" }, [a]).path).toBe(
      "증거 경로를 입력하세요.",
    );
    const file = { ...a, sourceType: "export" as const, path: "D:\\ev\\export.zip" };
    expect(
      validateEvidenceDraft({ ...file, verifyHash: true, expectedHash: "xyz" }, [file]).expectedHash,
    ).toContain("MD5");
    expect(
      validateEvidenceDraft({ ...file, verifyHash: true, expectedHash: "a".repeat(32) }, [file]),
    ).toEqual({});
    // E01: container bytes are not the media hash — an expected value is neither checked nor sent.
    const e01 = { ...a, verifyHash: true, expectedHash: "xyz" };
    expect(validateEvidenceDraft(e01, [e01])).toEqual({});
    expect(evidenceBody(e01).expected_hash).toBe("");
    expect(evidenceBody({ ...file, verifyHash: true, expectedHash: " ab " }).expected_hash).toBe("ab");
    expect(evidenceListReason([])).toBe("증거를 하나 이상 추가하세요.");
    expect(evidenceListReason([{ ...a, path: "" }])).toBe("증거 E-01: 증거 경로를 입력하세요.");
  });
});

describe("run option summary", () => {
  it("has exactly one row per key of the case run request (1:1)", () => {
    const form = { ...DEFAULT_RUN_FORM, mode: "hacking", maxFileCount: "500", knownGoodFeeds: "D:/kg.txt" };
    const body = caseRunBody(form, "C-EVID-000001");
    const rows = summarizeRunRequest(body as unknown as Record<string, unknown>);
    const sent = Object.keys(body).filter((key) => !["wait", "evidence_citation_id"].includes(key));
    expect(rows.map((row) => row.key).sort()).toEqual(sent.sort());
    const byKey = Object.fromEntries(rows.map((row) => [row.key, row.value]));
    expect(byKey.mode).toBe("침해사고 (hacking)");
    expect(byKey.max_file_count).toBe("500개");
    expect(byKey.known_good_hash_feeds).toBe("D:/kg.txt");
    expect(byKey.read_only).toBe("예");
    expect("root" in body).toBe(false);
  });
});

function fill(label: string, value: string, scope: HTMLElement = document.body) {
  fireEvent.change(within(scope).getByLabelText(label, { exact: false }), { target: { value } });
}

describe("CaseWizard (Q-X1)", () => {
  it("validates 사건 번호, adds 2 evidence, deletes 1, and posts case → evidence → run", async () => {
    let evidenceSeq = 0;
    const { calls } = mockFetch({
      "POST /api/cases": (call: RecordedCall) => ({
        case: { case_id: "case-1", ...(call.body as object), evidence: [] },
      }),
      "POST /api/cases/case-1/evidence": (call: RecordedCall) => {
        evidenceSeq += 1;
        return {
          evidence: { citation_id: `C-EVID-00000${evidenceSeq}`, ...(call.body as object), runs: [] },
        };
      },
      "POST /api/cases/case-1/runs": { run: { run_id: "run-new01", status: "queued" }, snapshot: {} },
    });
    const onClose = vi.fn();
    const onNotice = vi.fn();
    renderWithQuery(<CaseWizard runIsActive={false} onClose={onClose} onNotice={onNotice} />);

    // Step 1: 사건 번호 is required (Korean reason on the inert 다음 button).
    expect(screen.getByRole("dialog", { name: "케이스 만들기" })).toBeTruthy();
    const next = screen.getByTestId("wizard-next");
    expect(next.getAttribute("aria-disabled")).toBe("true");
    expect(screen.getAllByText("사건 번호를 입력하세요.").length).toBeGreaterThan(0);
    fireEvent.click(next);
    expect(screen.getByTestId("wizard-step-info")).toBeTruthy();
    fill("사건 번호", "2026-고단-1234");
    fill("검사관", "홍길동");
    fireEvent.click(screen.getByTestId("wizard-next"));

    // Step 2: two evidence items, then delete the second one.
    const step2 = await screen.findByTestId("wizard-step-evidence");
    expect(document.activeElement?.textContent).toContain("2단계");
    fireEvent.click(screen.getByTestId("wizard-add-evidence"));
    const items = within(step2).getAllByTestId("wizard-evidence");
    expect(items).toHaveLength(2);
    fill("증거 경로", "D:\\ev\\a.E01", items[0] as HTMLElement);
    fireEvent.click(within(items[0] as HTMLElement).getByRole("switch"));
    fill("증거 경로", "D:\\ev\\b.E01", items[1] as HTMLElement);
    fireEvent.click(screen.getByRole("button", { name: "증거 E-02 삭제" }));
    expect(within(step2).getAllByTestId("wizard-evidence")).toHaveLength(1);
    expect(screen.getByRole("button", { name: "증거 E-01 삭제" }).getAttribute("aria-disabled")).toBe("true");
    fireEvent.click(screen.getByTestId("wizard-next"));

    // Step 3: options + summary that matches the request 1:1.
    await screen.findByTestId("wizard-step-options");
    const summary = screen.getByTestId("wizard-summary");
    const summaryKeys = [...summary.querySelectorAll("tr[data-key]")].map((row) =>
      row.getAttribute("data-key"),
    );
    const expected = caseRunBody(DEFAULT_RUN_FORM, "x");
    expect(summaryKeys.sort()).toEqual(
      Object.keys(expected)
        .filter((key) => !["wait", "evidence_citation_id"].includes(key))
        .sort(),
    );
    fireEvent.click(screen.getByTestId("wizard-submit"));
    await waitFor(() => expect(onClose).toHaveBeenCalled());

    const posts = calls.filter((call) => call.method === "POST");
    expect(posts.map((call) => call.url)).toEqual([
      "/api/cases",
      "/api/cases/case-1/evidence",
      "/api/cases/case-1/runs",
    ]);
    expect(posts[0]?.body).toMatchObject({ case_number: "2026-고단-1234", examiner: "홍길동" });
    expect(posts[1]?.body).toMatchObject({ evidence_number: "E-01", source_type: "e01", verify_hash: true });
    expect(posts[2]?.body).toEqual(caseRunBody(DEFAULT_RUN_FORM, "C-EVID-000001"));
    expect(onNotice).toHaveBeenCalledWith("케이스 2026-고단-1234를 만들고 런 1개를 시작했습니다.");
    expect(window.location.hash).toBe("#/case/run-new01/intake");
  });

  it("keeps the created case when an evidence call fails and retries from there", async () => {
    let fail = true;
    const { calls } = mockFetch({
      "POST /api/cases": { case: { case_id: "case-9", case_number: "9", evidence: [] } },
      "POST /api/cases/case-9/evidence": () =>
        fail
          ? new Response(JSON.stringify({ detail: "증거 경로가 없습니다: D:\\x.E01" }), { status: 422 })
          : { evidence: { citation_id: "9-EVID-000001", runs: [] } },
      "POST /api/cases/case-9/runs": { run: { run_id: "run-9" }, snapshot: {} },
    });
    renderWithQuery(<CaseWizard runIsActive={false} onClose={vi.fn()} />);
    fill("사건 번호", "9");
    fireEvent.click(screen.getByTestId("wizard-next"));
    await screen.findByTestId("wizard-step-evidence");
    fill("증거 경로", "D:\\x.E01");
    fireEvent.click(screen.getByTestId("wizard-next"));
    await screen.findByTestId("wizard-step-options");
    fireEvent.click(screen.getByTestId("wizard-submit"));
    await screen.findByText(/증거 E-01 추가 실패: 증거 경로가 없습니다/);
    fail = false;
    fireEvent.click(screen.getByTestId("wizard-submit"));
    await waitFor(() => expect(window.location.hash).toBe("#/case/run-9/intake"));
    expect(calls.filter((call) => call.url === "/api/cases").length).toBe(1);
  });

  it("blocks 실행 while another run is active", async () => {
    mockFetch({});
    renderWithQuery(<CaseWizard runIsActive onClose={vi.fn()} />);
    fill("사건 번호", "1");
    fireEvent.click(screen.getByTestId("wizard-next"));
    await screen.findByTestId("wizard-step-evidence");
    fill("증거 경로", "D:\\x.E01");
    fireEvent.click(screen.getByTestId("wizard-next"));
    await screen.findByTestId("wizard-step-options");
    expect(screen.getByTestId("wizard-submit").getAttribute("aria-disabled")).toBe("true");
    expect(screen.getAllByText("실행 중 런이 있습니다").length).toBeGreaterThan(0);
  });
});

describe("case switcher (케이스 › 증거 › 런)", () => {
  it("groups runs under case and evidence in Korean order, then runs without a case", async () => {
    mockFetch({
      "GET /api/runs": {
        runs: [
          { run_id: "run-b", status: "completed", request: { root: "D:/ev/b.E01" } },
          { run_id: "run-a", status: "running", request: { root: "D:/ev/a.E01" } },
          { run_id: "run-loose", status: "completed", request: { root: "D:/old" } },
        ],
      },
      "GET /api/cases": {
        cases: [
          {
            case_id: "c2",
            case_number: "나-2",
            name: "나 사건",
            evidence_count: 1,
            run_count: 1,
            evidence: [
              { citation_id: "e3", evidence_number: "E-01", display_name: "b", runs: [{ run_id: "run-b" }] },
            ],
          },
          {
            case_id: "c1",
            case_number: "가-1",
            name: "가 사건",
            evidence_count: 2,
            run_count: 1,
            evidence: [
              { citation_id: "e2", evidence_number: "E-10", display_name: "z", runs: [] },
              { citation_id: "e1", evidence_number: "E-2", display_name: "a", runs: [{ run_id: "run-a" }] },
            ],
          },
        ],
      },
    });
    renderWithQuery(<CasePicker currentRunId="run-a" onClose={vi.fn()} />);
    const tree = await screen.findByRole("list", { name: "케이스 › 증거 › 런" });
    const caseLines = [...tree.querySelectorAll(".case-tree-case")].map((p) => p.textContent);
    expect(caseLines[0]).toContain("가-1");
    expect(caseLines[1]).toContain("나-2");
    const evidence = within(screen.getByRole("list", { name: "가-1 증거" }))
      .getAllByText(/^증거 E-/)
      .map((node) => node.textContent);
    expect(evidence).toEqual(["증거 E-2 · a", "증거 E-10 · z"]);
    const current = screen.getByRole("button", { name: "가-1 › E-2 › a.E01 · 실행 중" });
    expect(current.getAttribute("aria-current")).toBe("true");
    const loose = screen.getByRole("list", { name: "케이스 없는 런 목록" });
    expect(within(loose).getByRole("button", { name: "old · 완료" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "나-2 › E-01 › b.E01 · 완료" }));
    expect(window.location.hash).toContain("run-b");
  });
});

describe("case link: commands and citation prefix", () => {
  it("disables case-scoped commands with Korean reasons until the run is linked", () => {
    const commands = buildCaseCommands({ reportCandidates: 0 });
    const find = (id: string) => commands.find((c) => c.id === id);
    expect(find("case.create")?.disabledReason?.(ctx)).toBeUndefined();
    expect(find("case.run")?.label).toBe("케이스 없이 빠른 런…");
    expect(find("case.edit")?.disabledReason?.(ctx)).toBe("케이스 정보를 불러오는 중입니다");
    useCaseLinks.getState().setLink("r1", null);
    expect(find("case.edit")?.disabledReason?.(ctx)).toBe("케이스에 연결되지 않은 런입니다");
    expect(find("case.link")?.disabledReason?.(ctx)).toBeUndefined();
    expect(find("case.link")?.disabledReason?.({ ...ctx, runId: null })).toBe("열린 케이스가 없습니다");
    useCaseLinks.getState().setLink("r1", {
      caseId: "c1",
      caseNumber: "2026-1",
      evidenceCitationId: "e1",
      evidenceNumber: "E-01",
      examiner: "",
    });
    expect(find("case.edit")?.disabledReason?.(ctx)).toBeUndefined();
    expect(find("case.link")?.disabledReason?.(ctx)).toBe("이미 케이스 2026-1에 연결된 런입니다");
    expect(find("case.run.add")?.disabledReason?.({ ...ctx, runIsActive: true })).toBe(
      "실행 중 런이 있습니다",
    );
  });

  it("prefixes citations with 사건 번호 and 증거 번호", () => {
    const link = linkFromSnapshot({
      source: "case-db",
      run_id: "r1",
      case_id: "c1",
      evidence_citation_id: "e1",
      captured_at: null,
      snapshot: {},
      case: { case_number: "2026-고단-1234" } as never,
      evidence: { evidence_number: "E-01" } as never,
    });
    useCaseLinks.getState().setLink("r1", link);
    expect(caseCitationParts("r1")).toEqual(["사건=2026-고단-1234", "증거=E-01"]);
    expect(caseCitationParts("r2")).toEqual([]);
    const text = buildCitation(
      {
        runId: "r1",
        sourcePath: "C:/x.txt",
        ref: { collection: "files", locator: "/candidates/1" },
      } as never,
      null,
    );
    expect(text.startsWith("사건=2026-고단-1234; 증거=E-01; 원본=C:/x.txt")).toBe(true);
    expect(linkFromSnapshot({ source: "run-request" } as never)).toBeNull();
  });
});
