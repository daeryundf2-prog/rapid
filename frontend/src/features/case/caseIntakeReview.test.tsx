// Case intake adversarial-review regressions (AXIOM adoption E1 fixer): one test per finding that
// has a console side — output folder vs N runs (1), register-only evidence (2), forced link (3),
// output hint text (6), re-hash button (7), changed-fields PATCH (9), evidence 409 adopt (10),
// citation prefix while loading (11), Enter moves on (12).

import { cleanup, configure, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CaseDetail, CaseEvidence } from "../../api/cases";
import { EvidenceHashButton } from "../dashboard/caseCards";
import { buildCitation } from "../viewer/citation";
import { AddRunDialog, CaseEditDialog, changedCaseFields, LinkCaseDialog } from "./CaseDialogs";
import { adoptableEvidence, CaseWizard } from "./CaseWizard";
import { CASE_LINK_LOADING_REASON, citationDisabledReason, resolveCaseLink, useCaseLinks } from "./caseLink";
import { summarizeRunRequest } from "./runSummary";
import { mockFetch, type RecordedCall, renderWithQuery } from "./testUtils";
import { newEvidenceDraft, outputDirReason, samePathText } from "./wizardModel";

configure({ asyncUtilTimeout: 5000 });

beforeEach(() => {
  window.location.hash = "";
  useCaseLinks.setState({ byRun: {}, loading: {} });
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function fill(label: string, value: string, scope: HTMLElement = document.body) {
  fireEvent.change(within(scope).getByLabelText(label, { exact: false }), { target: { value } });
}

const RUNNABLE = { ok: true, problem: "", runnable: true, run_blocked_reason: "" };
const ZIP_BLOCKED = {
  ok: true,
  problem: "",
  runnable: false,
  run_blocked_reason: "바로 처리할 수 없는 형식입니다 (zip) — 증거로 등록만 됩니다.",
};

function evidenceRow(over: Partial<CaseEvidence>): CaseEvidence {
  return {
    citation_id: "C-EVID-000001",
    case_id: "case-1",
    evidence_number: "E-01",
    display_name: "a",
    source_type: "folder",
    path: "D:\\ev\\a",
    size_bytes: null,
    hash_verify: false,
    hash_expected: "",
    hash_status: "not-requested",
    hash_status_label: "해시 검증 안 함",
    hash_message: "",
    hashes: {},
    added_at: null,
    runs: [],
    runnable: true,
    run_blocked_reason: "",
    ...over,
  };
}

/** Steps 1–2 of the wizard with the given evidence (type, path) items; ends on step 3. */
async function fillWizard(items: Array<[string, string]>, caseNumber = "2026-1") {
  fill("사건 번호", caseNumber);
  fireEvent.click(screen.getByTestId("wizard-next"));
  const step2 = await screen.findByTestId("wizard-step-evidence");
  for (let i = 1; i < items.length; i += 1) fireEvent.click(screen.getByTestId("wizard-add-evidence"));
  const fields = within(step2).getAllByTestId("wizard-evidence");
  items.forEach(([type, path], index) => {
    const scope = fields[index] as HTMLElement;
    fireEvent.change(within(scope).getByLabelText("증거 종류"), { target: { value: type } });
    fill("증거 경로", path, scope);
  });
  fireEvent.click(screen.getByTestId("wizard-next"));
}

describe("review 1: one output folder never serves several runs", () => {
  it("blocks 실행 with a Korean reason when an output folder is set for 2 runs", async () => {
    mockFetch({ "POST /api/cases/evidence-check": RUNNABLE });
    renderWithQuery(<CaseWizard runIsActive={false} onClose={vi.fn()} />);
    await fillWizard([
      ["folder", "D:\\ev\\a"],
      ["folder", "D:\\ev\\b"],
    ]);
    await screen.findByTestId("wizard-step-options");
    fireEvent.click(screen.getByRole("button", { name: /고급 옵션/ }));
    fill("출력 폴더", "D:\\out");
    const submit = screen.getByTestId("wizard-submit");
    expect(submit.getAttribute("aria-disabled")).toBe("true");
    expect(screen.getByTestId("wizard-output-dir-problem").textContent).toContain("런 1개만");
    fill("출력 폴더", "");
    expect(screen.getByTestId("wizard-submit").getAttribute("aria-disabled")).toBeNull();
    expect(outputDirReason("D:\\out", 1)).toBeUndefined();
    expect(outputDirReason("", 3)).toBeUndefined();
  });
});

describe("review 2: register-only evidence", () => {
  it("pre-checks paths, marks register-only evidence and starts runs only for runnable ones", async () => {
    let seq = 0;
    const { calls } = mockFetch({
      "POST /api/cases/evidence-check": (call: RecordedCall) =>
        String((call.body as { path: string }).path).endsWith(".zip") ? ZIP_BLOCKED : RUNNABLE,
      "POST /api/cases": { case: { case_id: "case-1", case_number: "2026-1", evidence: [] } },
      "POST /api/cases/case-1/evidence": () => {
        seq += 1;
        return { evidence: { citation_id: `C-EVID-00000${seq}`, runs: [] } };
      },
      "POST /api/cases/case-1/runs": { run: { run_id: "run-1" }, snapshot: {} },
    });
    const onNotice = vi.fn();
    renderWithQuery(<CaseWizard runIsActive={false} onClose={vi.fn()} onNotice={onNotice} />);
    await fillWizard([
      ["folder", "D:\\ev\\a"],
      ["export", "D:\\ev\\b.zip"],
    ]);
    await screen.findByTestId("wizard-step-options");
    expect(screen.getByTestId("wizard-skipped").textContent).toContain("E-02");
    expect(screen.getByRole("table", { name: "증거 요약" }).textContent).toContain(
      "등록만 — 바로 처리할 수 없는",
    );
    expect(screen.getByTestId("wizard-submit").textContent).toBe("실행 (런 1개)");
    fireEvent.click(screen.getByTestId("wizard-submit"));
    await waitFor(() => expect(onNotice).toHaveBeenCalled());
    const runs = calls.filter((call) => call.url === "/api/cases/case-1/runs");
    expect(runs).toHaveLength(1);
    const runBody = runs[0]?.body as { evidence_citation_id?: string } | undefined;
    expect(runBody?.evidence_citation_id).toBe("C-EVID-000001");
    expect(calls.filter((call) => call.url === "/api/cases/case-1/evidence")).toHaveLength(2);
    expect(onNotice.mock.calls[0]?.[0]).toContain("등록만 한 증거 1개(E-02)");
  });

  it("keeps the examiner on the evidence step when a path fails the pre-check", async () => {
    const { calls } = mockFetch({
      "POST /api/cases/evidence-check": {
        ok: false,
        problem: "증거 경로가 없습니다: D:\\nope",
        runnable: false,
        run_blocked_reason: "",
      },
    });
    renderWithQuery(<CaseWizard runIsActive={false} onClose={vi.fn()} />);
    await fillWizard([["folder", "D:\\nope"]]);
    expect(await screen.findByTestId("wizard-evidence-problem")).toBeTruthy();
    expect(screen.getByTestId("wizard-step-evidence")).toBeTruthy();
    expect(screen.getByTestId("wizard-next").getAttribute("aria-disabled")).toBe("true");
    // Nothing was saved.
    expect(calls.filter((call) => call.url === "/api/cases")).toHaveLength(0);
  });

  it("AddRunDialog does not offer register-only evidence and says why", async () => {
    mockFetch({
      "GET /api/cases/case-1": {
        case: {
          case_id: "case-1",
          evidence: [
            evidenceRow({}),
            evidenceRow({
              citation_id: "C-EVID-000002",
              evidence_number: "E-02",
              display_name: "b.zip",
              runnable: false,
              run_blocked_reason: ZIP_BLOCKED.run_blocked_reason,
            }),
          ],
        },
      },
    });
    renderWithQuery(
      <AddRunDialog
        caseId="case-1"
        evidenceCitationId="C-EVID-000002"
        runIsActive={false}
        onClose={vi.fn()}
      />,
    );
    const blocked = await screen.findByTestId("run-add-blocked");
    expect(blocked.textContent).toContain("E-02");
    expect(blocked.textContent).toContain("등록만");
    const select = screen.getByLabelText("증거") as HTMLSelectElement;
    expect([...select.options].map((o) => o.value)).toEqual(["", "C-EVID-000001"]);
    expect(select.value).toBe("");
  });
});

describe("review 3: forced link", () => {
  it("requires a reason and sends force when the run root differs from the evidence path", async () => {
    const { calls } = mockFetch({
      "GET /api/cases": {
        cases: [{ case_id: "case-1", case_number: "2026-1", name: "x", evidence: [evidenceRow({})] }],
      },
      "GET /api/runs/r1/processing-snapshot": {
        source: "run-request",
        run_id: "r1",
        snapshot: { request: { root: "D:/other" } },
      },
      "POST /api/cases/case-1/runs/link": {},
    });
    const onClose = vi.fn();
    renderWithQuery(<LinkCaseDialog runId="r1" onClose={onClose} />);
    fireEvent.change(await screen.findByLabelText("케이스", { exact: true }), {
      target: { value: "case-1" },
    });
    fireEvent.change(screen.getByLabelText("증거", { exact: true }), { target: { value: "C-EVID-000001" } });
    await screen.findByTestId("link-force");
    const linkButton = screen.getByRole("button", { name: "연결" });
    expect(linkButton.getAttribute("aria-disabled")).toBe("true");
    fill("강제 연결 사유", "사본 경로로 처리");
    fireEvent.click(screen.getByRole("button", { name: "연결" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    const post = calls.find((call) => call.url === "/api/cases/case-1/runs/link");
    expect(post?.body).toMatchObject({ force: true, force_reason: "사본 경로로 처리" });
  });

  it("links without force when the paths match (case/separator insensitive)", () => {
    expect(samePathText("D:/ev/a/", "d:\\EV\\a")).toBe(true);
    expect(samePathText("D:/ev/a", "D:/ev/b")).toBe(false);
  });
});

describe("review 6: automatic output location text", () => {
  it("says folder evidence gets its output inside the folder", () => {
    const row = summarizeRunRequest({ output_dir: null }).find((r) => r.key === "output_dir");
    expect(row?.value).toContain("폴더 증거는 그 폴더 안에");
    expect(row?.value).toContain("파일 증거는 파일 옆에");
  });
});

describe("review 7: re-hash button", () => {
  it("offers 해시 다시 계산 for an interrupted file item and posts the re-hash", async () => {
    const { calls } = mockFetch({
      "POST /api/cases/case-1/evidence/C-EVID-000001/hash": {
        evidence: evidenceRow({ hash_status: "hashing" }),
      },
    });
    renderWithQuery(
      <EvidenceHashButton
        caseId="case-1"
        item={evidenceRow({ size_bytes: 10, hash_status: "interrupted", source_type: "export" })}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "증거 E-01 해시 다시 계산" }));
    await waitFor(() =>
      expect(calls.some((call) => call.url === "/api/cases/case-1/evidence/C-EVID-000001/hash")).toBe(true),
    );
    cleanup();
    // Folder evidence and a running hash have no button.
    renderWithQuery(
      <EvidenceHashButton caseId="case-1" item={evidenceRow({ hash_status: "interrupted" })} />,
    );
    expect(screen.queryByRole("button")).toBeNull();
  });
});

describe("review 9: edit sends only changed fields", () => {
  const detail = {
    case_id: "case-1",
    case_number: "2026-1",
    name: "사건",
    case_type: "",
    examiner: "홍길동",
    requester: "",
    organization: "",
    description: "",
    case_root: "",
    citation_prefix: "2026-1",
    evidence: [],
  } as unknown as CaseDetail;

  it("diffs the form against the loaded case", () => {
    const form = {
      caseNumber: "2026-1",
      name: "  ",
      caseType: "",
      examiner: "홍길동",
      requester: "경찰청",
      organization: "",
      description: "",
      caseRoot: "",
    };
    expect(changedCaseFields(detail, form)).toEqual({ name: "", requester: "경찰청" });
  });

  it("PATCHes only the edited field", async () => {
    const { calls } = mockFetch({
      "GET /api/cases/case-1": { case: detail },
      "PATCH /api/cases/case-1": { case: { ...detail, requester: "경찰청" } },
    });
    const onClose = vi.fn();
    renderWithQuery(<CaseEditDialog caseId="case-1" onClose={onClose} />);
    await screen.findByLabelText("의뢰처");
    fill("의뢰처", "경찰청");
    fireEvent.click(screen.getByRole("button", { name: "저장" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(calls.find((call) => call.method === "PATCH")?.body).toEqual({ requester: "경찰청" });
  });
});

describe("review 10: retry adopts evidence that already exists", () => {
  it("adopts the saved row on 409 instead of failing forever", async () => {
    let attempts = 0;
    const { calls } = mockFetch({
      "POST /api/cases/evidence-check": RUNNABLE,
      "POST /api/cases": { case: { case_id: "case-9", case_number: "9", evidence: [] } },
      "POST /api/cases/case-9/evidence": () => {
        attempts += 1;
        return new Response(JSON.stringify({ detail: "같은 경로의 증거가 이미 있습니다: 증거 E-01" }), {
          status: 409,
        });
      },
      "GET /api/cases/case-9/evidence": {
        evidence: [evidenceRow({ case_id: "case-9", citation_id: "9-EVID-000001", path: "d:/ev/A" })],
      },
      "POST /api/cases/case-9/runs": { run: { run_id: "run-9" }, snapshot: {} },
    });
    renderWithQuery(<CaseWizard runIsActive={false} onClose={vi.fn()} />);
    await fillWizard([["folder", "D:\\ev\\a"]], "9");
    await screen.findByTestId("wizard-step-options");
    fireEvent.click(screen.getByTestId("wizard-submit"));
    await waitFor(() => expect(window.location.hash).toBe("#/case/run-9/intake"));
    expect(attempts).toBe(1);
    const run = calls.find((call) => call.url === "/api/cases/case-9/runs");
    const runBody = run?.body as { evidence_citation_id?: string } | undefined;
    expect(runBody?.evidence_citation_id).toBe("9-EVID-000001");
  });

  it("matches by path only (a same-number row with another path is a real conflict)", () => {
    const draft = { ...newEvidenceDraft([]), evidenceNumber: "E-01", path: "D:\\ev\\a" };
    expect(adoptableEvidence([evidenceRow({ path: "D:/ev/a" })], draft)?.citation_id).toBe("C-EVID-000001");
    expect(adoptableEvidence([evidenceRow({ path: "D:/ev/zzz" })], draft)).toBeNull();
  });
});

describe("review 11: citation prefix while the case link loads", () => {
  it("blocks citation copy while loading and resolves the link before copying", async () => {
    useCaseLinks.getState().setLoading("r1", true);
    expect(citationDisabledReason("r1")).toBe(CASE_LINK_LOADING_REASON);
    expect(CASE_LINK_LOADING_REASON).toBe("케이스 정보를 불러오는 중입니다");
    useCaseLinks.getState().setLink("r1", null);
    expect(citationDisabledReason("r1")).toBeUndefined();
    // Nothing loading it (viewer window): not blocked, the copy resolves the link first.
    expect(citationDisabledReason("r2")).toBeUndefined();
    mockFetch({
      "GET /api/runs/r2/processing-snapshot": {
        source: "case-db",
        run_id: "r2",
        case_id: "c1",
        evidence_citation_id: "e1",
        snapshot: {},
        case: { case_number: "2026-고단-1" },
        evidence: { evidence_number: "E-03" },
      },
    });
    await resolveCaseLink("r2");
    const text = buildCitation(
      { runId: "r2", sourcePath: "C:/x", ref: { collection: "files", locator: "/candidates/1" } } as never,
      null,
    );
    expect(text.startsWith("사건=2026-고단-1; 증거=E-03; ")).toBe(true);
  });
});

describe("review 12: Enter moves on", () => {
  it("Enter in a field goes to the next step; IME composition Enter does not", async () => {
    mockFetch({ "POST /api/cases/evidence-check": RUNNABLE });
    renderWithQuery(<CaseWizard runIsActive={false} onClose={vi.fn()} />);
    const number = screen.getByLabelText("사건 번호", { exact: false });
    fireEvent.change(number, { target: { value: "2026-1" } });
    fireEvent.keyDown(number, { key: "Enter", keyCode: 229, isComposing: true });
    expect(screen.getByTestId("wizard-step-info")).toBeTruthy();
    fireEvent.keyDown(number, { key: "Enter" });
    const step2 = await screen.findByTestId("wizard-step-evidence");
    const path = within(step2).getByLabelText("증거 경로", { exact: false });
    fireEvent.change(path, { target: { value: "D:\\ev\\a.E01" } });
    // A switch keeps Enter (no step change).
    fireEvent.keyDown(within(step2).getByRole("switch"), { key: "Enter" });
    expect(screen.getByTestId("wizard-step-evidence")).toBeTruthy();
    fireEvent.keyDown(path, { key: "Enter" });
    expect(await screen.findByTestId("wizard-step-options")).toBeTruthy();
    // The form has a (hidden) submit button, so implicit submission is defined too.
    const form = screen.getByTestId("wizard-step-options").closest("form") as HTMLFormElement;
    expect(form.querySelector("button[type=submit][hidden]")).not.toBeNull();
  });
});
