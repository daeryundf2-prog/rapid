// 접수 case cards (AXIOM adoption E1; r7 merged cards): 사건 정보 · 증거 · 처리 경고·제한 사항 · 노트·메모,
// and the caseless-run fallback (Q-X2).

import { cleanup, configure, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetAppStore, useAppStore } from "../../state/store";
import { registerCaseCommands } from "../case/commands";
import { useCaseDialogs } from "../case/dialogs";
import { mockFetch, type RecordedCall, renderWithQuery } from "../case/testUtils";
import { CaseDashboard } from "./CaseDashboard";

const run = {
  run_id: "r1",
  status: "completed",
  created_at: "2026-10-17T00:00:00Z",
  request: { root: "D:/ev/a.E01", mode: "fraud" },
};

const caseDetail = {
  case_id: "case-1",
  case_number: "2026-고단-1234",
  name: "법인 자금 유출",
  case_type: "횡령·배임",
  examiner: "홍길동",
  requester: "서울중앙지검",
  organization: "",
  description: "",
  case_root: "",
  citation_prefix: "2026-고단-1234",
  status: "open",
  created_at: "2026-10-17T00:00:00Z",
  updated_at: "2026-10-17T00:00:00Z",
  evidence_count: 2,
  run_count: 1,
  note_count: 1,
  evidence: [
    {
      citation_id: "2026-고단-1234-EVID-000002",
      evidence_number: "E-10",
      display_name: "b.E01",
      source_type: "e01",
      path: "D:/ev/b.E01",
      size_bytes: 10,
      hash_status: "mismatched",
      hash_status_label: "해시 불일치",
      hash_message: "MD5 기대값 … / 계산값 …",
      hashes: {},
      runs: [],
    },
    {
      citation_id: "2026-고단-1234-EVID-000001",
      evidence_number: "E-2",
      display_name: "a.E01",
      source_type: "e01",
      path: "D:/ev/a.E01",
      size_bytes: 10,
      hash_status: "matched",
      hash_status_label: "해시 일치",
      hash_message: "",
      hashes: { md5: "a" },
      runs: [{ run_id: "r1", exists: true, status: "completed" }],
    },
  ],
};

const snapshotLinked = {
  source: "case-db",
  run_id: "r1",
  case_id: "case-1",
  evidence_citation_id: "2026-고단-1234-EVID-000001",
  captured_at: "2026-10-17T00:00:00Z",
  snapshot: {
    origin: "case-run",
    evidence: { evidence_number: "E-2", path: "D:/ev/a.E01" },
    request: { root: "D:/ev/a.E01", mode: "fraud", read_only: true, max_file_count: 500, case_db: true },
    profile: { keywords: ["송금", "invoice"], artifacts_kinds: ["browser", "eventlog"] },
  },
  case: caseDetail,
  evidence: caseDetail.evidence[1],
};

const problems = {
  run_id: "r1",
  total: 23,
  by_level: { warning: 3, notice: 20 },
  limit: 20,
  groups: [
    {
      reason_id: "row-truncated",
      label_ko: "행 단위 절단 (원문 일부만 보존)",
      level: "warning",
      count: 3,
      steps: [],
      items: [
        { source: "warning", step: "artifacts-recent-files", level: "warning", message: "행 단위 절단 10행" },
      ],
    },
    {
      reason_id: "no-rows",
      label_ko: "수집된 행 없음",
      level: "notice",
      count: 22,
      steps: [],
      items: Array.from({ length: 20 }, (_, i) => ({
        source: "warning",
        step: `artifacts-k${i}`,
        level: "notice",
        message: `No k${i} artifact rows were collected.`,
      })),
    },
  ],
};

let notes = {
  notes: [
    {
      id: 1,
      case_id: "case-1",
      author: "홍길동",
      text: "압수 목록 확인",
      created_at: "2026-10-17T01:00:00Z",
      updated_at: "2026-10-17T01:00:00Z",
      deleted_at: null,
      deleted_by: "",
    },
  ],
  count: 1,
  deleted_count: 0,
  history: [
    {
      id: 1,
      note_id: 1,
      action: "created",
      actor: "홍길동",
      at: "2026-10-17T01:00:00Z",
      text: "압수 목록 확인",
    },
  ],
};

function routes(linked: boolean) {
  return {
    "GET /api/runs/r1": run,
    "GET /api/runs/r1/processing-snapshot": linked
      ? snapshotLinked
      : {
          source: "run-request",
          run_id: "r1",
          case_id: null,
          evidence_citation_id: null,
          captured_at: "2026-10-17T00:00:00Z",
          snapshot: {
            origin: "run-request",
            request: { root: "D:/ev/a.E01", mode: "fraud", read_only: true },
          },
          case: null,
          evidence: null,
        },
    "GET /api/cases/case-1": { case: caseDetail },
    "GET /api/cases/case-1/notes": () => notes,
    "POST /api/cases/case-1/notes": (call: RecordedCall) => {
      const body = call.body as { text: string; author: string };
      const note = {
        ...notes.notes[0],
        id: 2,
        text: body.text,
        author: body.author,
        created_at: "2026-10-17T02:00:00Z",
      };
      notes = { ...notes, notes: [note as (typeof notes.notes)[0], ...notes.notes], count: 2 };
      return { note };
    },
    "GET /api/runs/r1/problems": problems,
    "GET /api/runs/r1/dashboard": {
      run_id: "r1",
      completed: true,
      profile: { mode: "fraud", description: "", keywords: [] },
      evidence_source: {
        path: "D:/ev/a.E01",
        name: "a.E01",
        kind: "image",
        image_output: "e01",
        size_bytes: 10,
        partitions: [],
        selected_partition: null,
      },
      exports: [],
    },
    "GET /api/runs/r1/case-notes": {
      run_id: "r1",
      examiner: "",
      summary: "",
      updated_at: null,
      exists: false,
    },
  };
}

// The full suite runs many files in parallel: give async queries room beyond the 1 s default.
configure({ asyncUtilTimeout: 5000 });

const cardOf = (title: string) =>
  screen.getByRole("heading", { name: title }).closest("section") as HTMLElement;

let unregister: () => void = () => {};
beforeEach(() => {
  unregister = registerCaseCommands({ reportCandidates: 0 });
  window.localStorage.clear();
  window.history.replaceState(null, "", "/v2/#/case/r1/intake");
  resetAppStore({ route: { runId: "r1", collection: "intake" } });
});
afterEach(() => {
  unregister();
  cleanup();
  vi.unstubAllGlobals();
  useCaseDialogs.setState({ open: null, target: {} });
});

describe("접수 case cards (Q-X1/Q-X3/Q-X4, r7 merged cards)", () => {
  it("fills 사건 정보 · 증거 · 처리 경고·제한 사항 · 노트·메모 for a case run", async () => {
    const { calls } = mockFetch(routes(true));
    renderWithQuery(<CaseDashboard runId="r1" />);

    await waitFor(() => expect(within(cardOf("사건 정보")).getByText("서울중앙지검")).toBeTruthy());
    // The crumb names case › evidence; the raw run id is not printed (tooltip + copy action only).
    const crumb = screen.getByTestId("case-crumb");
    expect(crumb.textContent).toContain("2026-고단-1234 › E-2");
    expect(crumb.textContent).not.toContain("r1");

    const evidence = cardOf("증거");
    const numbers = [...evidence.querySelectorAll(".dash-evidence-number")].map((el) => el.textContent);
    // Korean natural order: E-2 before E-10.
    expect(numbers).toEqual(["E-2", "E-10"]);
    expect(within(evidence).getByText("해시 불일치")).toBeTruthy();
    expect(within(evidence).getByText("해시 일치")).toBeTruthy();
    const link = within(evidence).getByRole("link", { name: "증거 E-2 이 런 열기" });
    expect(link.textContent).toBe("이 런");
    expect(link.getAttribute("title")).toBe("런 ID r1");
    fireEvent.click(within(evidence).getByRole("button", { name: "증거 E-10 런 시작" }));
    expect(useCaseDialogs.getState().open).toBe("run-add");
    expect(useCaseDialogs.getState().target).toEqual({
      caseId: "case-1",
      evidenceCitationId: "2026-고단-1234-EVID-000002",
    });
    expect(within(evidence).getByRole("button", { name: "증거 추가" })).toBeTruthy();
    // 처리 설정 스냅샷 left the intake dashboard.
    expect(screen.queryByTestId("snapshot")).toBeNull();

    const warnings = cardOf("처리 경고·제한 사항");
    await waitFor(() => expect(within(warnings).getByText("수집된 행 없음")).toBeTruthy());
    const preview = within(warnings).getByRole("list", { name: "수집된 행 없음 미리보기" });
    expect(within(preview).getAllByRole("listitem")).toHaveLength(20);
    // Step ids read in Korean, the raw id is the tooltip.
    expect(preview.textContent).not.toContain("artifacts-k0");
    expect(within(warnings).getByText("미리보기 20건 / 전체 22건")).toBeTruthy();
    fireEvent.click(within(warnings).getByRole("button", { name: "수집된 행 없음 전체 보기 (22건)" }));
    expect(useCaseDialogs.getState().target).toMatchObject({ runId: "r1", reasonId: "no-rows" });
    expect(warnings.querySelector(".dash-card-meta")?.textContent).toBe("경고 3 · 알림 20 · 제한 0");

    const memo = cardOf("노트·메모");
    await waitFor(() => expect(within(memo).getByText("압수 목록 확인")).toBeTruthy());
    expect(within(memo).getByText("홍길동")).toBeTruthy();
    // One 검사관 field (from the case) drives the memo author.
    expect((within(memo).getByLabelText("검사관") as HTMLInputElement).value).toBe("홍길동");
    expect(within(memo).queryByLabelText("작성자")).toBeNull();
    expect(within(memo).getByRole("button", { name: "이력 1건" })).toBeTruthy();
    fireEvent.change(within(memo).getByLabelText("새 메모"), { target: { value: "USB 2개 확인" } });
    fireEvent.click(within(memo).getByRole("button", { name: "메모 추가" }));
    await waitFor(() => expect(within(memo).getByText("USB 2개 확인")).toBeTruthy());
    const post = calls.find((call) => call.method === "POST");
    expect(post?.body).toEqual({ text: "USB 2개 확인", author: "홍길동" });
  });

  it("memo delete asks first: wording, focus on 취소, Esc cancels, danger 삭제 deletes (T-034)", async () => {
    const { calls } = mockFetch({
      ...routes(true),
      "DELETE /api/cases/case-1/notes/1": { note: { ...notes.notes[0], deleted_at: "2026-10-18T00:00:00Z" } },
    });
    renderWithQuery(<CaseDashboard runId="r1" />);
    const memo = await waitFor(() => {
      const card = cardOf("노트·메모");
      expect(within(card).getByText("압수 목록 확인")).toBeTruthy();
      return card;
    });
    // The first test may have added a memo: take the delete button of "압수 목록 확인" (note 1).
    const item = within(memo).getByText("압수 목록 확인").closest("li") as HTMLElement;
    const opener = within(item).getByRole("button", { name: /^홍길동 메모 삭제/ });
    fireEvent.click(opener);
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);
    let confirm = within(item).getByRole("group", { name: "메모 삭제 확인" });
    expect(confirm.textContent).toContain("메모 이력에는 삭제 기록으로 남고");
    expect(document.activeElement).toBe(within(confirm).getByTestId("memo-delete-cancel"));
    expect(within(confirm).getByTestId("memo-delete-ok").className).toContain("danger");

    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "Escape" });
    expect(within(memo).queryByRole("group", { name: "메모 삭제 확인" })).toBeNull();
    expect(document.activeElement).toBe(opener);
    expect(calls.some((call) => call.method === "DELETE")).toBe(false);

    fireEvent.click(opener);
    confirm = within(item).getByRole("group", { name: "메모 삭제 확인" });
    fireEvent.click(within(confirm).getByTestId("memo-delete-ok"));
    await waitFor(() => expect(calls.some((call) => call.method === "DELETE")).toBe(true));
    expect(calls.find((call) => call.method === "DELETE")?.url).toBe(
      "/api/cases/case-1/notes/1?actor=%ED%99%8D%EA%B8%B8%EB%8F%99",
    );
  });

  it("a run without a case keeps working and offers 케이스에 연결 (Q-X2)", async () => {
    mockFetch(routes(false));
    renderWithQuery(<CaseDashboard runId="r1" />);
    const info = await waitFor(() => {
      const section = cardOf("사건 정보");
      expect(within(section).getByTestId("no-case")).toBeTruthy();
      return section;
    });
    expect(within(within(info).getByTestId("no-case")).getByText("케이스 없음")).toBeTruthy();
    expect(within(info).getByRole("button", { name: "케이스에 연결" })).toBeTruthy();
    await waitFor(() => expect(within(cardOf("증거")).getByText("a.E01")).toBeTruthy());
    expect(within(cardOf("증거")).getByText(/케이스에 연결하면/)).toBeTruthy();
    expect(within(cardOf("노트·메모")).getByText(/케이스에 연결하면/)).toBeTruthy();
    await waitFor(() =>
      expect(within(cardOf("처리 경고·제한 사항")).getByText("수집된 행 없음")).toBeTruthy(),
    );
    expect(screen.queryByTestId("case-crumb")).toBeNull();
  });
});

describe("메모 보호 (T-144)", () => {
  const ENGLISH = /[A-Za-z]{3,}/;

  async function openMemo() {
    renderWithQuery(<CaseDashboard runId="r1" />);
    return waitFor(() => {
      const card = cardOf("노트·메모");
      expect(within(card).getByText("압수 목록 확인")).toBeTruthy();
      return card;
    });
  }

  it("a failed delete keeps the confirmation and says why in Korean inside the memo block", async () => {
    mockFetch({
      ...routes(true),
      "DELETE /api/cases/case-1/notes/1": () =>
        new Response(
          JSON.stringify({ detail: "Internal Server Error: sqlite3.OperationalError database is locked" }),
          {
            status: 500,
            headers: { "content-type": "application/json" },
          },
        ),
    });
    const memo = await openMemo();
    const item = within(memo).getByText("압수 목록 확인").closest("li") as HTMLElement;
    fireEvent.click(within(item).getByRole("button", { name: /^홍길동 메모 삭제/ }));
    const confirm = within(item).getByRole("group", { name: "메모 삭제 확인" });
    // Nothing is deleted before the explicit 삭제; focus starts on 취소.
    expect(document.activeElement).toBe(within(confirm).getByTestId("memo-delete-cancel"));
    fireEvent.click(within(confirm).getByTestId("memo-delete-ok"));
    const error = await within(memo).findByTestId("memo-delete-error");
    expect(error.textContent).toContain("메모를 삭제하지 못했습니다");
    expect(error.textContent).not.toMatch(ENGLISH);
    expect(memo.textContent).not.toContain("sqlite3");
    expect(within(item).getByText("압수 목록 확인")).toBeTruthy();
  });

  it("a failed add says why in Korean (no raw English)", async () => {
    mockFetch({
      ...routes(true),
      "POST /api/cases/case-1/notes": () =>
        new Response(JSON.stringify({ detail: "Bad Gateway upstream" }), {
          status: 502,
          headers: { "content-type": "application/json" },
        }),
    });
    const memo = await openMemo();
    fireEvent.change(within(memo).getByLabelText("새 메모"), { target: { value: "추가 실패 확인" } });
    fireEvent.click(within(memo).getByRole("button", { name: "메모 추가" }));
    const error = await within(memo).findByTestId("memo-add-error");
    expect(error.textContent).toContain("메모를 추가하지 못했습니다");
    expect(error.textContent).not.toMatch(ENGLISH);
  });

  it("leaving the screen with unsaved memo input asks first; 취소 keeps the screen", async () => {
    mockFetch(routes(true));
    const memo = await openMemo();
    const confirmSpy = vi.fn((_message?: string) => false);
    vi.stubGlobal("confirm", confirmSpy);
    // Nothing typed: navigation is not interrupted.
    useAppStore.getState().navigate({ runId: "r1", collection: "files" });
    expect(confirmSpy).not.toHaveBeenCalled();
    useAppStore.getState().navigate({ runId: "r1", collection: "intake" });

    fireEvent.change(within(memo).getByLabelText("새 메모"), { target: { value: "아직 저장 안 함" } });
    useAppStore.getState().navigate({ runId: "r1", collection: "files" });
    expect(confirmSpy).toHaveBeenCalledTimes(1);
    expect(confirmSpy.mock.calls[0]?.[0]).toContain("저장하지 않은 내용이 있습니다");
    expect(useAppStore.getState().route.collection).toBe("intake");
    // Staying on the dashboard (same run, same screen) never asks.
    useAppStore.getState().patchRoute({ q: "x" });
    expect(confirmSpy).toHaveBeenCalledTimes(1);

    // An unsaved 검사관 edit counts too; confirming leaves.
    fireEvent.change(within(memo).getByLabelText("새 메모"), { target: { value: "" } });
    fireEvent.change(within(memo).getByLabelText("검사관"), { target: { value: "김 수사관" } });
    confirmSpy.mockReturnValue(true);
    useAppStore.getState().navigate({ runId: "r1", collection: "files" });
    expect(confirmSpy).toHaveBeenCalledTimes(2);
    expect(useAppStore.getState().route.collection).toBe("files");
  });

  it("back/forward away from unsaved input is undone when the analyst stays", async () => {
    mockFetch(routes(true));
    const memo = await openMemo();
    vi.stubGlobal(
      "confirm",
      vi.fn(() => false),
    );
    fireEvent.change(within(memo).getByLabelText("새 메모"), { target: { value: "아직 저장 안 함" } });
    useAppStore.getState().syncRouteFromLocation({ runId: "r1", collection: "files" });
    expect(useAppStore.getState().route.collection).toBe("intake");
    expect(window.location.hash).toBe("#/case/r1/intake");
  });
});
