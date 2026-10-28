// 접수 case cards (AXIOM adoption E1; r7 merged cards): 사건 정보 · 증거 · 처리 경고·제한 사항 · 노트·메모,
// and the caseless-run fallback (Q-X2).

import { cleanup, configure, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetAppStore } from "../../state/store";
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
    // One 분석관 field (from the case) drives the memo author.
    expect((within(memo).getByLabelText("분석관") as HTMLInputElement).value).toBe("홍길동");
    expect(within(memo).queryByLabelText("작성자")).toBeNull();
    expect(within(memo).getByRole("button", { name: "이력 1건" })).toBeTruthy();
    fireEvent.change(within(memo).getByLabelText("새 메모"), { target: { value: "USB 2개 확인" } });
    fireEvent.click(within(memo).getByRole("button", { name: "메모 추가" }));
    await waitFor(() => expect(within(memo).getByText("USB 2개 확인")).toBeTruthy());
    const post = calls.find((call) => call.method === "POST");
    expect(post?.body).toEqual({ text: "USB 2개 확인", author: "홍길동" });
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
