// 접수 case cards (AXIOM adoption E1; r7 merged cards): 사건 정보 · 증거 · 처리 경고·제한 사항 · 노트·메모,
// and the caseless-run fallback (Q-X2). 메모 보호 (T-144) lives in caseMemo.test.tsx.

import { cleanup, configure, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetAppStore } from "../../state/store";
import { registerCaseCommands } from "../case/commands";
import { useCaseDialogs } from "../case/dialogs";
import { mockFetch, renderWithQuery } from "../case/testUtils";
import { CaseDashboard } from "./CaseDashboard";
import { cardOf, notes, routes } from "./caseCardsTestData";

// The full suite runs many files in parallel: give async queries room beyond the 1 s default.
configure({ asyncUtilTimeout: 5000 });

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
    // E01 (T-129): container-byte labels, a mismatch is amber and says the media hash was not compared.
    expect(within(evidence).getByText("컨테이너 해시가 입력값과 다름 — 매체 해시 미대조")).toBeTruthy();
    expect(within(evidence).getByText("컨테이너 해시 일치")).toBeTruthy();
    expect(within(evidence).queryByText("해시 불일치")).toBeNull();
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
