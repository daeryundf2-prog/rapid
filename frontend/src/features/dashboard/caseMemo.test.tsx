// 메모 보호 (T-144) of the 접수 노트·메모 block (caseMemo.tsx): Korean failure text for memo add/delete
// and the unsaved-input leave guard.

import { cleanup, configure, fireEvent, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetAppStore, useAppStore } from "../../state/store";
import { registerCaseCommands } from "../case/commands";
import { useCaseDialogs } from "../case/dialogs";
import { mockFetch, renderWithQuery } from "../case/testUtils";
import { CaseDashboard } from "./CaseDashboard";
import { cardOf, routes } from "./caseCardsTestData";

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
