// T-034 (WB-4, GAP-129 / IS-094 / QA-086): destructive confirmations say what happens, use the danger
// button, start on 취소, need an explicit click and treat Esc as cancel; the shared Modal's Tab cycle
// skips aria-disabled and hidden elements.
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DeleteCaseDialog } from "./CasePicker";
import { buildCaseCommands, runSampleWithConfirm } from "./commands";
import { DELETE_RUN_LABEL, DELETE_RUN_TITLE } from "./dialogs";
import { Modal } from "./Modal";
import { mockFetch, renderWithQuery } from "./testUtils";
import { confirmWrite, useWriteConfirm, WriteConfirmHost } from "./WriteConfirm";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  useWriteConfirm.getState().settle(false);
});

const tab = (shift = false) =>
  fireEvent.keyDown(document.activeElement as HTMLElement, { key: "Tab", shiftKey: shift });
const focused = () => (document.activeElement as HTMLElement | null)?.textContent ?? "";

describe("Modal Tab cycle (T-034)", () => {
  it("cycles over the visible, enabled stops both ways and never leaves the dialog", () => {
    render(
      <Modal title="t" onClose={() => {}}>
        <button type="button">하나</button>
        <button type="button">둘</button>
      </Modal>,
    );
    // No field: the first stop is the header's 닫기 (icon button, empty text).
    expect(document.activeElement?.getAttribute("aria-label")).toBe("닫기");
    tab();
    expect(focused()).toBe("하나");
    tab();
    expect(focused()).toBe("둘");
    tab();
    expect(document.activeElement?.getAttribute("aria-label")).toBe("닫기");
    tab(true);
    expect(focused()).toBe("둘");
  });

  it('skips aria-disabled="true"', () => {
    render(
      <Modal title="t" onClose={() => {}}>
        <button type="button">하나</button>
        <button type="button" aria-disabled="true">
          막힘
        </button>
      </Modal>,
    );
    screen.getByText("하나").focus();
    tab();
    // 막힘 is last in the DOM: the cycle wraps to 닫기 instead of stopping on it.
    expect(document.activeElement?.getAttribute("aria-label")).toBe("닫기");
    tab(true);
    expect(focused()).toBe("하나");
  });

  it("skips elements with the hidden attribute (on themselves or an ancestor)", () => {
    render(
      <Modal title="t" onClose={() => {}}>
        <button type="button">하나</button>
        <button type="button" hidden>
          숨김
        </button>
        <div hidden>
          <button type="button">숨김 안</button>
        </div>
        <button type="button">둘</button>
      </Modal>,
    );
    screen.getByText("하나").focus();
    tab();
    expect(focused()).toBe("둘");
  });

  it("skips display:none elements (on themselves or an ancestor)", () => {
    render(
      <Modal title="t" onClose={() => {}}>
        <button type="button">하나</button>
        <button type="button" style={{ display: "none" }}>
          안 보임
        </button>
        <div style={{ display: "none" }}>
          <button type="button">안 보임 안</button>
        </div>
        <button type="button">둘</button>
      </Modal>,
    );
    screen.getByText("둘").focus();
    tab();
    expect(document.activeElement?.getAttribute("aria-label")).toBe("닫기");
    tab(true);
    expect(focused()).toBe("둘");
    tab(true);
    expect(focused()).toBe("하나");
  });
});

describe("처리 결과 삭제 dialog (T-034)", () => {
  it("names the command the way its dialog is titled", () => {
    const command = buildCaseCommands({ reportCandidates: 0 }).find((c) => c.id === "case.delete");
    expect(command?.label).toBe(DELETE_RUN_LABEL);
    expect(DELETE_RUN_LABEL).toBe(`${DELETE_RUN_TITLE}…`);
    renderWithQuery(<DeleteCaseDialog runId="r9" currentRunId={null} onClose={() => {}} />);
    expect(screen.getByRole("dialog", { name: DELETE_RUN_TITLE })).toBeTruthy();
  });

  it("says what happens, starts on 취소, uses the danger button and deletes only on click", async () => {
    const { calls } = mockFetch({ "DELETE /api/runs/r9": new Response(null, { status: 204 }) });
    const onClose = vi.fn();
    renderWithQuery(<DeleteCaseDialog runId="r9" currentRunId={null} onClose={onClose} />);
    const dialog = screen.getByTestId("delete-run-dialog");
    expect(dialog.textContent).toContain("목록(등록 정보)에서만 제거합니다");
    expect(dialog.textContent).toContain("출력 폴더와 그 안의 결과 파일은 디스크에 그대로 남으며");
    expect(dialog.textContent).toContain("원본 증거 파일은 바꾸지 않습니다");
    const cancel = screen.getByTestId("delete-run-cancel");
    expect(document.activeElement).toBe(cancel);
    const ok = screen.getByRole("button", { name: "삭제" });
    expect(ok.className).toContain("danger");
    expect(ok.className).not.toContain("primary");
    // Enter on the focused 취소 is a cancel, never a delete.
    fireEvent.click(cancel);
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(0);
  });

  it("Esc cancels without a request", () => {
    const { calls } = mockFetch({});
    const onClose = vi.fn();
    renderWithQuery(<DeleteCaseDialog runId="r9" currentRunId={null} onClose={onClose} />);
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(0);
  });
});

describe("write confirmations that overwrite or cannot be undone (T-034)", () => {
  it("샘플 케이스 실행 (replaces the previous sample) uses the danger button and starts on 취소", async () => {
    mockFetch({});
    render(<WriteConfirmHost />);
    let result: Promise<string | null> = Promise.resolve(null);
    act(() => {
      result = runSampleWithConfirm();
    });
    expect(screen.getByTestId("write-confirm").textContent).toContain("이전 샘플은 덮어씀");
    expect(document.activeElement).toBe(screen.getByTestId("write-confirm-cancel"));
    expect(screen.getByTestId("write-confirm-ok").className).toContain("danger");
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "Escape" });
    await act(async () => {
      expect(await result).toBeNull();
    });
  });

  it("a plain write keeps the primary button", () => {
    render(<WriteConfirmHost />);
    act(() => {
      void confirmWrite({ title: "쓰기", writes: [{ what: "a", where: "b" }], confirmLabel: "확인" });
    });
    const ok = screen.getByTestId("write-confirm-ok");
    expect(ok.className).toContain("primary");
    expect(ok.className).not.toContain("danger");
    expect(document.activeElement).toBe(screen.getByTestId("write-confirm-cancel"));
  });
});
