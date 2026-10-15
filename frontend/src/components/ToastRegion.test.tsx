import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAppStore } from "../state/store";
import { ToastRegion } from "./ToastRegion";
import { pushToast, TOAST_MAX, TOAST_MS, useToastStore } from "./toastStore";

beforeEach(() => {
  vi.useFakeTimers();
  useToastStore.getState().clear();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("toast stack (visual-polish U-V7)", () => {
  it("stacks at most three, oldest dropped first", () => {
    render(<ToastRegion />);
    act(() => {
      for (let i = 1; i <= 5; i++) pushToast(`알림 ${i}`);
    });
    const texts = screen.getAllByTestId("toast").map((t) => t.textContent);
    expect(texts).toHaveLength(TOAST_MAX);
    expect(texts[0]).toContain("알림 3");
    expect(texts[2]).toContain("알림 5");
  });

  it("auto-dismisses after 6 s unless it is an error", () => {
    render(<ToastRegion />);
    act(() => {
      pushToast("저장했습니다", "info");
      pushToast("실패했습니다", "error");
    });
    act(() => {
      vi.advanceTimersByTime(TOAST_MS + 10);
    });
    const tones = screen.getAllByTestId("toast").map((t) => t.dataset.tone);
    expect(tones).toEqual(["error"]);
  });

  it("Esc closes the toast the focus is in", () => {
    render(<ToastRegion />);
    act(() => {
      pushToast("첫 번째", "error");
      pushToast("두 번째", "error");
    });
    const close = screen.getAllByRole("button", { name: "알림 닫기 (Esc)" })[1] as HTMLElement;
    close.focus();
    fireEvent.keyDown(close, { key: "Escape" });
    expect(screen.getAllByTestId("toast").map((t) => t.textContent)).toEqual(["첫 번째"]);
  });

  it("is not a live region (the shell's one polite region stays the only one)", () => {
    render(<ToastRegion />);
    act(() => {
      pushToast("알림", "info");
      pushToast("오류", "error");
    });
    expect(document.querySelectorAll("[aria-live],[role=status],[role=alert]")).toHaveLength(0);
  });

  it("command notices (showNotice) land in the stack", () => {
    render(<ToastRegion />);
    act(() => useAppStore.getState().showNotice("명령: 케이스를 먼저 선택하세요"));
    expect(screen.getByTestId("toast").textContent).toContain("케이스를 먼저 선택하세요");
  });
});
