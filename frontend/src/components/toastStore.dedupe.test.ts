import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TOAST_DEDUPE_MS, useToastStore } from "./toastStore";

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-10-28T09:00:00Z"));
  useToastStore.getState().clear();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("toast dedupe (todo 17)", () => {
  it("drops an identical toast pushed within 2 s", () => {
    const { push } = useToastStore.getState();
    const first = push("미검토 없음", "info");
    vi.setSystemTime(Date.now() + TOAST_DEDUPE_MS - 1);
    const second = push("미검토 없음", "info");
    expect(second).toBe(first);
    expect(useToastStore.getState().toasts).toHaveLength(1);
  });

  it("shows an identical toast again once the 2 s window has passed", () => {
    const { push } = useToastStore.getState();
    const first = push("미검토 없음", "info");
    vi.setSystemTime(Date.now() + TOAST_DEDUPE_MS);
    const second = push("미검토 없음", "info");
    expect(second).not.toBe(first);
    expect(useToastStore.getState().toasts.map((t) => t.id)).toEqual([second]);
  });

  it("does not dedupe the same sentence in another tone", () => {
    const { push } = useToastStore.getState();
    const first = push("저장됨", "info");
    const second = push("저장됨", "error");
    expect(second).not.toBe(first);
    expect(useToastStore.getState().toasts.map((t) => t.tone)).toEqual(["info", "error"]);
  });

  it("does not dedupe the same sentence with another detail line", () => {
    const { push } = useToastStore.getState();
    push("파일 저장됨", "ok", { detail: "a.csv" });
    push("파일 저장됨", "ok", { detail: "b.csv" });
    expect(useToastStore.getState().toasts.map((t) => t.detail)).toEqual(["a.csv", "b.csv"]);
  });

  it("does not dedupe different sentences", () => {
    const { push } = useToastStore.getState();
    push("미검토 1/2", "info");
    push("미검토 2/2", "info");
    expect(useToastStore.getState().toasts).toHaveLength(2);
  });
});
