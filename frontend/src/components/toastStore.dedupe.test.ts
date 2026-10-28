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

  it("does not dedupe different sentences", () => {
    const { push } = useToastStore.getState();
    push("미검토 1/2", "info");
    push("미검토 2/2", "info");
    expect(useToastStore.getState().toasts).toHaveLength(2);
  });
});
