import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ANNOUNCE_DEBOUNCE_MS, getAnnouncerSnapshot, resetAnnouncer } from "../a11y/announcer";
import { LoadingCard } from "../features/views/ViewState";
import { WAIT_DELAY_MS, WaitPanel, waitText } from "./WaitPanel";

const LABEL = "트리 불러오는 중…";
const advance = (ms: number) =>
  act(() => {
    vi.advanceTimersByTime(ms);
  });
const elapsed = () => screen.getByTestId("wait").querySelector(".wait-panel-elapsed")?.textContent;

beforeEach(() => {
  vi.useFakeTimers();
  resetAnnouncer();
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("WaitPanel", () => {
  it("stays out of a load that ends within the delay", () => {
    const view = render(<WaitPanel label={LABEL} testId="wait" />);
    advance(WAIT_DELAY_MS - 1);
    expect(screen.queryByTestId("wait")).toBeNull();
    view.unmount();
    advance(5000);
    expect(getAnnouncerSnapshot().polite).toBe("");
  });

  it("appears after the delay and counts the whole seconds waited", () => {
    render(<WaitPanel label={LABEL} testId="wait" />);
    advance(WAIT_DELAY_MS);
    expect(screen.getByTestId("wait").textContent).toContain(LABEL);
    expect(elapsed()).toBe(waitText(0));
    advance(1000 - WAIT_DELAY_MS - 1);
    expect(elapsed()).toBe(waitText(0));
    advance(1);
    expect(elapsed()).toBe(waitText(1));
    advance(2000);
    expect(elapsed()).toBe(waitText(3));
    advance(62_000);
    expect(elapsed()).toBe(waitText(65));
  });

  it("says the label once through the shell's live region and is not one itself", () => {
    const view = render(<WaitPanel label={LABEL} testId="wait" />);
    advance(WAIT_DELAY_MS);
    // The announcer debounces: the sentence lands one debounce after the panel appeared.
    advance(ANNOUNCE_DEBOUNCE_MS.polite);
    expect(getAnnouncerSnapshot().polite.trim()).toBe(LABEL);
    expect(document.querySelector("[aria-live],[role=status],[role=alert]")).toBeNull();
    // A label that changes while waiting (행 n개 확인) is not announced again.
    resetAnnouncer();
    view.rerender(<WaitPanel label="다른 문장" testId="wait" />);
    advance(3000);
    expect(getAnnouncerSnapshot().polite).toBe("");
  });

  it("writes minutes from 60 seconds", () => {
    expect([waitText(0), waitText(59), waitText(60), waitText(65)]).toEqual([
      "0초",
      "59초",
      "1분 0초",
      "1분 5초",
    ]);
  });
});

describe("LoadingCard", () => {
  it("is the wait panel with its 취소 action", () => {
    const onCancel = vi.fn();
    render(<LoadingCard label={LABEL} onCancel={onCancel} />);
    expect(screen.queryByRole("button")).toBeNull();
    advance(WAIT_DELAY_MS + 2000);
    expect(document.querySelector(".wait-panel-elapsed")?.textContent).toBe(waitText(2));
    fireEvent.click(screen.getByRole("button", { name: "취소" }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });
});
