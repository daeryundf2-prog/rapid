import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { authToken, clearAuthToken } from "../../api/client";
import type { RunWithProgress } from "../../api/runsProgress";
import { TokenGate } from "../../app/TokenGate";
import { useAppStore } from "../../state/store";
import { LANDING_RECENT_COUNT, Landing } from "./Landing";

afterEach(() => {
  cleanup();
  useAppStore.setState({ runs: [] });
});

describe("landing card (visual-polish S10)", () => {
  it("without a token the card asks for it (the token field lives inside the card)", () => {
    const onSaved = vi.fn();
    render(<TokenGate onSaved={onSaved} />);
    const card = screen.getByRole("region", { name: "RapidForensic" });
    const field = screen.getByLabelText("API 토큰");
    expect(card.contains(field)).toBe(true);
    expect(screen.getByRole("main").contains(card)).toBe(true);
    // No start actions until connected.
    expect(screen.queryByRole("button", { name: "샘플" })).toBeNull();
    fireEvent.change(field, { target: { value: "  tok-123  " } });
    fireEvent.click(screen.getByRole("button", { name: "연결" }));
    expect(onSaved).toHaveBeenCalledTimes(1);
    expect(authToken()).toBe("tok-123");
    clearAuthToken();
  });

  it("lists the newest cases first, at most LANDING_RECENT_COUNT, each linking to its 접수", () => {
    const runs = Array.from({ length: LANDING_RECENT_COUNT + 2 }, (_, i) => ({
      run_id: `run-${i}aaaaaaa`,
      status: "completed",
      created_at: `2026-10-0${i + 1}T00:00:00Z`,
      request: { root: `C:/ev/case${i}`, mode: "fraud" },
    }));
    useAppStore.setState({ runs: runs as unknown as RunWithProgress[] });
    render(<Landing />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(LANDING_RECENT_COUNT);
    expect(links[0]?.textContent).toContain(`case${LANDING_RECENT_COUNT + 1}`);
    expect(links[0]?.getAttribute("href")).toBe(`#/case/run-${LANDING_RECENT_COUNT + 1}aaaaaaa/intake`);
  });

  it("with no cases says how to start", () => {
    render(<Landing />);
    expect(screen.getByText(/아직 케이스가 없습니다/)).toBeTruthy();
  });
});
