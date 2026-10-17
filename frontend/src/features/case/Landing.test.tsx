import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { authToken, clearAuthToken } from "../../api/client";
import type { RunWithProgress } from "../../api/runsProgress";
import { TokenGate } from "../../app/TokenGate";
import { useAppStore } from "../../state/store";
import { registerCaseCommands } from "./commands";
import { LANDING_RECENT_COUNT, Landing } from "./Landing";
import { mockFetch, renderWithQuery } from "./testUtils";

afterEach(() => {
  cleanup();
  useAppStore.setState({ runs: [] });
  vi.unstubAllGlobals();
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
    renderWithQuery(<Landing />);
    const links = screen.getAllByRole("link");
    expect(links).toHaveLength(LANDING_RECENT_COUNT);
    expect(links[0]?.textContent).toContain(`case${LANDING_RECENT_COUNT + 1}`);
    expect(links[0]?.getAttribute("href")).toBe(`#/case/run-${LANDING_RECENT_COUNT + 1}aaaaaaa/intake`);
  });

  it("start actions: 케이스 만들기 first, the quick run labelled 케이스 없이 빠른 런 (E1)", () => {
    const unregister = registerCaseCommands({ reportCandidates: undefined });
    renderWithQuery(<Landing />);
    const names = screen
      .getAllByRole("button")
      .map((button) => button.textContent?.trim())
      .filter(Boolean);
    expect(names.slice(0, 4)).toEqual(["케이스 만들기", "케이스 열기", "케이스 없이 빠른 런", "샘플"]);
    unregister();
  });

  it("recent runs show 사건 › 증거 for case runs and 케이스 없음 for the others (Q-X2)", async () => {
    mockFetch({
      "GET /api/cases": {
        cases: [
          {
            case_id: "c1",
            case_number: "2026-1",
            name: "x",
            evidence: [{ citation_id: "e1", evidence_number: "E-01", runs: [{ run_id: "run-linked01" }] }],
          },
        ],
      },
    });
    useAppStore.setState({
      runs: [
        {
          run_id: "run-linked01",
          status: "completed",
          created_at: "2026-10-02T00:00:00Z",
          request: { root: "C:/a" },
        },
        {
          run_id: "run-loose001",
          status: "completed",
          created_at: "2026-10-01T00:00:00Z",
          request: { root: "C:/b" },
        },
      ] as unknown as RunWithProgress[],
    });
    renderWithQuery(<Landing />);
    await waitFor(() => expect(screen.getAllByRole("link")[0]?.textContent).toContain("2026-1 › E-01"));
    expect(screen.getAllByRole("link")[1]?.textContent).toContain("케이스 없음");
  });

  it("with no cases says how to start", () => {
    renderWithQuery(<Landing />);
    expect(screen.getByText(/아직 케이스가 없습니다/)).toBeTruthy();
  });

  it("start actions carry their icons: open = folder, run = play, sample = package (B2 #6)", () => {
    const unregister = registerCaseCommands({ reportCandidates: undefined });
    renderWithQuery(<Landing />);
    const icon = (testId: string) =>
      screen.getByTestId(testId).querySelector("svg")?.getAttribute("data-icon");
    expect(icon("landing-create")).toBe("inbox");
    expect(icon("landing-open")).toBe("folder");
    expect(icon("landing-run")).toBe("play");
    expect(icon("landing-sample")).toBe("package");
    unregister();
  });
});
