import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { authToken, clearAuthToken } from "../../api/client";
import type { RunWithProgress } from "../../api/runsProgress";
import { TokenGate } from "../../app/TokenGate";
import { useAppStore } from "../../state/store";
import { registerCaseCommands } from "./commands";
import { caseIndex, LANDING_RECENT_COUNT, Landing, NO_CASE_LABEL, recentCaseRow } from "./Landing";
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

  it("each recent row leads with the case number and name, then activity, then the evidence (F29)", async () => {
    mockFetch({
      "GET /api/cases": {
        cases: [
          {
            case_id: "c1",
            case_number: "2026-1",
            name: "회계 부정 내부 감사 — 재무팀 공용 PC 두 대와 메일함 사본",
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
          request: { root: "C:/a", mode: "fraud" },
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
    await waitFor(() =>
      expect(screen.getAllByRole("link")[0]?.querySelector(".landing-case-number")?.textContent).toBe(
        "2026-1",
      ),
    );
    const first = screen.getAllByRole("link")[0] as HTMLElement;
    const title = first.querySelector(".landing-case-title") as HTMLElement;
    // The title is the row's first child: number, then the whole name (wraps, no ellipsis).
    expect(first.firstElementChild).toBe(title);
    expect(title.textContent).toBe("2026-1회계 부정 내부 감사 — 재무팀 공용 PC 두 대와 메일함 사본");
    expect(first.querySelector(".landing-case-meta")?.textContent).toContain("마지막 활동");
    expect(first.querySelector(".landing-case-meta")?.textContent).toContain("문서·부정 조사");
    expect(first.querySelector(".landing-case-evidence")?.textContent).toContain("E-01");
    expect(screen.getAllByRole("link")[1]?.querySelector(".landing-case-title")?.textContent).toBe(
      "케이스 없음b",
    );
  });

  it("recentCaseRow: a case named like its number shows the evidence folder; the last update orders", () => {
    const index = caseIndex([
      {
        case_number: "2026-7",
        name: "2026-7",
        evidence: [{ evidence_number: "E-02", runs: [{ run_id: "r1" }] }],
      },
    ] as never);
    const row = recentCaseRow(
      {
        run_id: "r1",
        created_at: "2026-10-01T00:00:00Z",
        updated_at: "2026-10-03T00:00:00Z",
        request: { root: "/ev/disk-a/" },
      },
      index,
    );
    expect(row).toEqual({
      number: "2026-7",
      name: "disk-a",
      evidence: "E-02",
      activeAt: "2026-10-03T00:00:00Z",
      mode: "",
    });
    // Case list still loading: no number yet rather than a wrong "케이스 없음".
    expect(recentCaseRow({ run_id: "r9", request: { root: "/x/y" } }, null).number).toBe("");
    expect(recentCaseRow({ run_id: "r9", request: { root: "/x/y" } }, index).number).toBe(NO_CASE_LABEL);
  });

  it("one primary start; 열기 · 빠른 런 · 샘플 are one quieter group", () => {
    const unregister = registerCaseCommands({ reportCandidates: undefined });
    renderWithQuery(<Landing />);
    expect(screen.getByTestId("landing-create").className).toContain("primary");
    const group = screen.getByRole("group", { name: "다른 시작 방법" });
    for (const id of ["landing-open", "landing-run", "landing-sample"]) {
      const button = screen.getByTestId(id);
      expect(group.contains(button)).toBe(true);
      expect(button.className).not.toContain("primary");
    }
    unregister();
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
