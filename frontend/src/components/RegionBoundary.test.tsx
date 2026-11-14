import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useEffect } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetAppStore, useAppStore } from "../state/store";
import { RegionBoundary } from "./RegionBoundary";

let shouldThrow = true;

function Bomb({ inEffect = false }: { inEffect?: boolean }) {
  useEffect(() => {
    if (inEffect && shouldThrow) throw new Error("명령 id 중복: tree.goto.evidence.partition.1");
  }, [inEffect]);
  if (!inEffect && shouldThrow) throw new Error("렌더 실패");
  return <p>정상 화면</p>;
}

beforeEach(() => {
  shouldThrow = true;
  window.history.replaceState(null, "", "/v2/");
  resetAppStore({ route: { runId: "r1", collection: "files" } });
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("RegionBoundary", () => {
  it("contains a render error to its region and keeps siblings alive", () => {
    render(
      <>
        <RegionBoundary region="탐색 트리">
          <Bomb />
        </RegionBoundary>
        <RegionBoundary region="목록">
          <p>목록 행</p>
        </RegionBoundary>
      </>,
    );
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("탐색 트리을(를) 표시하지 못했습니다.");
    expect(alert.textContent).toContain("렌더 실패");
    expect(screen.getByText("목록 행")).toBeTruthy();
    expect(screen.getByRole("button", { name: "다른 화면으로" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "새로 고침" })).toBeTruthy();
  });

  it("catches an effect error (the IMG-B duplicate-command crash) and retries", () => {
    render(
      <RegionBoundary region="콘솔">
        <Bomb inEffect />
      </RegionBoundary>,
    );
    expect(screen.getByRole("alert").textContent).toContain("tree.goto.evidence.partition.1");
    shouldThrow = false;
    fireEvent.click(screen.getByRole("button", { name: "다시 시도" }));
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByText("정상 화면")).toBeTruthy();
  });

  it("다른 화면으로 goes to the case's 접수 page; a route change clears the error", () => {
    render(
      <RegionBoundary region="목록">
        <Bomb />
      </RegionBoundary>,
    );
    shouldThrow = false;
    fireEvent.click(screen.getByRole("button", { name: "다른 화면으로" }));
    expect(useAppStore.getState().route.collection).toBe("intake");
    expect(screen.queryByRole("alert")).toBeNull();

    shouldThrow = true;
    cleanup();
    render(
      <RegionBoundary region="목록">
        <Bomb />
      </RegionBoundary>,
    );
    expect(screen.getByRole("alert")).toBeTruthy();
    shouldThrow = false;
    act(() => useAppStore.getState().navigate({ runId: "r1", collection: "timeline" }));
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
