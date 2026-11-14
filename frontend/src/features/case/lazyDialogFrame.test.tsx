// R8 WB-12 review P2-13: a case dialog whose chunk fails to load renders inside a modal with 닫기
// (and Esc), not as a block where the dialog host sits; the loading status is framed the same way.
import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { lazyDialog } from "./lazyDialogs";

function Done({ onClose }: { onClose: () => void }) {
  return (
    <button type="button" onClick={onClose}>
      완료
    </button>
  );
}

afterEach(() => vi.restoreAllMocks());

describe("lazyDialog", () => {
  it("shows the loading status inside a dialog, then the loaded dialog", async () => {
    let resolve!: (component: typeof Done) => void;
    const Lazy = lazyDialog("환경 점검", () => new Promise<typeof Done>((res) => (resolve = res)));
    render(<Lazy onClose={() => undefined} />);
    const dialog = screen.getByRole("dialog", { name: "환경 점검" });
    expect(dialog.querySelector("[data-testid=lazy-view-loading]")?.textContent).toContain(
      "환경 점검 불러오는 중",
    );
    expect(dialog.querySelector("[role=status],[aria-live]")).toBeNull();
    await act(async () => resolve(Done));
    expect(await screen.findByRole("button", { name: "완료" })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("a failed chunk renders in the dialog with 닫기 and Esc calling onClose", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const onClose = vi.fn();
    const Lazy = lazyDialog("보고서", () =>
      Promise.reject(new TypeError("Failed to fetch dynamically imported module")),
    );
    render(<Lazy onClose={onClose} />);
    const alert = await screen.findByRole("alert");
    const dialog = screen.getByRole("dialog", { name: "보고서" });
    expect(dialog.contains(alert)).toBe(true);
    expect(alert.textContent).toContain("보고서 화면을 불러오지 못했습니다.");
    expect(screen.getByRole("button", { name: "다시 시도" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "닫기" }));
    expect(onClose).toHaveBeenCalledTimes(1);
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it("reopening after a failed load imports again instead of replaying the failure", async () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    let calls = 0;
    const Lazy = lazyDialog("실행", () => {
      calls++;
      return calls === 1 ? Promise.reject(new Error("gone")) : Promise.resolve(Done);
    });
    const view = render(<Lazy onClose={() => undefined} />);
    await screen.findByRole("alert");
    view.unmount();
    render(<Lazy onClose={() => undefined} />);
    expect(await screen.findByRole("button", { name: "완료" })).toBeTruthy();
    expect(calls).toBe(2);
  });
});
