// T-186 / review WB-10/11 P1-3: the run-start disk advice reaches the examiner as a toast.
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useToastStore } from "../../components/toastStore";
import { preflightSpaceNotice, showPreflightSpace } from "./preflightSpace";
import { RunDialog } from "./RunDialog";
import { mockFetch, renderWithQuery } from "./testUtils";

const WARN = {
  level: "warn",
  code: "DISK_SPACE_LOW",
  message: "여유 공간 2.0 GB — 예상 출력 3.5 GB(추정)보다 작습니다",
};

beforeEach(() => {
  window.location.hash = "";
  useToastStore.getState().clear();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  useToastStore.getState().clear();
});

describe("preflightSpaceNotice", () => {
  it("warn and block become Korean notices with the level; ok and no check stay silent", () => {
    expect(preflightSpaceNotice(WARN)).toEqual({
      text: `디스크 여유 주의(추정) — 런은 시작됨: ${WARN.message}`,
      tone: "warn",
    });
    const block = preflightSpaceNotice({ level: "block", code: "DISK_SPACE_INSUFFICIENT", message: "부족" });
    expect(block?.tone).toBe("error");
    expect(block?.text).toContain("디스크 여유 부족(추정)");
    expect(preflightSpaceNotice({ level: "ok", code: null, message: "여유 공간 충분" })).toBeNull();
    expect(preflightSpaceNotice(null)).toBeNull();
    expect(preflightSpaceNotice(undefined)).toBeNull();
  });

  it("unknown is shown only when the server named a code", () => {
    expect(
      preflightSpaceNotice({ level: "unknown", code: null, message: "출력 폴더를 확인하지 못해…" }),
    ).toBeNull();
    const notice = preflightSpaceNotice({ level: "unknown", code: "DISK_SPACE_LOW", message: "추정 못 함" });
    expect(notice?.text).toBe("디스크 여유 확인 못 함 — 런은 시작됨: 추정 못 함");
  });

  it("showPreflightSpace pushes a non-blocking toast", () => {
    showPreflightSpace({ preflight_space: WARN });
    const toasts = useToastStore.getState().toasts;
    expect(toasts).toHaveLength(1);
    expect(toasts[0]?.tone).toBe("warn");
    expect(toasts[0]?.text).toContain(WARN.message);
    showPreflightSpace({ preflight_space: { level: "ok", message: "충분" } });
    expect(useToastStore.getState().toasts).toHaveLength(1);
  });
});

describe("RunDialog start", () => {
  it("shows the preflight_space warning of the POST /api/runs reply and still starts the run", async () => {
    mockFetch({
      "POST /api/runs": { run_id: "new1", status: "queued", preflight_space: WARN },
      "GET /api/collect/profiles": { profiles: [] },
    });
    const onClose = vi.fn();
    renderWithQuery(<RunDialog runIsActive={false} onClose={onClose} />);
    fireEvent.change(screen.getByLabelText(/증거 경로/), { target: { value: "D:/case/img.E01" } });
    fireEvent.change(screen.getByLabelText(/^출력 폴더/), { target: { value: "D:/out/run1" } });
    fireEvent.click(screen.getByRole("button", { name: "실행" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(window.location.hash).toBe("#/case/new1/intake");
    const texts = useToastStore.getState().toasts.map((toast) => toast.text);
    expect(
      texts.some((text) => text.startsWith("디스크 여유 주의(추정)") && text.includes(WARN.message)),
    ).toBe(true);
  });
});
