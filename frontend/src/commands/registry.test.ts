import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Command } from "../contracts/command";
import { resetAppStore, useAppStore } from "../state/store";
import { appCommands, caseCommands, NO_RUN_REASON, navigateCommands } from "./builtin";
import { fuzzyScore } from "./fuzzy";
import {
  CANONICAL_KEYS,
  CommandRegistrationError,
  commandForShortcut,
  getCommands,
  normalizeShortcut,
  registerCommand,
  registerCommands,
  resetCommandRegistry,
  runCommand,
} from "./registry";

const cmd = (over: Partial<Command> = {}): Command => ({
  id: "test.cmd",
  label: "테스트",
  group: "app",
  run: vi.fn(),
  ...over,
});

beforeEach(() => {
  resetCommandRegistry();
  window.history.replaceState(null, "", "/v2/");
  resetAppStore({ route: { runId: null, collection: null } });
});

afterEach(() => resetCommandRegistry());

describe("registry", () => {
  it("runs an enabled command with the store context", async () => {
    const run = vi.fn();
    registerCommand(cmd({ run }));
    useAppStore.getState().navigate({ runId: "r1", collection: "files" });
    useAppStore.getState().setSelectedRows(["files:/c/1"]);
    expect(await runCommand("test.cmd")).toEqual({ ok: true });
    expect(run).toHaveBeenCalledWith(
      expect.objectContaining({
        runId: "r1",
        collection: "files",
        selectedRowKeys: ["files:/c/1"],
        runIsActive: false,
      }),
    );
  });

  it("reports disabledReason instead of silently doing nothing", async () => {
    const run = vi.fn();
    registerCommand(cmd({ run, disabledReason: (ctx) => (ctx.runId ? undefined : "케이스 없음") }));
    const result = await runCommand("test.cmd");
    expect(result).toEqual({ ok: false, reason: "케이스 없음" });
    expect(run).not.toHaveBeenCalled();
    expect(useAppStore.getState().notice?.text).toBe("테스트: 케이스 없음");
  });

  it("silentWhenDisabled skips the notice (Esc with nothing open)", async () => {
    registerCommand(cmd({ disabledReason: () => "닫을 창이 없습니다" }));
    await runCommand("test.cmd", { silentWhenDisabled: true });
    expect(useAppStore.getState().notice).toBeNull();
  });

  it("reports unknown ids and thrown errors", async () => {
    expect(await runCommand("nope")).toMatchObject({ ok: false });
    registerCommand(
      cmd({
        run: () => {
          throw new Error("boom");
        },
      }),
    );
    const result = await runCommand("test.cmd");
    expect(result).toEqual({ ok: false, reason: "테스트 실패: boom" });
    expect(useAppStore.getState().notice?.tone).toBe("error");
  });

  it("rejects duplicate ids, non-canonical keys and double bindings", () => {
    registerCommand(cmd({ shortcut: "ctrl+k" }));
    expect(() => registerCommand(cmd())).toThrow(CommandRegistrationError);
    expect(() => registerCommand(cmd({ id: "x", shortcut: "Ctrl+P" }))).toThrow(/KEY_MAP/);
    expect(() => registerCommand(cmd({ id: "y", shortcut: "Ctrl+K" }))).toThrow(/이미/);
    expect(commandForShortcut("Meta+K")?.id).toBe("test.cmd");
  });

  it("unregistering frees the id and the key; batch registration is atomic", () => {
    const off = registerCommand(cmd({ shortcut: "J" }));
    off();
    expect(commandForShortcut("J")).toBeUndefined();
    expect(() =>
      registerCommands([cmd({ id: "a", shortcut: "K" }), cmd({ id: "b", shortcut: "K" })]),
    ).toThrow();
    expect(getCommands()).toHaveLength(0);
  });

  it("knows the canonical key set (1–5 / 1–8 expanded)", () => {
    expect(normalizeShortcut("alt+left")).toBe("Alt+ArrowLeft");
    expect(normalizeShortcut("esc")).toBe("Escape");
    for (const key of [
      "Ctrl+K",
      "/",
      "J",
      "K",
      "Enter",
      "Space",
      "R",
      "X",
      "I",
      "B",
      "1",
      "5",
      "?",
      "Escape",
      "F",
      "Ctrl+Shift+V",
      "8",
    ]) {
      expect(CANONICAL_KEYS.has(key)).toBe(true);
    }
    // Viewer-window modes stop at 8 (viewer-families U-F2); 9 is a review-tag key (AXIOM E3, 1–9).
    expect(CANONICAL_KEYS.has("9")).toBe(true);
    expect(CANONICAL_KEYS.has("0")).toBe(false);
    expect(CANONICAL_KEYS.has("`")).toBe(true);
    expect(CANONICAL_KEYS.has("Shift+B")).toBe(true);
  });
});

describe("built-in commands", () => {
  it("register without key conflicts and explain why they are disabled", async () => {
    const client = { invalidateQueries: vi.fn() } as never;
    registerCommands([...appCommands(), ...navigateCommands(), ...caseCommands(client)]);
    // One per COLLECTION_NODES entry (incl. 분석 작업).
    expect(getCommands("navigate")).toHaveLength(11);
    expect(await runCommand("navigate.files")).toEqual({ ok: false, reason: NO_RUN_REASON });
    // No case open: the landing page mounts no viewer.
    expect(await runCommand("viewer.open")).toEqual({ ok: false, reason: "이 단계에는 뷰어가 없습니다" });
    expect(await runCommand("case.cancel")).toEqual({ ok: false, reason: NO_RUN_REASON });
    useAppStore.getState().navigate({ runId: "r1", collection: "intake" });
    useAppStore.getState().setRuns([{ run_id: "r1", status: "completed" }]);
    expect(await runCommand("case.cancel")).toEqual({ ok: false, reason: "실행 중인 런이 아닙니다" });
    expect(await runCommand("navigate.review")).toEqual({ ok: true });
    // 검토 has a viewer; 보고 (two columns) does not: viewer.open says so (review B2-2).
    expect(await runCommand("viewer.open")).toEqual({ ok: false, reason: "선택된 행이 없습니다" });
    useAppStore.getState().navigate({ runId: "r1", collection: "outputs" });
    expect(await runCommand("viewer.open")).toEqual({ ok: false, reason: "이 단계에는 뷰어가 없습니다" });
    useAppStore.getState().navigate({ runId: "r1", collection: "review" });
    expect(window.location.hash).toBe("#/case/r1/review/board");
    expect(await runCommand("app.density.default")).toEqual({ ok: false, reason: "현재 밀도입니다" });
    expect(await runCommand("app.help")).toEqual({ ok: true });
    expect(useAppStore.getState().helpOpen).toBe(true);
    expect(await runCommand("app.close")).toEqual({ ok: true });
    expect(useAppStore.getState().helpOpen).toBe(false);
  });
});

describe("fuzzyScore", () => {
  it("matches subsequences, prefers substrings, rejects misses", () => {
    expect(fuzzyScore("", "아무거나")).toBe(0);
    expect(fuzzyScore("리뷰", "이동: 리뷰보드")).not.toBeNull();
    expect(fuzzyScore("ㅁ", "이동: 리뷰보드")).toBeNull();
    const substring = fuzzyScore("time", "이동: 타임라인 navigate.timeline") ?? 0;
    const scattered = fuzzyScore("tmln", "이동: 타임라인 navigate.timeline") ?? 0;
    expect(substring).toBeGreaterThan(scattered);
    expect(fuzzyScore("zzz", "theme")).toBeNull();
  });
});
