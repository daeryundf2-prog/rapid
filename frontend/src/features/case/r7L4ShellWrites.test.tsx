// r7 stage 1 lane L4 (plan r7-master-2026-10-26 §3.4): write confirmations, toasts, palette,
// router, SQLite detection, evidence-time display, derived cells, case_db_ready.
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SourcePreview } from "../../api/viewer";
import { appCommands } from "../../commands/builtin";
import { NO_RUN_REASON } from "../../commands/reasons";
import { ToastRegion } from "../../components/ToastRegion";
import { pushToast, useToastStore } from "../../components/toastStore";
import type { Command } from "../../contracts/command";
import { parseHash, serializeRoute, stageOf } from "../../router";
import { buildPaletteGroups } from "../../shell/CommandPalette";
import { useAppStore } from "../../state/store";
import { evidenceTime } from "../../utils/time";
import { derivedCellDisplay } from "../derived/DerivedPane";
import { COLLECTIONS } from "../grid/columns";
import { applyReviewAction, CASE_DB_PREPARING_NOTICE, resetCaseDbHandles } from "../grid/reviewActions";
import { installFetch, jsonResponse } from "../grid/testSupport";
import { displayEvidenceTime } from "../viewer/evidenceTimeDisplay";
import { resolveModes, sqliteRowTarget } from "../viewer/modes";
import { exportWrites } from "./exports";
import { confirmWrite, joinRunPath, useWriteConfirm, WriteConfirmHost } from "./WriteConfirm";

beforeEach(() => {
  useToastStore.getState().clear();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  resetCaseDbHandles();
  useWriteConfirm.getState().settle(false);
});

describe("write confirmation (D8)", () => {
  it("names what is written where and sends nothing until confirmed", async () => {
    render(<WriteConfirmHost />);
    let answer: boolean | null = null;
    act(() => {
      void confirmWrite({
        title: "검증 패키지 내보내기",
        writes: [{ what: "검증 패키지(JSON)", where: "D:\\run\\rapidforensic-run-validation-package.json" }],
        confirmLabel: "내보내기",
      }).then((ok) => {
        answer = ok;
      });
    });
    expect(screen.getByTestId("write-confirm-where").textContent).toBe(
      "D:\\run\\rapidforensic-run-validation-package.json",
    );
    // Cancel is the initial focus: Enter on an unread dialog never writes.
    expect(document.activeElement).toBe(screen.getByTestId("write-confirm-cancel"));
    await act(async () => {
      fireEvent.click(screen.getByTestId("write-confirm-cancel"));
    });
    expect(answer).toBe(false);
    expect(screen.queryByTestId("write-confirm")).toBeNull();
  });

  it("resolves true only on the confirm button", async () => {
    render(<WriteConfirmHost />);
    let answer: boolean | null = null;
    act(() => {
      void confirmWrite({
        title: "t",
        writes: [{ what: "w", where: "x" }],
        confirmLabel: "다시 만들기",
      }).then((ok) => {
        answer = ok;
      });
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("write-confirm-ok"));
    });
    expect(answer).toBe(true);
  });

  it("export dialog lists the run-folder files of each kind", () => {
    expect(exportWrites("validation-package", "D:\\out\\run").map((w) => w.where)).toEqual([
      "D:\\out\\run\\rapidforensic-run-validation-package.json",
      "D:\\out\\run\\rapidforensic-run-validation-package.audit.json",
    ]);
    expect(joinRunPath("/data/run/", "a.json")).toBe("/data/run/a.json");
    expect(joinRunPath(null, "a.json")).toContain("이 런의 출력 폴더");
  });
});

describe("toasts (C-G12, P2)", () => {
  it("shows the written path and a 열기 action", () => {
    const open = vi.fn();
    render(<ToastRegion />);
    act(() => {
      pushToast("검증 패키지를 저장했습니다.", "ok", {
        detail: "D:\\run\\pkg.json",
        action: { label: "열기", run: open },
      });
    });
    expect(screen.getByTestId("toast-detail").textContent).toBe("D:\\run\\pkg.json");
    fireEvent.click(screen.getByTestId("toast-action"));
    expect(open).toHaveBeenCalledOnce();
  });

  it("global Esc (app.close) closes the newest toast when no dialog is open", async () => {
    act(() => {
      pushToast("하나", "error");
      pushToast("둘", "error");
    });
    const close = appCommands().find((c) => c.id === "app.close") as Command;
    const ctx = {} as Parameters<NonNullable<Command["disabledReason"]>>[0];
    expect(close.disabledReason?.(ctx)).toBeUndefined();
    await close.run(ctx);
    expect(useToastStore.getState().toasts.map((t) => t.text)).toEqual(["하나"]);
  });

  it("error toasts are cleared on a stage change", () => {
    render(<ToastRegion />);
    act(() => {
      useAppStore.getState().navigate({ runId: "r1", collection: "files" });
    });
    act(() => {
      pushToast("실패했습니다", "error");
      pushToast("저장했습니다", "info");
    });
    act(() => {
      useAppStore.getState().navigate({ runId: "r1", collection: "intake" });
    });
    expect(useToastStore.getState().toasts.map((t) => t.text)).toEqual(["저장했습니다"]);
  });
});

describe("palette without a case (C-G11)", () => {
  const command = (id: string, group: Command["group"], label: string): Command => ({
    id,
    group,
    label,
    run: () => undefined,
  });
  it("hides 이동 commands and says one reason", () => {
    const commands = [
      command("navigate.files", "navigate", "이동: 파일"),
      command("search.options", "search", "검색 옵션"),
      command("grid.x", "grid", "열 설정"),
    ];
    const reasons: Record<string, string> = {
      "navigate.files": NO_RUN_REASON,
      "search.options": "열린 케이스가 없습니다",
      "grid.x": "열린 케이스가 없습니다.",
    };
    // C-G11 remainder: with no query, commands that cannot run stay out of the list …
    const plain = buildPaletteGroups(commands, "", (c) => reasons[c.id], [], { caseOpen: false });
    expect(plain.flatMap((g) => g.items)).toEqual([]);
    // … typing their name finds them, with the one reason.
    const groups = buildPaletteGroups(commands, "옵션", (c) => reasons[c.id], [], { caseOpen: false });
    const items = groups.flatMap((g) => g.items);
    expect(items.map((i) => i.key)).toEqual(["search.options"]);
    expect(new Set(items.map((i) => i.disabledReason))).toEqual(new Set([NO_RUN_REASON]));
    // 이동 stays hidden even when typed.
    const moves = buildPaletteGroups(commands, "이동", (c) => reasons[c.id], [], { caseOpen: false });
    expect(moves.flatMap((g) => g.items).map((i) => i.key)).not.toContain("navigate.files");
  });

  it("enabled commands still list without a query when no case is open", () => {
    const commands = [command("case.open", "case", "케이스 열기…"), command("grid.x", "grid", "열 설정")];
    const groups = buildPaletteGroups(
      commands,
      "",
      (c) => (c.id === "grid.x" ? NO_RUN_REASON : undefined),
      [],
      { caseOpen: false },
    );
    expect(groups.flatMap((g) => g.items).map((i) => i.key)).toEqual(["case.open"]);
  });

  it("C-G9: one name for adding a run — top bar and palette both read 런 추가…", () => {
    const commands = [
      command("case.run.add", "case", "런 추가…"),
      command("case.run.new", "case", "런 추가…"),
    ];
    const items = buildPaletteGroups(commands, "", () => undefined).flatMap((g) => g.items);
    expect(items.map((i) => [i.key, i.label])).toEqual([["case.run.new", "런 추가…"]]);
  });
});

describe("router (C-G17, C-R2)", () => {
  const row = { collection: "artifacts" as const, kind: "browser", locator: "/artifacts/3" };
  it("drops row/mode on a stage without a viewer", () => {
    expect(serializeRoute({ runId: "r1", collection: "artifacts", kind: "browser", row })).toContain("row=");
    const intake = serializeRoute({ runId: "r1", collection: "intake", row, mode: "hex" });
    expect(intake).not.toContain("row=");
    expect(intake).not.toContain("mode=");
  });
  it("the 검토 특이사항 node stays in the 검토 stage and round-trips", () => {
    const hash = serializeRoute({ runId: "r1", collection: "artifacts", flagGrade: "B", inReview: true });
    expect(hash).toBe("#/case/r1/review/flags?flag_grade=B");
    const parsed = parseHash(hash);
    expect(parsed.collection).toBe("artifacts");
    expect(parsed.inReview).toBe(true);
    expect(stageOf(parsed)).toBe("review");
    expect(stageOf({ collection: "artifacts" })).toBe("explore");
  });
});

describe("SQLite by magic bytes (C-W1)", () => {
  const history: SourcePreview = {
    path: "C:/e/Users/a/AppData/Local/Google/Chrome/User Data/Default/History",
    name: "History",
    extension: "",
    size: 4096,
    mime_type: "application/octet-stream",
    preview_type: "sqlite",
    sqlite: { table_count: 12, tables: [{ name: "downloads" }] },
    viewer_hint: {
      mode: "sqlite",
      detected_by: "magic-bytes",
      sqlite_tables: ["downloads", "urls", "visits"],
      row_tables: { "browser-history": "urls", "browser-visit": "visits" },
    },
  };
  it("enables the SQLite tab for an extension-less History file", () => {
    const target = {
      runId: "r1",
      ref: { collection: "files" as const, locator: "/candidates/1" },
      sourcePath: history.path,
    };
    const { modes } = resolveModes({ target, preview: history });
    expect(modes.find((m) => m.mode === "sqlite")?.available).toBe(true);
  });
  it("jumps a browser-history row to urls at its source_row_id", () => {
    const row = { artifactType: "browser-history", fields: { details: { source_row_id: 1234 } } };
    expect(sqliteRowTarget(history, row)).toEqual({ table: "urls", rowid: 1234 });
    const own = {
      artifactType: "browser-visit",
      fields: { details: { source_row_id: "7", source_table: "visits" } },
    };
    expect(sqliteRowTarget(history, own)).toEqual({ table: "visits", rowid: 7 });
    expect(sqliteRowTarget(history, { artifactType: "browser-cookie", fields: { details: {} } })).toBeNull();
  });
});

describe("evidence time display (C-W5)", () => {
  it("seconds by default, the UTC side with its date, sub-seconds only in the precise line", () => {
    const reading = evidenceTime("2025-05-29T20:00:00.123456Z", "Asia/Seoul");
    if (!reading) throw new Error("no reading");
    const shown = displayEvidenceTime(reading);
    expect(shown.local).toBe("2025-05-30 05:00:00");
    expect(shown.utc).toBe("UTC 2025-05-29 20:00:00");
    expect(shown.text).not.toContain(".123456");
    expect(shown.precise).toContain(".123456");
  });
});

describe("derived cells (C-X3)", () => {
  const row = { first_seen: "1980-01-01T00:00:00Z", last_seen: "2024-01-01T00:00:00Z", value: "S-1-5-18" };
  it("DOS epoch reads as — and well-known SIDs get their name", () => {
    expect(derivedCellDisplay("first", row, "1980-01-01 09:00:00 KST").text).toBe("");
    expect(derivedCellDisplay("last", row, "2024-01-01 09:00:00 KST").text).toBe("2024-01-01 09:00:00 KST");
    expect(derivedCellDisplay("value", row, "S-1-5-18").text).toBe("S-1-5-18 (SYSTEM (LocalSystem))");
  });
});

describe("case DB ready (C-G13)", () => {
  const fileRow = COLLECTIONS.files.mapRow({ path: "C:/ev/f1.txt", name: "f1.txt" }, 1, {
    ref: { id: "files" },
  });
  it("skips /case-db/ensure and the preparing notice when the run reports case_db_ready", async () => {
    const calls = installFetch({
      "/api/runs/r9": () =>
        jsonResponse({
          run_id: "r9",
          status: "completed",
          case_db_ready: true,
          case_db: { database: "D:/out/rapidtriage-case.db", case_id: "run-out" },
        }),
      "/review-batch": () => jsonResponse({ updated_count: 1 }),
    });
    await applyReviewAction("r9", [fileRow], "relevant");
    expect(calls.some((c) => c.url.includes("/case-db/ensure"))).toBe(false);
    expect(calls.filter((c) => c.url.includes("/review-batch"))).toHaveLength(1);
    expect(useToastStore.getState().toasts.some((t) => t.text === CASE_DB_PREPARING_NOTICE)).toBe(false);
  });
});
