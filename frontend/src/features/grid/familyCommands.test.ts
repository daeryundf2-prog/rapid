/**
 * 계열 grid commands (R7 갈래 A, Q-A1 / Q-A6): 계열 보기, 상위 항목으로 and the selection expansion.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../contracts/collection";
import type { CommandContext } from "../../contracts/command";
import { useAppStore } from "../../state/store";
import { useGridLocalStore } from "./adapter";
import { makeRef, makeRow } from "./columns/common";
import {
  applyExpansion,
  buildFamilyCommands,
  EXPAND_COLLECTION_REASON,
  FAMILY_EXPAND_COMMAND,
  FAMILY_PARENT_COMMAND,
  FAMILY_VIEW_COMMAND,
  NO_FAMILY_ROW,
  NO_PARENT,
  rowItemRef,
} from "./familyCommands";
import type { GridCommandHost } from "./gridCommands";

const ctx: CommandContext = {
  runId: "r1",
  collection: null,
  selectedRowKeys: [],
  focusedRowKey: null,
  viewerHasTarget: false,
  runIsActive: false,
};

function row(kind: string, index: number, fields: Record<string, unknown> = {}): GridRow {
  return makeRow(makeRef("artifacts", `/artifacts/${index}`, kind), { title: `row ${index}` }, fields);
}

function host(overrides: Partial<GridCommandHost> = {}): GridCommandHost & { toasts: string[] } {
  const toasts: string[] = [];
  return {
    toasts,
    runId: "r1",
    collection: { id: "artifacts", kind: "email" },
    getFocusedRow: () => undefined,
    getSelectedRows: () => [],
    openRow: () => undefined,
    setFilter: () => undefined,
    navigate: () => undefined,
    patchRows: () => () => undefined,
    toast: (message: string) => {
      toasts.push(message);
    },
    refetch: () => undefined,
    showExtract: () => undefined,
    openTagPrompt: () => undefined,
    runIsActive: false,
    ...overrides,
  };
}

function commands(h: GridCommandHost) {
  const list = buildFamilyCommands({ current: h });
  const byId = (id: string) => list.find((command) => command.id === id);
  return {
    view: byId(FAMILY_VIEW_COMMAND),
    parent: byId(FAMILY_PARENT_COMMAND),
    expand: byId(FAMILY_EXPAND_COMMAND),
  };
}

beforeEach(() => {
  useAppStore.getState().navigate({ runId: "r1", collection: "artifacts", kind: "email" });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("계열 보기 · 상위 항목으로", () => {
  it("names the reason on rows without an item ref and on a top-level row", () => {
    const timeline = makeRow(makeRef("timeline", "/events/1"), { title: "e" });
    expect(commands(host({ getFocusedRow: () => timeline })).view?.disabledReason?.(ctx)).toBe(NO_FAMILY_ROW);
    const top = row("email", 1, {
      familyInfo: { parent: null, children: 2, top: "artifacts:email:/artifacts/1" },
    });
    const c = commands(host({ getFocusedRow: () => top }));
    expect(c.view?.disabledReason?.(ctx)).toBeUndefined();
    expect(c.parent?.disabledReason?.(ctx)).toBe(NO_PARENT);
    expect(c.view?.shortcut).toBe("Shift+F");
    expect(c.parent?.shortcut).toBe("U");
  });

  it("계열 보기 lists the family across kinds with the row in the 계열 tab", async () => {
    const c = commands(host({ getFocusedRow: () => row("email", 2) }));
    await c.view?.run(ctx);
    const route = useAppStore.getState().route;
    expect(route).toMatchObject({
      collection: "artifacts",
      family: ["artifacts:email:/artifacts/2"],
      row: { collection: "artifacts", kind: "email", locator: "/artifacts/2" },
      mode: "family",
    });
    expect(route.kind).toBeUndefined();
  });

  it("Q-A1: 상위 항목으로 opens the parent mail row, its family listed", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = new URL(String(input), "http://localhost");
        expect(url.searchParams.get("direction")).toBe("up");
        const mail = { ref: "artifacts:email:/artifacts/1", navigable: true, title: "견적서 송부" };
        return new Response(JSON.stringify({ parent: mail, top: mail }), {
          headers: { "content-type": "application/json" },
        });
      }),
    );
    const c = commands(host({ getFocusedRow: () => row("email", 2) }));
    await c.parent?.run(ctx);
    expect(useAppStore.getState().route).toMatchObject({
      collection: "artifacts",
      family: ["artifacts:email:/artifacts/1"],
      row: { collection: "artifacts", kind: "email", locator: "/artifacts/1" },
      mode: "family",
    });
  });

  it("says so when the parent is no row (a carved row's source file)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              parent: { ref: "source::C:\\pagefile.sys", navigable: false, title: "pagefile.sys" },
              top: { ref: "source::C:\\pagefile.sys" },
            }),
            { headers: { "content-type": "application/json" } },
          ),
      ),
    );
    const h = host({ getFocusedRow: () => row("email", 2) });
    await commands(h).parent?.run(ctx);
    expect(h.toasts[0]).toContain("행으로 기록되지 않았습니다");
  });
});

describe("선택을 상위+하위 항목으로 확장 (Q-A6)", () => {
  it("is for the files and artifacts lists only", () => {
    const h = host({ collection: { id: "timeline" }, getSelectedRows: () => [row("email", 2)] });
    expect(commands(h).expand?.disabledReason?.(ctx)).toBe(EXPAND_COLLECTION_REASON);
  });

  it("lists the families and selects every expanded row of this list (one review batch later)", () => {
    const h = host();
    applyExpansion(
      h,
      "r1",
      ["artifacts:email:/artifacts/2"],
      [
        "artifacts:email:/artifacts/2",
        "artifacts:email:/artifacts/1",
        "artifacts:email:/artifacts/3",
        "files::/candidates/0",
      ],
    );
    const state = useAppStore.getState();
    // The whole expansion of this list is one kind: the grid stays on it (same selection scope).
    expect(state.route).toMatchObject({
      collection: "artifacts",
      kind: "email",
      family: ["artifacts:email:/artifacts/2"],
    });
    expect([...useGridLocalStore.getState().selectedKeys]).toEqual([
      "artifacts:email:/artifacts/2",
      "artifacts:email:/artifacts/1",
      "artifacts:email:/artifacts/3",
    ]);
    expect(h.toasts[0]).toContain("이 목록 3건 선택");
    expect(h.toasts[0]).toContain("다른 목록 1건");
  });

  it("a search hit expands through the run-output row it names", () => {
    const hit = makeRow(
      makeRef("search", "search:1"),
      { title: "hit" },
      {
        reviewCollection: "artifacts",
        reviewKind: "email",
        reviewPointer: "/artifacts/5",
      },
    );
    expect(rowItemRef(hit)).toBe("artifacts:email:/artifacts/5");
  });
});
