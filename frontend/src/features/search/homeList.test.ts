import { beforeEach, describe, expect, it } from "vitest";
import type { CommandContext } from "../../contracts/command";
import { resetAppStore, useAppStore } from "../../state/store";
import { useGridLocalStore } from "../grid/adapter";
import { COLLECTIONS } from "../grid/columns";
import { indexFromRef } from "../grid/gridUtils";
import { homeListCommand } from "./homeList";

const context: CommandContext = {
  runId: "r1",
  collection: "search",
  selectedRowKeys: [],
  focusedRowKey: null,
  viewerHasTarget: false,
  runIsActive: false,
};

const searchRow = (raw: Record<string, unknown>) =>
  COLLECTIONS.search.mapRow(raw, 0, { ref: { id: "search" } });
const focus = (raw: Record<string, unknown>) => useGridLocalStore.setState({ focusedRow: searchRow(raw) });

beforeEach(() => {
  window.history.replaceState(null, "", "/v2/");
  resetAppStore({ route: { runId: "r1", collection: "search", q: "AnyDesk" } });
  useGridLocalStore.setState({ focusedRow: null });
});

describe("원본 목록에서 보기", () => {
  it("opens an index hit in its own list, addressed so that list can focus the row", () => {
    focus({
      doc_id: 1,
      collection: "artifacts",
      kind: "eventlog",
      locator: "/artifacts/500123",
      title: "4688",
    });
    const command = homeListCommand();
    expect(command.disabledReason?.(context)).toBeUndefined();
    void command.run(context);
    const { route } = useAppStore.getState();
    expect(route).toEqual({
      runId: "r1",
      collection: "artifacts",
      kind: "eventlog",
      row: { collection: "artifacts", kind: "eventlog", locator: "/artifacts/500123" },
    });
    expect(route.row && indexFromRef(route.row)).toBe(500123);
  });

  it("is not offered for a scan match or when no row is focused", () => {
    const command = homeListCommand();
    expect(command.disabledReason?.(context)).toBeTruthy();
    focus({ source: "files", pointer: "/candidates/3", path: "C:/a.txt", title: "a" });
    expect(command.disabledReason?.(context)).toBeTruthy();
    void command.run(context);
    expect(useAppStore.getState().route.collection).toBe("search");
  });
});
