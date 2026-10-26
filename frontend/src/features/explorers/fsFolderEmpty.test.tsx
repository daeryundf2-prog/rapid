// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
// C-E1 remainder: the folder explorer's files grid at a folder without direct files (the volume
// root, Users) says so and names its sub-folders instead of the generic empty text.
import { cleanup, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useGridLocalStore } from "../grid/adapter";
import { DataGrid } from "../grid/DataGrid";
import {
  installFetch,
  jsonResponse,
  mockLayout,
  renderWithClient,
  resetGridStore,
} from "../grid/testSupport";
import { fsFolderEmptyText } from "./FsExplorer";

vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: vi.fn(),
}));

let restoreLayout: () => void;
beforeEach(() => {
  resetGridStore();
  restoreLayout = mockLayout();
});
afterEach(() => {
  cleanup();
  restoreLayout();
  vi.unstubAllGlobals();
});

const folder = (over: Record<string, unknown> = {}) => ({
  name: "",
  path: "",
  direct_file_count: 0,
  direct_size: 0,
  file_count: 4814,
  size: 1,
  folder_count: 3,
  has_children: true,
  ...over,
});

describe("C-E1: folder without direct files", () => {
  it("names the sub-folders; null when the folder has direct files", () => {
    expect(fsFolderEmptyText({ node: folder(), children: [], child_total: 3 })).toBe(
      "이 폴더에 직속 파일이 없습니다 — 하위 폴더 3개 (위 목록에서 열거나 '하위 폴더 포함'을 켜세요)",
    );
    expect(
      fsFolderEmptyText({ node: folder({ direct_file_count: 2 }), children: [], child_total: 3 }),
    ).toBeNull();
    expect(fsFolderEmptyText({ node: folder({ has_children: false }), children: [], child_total: 0 })).toBe(
      "이 폴더에는 파일도 하위 폴더도 없습니다.",
    );
    expect(fsFolderEmptyText(undefined)).toBeNull();
  });

  it("the explorer's files grid at the volume root uses that text", async () => {
    useGridLocalStore.getState().setRoute({ collection: { id: "files", dir: "" } });
    installFetch({
      "/fs-tree": () =>
        jsonResponse({
          run_id: "run-1",
          scope: "candidates",
          scope_counts: { candidates: 4814, inventory: 0 },
          volume: {
            id: "v",
            label: "볼륨",
            root: null,
            filesystem: null,
            partition_start_sector: null,
            source_image: null,
          },
          node: folder(),
          breadcrumb: [],
          children: [folder({ name: "Users", path: "Users" }), folder({ name: "Windows", path: "Windows" })],
          child_total: 3,
          limit: 200,
          next_after: null,
          index: { rows: 1, indexed: 1, outside_root: 0, folders: 3, truncated: false },
        }),
      "/files": () => jsonResponse({ candidates: [], total: 0, offset: 0, limit: 250 }),
    });
    renderWithClient(<DataGrid />);
    const empty = await screen.findByTestId("grid-empty");
    await waitFor(() =>
      expect(empty.textContent).toContain("이 폴더에 직속 파일이 없습니다 — 하위 폴더 3개"),
    );
  });
});
