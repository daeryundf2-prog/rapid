// biome-ignore-all lint/a11y: tests drive the ARIA trees through their DOM roles
/**
 * 탐색기 (plan r4 §2.2 V2): routes, the lazy folder / key trees (keyboard, ARIA, empty states),
 * the files path filter, the registry value pane and the media panel.
 */

import { act, cleanup, configure, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { filesPathQueryString } from "../../api/collections";
import type { FsTreePage, RegistryLevel, RegistryValues } from "../../api/explorers";
import { getCommand, registerCommands, resetCommandRegistry, runCommand } from "../../commands/registry";
import type { GridRow } from "../../contracts/collection";
import { parseHash, serializeRoute } from "../../router";
import { resetAppStore, useAppStore } from "../../state/store";
import { explorerCommands } from "../explorers/commands";
import { MAX_AUTO_PAGES } from "../explorers/ExplorerTree";
import { ancestorIds, FsExplorerLayout, fsExplorerOpen, fsScopeOf } from "../explorers/FsExplorer";
import { MediaExplorerPanel, mediaPathKey } from "../explorers/MediaExplorerPanel";
import { keyAncestorIds, RegistryExplorer } from "../explorers/RegistryExplorer";
import { installFetch, jsonResponse, renderWithClient, resetGridStore } from "../grid/testSupport";
import { collectionQueryKey } from "../grid/useCollectionQuery";
import { targetKey } from "../tree/domains";
import { buildTreeModel, domainNodeCount, domainRoute, NO_REGISTRY_TREE_REASON } from "../tree/model";
import { narrowedActiveIndex } from "./ThumbnailView";

configure({ asyncUtilTimeout: 5000 });

const announceMock = vi.hoisted(() => vi.fn());
vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: announceMock,
}));

const RUN = "run-1";

beforeEach(() => {
  resetCommandRegistry();
  resetAppStore();
  resetGridStore();
  announceMock.mockClear();
});

afterEach(() => {
  cleanup();
  resetCommandRegistry();
  vi.unstubAllGlobals();
  window.location.hash = "";
});

// --- routes -------------------------------------------------------------------------------

describe("explorer routes", () => {
  it("round-trips the folder, subtree, special node and registry key", () => {
    const fs = parseHash("#/case/r1/explore/files?dir=%2FUsers%2Fuser%20one&rec=1");
    expect(fs).toMatchObject({ collection: "files", dir: "Users/user one", rec: true });
    expect(parseHash(serializeRoute(fs))).toEqual(fs);
    const root = parseHash("#/case/r1/explore/files?dir=%2F");
    expect(root.dir).toBe("");
    expect(serializeRoute(root)).toBe("#/case/r1/explore/files?dir=%2F");
    expect(fsExplorerOpen(root)).toBe(true);
    expect(fsExplorerOpen(parseHash("#/case/r1/explore/files"))).toBe(false);
    const special = parseHash("#/case/r1/explore/files?special=orphan");
    expect(special.special).toBe("orphan");
    expect(fsExplorerOpen(special)).toBe(true);
    expect(parseHash("#/case/r1/explore/files?special=trash").special).toBeUndefined();
    // dir= belongs to the files listing only.
    expect(parseHash("#/case/r1/explore/docs?dir=%2Fx").dir).toBeUndefined();
    const reg = parseHash("#/case/r1/explore/registry/abc123?key=HKLM%5CSYSTEM%5CSelect");
    expect(reg).toMatchObject({ collection: "registry", kind: "abc123", key: "HKLM\\SYSTEM\\Select" });
    expect(parseHash(serializeRoute(reg))).toEqual(reg);
  });

  it("keys the grid cache and the tree selection by folder", () => {
    const base = { id: "files" as const };
    const a = collectionQueryKey(RUN, { ref: { ...base, dir: "Users" }, offset: 0, limit: 250 }, 250);
    const b = collectionQueryKey(
      RUN,
      { ref: { ...base, dir: "Users", recursive: true }, offset: 0, limit: 250 },
      250,
    );
    const c = collectionQueryKey(RUN, { ref: base, offset: 0, limit: 250 }, 250);
    expect(JSON.stringify(a)).not.toBe(JSON.stringify(b));
    expect(JSON.stringify(a)).not.toBe(JSON.stringify(c));
    expect(targetKey({ collection: "files", dir: "" })).toBe(
      targetKey({ collection: "files", dir: "Users/x" }),
    );
    expect(targetKey({ collection: "files", dir: "" })).not.toBe(targetKey({ collection: "files" }));
    expect(filesPathQueryString({ dir: "Users/a b", recursive: true })).toBe(
      "&path_prefix=Users%2Fa+b&recursive=1",
    );
    expect(filesPathQueryString({ dir: "" })).toBe("&path_prefix=");
    expect(filesPathQueryString({ special: "orphan" })).toBe("&special=orphan");
    expect(filesPathQueryString(undefined)).toBe("");
    expect(fsScopeOf("inventory")).toBe("inventory");
    expect(fsScopeOf("inventory:other")).toBe("inventory");
    expect(fsScopeOf("images")).toBe("candidates");
    expect(ancestorIds("Users/user/Desktop")).toEqual(["dir:", "dir:Users", "dir:Users/user"]);
  });

  it("puts both explorers in the tree and the command palette", () => {
    const tree = {
      run_id: RUN,
      nodes: [
        {
          id: "artifacts",
          label: "아티팩트",
          count: 5,
          children: [
            {
              id: "artifacts:windows-registry",
              label: "레지스트리",
              count: 5,
              collection: "artifacts",
              kind: "windows-registry",
              artifact_type_counts: { "registry-key-tree-node": 4, "registry-hive": 1 },
            },
          ],
        },
      ],
    };
    // biome-ignore lint/suspicious/noExplicitAny: minimal /tree payload
    const input = { tree: tree as any };
    expect(domainNodeCount({ collection: "registry" }, input)).toEqual({ count: 4 });
    expect(
      domainNodeCount({ collection: "registry" }, { tree: { run_id: RUN, nodes: [] } as never }),
    ).toEqual({
      count: 0,
      disabledReason: NO_REGISTRY_TREE_REASON,
    });
    expect(domainRoute({ collection: "files", dir: "" })).toEqual({ collection: "files", dir: "" });
    const model = buildTreeModel(input);
    // R7 L3 (C-T1/T2): each explorer is one node, under 전체 보기 — never repeated in a domain.
    const views = model.find((node) => node.id === "views");
    expect(views?.children?.find((node) => node.id === "fs-explorer")).toMatchObject({
      label: "폴더 탐색기",
      target: { collection: "files", dir: "" },
    });
    expect(views?.children?.find((node) => node.id === "registry-explorer")).toMatchObject({
      label: "레지스트리 탐색기",
      count: 4,
    });
    const labels = (nodes: typeof model): string[] =>
      nodes.flatMap((node) => [node.label, ...labels(node.children ?? [])]);
    const all = labels(model);
    expect(all.filter((label) => label === "파일 목록")).toHaveLength(1);
    expect(all.filter((label) => label === "폴더 탐색기")).toHaveLength(1);
    expect(all.filter((label) => label.startsWith("레지스트리 탐색기"))).toHaveLength(1);
    expect(model.find((node) => node.id === "domain:filesystem")?.label).toBe("NTFS·파일시스템 아티팩트");

    registerCommands(explorerCommands());
    const noCase = {
      runId: null,
      collection: null,
      selectedRowKeys: [],
      focusedRowKey: null,
      viewerHasTarget: false,
      runIsActive: false,
    };
    expect(getCommand("explorer.fs")?.disabledReason?.(noCase)).toBeTruthy();
    useAppStore.getState().navigate({ runId: RUN, collection: "artifacts" });
    void runCommand("explorer.registry");
    expect(useAppStore.getState().route).toMatchObject({ collection: "registry" });
    void runCommand("explorer.fs");
    expect(useAppStore.getState().route).toMatchObject({ collection: "files", dir: "" });
  });
});

// --- file system ----------------------------------------------------------------------------

function folder(path: string, files: number, children = 0) {
  return {
    name: path.split("/").pop() ?? "",
    path,
    direct_file_count: Math.floor(files / 2),
    direct_size: files * 10,
    file_count: files,
    size: files * 100,
    folder_count: children,
    has_children: children > 0,
  };
}

function fsPage(
  path: string,
  children: ReturnType<typeof folder>[],
  extra: Partial<FsTreePage> = {},
): FsTreePage {
  const parts = path.split("/").filter(Boolean);
  return {
    run_id: RUN,
    scope: "candidates",
    scope_counts: { candidates: 10, inventory: 3 },
    volume: {
      id: "volume-1",
      label: "볼륨 1 (스캔 루트)",
      root: "D:/ev",
      filesystem: null,
      partition_start_sector: null,
      source_image: null,
    },
    node: path ? folder(path, 6, children.length) : { ...folder("", 10, children.length), name: "" },
    breadcrumb: parts.map((_, i) => ({ name: parts[i] as string, path: parts.slice(0, i + 1).join("/") })),
    children,
    child_total: children.length,
    limit: 200,
    next_after: null,
    index: { rows: 10, indexed: 10, outside_root: 0, folders: 4, truncated: false },
    ...extra,
  };
}

describe("파일 시스템 탐색기", () => {
  function setup(routes: Record<string, (url: URL) => Response>) {
    const calls = installFetch({
      "/fs-tree": (url) => {
        const path = url.searchParams.get("path") ?? "";
        const handler = routes[path];
        return handler ? handler(url) : jsonResponse({ detail: "폴더를 찾을 수 없습니다" }, 404);
      },
    });
    useAppStore.getState().navigate({ runId: RUN, collection: "files", dir: "" });
    renderWithClient(
      <FsExplorerLayout>
        <p>grid</p>
      </FsExplorerLayout>,
    );
    return calls;
  }

  it("lazy-loads folders with ←/→, opens with Enter and shows breadcrumb counts", async () => {
    const after = "QQ";
    const calls = setup({
      "": (url) =>
        url.searchParams.get("after")
          ? jsonResponse(fsPage("", [folder("Windows", 2, 0)]))
          : jsonResponse(
              fsPage("", [folder("Users", 8, 1)], {
                child_total: 2,
                next_after: after,
                hidden_special_nodes: [{ id: "slack", label: "슬랙", reason: "슬랙 데이터가 없습니다" }],
                special_nodes: [
                  {
                    id: "orphan",
                    label: "고아 파일",
                    count: 3,
                    counts: { candidates: 0, inventory: 3 },
                    source: "files",
                    files_query: { special: "orphan" },
                  },
                ],
              }),
            ),
      Users: () => jsonResponse(fsPage("Users", [folder("Users/alice", 8, 0)])),
    });
    const tree = await screen.findByRole("tree", { name: "파일 시스템 폴더 트리" });
    const volume = await within(tree).findByRole("treeitem", { name: /볼륨 1 \(스캔 루트\), 파일 10개/ });
    expect(volume.getAttribute("aria-expanded")).toBe("true");
    expect(volume.getAttribute("aria-current")).toBe("location");
    expect(volume.getAttribute("aria-level")).toBe("1");
    const users = await within(tree).findByRole("treeitem", { name: /^Users, 파일 8개/ });
    expect(users.getAttribute("aria-level")).toBe("2");
    expect(users.getAttribute("aria-setsize")).toBe("1");
    expect(users.getAttribute("aria-expanded")).toBe("false");
    expect(within(tree).getByRole("treeitem", { name: /고아 파일, 3건/ })).toBeTruthy();
    expect(screen.getByText(/숨긴 특수 노드 1개/)).toBeTruthy();
    expect(screen.getByText(/슬랙 데이터가 없습니다/)).toBeTruthy();
    // One tab stop.
    expect(
      within(tree)
        .getAllByRole("treeitem")
        .filter((item) => item.tabIndex === 0),
    ).toHaveLength(1);

    act(() => volume.focus());
    fireEvent.keyDown(volume, { key: "ArrowDown" });
    expect(document.activeElement).toBe(users);
    fireEvent.keyDown(users, { key: "ArrowRight" });
    await waitFor(() => expect(users.getAttribute("aria-expanded")).toBe("true"));
    expect(announceMock).toHaveBeenCalledWith(expect.stringContaining("Users 펼침"));
    const alice = await within(tree).findByRole("treeitem", { name: /^alice, 파일 8개/ });
    expect(alice.getAttribute("aria-level")).toBe("3");
    fireEvent.keyDown(users, { key: "ArrowRight" });
    expect(document.activeElement).toBe(alice);
    fireEvent.keyDown(alice, { key: "ArrowLeft" });
    expect(document.activeElement).toBe(users);
    fireEvent.keyDown(users, { key: "ArrowLeft" });
    await waitFor(() => expect(users.getAttribute("aria-expanded")).toBe("false"));

    // 더 보기 loads the next page behind the cursor.
    const more = within(tree).getByRole("treeitem", { name: /더 보기 \(1개 남음\)/ });
    fireEvent.click(more);
    expect(await within(tree).findByRole("treeitem", { name: /^Windows, 파일 2개/ })).toBeTruthy();
    expect(calls.some((call) => call.url.includes(`after=${after}`))).toBe(true);

    fireEvent.keyDown(users, { key: "Enter" });
    expect(useAppStore.getState().route).toMatchObject({ collection: "files", dir: "Users" });
    const header = await screen.findByTestId("fs-explorer-header");
    const crumbs = within(header).getByRole("navigation", { name: "폴더 경로" });
    await waitFor(() => expect(within(crumbs).getByText("Users").getAttribute("aria-current")).toBe("page"));
    expect(within(header).getByTestId("fs-explorer-counts").textContent).toContain("하위 포함 6개");

    fireEvent.click(within(header).getByRole("checkbox", { name: "하위 폴더 포함" }));
    expect(useAppStore.getState().route.rec).toBe(true);
    fireEvent.click(within(crumbs).getByRole("button", { name: "볼륨 1 (스캔 루트)" }));
    expect(useAppStore.getState().route.dir).toBe("");

    // Special node → the files listing filtered server-side.
    fireEvent.click(within(tree).getByRole("treeitem", { name: /고아 파일/ }));
    // Its rows live only in the inventory: the listing switches to that list.
    expect(useAppStore.getState().route).toMatchObject({
      collection: "files",
      special: "orphan",
      category: "inventory",
    });
    expect(useAppStore.getState().route.dir).toBeUndefined();

    fireEvent.click(screen.getByTestId("fs-explorer-close"));
    expect(fsExplorerOpen(useAppStore.getState().route)).toBe(false);
  });

  it("pages on to reveal a deep-linked folder past the first page", async () => {
    installFetch({
      "/fs-tree": (url) => {
        const path = url.searchParams.get("path") ?? "";
        if (path === "Zed") return jsonResponse(fsPage("Zed", []));
        return url.searchParams.get("after")
          ? jsonResponse(fsPage("", [folder("Zed", 1, 0)]))
          : jsonResponse(fsPage("", [folder("Alpha", 2, 0)], { child_total: 2, next_after: "QWxwaGE" }));
      },
    });
    useAppStore.getState().navigate({ runId: RUN, collection: "files", dir: "Zed" });
    renderWithClient(
      <FsExplorerLayout>
        <p>grid</p>
      </FsExplorerLayout>,
    );
    const tree = await screen.findByRole("tree", { name: "파일 시스템 폴더 트리" });
    const zed = await within(tree).findByRole("treeitem", { name: /^Zed, 파일 1개/ });
    expect(zed.getAttribute("aria-current")).toBe("location");
    expect(within(tree).queryByRole("treeitem", { name: /더 보기/ })).toBeNull();
  });

  it("explains an empty list and a failed load", async () => {
    setup({ "": () => jsonResponse(fsPage("", [], { node: { ...folder("", 0, 0), name: "" } })) });
    expect(await screen.findByText(/폴더에 놓을 파일이 없습니다/)).toBeTruthy();
    cleanup();
    setup({ "": () => jsonResponse({ detail: "완료된 런이 아닙니다" }, 409) });
    expect((await screen.findByRole("alert")).textContent).toContain("완료된 런이 아닙니다");
  });

  it("switches to the inventory list", async () => {
    const calls = setup({ "": () => jsonResponse(fsPage("", [folder("Users", 8, 1)])) });
    const select = await screen.findByRole("combobox", { name: "목록" });
    fireEvent.change(select, { target: { value: "inventory" } });
    expect(useAppStore.getState().route.category).toBe("inventory");
    expect(useAppStore.getState().route.dir).toBe("");
    await waitFor(() => expect(calls.some((call) => call.url.includes("scope=inventory"))).toBe(true));
  });
});

// --- registry --------------------------------------------------------------------------------

const HIVE = {
  id: "h1",
  name: "SYSTEM",
  path: "D:\\ev\\Windows\\System32\\config\\SYSTEM",
  mount: "HKLM\\SYSTEM",
  label: "SYSTEM (HKLM\\SYSTEM)",
  key_count: 3,
  root_last_written_at: null,
};

function regKey(name: string, path: string, children = 0) {
  return {
    name,
    key_path: path,
    last_written_at: "2024-04-01T07:26:32+00:00",
    value_count: 2,
    subkey_count: children,
    child_count: children,
    has_children: children > 0,
    record_index: 7,
    synthetic: false,
    linked_row_count: 1,
  };
}

function regLevel(key: ReturnType<typeof regKey>, children: ReturnType<typeof regKey>[]): RegistryLevel {
  return {
    run_id: RUN,
    hive: HIVE,
    key,
    breadcrumb: [],
    children,
    child_total: children.length,
    limit: 200,
    next_after: null,
    index: { key_rows: 3, keys: 3, hives: 1, truncated: false },
  };
}

const VALUES: RegistryValues = {
  run_id: RUN,
  hive: HIVE,
  key: regKey("Select", "HKLM\\SYSTEM\\Select"),
  values: [
    {
      name: "Current",
      display_name: "Current",
      type: "REG_DWORD",
      type_code: 4,
      data_size: 4,
      data_hex: "01 00 00 00",
      data_truncated: false,
      decoded: 1,
      decoded_kind: "number",
      decoded_hex: "0x1",
    },
    {
      name: "",
      display_name: "(기본값)",
      type: "REG_SZ",
      type_code: 1,
      data_size: 4,
      data_hex: "61 00",
      data_truncated: false,
      decoded: "a",
      decoded_kind: "text",
    },
  ],
  value_total: 2,
  values_status: "parsed",
  citation: {
    text: "D:\\ev\\SYSTEM › HKLM\\SYSTEM\\Select › 셀 오프셋 0x20",
    hive_path: HIVE.path,
    key_path: "HKLM\\SYSTEM\\Select",
    last_written_at: null,
    cell_offset: 32,
    kind: "windows-registry",
    record_index: 7,
    locator: "/artifacts/7",
  },
  artifact_rows: [
    {
      kind: "windows-registry",
      record_index: 99,
      artifact_type: "windows-control-set",
      label: "현재 컨트롤 세트",
      locator: "/artifacts/99",
    },
  ],
  artifact_row_total: 1,
  artifact_types: { "windows-control-set": 1 },
};

describe("레지스트리 탐색기", () => {
  it("walks hive → keys, shows decoded values, copies the path and jumps to linked rows", async () => {
    const writeText = vi.fn(async () => {});
    Object.assign(navigator, { clipboard: { writeText } });
    installFetch({
      "/registry-tree": (url) => {
        const hive = url.searchParams.get("hive");
        if (!hive)
          return jsonResponse({
            run_id: RUN,
            hives: [HIVE],
            index: { key_rows: 3, keys: 3, hives: 1, truncated: false },
          });
        return jsonResponse(
          regLevel(regKey("HKLM\\SYSTEM", "HKLM\\SYSTEM", 2), [
            regKey("ControlSet001", "HKLM\\SYSTEM\\ControlSet001", 1),
            regKey("Select", "HKLM\\SYSTEM\\Select"),
          ]),
        );
      },
      "/registry-values": () => jsonResponse(VALUES),
    });
    useAppStore.getState().navigate({ runId: RUN, collection: "registry" });
    renderWithClient(<RegistryExplorer />);
    const tree = await screen.findByRole("tree", { name: "레지스트리 키 트리" });
    const hive = await within(tree).findByRole("treeitem", { name: /SYSTEM \(HKLM\\SYSTEM\), 키 3개/ });
    expect(screen.getByText(/왼쪽 트리에서 하이브와 키를 고르면/)).toBeTruthy();
    act(() => hive.focus());
    fireEvent.keyDown(hive, { key: "ArrowRight" });
    const select = await within(tree).findByRole("treeitem", { name: /^Select, 하위 키 0개, 값 2개/ });
    expect(select.getAttribute("aria-posinset")).toBe("2");
    expect(select.getAttribute("aria-setsize")).toBe("2");
    fireEvent.keyDown(hive, { key: "ArrowDown" });
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: "ArrowDown" });
    expect(document.activeElement).toBe(select);
    fireEvent.keyDown(select, { key: "Enter" });
    expect(useAppStore.getState().route).toMatchObject({
      collection: "registry",
      kind: "h1",
      key: "HKLM\\SYSTEM\\Select",
    });

    const details = await screen.findByTestId("registry-key-details");
    const table = within(details).getByRole("table", { name: /Select 값 2개/ });
    expect(within(table).getByRole("rowheader", { name: "(기본값)" })).toBeTruthy();
    expect(within(table).getByText("1 (0x1)")).toBeTruthy();
    fireEvent.click(within(details).getByRole("button", { name: /키 경로 복사/ }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("HKLM\\SYSTEM\\Select"));
    fireEvent.click(within(details).getByRole("button", { name: /인용 복사/ }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(VALUES.citation.text));
    expect(within(details).getByText(/이 키에서 나온 아티팩트 행 1건/)).toBeTruthy();
    fireEvent.click(within(details).getByRole("button", { name: /현재 컨트롤 세트 행 열기/ }));
    expect(useAppStore.getState().route.types).toBeUndefined();
    expect(useAppStore.getState().route).toMatchObject({
      collection: "artifacts",
      kind: "windows-registry",
      row: { collection: "artifacts", kind: "windows-registry", locator: "/artifacts/99" },
    });
  });

  it("says why there is nothing to explore, and shows names-only values with the reason", async () => {
    installFetch({
      "/registry-tree": () =>
        jsonResponse({
          run_id: RUN,
          hives: [],
          reason: "이 런에는 레지스트리 키 트리 행이 없습니다",
          index: null,
        }),
    });
    useAppStore.getState().navigate({ runId: RUN, collection: "registry" });
    renderWithClient(<RegistryExplorer />);
    expect(await screen.findByText("이 런에는 레지스트리 키 트리 행이 없습니다")).toBeTruthy();
    cleanup();
    vi.unstubAllGlobals();
    installFetch({
      "/registry-tree": () => jsonResponse({ run_id: RUN, hives: [HIVE], index: null }),
      "/registry-values": () =>
        jsonResponse({
          ...VALUES,
          values_status: "names-only",
          reason: "하이브 원본 파일을 찾을 수 없어 수집된 값 이름만 보여 줍니다",
          values: [
            {
              ...VALUES.values[0],
              type: null,
              decoded: null,
              decoded_kind: "unavailable",
              data_hex: null,
              data_size: null,
            },
          ],
          artifact_rows: [],
          artifact_row_total: 0,
          citation: { ...VALUES.citation, locator: null },
        }),
    });
    useAppStore
      .getState()
      .navigate({ runId: RUN, collection: "registry", kind: "h1", key: "HKLM\\SYSTEM\\Select" });
    renderWithClient(<RegistryExplorer />);
    expect(await screen.findByText(/수집된 값 이름만/)).toBeTruthy();
    expect(screen.getByText("값을 읽지 못함")).toBeTruthy();
    expect(screen.getByText(/이 키에서 나온 아티팩트 행이 없습니다/)).toBeTruthy();
    const open = screen.getByRole("button", { name: /키 트리 행 열기/ });
    expect(open.getAttribute("aria-disabled")).toBe("true");
    expect(keyAncestorIds(HIVE, "HKLM\\SYSTEM\\A\\B\\C")).toEqual([
      "h1\u0000",
      "h1\u0000HKLM\\SYSTEM\\A",
      "h1\u0000HKLM\\SYSTEM\\A\\B",
    ]);
  });
});

// --- media panel -------------------------------------------------------------------------------

describe("미디어 탐색기 패널", () => {
  const props = {
    runId: RUN,
    activePath: "C:\\case\\a.jpg",
    activeName: "a.jpg",
    loadedKeys: new Set([mediaPathKey("C:/case/a.jpg"), mediaPathKey("C:/case/near.jpg")]),
    onNarrow: vi.fn(),
    onSelect: vi.fn(),
    onFocusPath: vi.fn(() => false),
    onOpenRecord: vi.fn(),
  };

  const similar = {
    run_id: RUN,
    ref: { path: "C:\\case\\a.jpg", record_index: 0, perceptual_hash: "0", sha256: "aa" },
    max_distance: 8,
    limit: 100,
    items: [
      {
        path: "C:\\case\\copy.jpg",
        name: "copy.jpg",
        kind: "media-image",
        record_index: 1,
        locator: "/artifacts/1",
        distance: 0,
        same_hash: true,
        sha256: "aa",
        camera: null,
        captured_at: null,
      },
      {
        path: "C:\\case\\near.jpg",
        name: "near.jpg",
        kind: "media-image",
        record_index: 2,
        locator: "/artifacts/2",
        distance: 6,
        same_hash: false,
        sha256: "bb",
        camera: "Apple iPhone",
        captured_at: null,
      },
    ],
    counts: { indexed: 3, with_phash: 3, same_hash: 1, near: 1, matched: 2, returned: 2 },
  };

  it("shows same-hash and pHash ≤ 8 groups and narrows / selects / opens", async () => {
    const calls = installFetch({
      "/media/similar": () => jsonResponse(similar),
      "/related-media": () =>
        jsonResponse({ count: 1, paths: ["C:\\case\\copy.jpg"], source: "duplicate_content_groups" }),
    });
    renderWithClient(<MediaExplorerPanel {...props} mode="related" />);
    const panel = await screen.findByTestId("media-panel");
    expect(within(panel).getByRole("heading", { name: /관련 미디어 — a.jpg/ })).toBeTruthy();
    await waitFor(() => expect(within(panel).getByText(/같은 해시 1/)).toBeTruthy());
    await waitFor(() => expect(within(panel).getByText(/pHash 근접\(≤ 8\) 1/)).toBeTruthy());
    expect(calls.some((call) => call.url.includes("max_distance=8"))).toBe(true);
    const near = within(panel).getByRole("list", { name: "pHash 근접 이미지" });
    expect(within(near).getByText(/pHash 거리 6 · 폴더 case · Apple iPhone/)).toBeTruthy();
    fireEvent.click(within(near).getByRole("button", { name: "near.jpg" }));
    expect(props.onFocusPath).toHaveBeenCalledWith("C:\\case\\near.jpg");
    expect(props.onOpenRecord).toHaveBeenCalledWith(2, "C:\\case\\near.jpg");
    const narrowButtons = within(panel).getAllByRole("button", { name: "격자에 이 묶음만" });
    fireEvent.click(narrowButtons[1] as HTMLElement);
    expect(props.onNarrow).toHaveBeenCalledWith({
      label: "pHash 근접(≤ 8): a.jpg",
      paths: ["C:\\case\\a.jpg", "C:\\case\\near.jpg"],
    });
    fireEvent.click(within(panel).getAllByRole("button", { name: "이 묶음 선택(태그용)" })[1] as HTMLElement);
    expect(props.onSelect).toHaveBeenCalled();
  });

  it("finds similar photos with a chosen distance and explains a missing pHash", async () => {
    const calls = installFetch({ "/media/similar": () => jsonResponse(similar) });
    renderWithClient(<MediaExplorerPanel {...props} mode="similar" />);
    const distance = await screen.findByRole("combobox", { name: "최대 pHash 거리" });
    fireEvent.change(distance, { target: { value: "12" } });
    await waitFor(() => expect(calls.some((call) => call.url.includes("max_distance=12"))).toBe(true));
    expect(await screen.findByText(/2건 \(pHash 있는 이미지 3개 중\)/)).toBeTruthy();
    cleanup();
    vi.unstubAllGlobals();
    installFetch({ "/media/similar": () => jsonResponse({ detail: "pHash 없음" }, 409) });
    renderWithClient(<MediaExplorerPanel {...props} mode="similar" />);
    expect(await screen.findByText(/pHash\(지각 해시\)가 없어/)).toBeTruthy();
    cleanup();
    renderWithClient(<MediaExplorerPanel {...props} activePath={null} mode="related" />);
    expect(screen.getByText(/썸네일을 하나 고르면/)).toBeTruthy();
  });

  it("groups by camera and capture day", async () => {
    installFetch({
      "/media/groups": (url) =>
        url.searchParams.has("key")
          ? jsonResponse({
              run_id: RUN,
              by: "camera",
              groups: [],
              key: "Apple iPhone",
              paths: ["C:/case/a.jpg"],
              path_total: 1,
            })
          : jsonResponse({
              run_id: RUN,
              by: url.searchParams.get("by"),
              groups: [
                { key: "Apple iPhone", label: "Apple iPhone", count: 2, sample_paths: [] },
                { key: "", label: "카메라 정보 없음", count: 5, sample_paths: [] },
              ],
            }),
    });
    renderWithClient(<MediaExplorerPanel {...props} mode="groups" />);
    const list = await screen.findByRole("list", { name: "그룹" });
    fireEvent.click(within(list).getByRole("button", { name: "Apple iPhone (2)" }));
    expect(within(list).getByRole("button", { name: "Apple iPhone (2)" }).getAttribute("aria-pressed")).toBe(
      "true",
    );
    expect(await screen.findByText("격자에 있음 1/1")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "격자에 이 묶음만" }));
    expect(props.onNarrow).toHaveBeenLastCalledWith({
      label: "카메라: Apple iPhone",
      paths: ["C:/case/a.jpg"],
    });
  });
});

// --- review fixes (R4 console) ---------------------------------------------------------------

describe("탐색기 리뷰 수정", () => {
  function renderFs() {
    renderWithClient(
      <FsExplorerLayout>
        <p>grid</p>
      </FsExplorerLayout>,
    );
  }

  it("더 보기 keeps its row (busy) while loading, then focuses the first new child", async () => {
    let release: () => void = () => undefined;
    installFetch({
      "/fs-tree": (url) => {
        if (!url.searchParams.get("after")) {
          return jsonResponse(fsPage("", [folder("Users", 8, 0)], { child_total: 2, next_after: "QQ" }));
        }
        return new Promise<Response>((resolve) => {
          release = () => resolve(jsonResponse(fsPage("", [folder("Windows", 2, 0)])));
        });
      },
    });
    useAppStore.getState().navigate({ runId: RUN, collection: "files", dir: "" });
    renderFs();
    const tree = await screen.findByRole("tree", { name: "파일 시스템 폴더 트리" });
    const more = await within(tree).findByRole("treeitem", { name: /더 보기 \(1개 남음\)/ });
    act(() => more.focus());
    fireEvent.keyDown(more, { key: "Enter" });
    // Same element, still focused, marked busy.
    await waitFor(() => expect(more.getAttribute("aria-busy")).toBe("true"));
    expect(more.isConnected).toBe(true);
    expect(more.textContent).toContain("더 불러오는 중…");
    expect(document.activeElement).toBe(more);
    await act(async () => release());
    const windows = await within(tree).findByRole("treeitem", { name: /^Windows, 파일 2개/ });
    await waitFor(() => expect(document.activeElement).toBe(windows));
    expect(windows.tabIndex).toBe(0);
  });

  it("stops paging after MAX_AUTO_PAGES for a deep link that is not there and says so", async () => {
    const calls = installFetch({
      "/fs-tree": (url) => {
        const path = url.searchParams.get("path") ?? "";
        if (path !== "") return jsonResponse({ detail: "폴더를 찾을 수 없습니다" }, 404);
        const page = Number(url.searchParams.get("after") ?? "0");
        return jsonResponse(
          fsPage("", [folder(`F${page}`, 1, 0)], { child_total: 100, next_after: String(page + 1) }),
        );
      },
    });
    useAppStore.getState().navigate({ runId: RUN, collection: "files", dir: "Missing" });
    renderFs();
    const tree = await screen.findByRole("tree", { name: "파일 시스템 폴더 트리" });
    expect(await within(tree).findByText(/위치를 찾지 못했습니다/)).toBeTruthy();
    const paged = calls.filter((call) => call.url.includes("after="));
    expect(paged).toHaveLength(MAX_AUTO_PAGES);
    // The rest stays with the examiner (더 보기), and nothing pages on by itself.
    expect(within(tree).getByRole("treeitem", { name: /더 보기/ })).toBeTruthy();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(calls.filter((call) => call.url.includes("after="))).toHaveLength(MAX_AUTO_PAGES);
  });

  it("an empty folder list still offers the special nodes", async () => {
    installFetch({
      "/fs-tree": () =>
        jsonResponse(
          fsPage("", [], {
            node: { ...folder("", 0, 0), name: "" },
            special_nodes: [
              {
                id: "orphan",
                label: "고아 파일",
                count: 3,
                counts: { candidates: 3, inventory: 0 },
                source: "files",
                files_query: { special: "orphan" },
              },
            ],
          }),
        ),
    });
    useAppStore.getState().navigate({ runId: RUN, collection: "files", dir: "" });
    renderFs();
    expect(await screen.findByTestId("fs-explorer-empty")).toBeTruthy();
    const orphan = await screen.findByRole("treeitem", { name: /고아 파일, 3건/ });
    fireEvent.click(orphan);
    expect(useAppStore.getState().route).toMatchObject({ collection: "files", special: "orphan" });
  });

  it("a breadcrumb clears the open row and viewer mode", async () => {
    installFetch({
      "/fs-tree": (url) => {
        const path = url.searchParams.get("path") ?? "";
        if (path === "Users/alice") return jsonResponse(fsPage("Users/alice", []));
        if (path === "Users") return jsonResponse(fsPage("Users", [folder("Users/alice", 8, 0)]));
        return jsonResponse(fsPage("", [folder("Users", 8, 1)]));
      },
    });
    useAppStore.getState().navigate({
      runId: RUN,
      collection: "files",
      dir: "Users/alice",
      row: { collection: "files", locator: "/files/3" },
      mode: "hex",
    });
    renderFs();
    const header = await screen.findByTestId("fs-explorer-header");
    const crumbs = within(header).getByRole("navigation", { name: "폴더 경로" });
    fireEvent.click(await within(crumbs).findByRole("button", { name: "Users" }));
    expect(useAppStore.getState().route.dir).toBe("Users");
    expect(useAppStore.getState().route.row).toBeUndefined();
    expect(useAppStore.getState().route.mode).toBeUndefined();
    fireEvent.click(await within(crumbs).findByRole("button", { name: "볼륨 1 (스캔 루트)" }));
    expect(useAppStore.getState().route.dir).toBe("");
    expect(useAppStore.getState().route.row).toBeUndefined();
  });

  it("registry key details start over for another key (no stale copy message)", async () => {
    Object.assign(navigator, { clipboard: { writeText: vi.fn(async () => {}) } });
    installFetch({
      "/registry-tree": () => jsonResponse({ run_id: RUN, hives: [HIVE], index: null }),
      "/registry-values": () => jsonResponse(VALUES),
    });
    useAppStore
      .getState()
      .navigate({ runId: RUN, collection: "registry", kind: "h1", key: "HKLM\\SYSTEM\\Select" });
    renderWithClient(<RegistryExplorer />);
    const details = await screen.findByTestId("registry-key-details");
    fireEvent.click(within(details).getByRole("button", { name: /키 경로 복사/ }));
    expect(await screen.findByText(/복사했습니다/)).toBeTruthy();
    act(() => useAppStore.getState().patchRoute({ key: "HKLM\\SYSTEM\\ControlSet001" }));
    await screen.findByTestId("registry-key-details");
    expect(screen.queryByText(/복사했습니다/)).toBeNull();
  });

  it("narrowing the thumbnails keeps the active image when it is in the set", () => {
    const rows = ["C:/a.jpg", "C:/b.jpg", "C:/c.jpg"].map(
      (sourcePath, index) => ({ rowKey: String(index), sourcePath }) as unknown as GridRow,
    );
    const set = { label: "같은 해시", paths: ["c:\\c.jpg", "C:/b.jpg"] };
    expect(narrowedActiveIndex(rows, set, "C:/c.jpg")).toBe(1);
    expect(narrowedActiveIndex(rows, set, "C:/a.jpg")).toBe(0);
    expect(narrowedActiveIndex(rows, null, "C:/c.jpg")).toBe(2);
    expect(narrowedActiveIndex(rows, set, null)).toBe(0);
  });
});
