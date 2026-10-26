// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
import { act, cleanup, configure, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetArtifactCountsCache } from "../../api/collections";
import { EMPTY_CATALOG_FOR_TESTS, setCatalog } from "../flags/catalog";
import { useGridLocalStore } from "./adapter";
import { fieldColumnsStorageKey } from "./columns/fieldColumns";
import { CLIENT_SORT_HINT, DataGrid } from "./DataGrid";
import {
  installFetch,
  jsonResponse,
  mockLayout,
  renderWithClient,
  resetGridStore,
  sortedArtifactsHandler,
} from "./testSupport";

// Generous async timeouts: these tests must not depend on machine speed (CI under load).
configure({ asyncUtilTimeout: 5000 });

const announceMock = vi.hoisted(() => vi.fn());
vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: announceMock,
}));

let restoreLayout: () => void;
const KIND = "windows-prefetch";

beforeEach(() => {
  resetGridStore();
  resetArtifactCountsCache();
  window.localStorage.clear();
  useGridLocalStore.setState((s) => ({
    route: { ...s.route, collection: { id: "artifacts", kind: KIND }, q: "", rowRef: null },
  }));
  restoreLayout = mockLayout();
});
afterEach(() => {
  cleanup();
  setCatalog(null);
  restoreLayout();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  announceMock.mockReset();
  window.localStorage.clear();
});

const rows = () => screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index"));
const rowAt = (i: number) => rows().find((r) => r.getAttribute("data-index") === String(i)) as HTMLElement;
const header = (text: string) =>
  screen
    .getAllByRole("columnheader")
    .find((h) => within(h).queryByRole("button", { name: text })) as HTMLElement;
const hasHeader = (text: string) =>
  screen.getAllByRole("columnheader").some((h) => within(h).queryByRole("button", { name: text }));
const picker = () => within(screen.getByRole("group", { name: "레코드 필드 추가" }));
const titleOf = (i: number) => rowAt(i).querySelector('[data-col="title"]')?.textContent ?? "";
const status = () => screen.getByTestId("grid-sort-status");
/** Advance the fake clock and flush promises (quick mock responses settle without real time). */
const tick = (ms: number) =>
  act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
const settle = async () => {
  for (let i = 0; i < 5; i += 1) await tick(0);
};

async function renderArtifacts(options: Parameters<typeof sortedArtifactsHandler>[0] = {}) {
  const calls = installFetch({ "/artifacts": sortedArtifactsHandler({ total: 30, ...options }) });
  const view = renderWithClient(<DataGrid />);
  await waitFor(() => expect(rows().length).toBeGreaterThan(0));
  return { calls, ...view };
}

describe("artifacts header sort (server, whole kind)", () => {
  it("a column without a server sort key sorts the loaded rows (no server call, plan r7 §3.2 L2)", async () => {
    const { calls } = await renderArtifacts();
    const title = header("항목");
    const button = within(title).getByRole("button");
    expect(button.getAttribute("aria-disabled")).toBeNull();
    expect(button.getAttribute("title")).toBe(CLIENT_SORT_HINT);
    const before = calls.length;
    fireEvent.click(button);
    expect(title.getAttribute("aria-sort")).toBe("ascending");
    expect(useGridLocalStore.getState().route.sort).toBeUndefined();
    expect(calls.filter((c) => c.url.includes("sort=")).length).toBe(0);
    expect(calls.length).toBe(before);
    // All 30 rows are loaded: the sort covers the whole kind, so no "loaded rows" banner.
    expect(screen.queryByTestId("grid-scope-banner")).toBeNull();
    expect(screen.getByTestId("grid-scope-badge").textContent).toBe("불러온 30 / 전체 30");
  });

  it("a server sort replaces a loaded-rows sort and the other way round", async () => {
    await renderArtifacts();
    fireEvent.click(within(header("항목")).getByRole("button"));
    expect(header("항목").getAttribute("aria-sort")).toBe("ascending");
    fireEvent.click(within(header("실행 횟수")).getByRole("button"));
    expect(useGridLocalStore.getState().route.sort).toEqual({ key: "details.run_count", order: "asc" });
    expect(header("항목").getAttribute("aria-sort")).toBe("none");
    fireEvent.click(within(header("항목")).getByRole("button"));
    expect(useGridLocalStore.getState().route.sort).toBeUndefined();
    expect(header("항목").getAttribute("aria-sort")).toBe("ascending");
  });

  it("multi-key columns sort on their first key and the button says which", async () => {
    await renderArtifacts();
    // The header's accessible name stays the header text; the key hint is a description.
    const column = screen.getByRole("columnheader", { name: "실행 파일" });
    const button = within(column).getByRole("button", { name: "실행 파일" });
    const hintId = button.getAttribute("aria-describedby") ?? "";
    expect(document.getElementById(hintId)?.textContent).toBe("실행 파일 정렬 (executable_hint 기준)");
    expect(button.getAttribute("aria-disabled")).toBeNull();
    expect(button.getAttribute("title")).toBe("실행 파일 정렬 (executable_hint 기준)");
    fireEvent.click(button);
    expect(useGridLocalStore.getState().route.sort).toEqual({ key: "details.executable_hint", order: "asc" });
  });

  it("sortable header: building → progress status, 1 s poll → ready, rows in server order, locators kept", async () => {
    const { calls } = await renderArtifacts({ buildPolls: 1 });
    expect(titleOf(0)).toBe("APP0.EXE");
    vi.useFakeTimers();
    const sortCalls = (order: string) =>
      calls.filter((c) => c.url.includes(`order=${order}`) && !c.url.includes("locate="));
    const runCount = header("실행 횟수");
    expect(within(runCount).getByRole("button").getAttribute("aria-disabled")).toBeNull();

    fireEvent.click(within(runCount).getByRole("button"));
    expect(useGridLocalStore.getState().route.sort).toEqual({ key: "details.run_count", order: "asc" });
    await settle();
    expect(status().textContent).toMatch(/전체 정렬 인덱스 생성 중 … 50%/);
    // Plain text: transitions go through the single announce() live region.
    expect(status().getAttribute("aria-live")).toBeNull();
    expect(status().getAttribute("role")).toBeNull();
    expect(announceMock).toHaveBeenCalledWith("전체 정렬 인덱스 생성을 시작했습니다.");
    // The 1 s re-request is driven by the fake clock: none at 999 ms, exactly one at 1000 ms.
    expect(sortCalls("asc")).toHaveLength(1);
    await tick(999);
    expect(sortCalls("asc")).toHaveLength(1);
    await tick(1);
    expect(sortCalls("asc")).toHaveLength(2);
    await vi.waitFor(() => expect(status().textContent).toBe("정렬: 실행 횟수 오름차순 (전체 30건)"));
    expect(announceMock).toHaveBeenCalledWith("정렬: 실행 횟수 오름차순 (전체 30건)");
    expect(header("실행 횟수").getAttribute("aria-sort")).toBe("ascending");
    await vi.waitFor(() => expect(titleOf(0)).toBe("APP0.EXE"));

    fireEvent.click(within(header("실행 횟수")).getByRole("button"));
    await settle();
    expect(status().textContent).toMatch(/생성 중/);
    expect(sortCalls("desc")).toHaveLength(1);
    await tick(1000);
    expect(sortCalls("desc")).toHaveLength(2);
    await vi.waitFor(() => expect(status().textContent).toBe("정렬: 실행 횟수 내림차순 (전체 30건)"));
    await vi.waitFor(() => expect(titleOf(0)).toBe("APP17.EXE"));
    expect(rowAt(0).getAttribute("data-row-key")).toBe(`artifacts:${KIND}:/artifacts/17`);
    const sorted = calls.filter((c) => c.url.includes("sort=details.run_count"));
    expect(sorted.some((c) => c.url.includes("order=desc"))).toBe(true);
    // Paged mode, never the client "loaded rows only" sort.
    expect(screen.queryByText(/정렬은 불러온/)).toBeNull();

    fireEvent.click(within(header("실행 횟수")).getByRole("button"));
    expect(useGridLocalStore.getState().route.sort).toBeUndefined();
    expect(header("실행 횟수").getAttribute("aria-sort")).toBe("none");
  });

  it("unsupported: the reason shows in the status line and the sort is cleared", async () => {
    await renderArtifacts({ unsupported: ["details.run_count"] });
    fireEvent.click(within(header("실행 횟수")).getByRole("button"));
    await waitFor(() => expect(status().textContent).toBe("전체 정렬을 할 수 없습니다: 비스칼라 키입니다"));
    expect(announceMock).toHaveBeenCalledWith("전체 정렬을 할 수 없습니다: 비스칼라 키입니다");
    expect(useGridLocalStore.getState().route.sort).toBeUndefined();
    expect(header("실행 횟수").getAttribute("aria-sort")).toBe("none");
  });

  it("artifacts without one kind: headers sort the loaded rows (the server sorts one kind only)", async () => {
    useGridLocalStore.setState((s) => ({ route: { ...s.route, collection: { id: "artifacts" } } }));
    await renderArtifacts();
    const button = within(header("항목")).getByRole("button");
    expect(button.getAttribute("aria-disabled")).toBeNull();
    expect(button.getAttribute("title")).toBe(CLIENT_SORT_HINT);
    fireEvent.click(button);
    expect(header("항목").getAttribute("aria-sort")).toBe("ascending");
    expect(useGridLocalStore.getState().route.sort).toBeUndefined();
    expect(screen.queryByRole("button", { name: "열 설정" })).toBeTruthy();
  });
});

describe("focus follows the RowRef under a server sort (locate=)", () => {
  const focused = () => rows().find((r) => r.tabIndex === 0) as HTMLElement;

  it("a sorted deep link asks the server for the row's position and focuses that record", async () => {
    useGridLocalStore.setState((s) => ({
      route: {
        ...s.route,
        sort: { key: "details.run_count", order: "desc" },
        rowRef: { collection: "artifacts", kind: KIND, locator: "/artifacts/4" },
      },
    }));
    const { calls } = await renderArtifacts();
    // run_count = (i*7) % 30: record 4 has 28, second in descending order.
    await waitFor(() =>
      expect(focused().getAttribute("data-row-key")).toBe(`artifacts:${KIND}:/artifacts/4`),
    );
    expect(focused().getAttribute("data-index")).toBe("1");
    expect(calls.some((c) => c.url.includes("locate=4") && c.url.includes("order=desc"))).toBe(true);
    expect(useGridLocalStore.getState().route.rowRef?.locator).toBe("/artifacts/4");
  });

  it("applying a sort after picking row 3 re-finds record 3; row= never changes to another record", async () => {
    await renderArtifacts({ buildPolls: 1 });
    vi.useFakeTimers();
    fireEvent.mouseDown(rowAt(3), { button: 0 });
    expect(useGridLocalStore.getState().route.rowRef?.locator).toBe("/artifacts/3");
    const seen: string[] = [];
    const off = useGridLocalStore.subscribe((s) => {
      seen.push(s.route.rowRef?.locator ?? "");
    });
    fireEvent.click(within(header("실행 횟수")).getByRole("button"));
    await settle();
    expect(status().textContent).toMatch(/생성 중/);
    await tick(1000);
    await vi.waitFor(() => expect(status().textContent).toMatch(/^정렬:/));
    // Record 3 has run_count 21 → position 21 in ascending order.
    await vi.waitFor(() =>
      expect(focused().getAttribute("data-row-key")).toBe(`artifacts:${KIND}:/artifacts/3`),
    );
    expect(focused().getAttribute("data-index")).toBe("21");
    off();
    expect(new Set(seen.filter(Boolean))).toEqual(new Set(["/artifacts/3"]));
  });

  it("a row the sorted kind cannot locate falls back to position 0 without rewriting row=", async () => {
    useGridLocalStore.setState((s) => ({
      route: {
        ...s.route,
        sort: { key: "details.run_count", order: "asc" },
        rowRef: { collection: "artifacts", kind: KIND, locator: "/artifacts/999" },
      },
    }));
    await renderArtifacts();
    await waitFor(() => expect(focused().getAttribute("data-index")).toBe("0"));
    expect(useGridLocalStore.getState().route.rowRef?.locator).toBe("/artifacts/999");
  });
});

describe("record-field columns (열 설정 › 레코드 필드 추가)", () => {
  it("search + check promotes a field: column appears, URL cols and the kind's storage are set; Esc returns focus", async () => {
    await renderArtifacts();
    const menuButton = screen.getByRole("button", { name: "열 설정" });
    fireEvent.click(menuButton);
    const search = screen.getByRole("searchbox", { name: "필드 검색" });
    // run_count is already a prefetch kind column: not offered.
    expect(picker().queryByRole("checkbox", { name: /^run_count/ })).toBeNull();
    fireEvent.change(search, { target: { value: "serial" } });
    const box = picker().getByRole("checkbox", { name: /volume_serial/ });
    fireEvent.click(box);
    expect(useGridLocalStore.getState().route.cols).toEqual(["details.volume_serial"]);
    expect(JSON.parse(window.localStorage.getItem(fieldColumnsStorageKey(KIND)) ?? "null")).toEqual([
      "details.volume_serial",
    ]);
    const col = header("volume_serial");
    expect(col).toBeTruthy();
    expect(within(rowAt(0)).getByText("VS-0")).toBeTruthy();
    // The promoted column is server sortable.
    expect(within(col).getByRole("button").getAttribute("aria-disabled")).toBeNull();

    search.focus();
    act(() => {
      fireEvent.keyDown(search, { key: "Escape" });
    });
    expect(screen.queryByRole("searchbox", { name: "필드 검색" })).toBeNull();
    expect(document.activeElement).toBe(menuButton);

    // Unchecking removes it again.
    fireEvent.click(menuButton);
    fireEvent.click(picker().getByRole("checkbox", { name: /volume_serial/ }));
    expect(useGridLocalStore.getState().route.cols).toBeUndefined();
    expect(hasHeader("volume_serial")).toBe(false);
  });

  it("lists keys of every artifact type on the loaded page; the second type's keys are searchable", async () => {
    installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            [KIND]: {
              total: 3,
              artifacts: [
                {
                  artifact_type: "prefetch-file",
                  details: { executable_hint: "A.EXE", prefetch_version: 30 },
                  record_index: 0,
                },
                {
                  artifact_type: "prefetch-reference",
                  details: { referenced_path: "C:/a", referenced_extension: ".DLL" },
                  record_index: 1,
                },
                {
                  artifact_type: "prefetch-reference",
                  details: { referenced_path: "C:/b", referenced_extension: "" },
                  record_index: 2,
                },
              ],
            },
          },
        }),
    });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBe(3));
    fireEvent.click(screen.getByRole("button", { name: "열 설정" }));
    expect(picker().getByRole("checkbox", { name: "prefetch_version" })).toBeTruthy();
    fireEvent.change(screen.getByRole("searchbox", { name: "필드 검색" }), {
      target: { value: "extension" },
    });
    const box = picker().getByRole("checkbox", { name: "referenced_extension" });
    fireEvent.click(box);
    expect(useGridLocalStore.getState().route.cols).toEqual(["details.referenced_extension"]);
  });

  it("restores the kind's stored columns into the route; promoted columns survive preset changes", async () => {
    window.localStorage.setItem(fieldColumnsStorageKey(KIND), JSON.stringify(["details.volume_serial"]));
    await renderArtifacts();
    await waitFor(() => expect(useGridLocalStore.getState().route.cols).toEqual(["details.volume_serial"]));
    expect(header("volume_serial")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /^조건/ }));
    fireEvent.change(screen.getByRole("combobox", { name: "열 구성" }), { target: { value: "compact" } });
    expect(header("volume_serial")).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox", { name: "열 구성" }), { target: { value: "source" } });
    expect(header("volume_serial")).toBeTruthy();
  });

  it("the URL's cols win over the stored set", async () => {
    window.localStorage.setItem(fieldColumnsStorageKey(KIND), JSON.stringify(["details.volume_serial"]));
    useGridLocalStore.setState((s) => ({ route: { ...s.route, cols: ["details.last_run_at"] } }));
    await renderArtifacts();
    expect(header("최근 실행")).toBeTruthy();
    expect(hasHeader("volume_serial")).toBe(false);
  });
});

describe("artifact-columns review fixes", () => {
  const page = (kind: string, rows: Array<Record<string, unknown>>) => () =>
    jsonResponse({
      artifacts: {
        [kind]: { total: rows.length, artifacts: rows.map((row, i) => ({ record_index: i, ...row })) },
      },
    });

  it("a sorted deep link retries locate while the index builds, then focuses the record", async () => {
    useGridLocalStore.setState((s) => ({
      route: {
        ...s.route,
        sort: { key: "details.run_count", order: "desc" },
        rowRef: { collection: "artifacts", kind: KIND, locator: "/artifacts/4" },
      },
    }));
    const { calls } = await renderArtifacts({ locateBuildPolls: 1 });
    await waitFor(() =>
      expect(
        rows()
          .find((r) => r.tabIndex === 0)
          ?.getAttribute("data-row-key"),
      ).toBe(`artifacts:${KIND}:/artifacts/4`),
    );
    expect(calls.filter((c) => c.url.includes("locate=4"))).toHaveLength(2);
  });

  it("no locate under a server path filter: focus falls back to row 0, row= kept", async () => {
    useGridLocalStore.setState((s) => ({
      route: {
        ...s.route,
        q: "APP",
        sort: { key: "details.run_count", order: "asc" },
        rowRef: { collection: "artifacts", kind: KIND, locator: "/artifacts/4" },
      },
    }));
    const { calls } = await renderArtifacts();
    await waitFor(() =>
      expect(
        rows()
          .find((r) => r.tabIndex === 0)
          ?.getAttribute("data-index"),
      ).toBe("0"),
    );
    expect(calls.some((c) => c.url.includes("locate="))).toBe(false);
    expect(useGridLocalStore.getState().route.rowRef?.locator).toBe("/artifacts/4");
  });

  it("re-promoting a field the checkbox list had hidden shows it again", async () => {
    await renderArtifacts();
    fireEvent.click(screen.getByRole("button", { name: "열 설정" }));
    fireEvent.click(picker().getByRole("checkbox", { name: "volume_serial" }));
    expect(hasHeader("volume_serial")).toBe(true);
    const shown = within(screen.getByRole("group", { name: "표시할 열" }));
    fireEvent.click(shown.getAllByRole("checkbox", { name: "volume_serial" })[0] as HTMLElement);
    expect(hasHeader("volume_serial")).toBe(false);
    fireEvent.click(picker().getByRole("checkbox", { name: "volume_serial" })); // remove
    fireEvent.click(picker().getByRole("checkbox", { name: "volume_serial" })); // promote again
    expect(hasHeader("volume_serial")).toBe(true);
  });

  it("list keys: promoted column is not sortable (reason); unshareable keys are greyed with a reason; counts are descriptions", async () => {
    installFetch({
      "/artifacts": page(KIND, [
        { artifact_type: "prefetch-file", details: { tags: ["a", "b"], "bad key": "x", serial: "S1" } },
        { artifact_type: "prefetch-file", details: { tags: ["c"], serial: "" } },
      ]),
    });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBe(2));
    fireEvent.click(screen.getByRole("button", { name: "열 설정" }));
    const bad = picker().getByRole("checkbox", { name: "bad key" });
    expect(bad.getAttribute("aria-disabled")).toBe("true");
    expect(bad.getAttribute("data-disabled-reason")).toBe(
      "열 이름에 공백/쉼표/콜론이 있어 공유 링크에 담을 수 없습니다",
    );
    fireEvent.click(bad);
    expect(useGridLocalStore.getState().route.cols).toBeUndefined();
    const serial = picker().getByRole("checkbox", { name: "serial" });
    const desc = (serial.getAttribute("aria-describedby") ?? "").split(" ")[0] ?? "";
    expect(document.getElementById(desc)?.textContent).toBe("불러온 행 중 1행에 값 있음");
    fireEvent.click(picker().getByRole("checkbox", { name: "tags" }));
    const tagsHeader = screen.getByRole("columnheader", { name: "tags" });
    expect(tagsHeader.getAttribute("data-col")).toBe("f:tags");
    // A list-valued column has no server sort: it sorts the loaded rows (header hint).
    const button = within(tagsHeader).getByRole("button", { name: "tags" });
    expect(button.getAttribute("aria-disabled")).toBeNull();
    expect(button.getAttribute("title")).toBe(CLIENT_SORT_HINT);
  });

  it("eventlog 메시지 sorts on the key the cells show: message when present, else raw event_message", async () => {
    // KIND_COLUMNS layout: a catalogue that does not claim eventlog (the catalogue layout keeps
    // the same 메시지 column, off by default — artifactColumns.test).
    setCatalog(EMPTY_CATALOG_FOR_TESTS, "server");
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, collection: { id: "artifacts", kind: "eventlog" } },
    }));
    installFetch({
      "/artifacts": page("eventlog", [
        {
          artifact_type: "eventlog-event",
          details: { message: "hello", event_message: "provider=x | hello" },
        },
      ]),
    });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBe(1));
    const message = screen.getByRole("columnheader", { name: "메시지" });
    const button = within(message).getByRole("button", { name: "메시지" });
    const hint = document.getElementById(button.getAttribute("aria-describedby") ?? "");
    expect(hint?.textContent).toBe("메시지 정렬 (message 기준)");
    fireEvent.click(button);
    expect(useGridLocalStore.getState().route.sort).toEqual({ key: "details.message", order: "asc" });
  });

  it("a 409 (stale index) twice in a row shows the server detail in the status line", async () => {
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, sort: { key: "details.run_count", order: "asc" } },
    }));
    const calls = installFetch({
      "/artifacts": () => jsonResponse({ detail: "artifact file changed; sort index rebuilt" }, 409),
    });
    renderWithClient(<DataGrid />);
    await waitFor(() =>
      expect(status().textContent).toBe(
        "정렬 인덱스를 다시 만들어야 합니다: artifact file changed; sort index rebuilt",
      ),
    );
    expect(calls.filter((c) => c.url.includes("sort=")).length).toBe(2);
  });
});
