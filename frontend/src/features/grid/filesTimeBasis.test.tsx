// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
// R7 stage 1 re-review R-2 (UI) and R-9 (UI): the files grid says when its times are
// acquisition-copy times, why a time condition matched nothing, and when a sort did nothing.
import { act, cleanup, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EMPTY_FILTERS } from "../filters/filterModel";
import { useFilterStore } from "../filters/filterStore";
import { useGridLocalStore } from "./adapter";
import { DataGrid } from "./DataGrid";
import {
  ACQUISITION_COPY_BANNER,
  sortIneffectiveText,
  timeBasisBanner,
  timeBasisEmptyText,
  timeBasisOf,
  timeConditionActive,
} from "./filesTimeBasis";
import {
  filesHandler,
  type Handler,
  installFetch,
  jsonResponse,
  mockLayout,
  renderWithClient,
  resetGridStore,
} from "./testSupport";

vi.mock("../../a11y", () => ({ announce: vi.fn() }));

let restoreLayout: () => void;
beforeEach(() => {
  resetGridStore();
  useFilterStore.setState({ filters: { ...EMPTY_FILTERS } });
  restoreLayout = mockLayout();
});
afterEach(() => {
  cleanup();
  restoreLayout();
  vi.unstubAllGlobals();
});

const rows = () => screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index"));

/** filesHandler with extra top-level fields (and an optional sort-descriptor patch). */
function withFields(
  base: Handler,
  extra: Record<string, unknown>,
  sortPatch?: Record<string, unknown>,
): Handler {
  return async (url, init) => {
    const response = (await base(url, init)) as Response;
    const body = (await response.json()) as Record<string, unknown>;
    const sort = body.sort && sortPatch ? { ...(body.sort as object), ...sortPatch } : body.sort;
    return jsonResponse({ ...body, ...extra, ...(sort ? { sort } : {}) });
  };
}

describe("helpers", () => {
  it("time basis, banner, empty text and time-condition detection", () => {
    expect(timeBasisOf({ time_basis: "acquisition-copy" })).toBe("acquisition-copy");
    expect(timeBasisOf({ time_basis: "weird" })).toBeNull();
    expect(timeBasisOf(undefined)).toBeNull();
    expect(timeBasisBanner("acquisition-copy")).toBe(
      "시간 조건·정렬은 취득 사본 시각 기준입니다(NTFS 시각 없음)",
    );
    expect(timeBasisBanner("ntfs")).toBeNull();
    expect(timeBasisBanner("mixed")).toContain("취득 사본 시각");
    expect(timeBasisEmptyText("acquisition-copy")).toContain("취득 사본 시각");
    expect(timeBasisEmptyText("ntfs")).toBeNull();
    expect(timeConditionActive({})).toBe(false);
    expect(timeConditionActive({ from: "2025-01-01T00:00" })).toBe(true);
    expect(timeConditionActive({ weekdays: ["sat"] })).toBe(true);
    expect(timeConditionActive({ offhours: true })).toBe(true);
  });

  it("sort notices: unknown key, not applied, all-empty column", () => {
    const ready = { key: "size", order: "asc" as const, status: "ready" as const, progress: 1 };
    expect(sortIneffectiveText("bogus", undefined, null, false)).toBe(
      "알 수 없는 정렬 키(bogus) — 정렬하지 않았습니다",
    );
    expect(sortIneffectiveText("size", "크기", { ...ready, empty: true }, true)).toBe(
      "크기 — 값이 없어 정렬 효과 없음",
    );
    expect(
      sortIneffectiveText("size", "크기", { ...ready, applied: false, reason: "알 수 없는 정렬 키" }, true),
    ).toBe("정렬하지 않았습니다: 알 수 없는 정렬 키");
    expect(sortIneffectiveText("size", "크기", ready, true)).toBeNull();
  });
});

describe("files grid (R-9): sort status line", () => {
  it("?sort=bogus says 알 수 없는 정렬 키 instead of silently ignoring it", async () => {
    useGridLocalStore.getState().setRoute({ sort: { key: "bogus", order: "asc" } });
    const calls = installFetch({ "/files": filesHandler(30) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBeGreaterThan(0));
    await waitFor(() =>
      expect(screen.getByTestId("grid-sort-status").textContent).toBe(
        "알 수 없는 정렬 키(bogus) — 정렬하지 않았습니다",
      ),
    );
    expect(screen.getByTestId("grid-sort-status").hidden).toBe(false);
    // Never sent to the server as a sort.
    expect(calls.some((c) => /sort=bogus/.test(c.url))).toBe(false);
  });

  it("an all-empty column's sort says it has no effect (descriptor empty: true)", async () => {
    useGridLocalStore.getState().setRoute({ sort: { key: "size", order: "asc" } });
    installFetch({ "/files": withFields(filesHandler(30), {}, { empty: true }) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBeGreaterThan(0));
    await waitFor(() =>
      expect(screen.getByTestId("grid-sort-status").textContent).toBe("크기 — 값이 없어 정렬 효과 없음"),
    );
  });

  it("a descriptor with applied: false shows the server's reason", async () => {
    useGridLocalStore.getState().setRoute({ sort: { key: "size", order: "asc" } });
    installFetch({
      "/files": withFields(filesHandler(30), {}, { applied: false, reason: "알 수 없는 정렬 키" }),
    });
    renderWithClient(<DataGrid />);
    await waitFor(() =>
      expect(screen.getByTestId("grid-sort-status").textContent).toBe(
        "정렬하지 않았습니다: 알 수 없는 정렬 키",
      ),
    );
  });
});

describe("files grid (R-2): acquisition-copy times", () => {
  it("shows the one-line banner when time_basis is acquisition-copy", async () => {
    installFetch({ "/files": withFields(filesHandler(30), { time_basis: "acquisition-copy" }) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBeGreaterThan(0));
    expect((await screen.findByTestId("grid-time-basis")).textContent).toBe(ACQUISITION_COPY_BANNER);
  });

  it("no banner on NTFS times or an older server", async () => {
    installFetch({ "/files": withFields(filesHandler(30), { time_basis: "ntfs" }) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(rows().length).toBeGreaterThan(0));
    expect(screen.queryByTestId("grid-time-basis")).toBeNull();
  });

  it("a time condition with 0 rows on such a run says why in the empty state", async () => {
    act(() => useFilterStore.getState().patchFilters({ from: "2025-03-03T00:00", to: "2025-03-10T00:00" }));
    installFetch({
      "/files": () =>
        jsonResponse({
          candidates: [],
          matched: 0,
          total: 4814,
          time_basis: "acquisition-copy",
          pagination: {
            offset: 0,
            limit: 250,
            returned: 0,
            total: 0,
            matched: 0,
            has_more: false,
            truncated: false,
          },
        }),
    });
    renderWithClient(<DataGrid />);
    const empty = await screen.findByTestId("grid-empty");
    await waitFor(() => expect(empty.textContent).toContain("취득 사본 시각"));
    expect(empty.textContent).toContain("시간 조건에 맞는 파일이 없습니다");
  });
});
