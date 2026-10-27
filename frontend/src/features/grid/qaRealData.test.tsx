// biome-ignore-all lint/a11y: tests drive the grid / viewer through their DOM roles
// Real-data QA (2026-10-12, grid + viewer side): files/indicators paging totals, cross-case
// navigation, un-pressing review toggles, directory rows, 유형 substring matching, loading
// states, viewer tab wrapping, disabled-control contrast, the files default preset.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { act, cleanup, configure, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// @ts-expect-error untyped node script (the check:contrast gate); its formula is reused here
import { contrast, parseThemes } from "../../../scripts/check-contrast.mjs";
import { LiveRegion } from "../../a11y";
import { resetAnnouncer } from "../../a11y/announcer";
import { fetchFilesPage, fetchIndicatorsPage, resetArtifactCountsCache } from "../../api/collections";
import type { RunWithProgress } from "../../api/runsProgress";
import { resetCommandRegistry } from "../../commands/registry";
import type { GridRow } from "../../contracts/collection";
import { EMPTY_ROUTE, parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import { useAnalysisStore } from "../analysis/store";
import { partitionFilters, typeMatches } from "../filters/filterModel";
import { useFilterStore } from "../filters/filterStore";
import { resetViewerAdapter, setViewerTarget } from "../viewer/adapter";
import { clearCaseDbCache } from "../viewer/citation";
import { resolveModes } from "../viewer/modes";
import { installFetch as installViewerFetch, metadata, preview, target } from "../viewer/testSupport";
import { targetTitle, Viewer } from "../viewer/Viewer";
import { presetColumnIds } from "./columns";
import { analysisCollection, analysisColumnsForKind } from "./columns/analysis";
import { filesCollection } from "./columns/files";
import { DataGrid } from "./DataGrid";
import { buildGridCommands, buildViewerTarget, OPEN_OTHER_CASE_COMMAND } from "./gridCommands";
import { ROW_MENU_CONTEXTUAL_IDS } from "./RowMenu";
import { optimisticPatch } from "./reviewActions";
import { overlayReview } from "./reviewMap";
import {
  fileCandidates,
  installFetch,
  jsonResponse,
  mockLayout,
  renderWithClient,
  resetGridStore,
} from "./testSupport";

configure({ asyncUtilTimeout: 5000 });

const RUN = "run-1";
let restoreLayout: () => void = () => undefined;

function setRoute(hash: string) {
  window.location.hash = hash;
  useAppStore.getState().syncRouteFromLocation(parseHash(hash));
}

beforeEach(() => {
  resetCommandRegistry();
  resetGridStore();
  resetArtifactCountsCache();
  resetAnnouncer();
  resetViewerAdapter();
  clearCaseDbCache();
  window.localStorage.clear();
  useAppStore.setState({
    route: { ...EMPTY_ROUTE },
    runs: [
      { run_id: RUN, status: "completed", request: { root: "C:/ev/case1" } },
      { run_id: "run-2", status: "completed", request: { root: "C:/ev/BSH.E01" } },
    ] as unknown as RunWithProgress[],
  });
  useAnalysisStore.setState({ runId: null, analyses: [], available: true, dialog: null });
  useFilterStore.getState().clearFilters();
  restoreLayout = mockLayout();
  URL.createObjectURL = vi.fn(() => "blob:mock");
  URL.revokeObjectURL = vi.fn();
});
afterEach(() => {
  cleanup();
  restoreLayout();
  vi.unstubAllGlobals();
  resetCommandRegistry();
  window.localStorage.clear();
});

/** paginate_payload shape: the total lives in `pagination.total`, never at the top level. */
function paginatedFiles(total: number) {
  return (url: URL) => {
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const limit = Number(url.searchParams.get("limit") ?? 250);
    const end = Math.min(offset + limit, total);
    return jsonResponse({
      candidates: fileCandidates(offset, end),
      pagination: {
        collection: "candidates",
        offset,
        limit,
        returned: end - offset,
        total,
        has_more: end < total,
      },
    });
  };
}

describe("jsonPaged reads pagination.total (Q: 총 250건, never paged past 250)", () => {
  it("files and indicators report the collection total and that more pages exist", async () => {
    installFetch({ "/files": paginatedFiles(4770) });
    expect(await fetchFilesPage(RUN, 0, 250)).toMatchObject({ total: 4770, hasMore: true });
    installFetch({
      "/indicators": () =>
        jsonResponse({
          indicators: [{ value: "1.2.3.4" }],
          pagination: { offset: 0, limit: 250, returned: 1, total: 900, has_more: true },
        }),
    });
    expect((await fetchIndicatorsPage(RUN, 0, 250)).total).toBe(900);
  });

  it("the files grid footer says 총 4,770건 and the next page loads on scroll", async () => {
    setRoute(`#/case/${RUN}/explore/files`);
    const calls = installFetch({ "/files": paginatedFiles(4770) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(screen.getByTestId("grid-footer-total").textContent).toBe("총 4,770건"));
    const grid = screen.getByRole("grid");
    expect(grid.getAttribute("aria-rowcount")).toBe(String(4770 + 1));
    // Scroll to the end of page 1: page 2 (offset=250) is requested.
    Object.defineProperty(grid, "scrollTop", { configurable: true, value: 240 * 28 });
    fireEvent.scroll(grid);
    await waitFor(() => expect(calls.some((c) => c.url.includes("offset=250"))).toBe(true));
  }, 20_000);
});

describe("loading state while a server filter scans (16)", () => {
  it("shows a loading line in the grid and the footer instead of a blank grid", async () => {
    setRoute(`#/case/${RUN}/explore/files`);
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    installFetch({
      "/files": async (url) => {
        await gate;
        return paginatedFiles(3)(url);
      },
    });
    renderWithClient(<DataGrid />);
    // Skeleton rows in the grid; the sentence sits in the footer (review #11).
    expect((await screen.findByTestId("grid-loading")).querySelectorAll(".grid-skeleton-row")).toHaveLength(
      8,
    );
    expect(screen.getByTestId("grid-footer-total").textContent).toBe("총 세는 중…");
    expect(screen.getByTestId("grid-footer-loading").textContent).toContain("불러오는 중");
    release();
    await waitFor(() => expect(screen.queryByTestId("grid-loading")).toBeNull());
    expect(screen.getByTestId("grid-footer-total").textContent).toBe("총 3건");
  });
});

describe("files default preset (17)", () => {
  it("the default (분석) preset is 이름 · 경로 · 크기 · 수정 · NTFS 생성 · 선별 (visual-polish S4)", async () => {
    setRoute(`#/case/${RUN}/explore/files`);
    installFetch({ "/files": paginatedFiles(2) });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(screen.getAllByRole("columnheader").length).toBeGreaterThan(3));
    const cols = screen
      .getAllByRole("columnheader")
      .map((h) => h.getAttribute("data-col"))
      .filter(Boolean);
    expect(presetColumnIds(filesCollection.columns, "analysis")).toEqual([
      "title",
      "flags",
      "path",
      "size",
      "timestamp",
      "ntfsCreated",
      "review",
      // R7 갈래 A: 중복 · 계열 (hidden while no loaded row has a value).
      "dedup",
      "family",
    ]);
    // No loaded row is reviewed or flagged yet: 검토 / 특이사항 wait in the 열 menu ("값이 없어 숨김", review #9);
    // NTFS 생성 is empty and this is no image input (nothing to run, C-D12): it waits there too.
    expect(cols).toEqual(["title", "path", "size", "timestamp"]);
    expect(filesCollection.columns.find((c) => c.id === "ntfsCreated")?.presets).toEqual([
      "analysis",
      "source",
    ]);
    // The other NTFS columns stay in 출처 중심.
    expect(filesCollection.columns.find((c) => c.id === "ntfsAccessed")?.presets).toEqual(["source"]);
  });
});

// --- cross-case --------------------------------------------------------------

function crossCaseRow(): GridRow {
  return analysisCollection.mapRow(
    {
      artifact_type: "cross-case-row",
      record_index: 0,
      details: {
        indicator: "a".repeat(64),
        kind: "sha256",
        cases: [RUN, "run-2"],
        occurrences: [
          {
            case_id: RUN,
            run_id: RUN,
            path: "C:/ev/case1/x.exe",
            target: { collection: "files", kind: "", locator: "/candidates/3" },
          },
          {
            case_id: "run-2",
            run_id: "run-2",
            path: "C:/ev/other/x.exe",
            case_scope: "s1",
            target: { collection: "files", kind: "", locator: "/candidates/9" },
          },
        ],
      },
    },
    0,
    { ref: { id: "analysis", kind: "cross-case", analysisId: "cc1" } } as never,
  );
}

describe("cross-case navigation (Q-P1-11)", () => {
  it("the 케이스 cell links the other case to its occurrence row", () => {
    setRoute(`#/case/${RUN}/explore/analysis/cross-case?id=cc1`);
    const row = crossCaseRow();
    const spec = analysisColumnsForKind("cross-case").find((c) => c.header === "케이스");
    render(<div>{spec?.render?.(row)}</div>);
    const link = screen.getByRole("link", { name: /BSH\.E01/ });
    expect(link.getAttribute("href")).toMatch(/^#\/case\/run-2\/explore\/files\?.*row=/);
    expect(decodeURIComponent(link.getAttribute("href") ?? "")).toContain("/candidates/9");
    // The open run is plain text, not a link.
    expect(screen.queryByRole("link", { name: /case1/ })).toBeNull();
  });

  it("the row menu offers 다른 케이스에서 열기 for cross-case rows only and navigates there", () => {
    setRoute(`#/case/${RUN}/explore/analysis/cross-case?id=cc1`);
    expect(ROW_MENU_CONTEXTUAL_IDS).toContain(OPEN_OTHER_CASE_COMMAND);
    let focused: GridRow | undefined = crossCaseRow();
    const host = {
      current: {
        runId: RUN,
        collection: { id: "analysis" as const, kind: "cross-case", analysisId: "cc1" },
        getFocusedRow: () => focused,
        getSelectedRows: () => [],
      },
    };
    const command = buildGridCommands(host as never).find((c) => c.id === OPEN_OTHER_CASE_COMMAND);
    expect(command?.disabledReason?.({} as never)).toBeUndefined();
    void command?.run({} as never);
    expect(useAppStore.getState().route).toMatchObject({ runId: "run-2", collection: "files" });
    expect(useAppStore.getState().route.row?.locator).toBe("/candidates/9");
    focused = filesCollection.mapRow(fileCandidates(0, 1)[0] as never, 0, undefined as never);
    expect(command?.disabledReason?.({} as never)).toBeTruthy();
  });

  it("the viewer titles the row by its indicator (not /rows/0) and lists the other case", async () => {
    setRoute(`#/case/${RUN}/explore/analysis/cross-case?id=cc1`);
    const row = crossCaseRow();
    expect(targetTitle(buildViewerTarget(RUN, row), null, row)).toBe("a".repeat(64));
    installViewerFetch({});
    render(<Viewer />);
    act(() => setViewerTarget(buildViewerTarget(RUN, row), row));
    expect(screen.getByRole("heading", { level: 2 }).textContent).toBe("a".repeat(64));
    const section = await screen.findByTestId("cross-case-links");
    const links = section.querySelectorAll("a");
    expect([...links].map((a) => a.textContent)).toEqual(["BSH.E01 (run-2) 열기", "C:/ev/other/x.exe"]);
  });
});

// --- review toggles ------------------------------------------------------------

describe("pressed review toggles clear the mark (4)", () => {
  it("pressing 재검토 again posts status unreviewed and un-presses the button", async () => {
    const calls = installViewerFetch({
      "source-preview": () => preview({ preview_type: "text", extension: ".txt", text: "hi" }),
      "source-metadata": (url) => metadata(url.searchParams.get("path") || "", 64),
      ensure: () => ({ database: "D:/case.db", case_id: "c" }),
      "review-batch": () => ({ ok: true }),
    });
    const row = {
      ...filesCollection.mapRow(fileCandidates(7, 8)[0] as never, 7, undefined as never),
      reviewStatus: "needs-review" as const,
    };
    render(
      <>
        <Viewer />
        <LiveRegion />
      </>,
    );
    act(() => setViewerTarget(target({ sourcePath: row.sourcePath, ref: row.ref }), row));
    // 재검토 lives in the one review-status chip menu (r7 L4, C-W9) as a checked item. Open the
    // menu only when it is closed: clicking a toggle on every waitFor poll re-fires waitFor's
    // MutationObserver on each open/close, a microtask loop that starves its timeout (the hang).
    const statusMenu = () => screen.getByTestId("viewer-review-status-menu");
    const item = () => {
      const selector = '[data-command="viewer.mark.needs-review"]';
      if (!document.querySelector(selector) && statusMenu().getAttribute("aria-expanded") !== "true")
        fireEvent.click(statusMenu());
      const el = document.querySelector<HTMLElement>(selector);
      if (!el) throw new Error("no menu item");
      return el;
    };
    const button = await waitFor(item);
    expect(button.getAttribute("aria-checked")).toBe("true");
    expect(statusMenu().getAttribute("aria-label")).toBe("리뷰 상태: 재검토");
    fireEvent.click(button);
    await waitFor(() => expect(calls.some((c) => c.url.pathname.endsWith("review-batch"))).toBe(true));
    const post = calls.find((c) => c.url.pathname.endsWith("review-batch"));
    expect(JSON.parse(String(post?.init?.body))).toMatchObject({ status: "unreviewed" });
    await waitFor(() => expect(item().getAttribute("aria-checked")).toBe("false"));
    expect(statusMenu().getAttribute("aria-label")).toBe("리뷰 상태: 미검토");
    // One un-press = one POST (no toggle re-post loop in the viewer).
    expect(calls.filter((c) => c.url.pathname.endsWith("review-batch"))).toHaveLength(1);
    expect(screen.getByTestId("viewer-review-status").textContent).toBe("미검토");
  });

  it("the grid overlay and optimistic patch clear the status", () => {
    const row = {
      ...filesCollection.mapRow(fileCandidates(0, 1)[0] as never, 0, undefined as never),
      reviewStatus: "relevant" as const,
    };
    expect(optimisticPatch("clear-review")(row).reviewStatus).toBeNull();
    const map = new Map([
      [
        "files||/candidates/0",
        {
          collection: "files",
          kind: "",
          locator: "/candidates/0",
          status: "unreviewed",
          tags: [],
          include_in_report: false,
        },
      ],
    ]);
    expect(overlayReview(row, map as never).reviewStatus).toBeNull();
  });
});

// --- directories ---------------------------------------------------------------

describe("directory rows (15)", () => {
  it("request no preview / metadata and show a directory state", async () => {
    const raw = { ...fileCandidates(0, 1)[0], path: "C:/evidence/dir0/", is_directory: true };
    const row = filesCollection.mapRow(raw as never, 0, undefined as never);
    const viewerTarget = buildViewerTarget(RUN, row);
    expect(viewerTarget.isDirectory).toBe(true);
    const calls = installViewerFetch({});
    render(<Viewer />);
    act(() => setViewerTarget(viewerTarget, row));
    expect((await screen.findByTestId("directory-info")).textContent).toContain("디렉터리입니다");
    expect(calls.filter((c) => /source-(preview|metadata)/.test(c.url.pathname))).toHaveLength(0);
  });

  it("a directory answer from the preview API disables every content mode with the reason", () => {
    const resolved = resolveModes({
      target: target({ sourcePath: "C:/evidence/dir0" }),
      preview: preview({ preview_type: "directory", is_directory: true, size: 0 }),
    });
    expect(resolved.best).toBe("meta");
    // 계열 (R7 갈래 A) is about the row's relations, not its content: still available.
    expect(resolved.modes.filter((m) => m.available).map((m) => m.mode)).toEqual(["meta", "family"]);
    expect(resolved.modes.find((m) => m.mode === "hex")?.reason).toContain("디렉터리");
  });
});

// --- 유형 substring --------------------------------------------------------------

describe("유형 column text matches known types by substring (14)", () => {
  const known = ["windows-error-report", "wer-queue", "prefetch-file"];

  it("sends every known type containing the text as exact artifact_type values", () => {
    expect(typeMatches("wer", known)).toEqual(["wer-queue"]);
    expect(typeMatches("ERROR", known)).toEqual(["windows-error-report"]);
    expect(typeMatches("prefetch-file", known)).toEqual(["prefetch-file"]);
    expect(typeMatches("nothing", known)).toEqual(["nothing"]);
    const filters = {
      ...useFilterStore.getState().filters,
      columns: [{ col: "type", op: ":" as const, value: "re" }],
    };
    const plan = partitionFilters({ id: "artifacts", kind: "windows-system" }, filters, known);
    expect(plan.server.artifactTypes).toEqual(["prefetch-file", "windows-error-report"]);
    expect(plan.serverLabels).toContain("유형(포함: 2개 유형)");
    // Without known types the text goes as typed (exact).
    expect(partitionFilters({ id: "artifacts" }, filters).server.artifactTypes).toEqual(["re"]);
  });
});

// --- CSS / tokens ----------------------------------------------------------------

describe("viewer tabs never wrap (6) and disabled controls pass contrast (5)", () => {
  it("tabs are nowrap / no-shrink in a scrolling strip", () => {
    const css = readFileSync(join(process.cwd(), "src/features/viewer/viewer.css"), "utf8");
    expect(css).toMatch(/\.viewer-tab \{[^}]*white-space: nowrap/);
    expect(css).toMatch(/\.viewer-tab \{[^}]*flex: none/);
    expect(css).toMatch(/\.viewer-tabs > \* \{\s*flex: none;/);
  });

  it("--disabled-text on --disabled-bg is ≥ 4.5:1 in every theme", () => {
    const themes = parseThemes(readFileSync(join(process.cwd(), "src/tokens/tokens.css"), "utf8")) as Record<
      string,
      Record<string, string>
    >;
    const resolve = (vars: Record<string, string>, name: string): string => {
      const value = vars[name] ?? "";
      const ref = /^var\((--[\w-]+)\)$/.exec(value);
      return ref ? resolve(vars, ref[1] as string) : value;
    };
    for (const vars of Object.values(themes)) {
      const ratio = contrast(resolve(vars, "--disabled-text"), resolve(vars, "--disabled-bg"));
      expect(ratio).toBeGreaterThanOrEqual(4.5);
    }
  });
});
