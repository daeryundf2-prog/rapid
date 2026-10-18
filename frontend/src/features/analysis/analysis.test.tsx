// biome-ignore-all lint/a11y: tests drive the ARIA grid / dialog through their DOM roles

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, configure, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AnalysisState } from "../../api/analyses";
import type { RunWithProgress } from "../../api/runsProgress";
import { getCommand, resetCommandRegistry, runCommand } from "../../commands/registry";
import { EMPTY_ROUTE, parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import { useGridLocalStore } from "../grid/adapter";
import { analysisCollection } from "../grid/columns/analysis";
import { buildViewerTarget } from "../grid/gridCommands";
import {
  installFetch,
  jsonResponse,
  mockLayout,
  quickJsonResponse,
  resetGridStore,
} from "../grid/testSupport";
import { AnalysisDialog } from "./AnalysisDialog";
import { AnalysisPane } from "./AnalysisPane";
import { AnalysisProgressChip } from "./AnalysisProgressChip";
import { buildAnalysisOptions, defaultForm, parseExtensions, validateAnalysisForm } from "./analysisForm";
import {
  ALREADY_RUNNING_REASON,
  NEEDS_DISCOVER_REASON,
  NOTHING_RUNNING_REASON,
  RUN_NOT_FINISHED_REASON,
  registerAnalysisCommands,
  runDisabledReason,
} from "./commands";
import { ANALYSIS_POLL_MS, useAnalysisStore } from "./store";

configure({ asyncUtilTimeout: 5000 });

const announceMock = vi.hoisted(() => vi.fn());
vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: announceMock,
}));

const RUN = "run-1";

function job(
  over: Partial<AnalysisState> & Pick<AnalysisState, "analysis_id" | "kind" | "status">,
): AnalysisState {
  return {
    options: {},
    created_at: "2026-10-12T01:00:00Z",
    started_at: "2026-10-12T01:00:01Z",
    finished_at: over.status === "completed" ? "2026-10-12T01:00:09Z" : null,
    elapsed_s: 8,
    progress: { done: 0, total: null, unit: "파일", message: "", percent: null },
    row_count: 0,
    summary: {},
    error: null,
    ...over,
  };
}

function setRun(status = "completed") {
  useAppStore.setState({
    runs: [{ run_id: RUN, status, request: { root: "C:/evidence/case1" } } as unknown as RunWithProgress],
    runsStatus: "ready" as never,
  });
}

/** Same as a manual URL edit: the hash, then the store follows. */
function setRoute(hash: string) {
  window.location.hash = hash;
  useAppStore.getState().syncRouteFromLocation(parseHash(hash));
}

function renderWithClient(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Number.POSITIVE_INFINITY } },
  });
  const view = render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
  return { client, ...view };
}

const tick = (ms: number) =>
  act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });

const settle = async () => {
  for (let i = 0; i < 5; i += 1) await tick(0);
};

let restoreLayout: () => void = () => undefined;
let offCommands: (() => void) | null = null;

beforeEach(() => {
  resetCommandRegistry();
  resetGridStore();
  useAnalysisStore.setState({ runId: null, analyses: [], available: true, dialog: null });
  useAppStore.setState({ route: { ...EMPTY_ROUTE }, runs: [] });
  window.location.hash = "";
  restoreLayout = mockLayout();
});
afterEach(() => {
  cleanup();
  offCommands?.();
  offCommands = null;
  restoreLayout();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  announceMock.mockReset();
  resetCommandRegistry();
});

// ---------------------------------------------------------------------------

describe("analysis dialog form (validation + options body)", () => {
  it("defaults are valid and build the §3.2 options (MB → bytes, ext list, fixed flags)", () => {
    expect(validateAnalysisForm("carve", defaultForm("carve"))).toEqual({});
    const carve = buildAnalysisOptions("carve", {
      ...defaultForm("carve"),
      ext: ".BIN, dat",
      kinds: ["jpeg"],
    });
    expect(carve).toEqual({
      ext: [".bin", ".dat"],
      kinds: ["jpeg"],
      max_scan_bytes: 256 * 1024 * 1024,
      max_carve_bytes: 50 * 1024 * 1024,
      max_candidates: 250,
      extract: false,
      include_rejected: false,
    });
    expect(buildAnalysisOptions("ntfs-meta", defaultForm("ntfs-meta"))).toEqual({
      full_journal: false,
      parse: true,
    });
    expect(buildAnalysisOptions("ocr-batch", defaultForm("ocr-batch"))).toMatchObject({
      target: { kind: "media-image" },
      languages: ["kor", "eng"],
      max_items: 50,
    });
    // The current run is never sent: the server prepends it (CrossCaseOptions / prepare_cross_case).
    expect(
      buildAnalysisOptions(
        "cross-case",
        { ...defaultForm("cross-case", { runId: "a" }), case_ids: ["a", "b"] },
        {
          runId: "a",
        },
      ),
    ).toEqual({ case_ids: ["b"], max_shared: 500 });
    expect(parseExtensions("*.Log; .TXT .log")).toEqual([".log", ".txt"]);
  });

  it("explains every invalid field in Korean", () => {
    const errors = validateAnalysisForm("carve", {
      ...defaultForm("carve"),
      max_candidates: "-1",
      max_scan_bytes: "",
      ext: ",,,",
    });
    expect(errors.max_candidates).toMatch(/0 이상의 정수/);
    expect(errors.max_scan_bytes).toMatch(/값을 입력하세요/);
    expect(errors.ext).toMatch(/확장자/);
    expect(validateAnalysisForm("vsc-compare", defaultForm("vsc-compare")).snapshot_root).toMatch(
      /스냅샷을 고르세요/,
    );
    expect(validateAnalysisForm("vsc-extract", { ...defaultForm("vsc-extract"), status: [] }).status).toMatch(
      /1개 이상/,
    );
    expect(
      validateAnalysisForm("cross-case", defaultForm("cross-case", { runId: "a" }), { runId: "a" }).case_ids,
    ).toMatch(/현재 케이스 외에 1개 이상/);
    expect(validateAnalysisForm("memory-import", defaultForm("memory-import")).volatility_output_dir).toMatch(
      /폴더를 고르세요/,
    );
    expect(validateAnalysisForm("vsc-discover", { max_depth: "99" }).max_depth).toMatch(/0~1 사이/);
  });
});

describe("AnalysisDialog", () => {
  it("opens with focus on the first form field, not the 닫기 button", () => {
    setRun();
    setRoute(`#/case/${RUN}/explore/analysis/carve`);
    installFetch({ "/analyses": () => jsonResponse({ analyses: [] }) });
    renderWithClient(<AnalysisDialog kind="carve" runId={RUN} onClose={() => undefined} />);
    const dialog = screen.getByRole("dialog", { name: "카빙 실행" });
    const firstField = dialog.querySelector(".analysis-form input, .analysis-form select");
    expect(document.activeElement).toBe(firstField);
    expect(document.activeElement).not.toBe(within(dialog).getByRole("button", { name: "닫기" }));
  });

  it("labels every field with help text, reveals messages on a blocked submit, and posts a valid run", async () => {
    setRun();
    setRoute(`#/case/${RUN}/explore/analysis/carve`);
    const calls = installFetch({
      "/analyses": (_url, init) =>
        init?.method === "POST"
          ? jsonResponse({ analysis_id: "new-1", kind: "carve", status: "queued" }, 202)
          : jsonResponse({ analyses: [] }),
    });
    const onClose = vi.fn();
    renderWithClient(<AnalysisDialog kind="carve" runId={RUN} onClose={onClose} />);
    const dialog = screen.getByRole("dialog", { name: "카빙 실행" });
    expect(within(dialog).getByTestId("analysis-caution").textContent).toMatch(/예상 범위·주의/);
    const candidates = within(dialog).getByLabelText("최대 후보 수");
    const help = document.getElementById(candidates.getAttribute("aria-describedby")?.split(" ")[0] ?? "");
    expect(help?.textContent).toBe("이 수에 이르면 멈춥니다.");

    fireEvent.change(candidates, { target: { value: "0" } });
    const submit = within(dialog).getByTestId("analysis-submit");
    expect(submit.getAttribute("aria-disabled")).toBe("true");
    fireEvent.mouseDown(submit);
    fireEvent.click(submit);
    expect(
      await within(dialog).findByText("최대 후보 수: 1~100000 사이로 입력하세요.", { selector: "p" }),
    ).toBeTruthy();
    expect(candidates.getAttribute("aria-invalid")).toBe("true");
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);

    fireEvent.change(candidates, { target: { value: "50" } });
    fireEvent.change(within(dialog).getByLabelText("소스 확장자"), { target: { value: ".bin" } });
    expect(submit.getAttribute("aria-disabled")).toBeNull();
    fireEvent.click(submit);
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    const post = calls.find((c) => c.method === "POST");
    expect(post?.url).toBe(`/api/runs/${RUN}/analyses`);
    expect(post?.body).toMatchObject({ kind: "carve", options: { ext: [".bin"], max_candidates: 50 } });
    expect(window.location.hash).toBe(`#/case/${RUN}/explore/analysis/carve?id=new-1`);
  });

  it("shows the server's reason when the run is refused (409) and blocks while the run is not finished", async () => {
    setRun();
    installFetch({
      "/analyses": (_url, init) =>
        init?.method === "POST"
          ? jsonResponse({ detail: "이미 실행 중인 분석이 있습니다" }, 409)
          : jsonResponse({ analyses: [] }),
    });
    renderWithClient(<AnalysisDialog kind="vsc-discover" runId={RUN} onClose={() => undefined} />);
    fireEvent.click(screen.getByTestId("analysis-submit"));
    expect(await screen.findByText("이미 실행 중인 분석이 있습니다")).toBeTruthy();
    cleanup();
    setRun("running");
    setRoute(`#/case/${RUN}/explore/analysis/vsc`);
    renderWithClient(<AnalysisDialog kind="vsc-discover" runId={RUN} onClose={() => undefined} />);
    expect(
      screen.getByTestId("analysis-submit").getAttribute("data-disabled-reason") ??
        screen.getByTestId("disabled-reason").textContent,
    ).toBe(RUN_NOT_FINISHED_REASON);
  });
});

// ---------------------------------------------------------------------------

describe("progress chip polling (1 s while running)", () => {
  it("polls every 1000 ms only while a job runs, then stops; unmount stops it too", async () => {
    setRun();
    setRoute(`#/case/${RUN}/explore/analysis/carve`);
    let state: AnalysisState["status"] = "running";
    let percent = 10;
    const listCalls: number[] = [];
    vi.useFakeTimers();
    installFetch({
      "/analyses": () => {
        listCalls.push(Date.now());
        return quickJsonResponse({
          analyses: [
            job({
              analysis_id: "c1",
              kind: "carve",
              status: state,
              row_count: 3,
              progress: { done: 1, total: 10, unit: "소스 파일", message: "스캔 중", percent },
            }),
          ],
        });
      },
    });
    const { client, unmount } = renderWithClient(<AnalysisProgressChip />);
    offCommands = registerAnalysisCommands(client);
    await settle();
    expect(listCalls).toHaveLength(1);
    // (No vi.waitFor here: under fake timers it advances the clock and would skew the poll count.)
    const chip = screen.getByTestId("analysis-progress-chip");
    expect(chip.textContent).toContain("분석: 카빙 · 10% · 소스 파일 1/10 · 스캔 중");
    expect(chip.getAttribute("role")).toBeNull(); // no extra live region
    const cancel = within(chip).getByRole("button", { name: "분석 취소" });
    expect(cancel.getAttribute("aria-disabled")).toBeNull();

    percent = 40;
    await tick(ANALYSIS_POLL_MS - 1);
    expect(listCalls).toHaveLength(1);
    await tick(1);
    expect(listCalls).toHaveLength(2);
    await settle();
    await tick(50); // React commits the re-render (poll timing above is already pinned)
    expect(screen.getByTestId("analysis-progress-chip").textContent).toContain("40%");

    state = "completed";
    await tick(ANALYSIS_POLL_MS);
    expect(listCalls).toHaveLength(3);
    await settle();
    await tick(50);
    expect(screen.queryByTestId("analysis-progress-chip")).toBeNull();
    expect(announceMock).toHaveBeenCalledWith("카빙 분석 완료 · 3건", { politeness: "polite" });
    await tick(ANALYSIS_POLL_MS * 5);
    expect(listCalls).toHaveLength(3); // not running → no poll

    // A new running job (e.g. started from the dialog) restarts the poll; unmount ends it.
    state = "running";
    await act(async () => {
      await client.invalidateQueries({ queryKey: ["analyses", RUN] });
    });
    expect(listCalls).toHaveLength(4);
    await tick(ANALYSIS_POLL_MS);
    expect(listCalls).toHaveLength(5);
    unmount();
    await tick(ANALYSIS_POLL_MS * 5);
    expect(listCalls).toHaveLength(5);
  });
});

// ---------------------------------------------------------------------------

describe("analysis commands: run / cancel / openLast", () => {
  it("run commands explain why they cannot start; cancel targets the routed running job", async () => {
    setRun();
    setRoute(`#/case/${RUN}/explore/analysis/carve?id=c2`);
    const calls = installFetch({
      "/cancel": () => jsonResponse(job({ analysis_id: "c2", kind: "carve", status: "cancelled" })),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    const client = new QueryClient();
    offCommands = registerAnalysisCommands(client);
    const ctx = { runId: RUN };
    expect(getCommand("analysis.run.carve")?.label).toBe("카빙 실행…");
    expect(runDisabledReason("carve", { runId: null })).toBe("케이스를 먼저 선택하세요");
    expect(runDisabledReason("vsc-compare", ctx)).toBe(NEEDS_DISCOVER_REASON);
    expect((await runCommand("analysis.cancel")).ok).toBe(false);
    expect(getCommand("analysis.cancel")?.disabledReason?.({ ...baseCtx, runId: RUN })).toBe(
      NOTHING_RUNNING_REASON,
    );

    useAnalysisStore.setState({
      runId: RUN,
      available: true,
      analyses: [
        job({ analysis_id: "c3", kind: "carve", status: "queued" }),
        job({ analysis_id: "c2", kind: "carve", status: "running" }),
        job({ analysis_id: "d1", kind: "vsc-discover", status: "completed" }),
      ],
    });
    expect(runDisabledReason("carve", ctx)).toBe(ALREADY_RUNNING_REASON);
    expect(runDisabledReason("vsc-compare", ctx)).toBeUndefined();
    setRun("running");
    expect(runDisabledReason("ntfs-meta", ctx)).toBe(RUN_NOT_FINISHED_REASON);
    setRun();

    expect((await runCommand("analysis.cancel")).ok).toBe(true);
    const post = calls.find((c) => c.method === "POST");
    expect(post?.url).toBe(`/api/runs/${RUN}/analyses/c2/cancel`);
    expect(announceMock).toHaveBeenCalledWith("카빙 분석 취소를 요청했습니다");

    expect((await runCommand("analysis.openLast")).ok).toBe(true);
    // openLast = the newest COMPLETED job (d1), not the queued c3.
    expect(window.location.hash).toBe(`#/case/${RUN}/explore/analysis/vsc?id=d1`);

    expect((await runCommand("analysis.run.ntfs-meta")).ok).toBe(true);
    expect(useAnalysisStore.getState().dialog).toEqual({ kind: "ntfs-meta" });
  });

  it("an older server without /analyses: every run command says the server lacks it", async () => {
    setRun();
    useAnalysisStore.setState({ runId: RUN, analyses: [], available: false });
    expect(runDisabledReason("carve", { runId: RUN })).toBe("이 서버는 분석 작업을 지원하지 않습니다");
  });
});

const baseCtx = {
  runId: null,
  collection: null,
  selectedRowKeys: [],
  focusedRowKey: null,
  viewerHasTarget: false,
  runIsActive: false,
};

// ---------------------------------------------------------------------------

function carveRows(id: string, count: number) {
  return Array.from({ length: count }, (_, i) => ({
    artifact_type: "carve-row",
    path: `C:/evidence/blob${i}.bin`,
    record_index: i,
    details: {
      signature_kind: i % 2 ? "png" : "jpeg",
      source_path: `C:/evidence/blob${i}.bin`,
      offset: 4096 * (i + 1),
      length: 512,
      sha256: "a".repeat(64),
      confidence: 0.9,
      notes: `${id}-${i}`,
    },
  }));
}

describe("AnalysisPane: history selection loads that job's rows", () => {
  it("opens on the newest completed job, lists history, and '보기' switches the grid to another job", async () => {
    setRun();
    setRoute(`#/case/${RUN}/explore/analysis/carve`);
    useGridLocalStore.setState((s) => ({ route: { ...s.route, runId: RUN } }));
    const calls = installFetch({
      "/rows": (url) => {
        const id = url.pathname.split("/")[5] as string;
        return jsonResponse({
          rows: carveRows(id, id === "old" ? 2 : 3),
          record_count: id === "old" ? 2 : 3,
        });
      },
      "/analyses": () =>
        jsonResponse({
          analyses: [
            job({ analysis_id: "run", kind: "carve", status: "running", row_count: 1 }),
            job({ analysis_id: "new", kind: "carve", status: "completed", row_count: 3 }),
            job({ analysis_id: "old", kind: "carve", status: "cancelled", row_count: 2, error: "취소됨" }),
          ],
        }),
    });
    offCommands = registerAnalysisCommands(new QueryClient());
    renderWithClient(<AnalysisPane />);
    expect(await screen.findByRole("heading", { name: "카빙" })).toBeTruthy();
    const history = await screen.findByRole("table", { name: "실행 이력" });
    expect(within(history).getAllByRole("row")).toHaveLength(4);
    await waitFor(() =>
      expect(calls.some((c) => c.url.startsWith(`/api/runs/${RUN}/analyses/new/rows`))).toBe(true),
    );
    const grid = await screen.findByRole("grid", { name: "분석 결과 목록" });
    await waitFor(() =>
      expect(
        within(grid)
          .getAllByRole("row")
          .filter((r) => r.dataset.index),
      ).toHaveLength(3),
    );
    // The header describes the job being viewed; the newest (running) one gets its own line.
    expect(screen.getByTestId("analysis-last").textContent).toMatch(/보고 있는 실행: 완료/);
    expect(screen.getByTestId("analysis-latest").textContent).toMatch(/최신 실행: 실행 중/);
    // Kind columns with server sort keys (details.<key>).
    const offsetHeader = within(grid)
      .getAllByRole("columnheader")
      .find((h) => h.getAttribute("data-col") === "d:offset") as HTMLElement;
    expect(
      within(offsetHeader).getByRole("button", { name: "오프셋" }).getAttribute("aria-disabled"),
    ).toBeNull();
    fireEvent.click(within(offsetHeader).getByRole("button", { name: "오프셋" }));
    expect(useGridLocalStore.getState().route.sort).toEqual({ key: "details.offset", order: "asc" });

    const pressed = within(history).getAllByRole("button", { pressed: true });
    expect(pressed).toHaveLength(1);
    const old = within(history)
      .getAllByRole("button")
      .find((b) => b.dataset.analysisId === "old") as HTMLElement;
    fireEvent.click(old);
    expect(useAppStore.getState().route.analysisId).toBe("old");
    await waitFor(() =>
      expect(calls.some((c) => c.url.startsWith(`/api/runs/${RUN}/analyses/old/rows`))).toBe(true),
    );
    await waitFor(() =>
      expect(
        within(screen.getByRole("grid", { name: "분석 결과 목록" }))
          .getAllByRole("row")
          .filter((r) => r.dataset.index),
      ).toHaveLength(2),
    );
    expect(old.getAttribute("aria-pressed")).toBe("true");
  });

  it("a node that never ran says so and links to the 처리 card that runs it", async () => {
    setRun();
    setRoute(`#/case/${RUN}/explore/analysis/ntfs-meta`);
    installFetch({ "/analyses": () => jsonResponse({ analyses: [] }) });
    offCommands = registerAnalysisCommands(new QueryClient());
    renderWithClient(<AnalysisPane />);
    expect((await screen.findByTestId("analysis-last")).textContent).toContain("아직 실행하지 않았습니다");
    expect(screen.getByTestId("analysis-empty").textContent).toMatch(/처리 단계/);
    expect(screen.getByTestId("analysis-process-link").getAttribute("href")).toBe(
      `#/case/${RUN}/process/ntfs-meta`,
    );
    // Running lives on the 처리 cards, not in the results view.
    expect(screen.queryByRole("button", { name: "NTFS 메타 분석 실행…" })).toBeNull();
  });
});

// ---------------------------------------------------------------------------

describe("carve rows open in the viewer (hex at offset)", () => {
  it("maps a carve row to the source file with a hex highlight at its offset", () => {
    const raw = { ...carveRows("c", 1)[0], _index: 0, _analysis: "c" };
    const row = analysisCollection.mapRow(raw, 0, {
      ref: { id: "analysis", kind: "carve", analysisId: "c" },
    });
    expect(row.ref).toEqual({ collection: "analysis", kind: "c", locator: "/rows/0" });
    expect(row.rowKey).toBe("analysis:c:/rows/0");
    const target = buildViewerTarget(RUN, row);
    expect(target).toMatchObject({
      sourcePath: "C:/evidence/blob0.bin",
      preferredMode: "hex",
      highlight: { offset: 4096, length: 512 },
    });
    // Rows without a path have no viewer source (meta only).
    const ocr = analysisCollection.mapRow({ details: { text: "x" }, _index: 2 }, 2, {
      ref: { id: "analysis", kind: "ocr-batch", analysisId: "o" },
    });
    expect(ocr.sourcePath).toBeNull();
    expect(buildViewerTarget(RUN, ocr).preferredMode).toBeUndefined();
  });

  it("url-carve rows open at the hit with the URL's byte length and the 카빙 recovery badge", () => {
    const url = "https://example.com/a";
    const mapUrl = (details: Record<string, unknown>) =>
      analysisCollection.mapRow(
        { path: "C:/evidence/pagefile.sys", artifact_type: "carved-url-candidate", _index: 0, details },
        0,
        { ref: { id: "analysis", kind: "url-carve", analysisId: "u" } },
      );
    const utf16 = mapUrl({ url, encoding: "utf-16le", offset: 8192 });
    expect(buildViewerTarget(RUN, utf16)).toMatchObject({
      sourcePath: "C:/evidence/pagefile.sys",
      preferredMode: "hex",
      highlight: { offset: 8192, length: url.length * 2 },
    });
    expect(utf16.fields.recovery).toBe("carved");
    const ascii = mapUrl({ url, encoding: "ascii", offset: 16 });
    expect(buildViewerTarget(RUN, ascii).highlight).toEqual({ offset: 16, length: url.length });
    // A redacted URL is shorter than the bytes on disk: offset-only highlight.
    const redacted = mapUrl({ url, encoding: "ascii", offset: 16, url_tokens_redacted: true });
    expect(buildViewerTarget(RUN, redacted).highlight).toEqual({ offset: 16 });
  });
});

describe("backend contract details", () => {
  it("422 option errors are shown under their field", async () => {
    setRun();
    setRoute(`#/case/${RUN}/process/ntfs-meta`);
    installFetch({
      "/analyses": (_url, init) =>
        init?.method === "POST"
          ? jsonResponse(
              {
                detail: [
                  {
                    loc: ["options", "image_path"],
                    msg: "폴더 런에는 이미지 경로가 필요합니다",
                    type: "value_error",
                  },
                ],
              },
              422,
            )
          : jsonResponse({ analyses: [] }),
    });
    renderWithClient(<AnalysisDialog kind="ntfs-meta" runId={RUN} onClose={() => undefined} />);
    fireEvent.click(screen.getByTestId("analysis-submit"));
    const message = await screen.findByText("폴더 런에는 이미지 경로가 필요합니다", {
      selector: "p.case-error",
    });
    const input = screen.getByLabelText("증거 이미지 또는 $MFT 파일");
    expect(input.getAttribute("aria-describedby")).toContain(message.id);
    expect(input.getAttribute("aria-invalid")).toBe("true");
    fireEvent.change(input, { target: { value: "C:/rapid-qa/BSH.E01" } });
    expect(
      screen.queryByText("폴더 런에는 이미지 경로가 필요합니다", { selector: "p.case-error" }),
    ).toBeNull();
  });

  it("ntfs-meta rows are meta-only: the volume path is a record field, not a viewer source", () => {
    const row = analysisCollection.mapRow(
      { path: "/Users/a/x.txt", record_index: 4, _index: 4, details: { entry_number: 42, source: "mft" } },
      4,
      { ref: { id: "analysis", kind: "ntfs-meta", analysisId: "n1" } },
    );
    expect(row.sourcePath).toBeNull();
    expect(row.fields.volumePath).toBe("/Users/a/x.txt");
    expect((row.fields.details as Record<string, unknown>).path).toBe("/Users/a/x.txt");
    expect(buildViewerTarget(RUN, row).sourcePath).toBeNull();
  });
});
