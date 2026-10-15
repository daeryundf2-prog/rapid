// biome-ignore-all lint/a11y: tests drive the dialog / cards / panel through their DOM roles
// Real-data QA (2026-10-12, analysis + 처리 side): cross-case run eligibility, ntfs-meta file
// pick and $MFT input, snapshot loading state, visible disabled reasons, card / history
// layout, run list (recent N + disambiguated names), Korean plan statuses, OCR failure
// counts, per-kind 결과 links.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, configure, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AnalysisState } from "../../api/analyses";
import { ApiError } from "../../api/client";
import type { RunWithProgress } from "../../api/runsProgress";
import { resetCommandRegistry } from "../../commands/registry";
import { EMPTY_ROUTE, parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import { installFetch, jsonResponse } from "../grid/testSupport";
import { disambiguatedRunNames, ProcessPage, ProcessPanel, stepStatusLabel } from "../stages/ProcessStage";
import { AnalysisDialog, crossCaseChoice, pathFieldErrors } from "./AnalysisDialog";
import { lastStateText } from "./AnalysisPane";
import { buildAnalysisOptions, defaultForm } from "./analysisForm";
import { registerAnalysisCommands } from "./commands";
import { isAllFailed, ocrOutcome, summaryNotes } from "./kinds";
import { useAnalysisStore } from "./store";

configure({ asyncUtilTimeout: 5000 });

vi.mock("../grid/DataGrid", () => ({ DataGrid: () => <div data-testid="grid-stub" /> }));

const RUN = "run-1";

function job(
  over: Partial<AnalysisState> & Pick<AnalysisState, "analysis_id" | "kind" | "status">,
): AnalysisState {
  return {
    options: {},
    created_at: "2026-10-12T01:00:00Z",
    progress: { done: 1, total: 4, unit: "파일", message: "", percent: 25 },
    row_count: 0,
    ...over,
  };
}

function setRoute(hash: string) {
  window.location.hash = hash;
  useAppStore.getState().syncRouteFromLocation(parseHash(hash));
}

function renderWithClient(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

let off: Array<() => void> = [];

beforeEach(() => {
  resetCommandRegistry();
  window.location.hash = "";
  useAppStore.setState({
    route: { ...EMPTY_ROUTE },
    runs: [
      { run_id: RUN, status: "completed", request: { root: "C:/ev/case1" } },
      { run_id: "run-ok", status: "completed", request: { root: "C:/ev/case2" } },
      { run_id: "run-failed", status: "failed", request: { root: "C:/ev/case3" } },
      {
        run_id: "run-nodb",
        status: "completed",
        case_db_available: false,
        request: { root: "C:/ev/case4" },
      },
    ] as unknown as RunWithProgress[],
  });
  useAnalysisStore.setState({ runId: null, analyses: [], available: true, dialog: null });
});
afterEach(() => {
  cleanup();
  for (const fn of off) fn();
  off = [];
  vi.unstubAllGlobals();
  resetCommandRegistry();
});

describe("cross-case dialog: failed runs and runs without a case DB (Q-P1-11)", () => {
  it("lists them disabled with the reason, after the eligible run", () => {
    expect(crossCaseChoice({ run_id: "a", status: "failed" })).toEqual({
      eligible: false,
      reason: "실패한 런이라 비교할 수 없습니다",
    });
    expect(crossCaseChoice({ run_id: "a", status: "completed", case_db_available: false }).eligible).toBe(
      false,
    );
    expect(crossCaseChoice({ run_id: "a", status: "completed" }).eligible).toBe(true);
    // The server's verdict (GET /api/runs cross_case_eligible + Korean reason) wins.
    expect(
      crossCaseChoice({
        run_id: "a",
        status: "completed",
        cross_case_eligible: false,
        cross_case_ineligible_reason: "케이스 DB가 없습니다",
      }),
    ).toEqual({ eligible: false, reason: "케이스 DB가 없습니다" });
    expect(crossCaseChoice({ run_id: "a", status: "failed", cross_case_eligible: true }).eligible).toBe(true);

    installFetch({ "/analyses": () => jsonResponse({ analyses: [] }) });
    renderWithClient(<AnalysisDialog kind="cross-case" runId={RUN} onClose={() => {}} />);
    const group = within(screen.getByRole("dialog")).getByRole("group", { name: "비교할 케이스" });
    // Ineligible runs fold behind a disclosure (round 2, item 8).
    fireEvent.click(within(group).getByRole("button", { name: "사용할 수 없는 런 2개 보기" }));
    const boxes = within(group).getAllByRole("checkbox") as HTMLInputElement[];
    expect(boxes.map((b) => b.disabled)).toEqual([false, true, true]);
    expect(boxes[0]?.parentElement?.textContent).toContain("case2");
    expect(boxes[1]?.parentElement?.textContent).toContain("실패한 런이라 비교할 수 없습니다");
    expect(boxes[2]?.parentElement?.textContent).toContain("케이스 DB가 없어");
  });
});

describe("ntfs-meta image picker selects files; $MFT input (Q-P1-6)", () => {
  it("the browser lists files and picking one fills image_path", async () => {
    installFetch({
      "/api/browse": () =>
        jsonResponse({
          path: "C:/rapid-qa",
          parent: "C:/",
          entries: [
            { name: "sub", path: "C:/rapid-qa/sub", kind: "directory" },
            { name: "BSH.E01", path: "C:/rapid-qa/BSH.E01", kind: "file" },
          ],
          truncated: false,
        }),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    renderWithClient(<AnalysisDialog kind="ntfs-meta" runId={RUN} onClose={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "찾아보기" }));
    const list = await screen.findByRole("list", { name: "파일 목록" });
    // No "이 폴더 선택": a folder is not an image.
    expect(screen.queryByRole("button", { name: "이 폴더 선택" })).toBeNull();
    fireEvent.click(within(list).getByRole("button", { name: /BSH\.E01/ }));
    expect((screen.getByLabelText("증거 이미지 또는 $MFT 파일") as HTMLInputElement).value).toBe(
      "C:/rapid-qa/BSH.E01",
    );
  });

  it("offers the input kind; 자동 감지 sends no `source`, $MFT sends source=mft", () => {
    const form = defaultForm("ntfs-meta");
    expect(buildAnalysisOptions("ntfs-meta", form).source).toBeUndefined();
    expect(
      buildAnalysisOptions("ntfs-meta", { ...form, image_path: "C:/x/$MFT", source: "mft" }),
    ).toMatchObject({ image_path: "C:/x/$MFT", source: "mft", parse: true });
    installFetch({ "/analyses": () => jsonResponse({ analyses: [] }) });
    renderWithClient(<AnalysisDialog kind="ntfs-meta" runId={RUN} onClose={() => {}} />);
    const select = screen.getByLabelText("입력 종류") as HTMLSelectElement;
    expect([...select.options].map((o) => o.textContent)).toEqual([
      "자동 감지",
      "디스크 이미지(Sleuth Kit으로 추출)",
      "추출한 $MFT 파일(바로 파싱)",
    ]);
  });

  it("a 403 path refusal is shown under the field it names", () => {
    const message = "추출 출력 경로가 허용 범위(런 출력 디렉터리 또는 …) 밖에 있습니다: D:/x";
    const error = new ApiError(message, 403, message);
    expect(pathFieldErrors(error)).toEqual({ output_dir: error.message });
  });
});

describe("vsc-compare snapshot list loading (13)", () => {
  it("says it is loading and keeps 실행 disabled until the discover rows arrive", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    installFetch({
      "/rows": async () => {
        await gate;
        return jsonResponse({
          rows: [
            {
              artifact_type: "vsc-discover-row",
              details: { snapshot_root: "C:/snap1", score: 9 },
              record_index: 0,
            },
          ],
          record_count: 1,
        });
      },
      "/analyses": () =>
        jsonResponse({
          analyses: [job({ analysis_id: "d1", kind: "vsc-discover", status: "completed", row_count: 1 })],
        }),
    });
    renderWithClient(<AnalysisDialog kind="vsc-compare" runId={RUN} onClose={() => {}} />);
    expect(await screen.findByTestId("snapshot-loading")).toBeTruthy();
    expect(screen.getByRole("option", { name: "스냅샷 목록을 불러오는 중…" })).toBeTruthy();
    const submit = screen.getByTestId("analysis-submit");
    expect(submit.getAttribute("aria-disabled")).toBe("true");
    expect(document.body.textContent).toContain("스냅샷 목록을 불러오는 중입니다");
    release();
    expect(await screen.findByRole("option", { name: /C:\/snap1/ })).toBeTruthy();
    await waitFor(() => expect(screen.queryByTestId("snapshot-loading")).toBeNull());
  });
});

describe("OCR batch where every image failed (10)", () => {
  const failedAll = job({
    analysis_id: "o1",
    kind: "ocr-batch",
    status: "completed",
    row_count: 20,
    finished_at: "2026-10-12T02:00:00Z",
    summary: { status_counts: { failed: 20 }, engine_error: "tesseract를 찾을 수 없습니다" },
  });

  it("is not '완료 · 20건': it says 전부 실패 with the counts and the engine error", () => {
    expect(ocrOutcome(failedAll)).toEqual({ succeeded: 0, failed: 20 });
    expect(isAllFailed(failedAll)).toBe(true);
    const text = lastStateText(failedAll, "utc");
    expect(text).toMatch(/^마지막 실행: 전부 실패/);
    expect(text).toContain("성공 0 · 실패 20");
    expect(text).toContain("OCR 엔진: tesseract를 찾을 수 없습니다");
    // Newer servers: explicit counts.
    expect(ocrOutcome({ ...failedAll, summary: { failed_count: 3, succeeded_count: 17 } })).toEqual({
      succeeded: 17,
      failed: 3,
    });
    // A failed batch shows its Korean error.
    expect(
      summaryNotes(job({ analysis_id: "o2", kind: "ocr-batch", status: "failed", error: "OCR 엔진 없음" })),
    ).toContain("실패 사유: OCR 엔진 없음");
  });

  it("shows a truncated volume-shadow comparison with its reason", () => {
    expect(
      summaryNotes(
        job({
          analysis_id: "v1",
          kind: "vsc-compare",
          status: "completed",
          summary: { truncated: true, truncated_reason: "최대 변경 기록 수(10,000)에 도달" },
        }),
      ),
    ).toEqual(["일부만 처리: 최대 변경 기록 수(10,000)에 도달"]);
  });
});

describe("처리 stage cards (5, 7, 10, 12)", () => {
  it("볼륨 섀도우 links each kind's own result with its own count", async () => {
    setRoute(`#/case/${RUN}/process/vsc`);
    installFetch({
      "/summary": () => jsonResponse({ steps: [] }),
      "/analyses": () =>
        jsonResponse({
          analyses: [
            job({ analysis_id: "x1", kind: "vsc-extract", status: "completed", row_count: 0 }),
            job({ analysis_id: "c1", kind: "vsc-compare", status: "completed", row_count: 19034 }),
            job({ analysis_id: "d1", kind: "vsc-discover", status: "completed", row_count: 2 }),
          ],
        }),
    });
    off.push(registerAnalysisCommands(new QueryClient()));
    renderWithClient(<ProcessPage />);
    const card = await screen.findByTestId("analysis-card-vsc");
    await waitFor(() => expect(within(card).getAllByTestId("analysis-results-link")).toHaveLength(3));
    const links = within(card).getAllByTestId("analysis-results-link");
    expect(links.map((a) => a.textContent)).toEqual([
      "볼륨 섀도우 탐색 결과 → (2건)",
      "볼륨 섀도우 비교 결과 → (19,034건)",
      "볼륨 섀도우 추출 결과 → (0건)",
    ]);
    expect(links[1]?.getAttribute("href")).toBe(`#/case/${RUN}/explore/analysis/vsc?id=c1`);
  });

  it("a disabled 실행 button prints its reason visibly, not only on hover", async () => {
    setRoute(`#/case/${RUN}/process/carve`);
    installFetch({
      "/summary": () => jsonResponse({ steps: [] }),
      "/analyses": () =>
        jsonResponse({ analyses: [job({ analysis_id: "c2", kind: "carve", status: "running" })] }),
    });
    off.push(registerAnalysisCommands(new QueryClient()));
    renderWithClient(<ProcessPage />);
    const card = await screen.findByTestId("analysis-card-carve");
    await waitFor(() =>
      expect(within(card).getByRole("button", { name: "카빙 실행…" }).getAttribute("aria-disabled")).toBe(
        "true",
      ),
    );
    const visible = within(card).getByTestId("command-disabled-reason");
    expect(visible.textContent).toBeTruthy();
    expect(visible.closest("[hidden]")).toBeNull();
  });

  it("CSS: disabled primary drops the accent fill; cards and history tables do not overflow", () => {
    const shell = readFileSync(join(process.cwd(), "src/app/shell.css"), "utf8");
    expect(shell).toMatch(
      /\.button\.primary\[aria-disabled="true"\][^{]*\{[^}]*background: var\(--disabled-bg\)/,
    );
    expect(shell).toMatch(/\.disabled-reason-text \{/);
    const stages = readFileSync(join(process.cwd(), "src/features/stages/stages.css"), "utf8");
    expect(stages).toMatch(/\.analysis-card \{\s*min-width: 0;/);
    expect(stages).toMatch(/\.analysis-card \.analysis-history-wrap \{[^}]*overflow-x: auto/);
    expect(stages).toMatch(/\.analysis-card\.is-selected \{[^}]*grid-column: 1 \/ -1/);
  });
});

describe("처리 left panel (8, 9)", () => {
  const many = Array.from({ length: 42 }, (_, i) => ({
    run_id: `r${String(i).padStart(2, "0")}aaaaaaaa`,
    status: i % 5 === 0 ? "failed" : "completed",
    created_at: `2026-10-${String(1 + (i % 9)).padStart(2, "0")}T0${i % 10}:00:00Z`,
    request: { root: i % 2 ? "C:/ev/evidence" : "C:/qa/BSH.E01" },
  }));

  it("lists 추가 분석 first, then the recent runs with 더 보기, names disambiguated", () => {
    useAppStore.setState({ runs: many as unknown as RunWithProgress[] });
    setRoute(`#/case/${many[30]?.run_id}/process`);
    installFetch({ "/analyses": () => jsonResponse({ analyses: [] }) });
    renderWithClient(<ProcessPanel />);
    const panel = screen.getByTestId("process-panel");
    const headings = within(panel)
      .getAllByRole("heading")
      .map((h) => h.textContent);
    expect(headings).toEqual(["추가 분석", "런"]);
    const runs = within(panel).getByRole("list", { name: "런" });
    // 8 recent + the routed run (index 30).
    expect(within(runs).getAllByRole("link")).toHaveLength(9);
    const names = within(runs)
      .getAllByRole("link")
      .map((a) => a.querySelector(".stage-link-name")?.textContent);
    expect(new Set(names).size).toBe(names.length);
    expect(names[0]).toMatch(/^BSH\.E01 · 2026-10-01 \d\d:00 · r00aaaaa$/);
    const more = within(panel).getByRole("button", { name: "더 보기 (33개 더)" });
    expect(more.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(more);
    expect(within(runs).getAllByRole("link")).toHaveLength(42);
    // Accessible names are separated, not "카빙미실행".
    const extra = within(panel).getByRole("list", { name: "추가 분석" });
    expect(within(extra).getByRole("link", { name: "카빙, 미실행" })).toBeTruthy();
    expect(within(runs).getAllByRole("link")[0]?.getAttribute("aria-label")).toMatch(
      /^BSH\.E01 · .*, 실패, 소요 /,
    );
  });

  it("unique names stay plain", () => {
    const names = disambiguatedRunNames(
      [
        { run_id: "a", request: { root: "C:/x/one" } },
        { run_id: "b", request: { root: "C:/x/two" } },
      ],
      "utc",
    );
    expect([...names.values()]).toEqual(["one", "two"]);
  });

  it("the processing plan table shows Korean statuses", async () => {
    expect(stepStatusLabel("completed")).toBe("완료");
    expect(stepStatusLabel("skipped")).toBe("건너뜀");
    setRoute(`#/case/${RUN}/process`);
    installFetch({
      "/summary": () =>
        jsonResponse({
          steps: [
            { step: "files", status: "completed" },
            { step: "carving", status: "skipped" },
          ],
        }),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    renderWithClient(<ProcessPage />);
    const table = await screen.findByRole("table", { name: "처리 단계" });
    expect(table.textContent).toContain("완료");
    expect(table.textContent).toContain("건너뜀");
    expect(table.textContent).not.toMatch(/completed|skipped/);
  });
});
