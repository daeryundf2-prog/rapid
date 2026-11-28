// biome-ignore-all lint/a11y: tests drive the rail / panels through their DOM roles
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, configure, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AnalysisState } from "../../api/analyses";
import type { RunWithProgress } from "../../api/runsProgress";
import { resetCommandRegistry } from "../../commands/registry";
import {
  canonicalizeHash,
  EMPTY_ROUTE,
  isLegacyCaseHash,
  parseHash,
  serializeRoute,
  stageOf,
} from "../../router";
import { dispatchShortcut } from "../../shortcuts";
import { useAppStore } from "../../state/store";
import { registerAnalysisCommands } from "../analysis/commands";
import { useAnalysisStore } from "../analysis/store";
import { useExportHistory } from "../case/exports";
import { installFetch, jsonResponse } from "../grid/testSupport";
import { ProcessPage, ProcessPanel } from "./ProcessStage";
import { ReportPage, ReviewPanel } from "./ReviewReportStage";
import { StageRail } from "./StageRail";
import { registerStageCommands, resetStageMemory } from "./stages";

configure({ asyncUtilTimeout: 5000 });

vi.mock("../grid/DataGrid", () => ({ DataGrid: () => <div data-testid="grid-stub" /> }));

const RUN = "run-1";

function setRoute(hash: string) {
  window.location.hash = hash;
  useAppStore.getState().syncRouteFromLocation(parseHash(hash));
}

function renderWithClient(ui: ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

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

let off: Array<() => void> = [];

beforeEach(() => {
  resetCommandRegistry();
  resetStageMemory();
  useAppStore.setState({
    route: { ...EMPTY_ROUTE },
    runs: [
      { run_id: RUN, status: "completed", request: { root: "C:/ev/case1", mode: "fraud" } },
      { run_id: "run-2", status: "running", request: { root: "C:/ev/case2" }, progress: { error_count: 2 } },
    ] as unknown as RunWithProgress[],
  });
  useAnalysisStore.setState({ runId: null, analyses: [], available: true, dialog: null });
  window.location.hash = "";
});
afterEach(() => {
  cleanup();
  for (const fn of off) fn();
  off = [];
  vi.unstubAllGlobals();
  resetCommandRegistry();
});

describe("stage URLs and legacy redirects (console-ia §3, Q-IA-2)", () => {
  it("serialises every collection under its stage", () => {
    const at = (collection: never, extra = {}) => serializeRoute({ runId: "r", collection, ...extra });
    expect(at("intake" as never)).toBe("#/case/r/intake");
    expect(at("process" as never, { kind: "carve" })).toBe("#/case/r/process/carve");
    expect(at("artifacts" as never, { kind: "eventlog" })).toBe("#/case/r/explore/artifacts/eventlog");
    expect(at("analysis" as never, { kind: "carve", analysisId: "a1" })).toBe(
      "#/case/r/explore/analysis/carve?id=a1",
    );
    expect(at("review" as never, { status: "relevant" })).toBe("#/case/r/review/board/relevant");
    expect(at("outputs" as never)).toBe("#/case/r/report/outputs");
    expect(stageOf({ collection: "timeline" })).toBe("explore");
    expect(stageOf({ collection: "outputs" })).toBe("report");
  });

  it("parses the stage form; a bare explore / review / report opens the stage home", () => {
    expect(parseHash("#/case/r/explore")).toMatchObject({ collection: "files" });
    expect(parseHash("#/case/r/review")).toMatchObject({ collection: "review" });
    expect(parseHash("#/case/r/report")).toMatchObject({ collection: "outputs" });
    expect(parseHash("#/case/r/process")).toEqual({ runId: "r", collection: "process" });
  });

  it("rewrites an old link to the stage form in place (history replace), keeping row and filters", () => {
    const old = "#/case/x/artifacts/eventlog?row=artifacts%7Ceventlog%7C%2Fartifacts%2F3%7C%7C&types=a&q=k";
    window.location.hash = old;
    expect(isLegacyCaseHash(old)).toBe(true);
    const before = window.history.length;
    const route = canonicalizeHash();
    expect(route).toMatchObject({ collection: "artifacts", kind: "eventlog", types: ["a"], q: "k" });
    expect(window.location.hash).toBe(
      "#/case/x/explore/artifacts/eventlog?q=k&row=artifacts%7Ceventlog%7C%2Fartifacts%2F3%7C%7C&types=a",
    );
    expect(parseHash(window.location.hash).row).toEqual({
      collection: "artifacts",
      kind: "eventlog",
      locator: "/artifacts/3",
    });
    expect(window.history.length).toBe(before);
    expect(isLegacyCaseHash(window.location.hash)).toBe(false);
    for (const [legacy, stage] of [
      ["#/case/x/review/needs-review", "#/case/x/review/board/needs-review"],
      ["#/case/x/outputs", "#/case/x/report/outputs"],
      ["#/case/x/files", "#/case/x/explore/files"],
      ["#/case/x/intake", "#/case/x/intake"],
    ]) {
      expect(serializeRoute(parseHash(legacy as string))).toBe(stage);
    }
  });

  it("never rewrites a fragment that still carries the launch token", () => {
    window.location.hash = "#/case/x/files?token=abc";
    expect(canonicalizeHash()).toBeNull();
    expect(window.location.hash).toBe("#/case/x/files?token=abc");
  });
});

describe("stage rail (Q-IA-1)", () => {
  it("Alt+1..5 switch stages, the rail marks the current one, and each stage returns to its last view", () => {
    off.push(registerStageCommands());
    setRoute(`#/case/${RUN}/explore/artifacts/eventlog?q=x`);
    render(<StageRail />);
    const rail = screen.getByRole("navigation", { name: "작업 단계" });
    const button = (name: string) => within(rail).getByRole("button", { name });
    expect(button("탐색").getAttribute("aria-current")).toBe("page");
    expect(button("처리").getAttribute("aria-keyshortcuts")).toBe("Alt+2");

    const press = (digit: string) => {
      let claimed = false;
      act(() => {
        claimed = dispatchShortcut(
          new KeyboardEvent("keydown", {
            key: digit,
            code: `Digit${digit}`,
            altKey: true,
            cancelable: true,
          }),
        );
      });
      return claimed;
    };
    expect(press("2")).toBe(true);
    expect(window.location.hash).toBe(`#/case/${RUN}/process`);
    expect(button("처리").getAttribute("aria-current")).toBe("page");
    press("4");
    expect(window.location.hash).toBe(`#/case/${RUN}/review/board`);
    press("5");
    expect(window.location.hash).toBe(`#/case/${RUN}/report/outputs`);
    press("1");
    expect(window.location.hash).toBe(`#/case/${RUN}/intake`);
    // Back to 탐색: the remembered view, not the stage home.
    press("3");
    expect(window.location.hash).toBe(`#/case/${RUN}/explore/artifacts/eventlog?q=x`);
    fireEvent.click(button("검토"));
    expect(window.location.hash).toBe(`#/case/${RUN}/review/board`);
  });

  it("without a case the rail says why", () => {
    off.push(registerStageCommands());
    render(<StageRail />);
    const button = screen.getByRole("button", { name: "처리" });
    expect(button.getAttribute("aria-disabled")).toBe("true");
    expect(button.getAttribute("data-disabled-reason")).toBe("케이스를 먼저 선택하세요");
  });
});

describe("처리 stage (Q-IA-3)", () => {
  it("lists runs and 추가 분석 in the panel; cards run, show progress and link 결과 보기 → to 탐색", async () => {
    setRoute(`#/case/${RUN}/process/carve`);
    installFetch({
      "/summary": () => jsonResponse({ steps: [{ step: "files", status: "completed", record_count: 30 }] }),
      "/analyses": () =>
        jsonResponse({
          analyses: [
            job({ analysis_id: "c2", kind: "carve", status: "running" }),
            job({ analysis_id: "c1", kind: "carve", status: "completed", row_count: 7 }),
          ],
        }),
    });
    off.push(registerAnalysisCommands(new QueryClient()));
    renderWithClient(
      <>
        <ProcessPanel />
        <ProcessPage />
      </>,
    );
    const panel = screen.getByTestId("process-panel");
    const runs = within(panel).getByRole("list", { name: "런" });
    expect(within(runs).getAllByRole("link")).toHaveLength(2);
    expect(within(runs).getByRole("link", { current: "page" }).textContent).toContain("case1");
    expect(within(runs).getAllByRole("link")[1]?.textContent).toContain("오류 2");
    const extra = within(panel).getByRole("list", { name: "추가 분석" });
    expect(
      within(extra)
        .getAllByRole("link")
        .map((a) => a.textContent?.split("미실행")[0]),
    ).toHaveLength(7);

    const card = await screen.findByTestId("analysis-card-carve");
    await waitFor(() => expect(card.className).toContain("is-selected"));
    await waitFor(() => expect(within(card).getByTestId("analysis-results-link")).toBeTruthy());
    const results = within(card).getByTestId("analysis-results-link");
    expect(results.getAttribute("href")).toBe(`#/case/${RUN}/explore/analysis/carve?id=c1`);
    expect(results.textContent).toContain("7건");
    expect(within(card).getByRole("button", { name: "카빙 실행…" })).toBeTruthy();
    expect(within(card).getByRole("button", { name: "분석 취소" }).getAttribute("aria-disabled")).toBeNull();
    expect(within(card).getByRole("progressbar", { name: "카빙 진행률" })).toBeTruthy();
    expect(within(card).getByRole("table", { name: "실행 이력" })).toBeTruthy();
    // Picking a history row marks it (aria-pressed) and 결과 보기 follows it.
    const pick = within(card)
      .getAllByRole("button")
      .find((b) => b.dataset.analysisId === "c2") as HTMLElement;
    fireEvent.click(pick);
    expect(pick.getAttribute("aria-pressed")).toBe("true");
    expect(within(card).getByTestId("analysis-results-link").getAttribute("href")).toBe(
      `#/case/${RUN}/explore/analysis/carve?id=c2`,
    );
    // Step ids read in Korean (files → 파일 목록).
    expect(screen.getByRole("table", { name: "처리 단계" }).textContent).toContain("파일 목록");
    // Every analysis kind has its card.
    expect(screen.getAllByTestId(/^analysis-card-/)).toHaveLength(7);
  });

  it("panel cards show state, last run and a run button; the plan table reads counts and notes (S8)", async () => {
    setRoute(`#/case/${RUN}/process`);
    installFetch({
      "/summary": () =>
        jsonResponse({
          steps: [
            { name: "files", status: "completed", candidate_count: 4770, scanned_file_count: 19033 },
            {
              name: "docs-extract",
              status: "skipped",
              disabled: true,
              disabled_reason: "extraction-disabled-by-default; rerun with --extract",
            },
            {
              name: "artifacts-browser",
              status: "completed",
              artifact_count: 0,
              warning_level: "notice",
              warning_messages: ["No browser artifact rows were collected."],
            },
          ],
        }),
      "/analyses": () =>
        jsonResponse({
          analyses: [
            job({
              analysis_id: "c1",
              kind: "carve",
              status: "completed",
              row_count: 35,
              finished_at: "2026-10-12T12:37:17Z",
            }),
          ],
        }),
    });
    off.push(registerAnalysisCommands(new QueryClient()));
    renderWithClient(
      <>
        <ProcessPanel />
        <ProcessPage />
      </>,
    );
    const panel = screen.getByTestId("process-panel");
    const card = await within(panel).findByTestId("process-analysis-carve");
    await waitFor(() => expect(within(card).getByRole("link").getAttribute("aria-label")).toBe("카빙, 완료"));
    expect(card.textContent).toContain("35건");
    expect(within(panel).getByTestId("process-analysis-ocr-batch").textContent).toContain(
      "아직 실행하지 않았습니다",
    );
    // Cards come before the run list, each with its own run button.
    const order = within(panel)
      .getAllByRole("heading")
      .map((h) => h.textContent);
    expect(order).toEqual(["추가 분석", "런"]);
    fireEvent.click(within(card).getByRole("button", { name: "카빙 실행" }));
    await waitFor(() => expect(useAnalysisStore.getState().dialog?.kind).toBe("carve"));

    const table = await screen.findByRole("table", { name: "처리 단계" });
    expect(table.textContent).toContain("후보 4,770");
    expect(table.textContent).toContain("스캔 19,033");
    expect(table.textContent).toContain("기본 설정에서 꺼짐");
    expect(table.textContent).toContain("메시지 1건");
    expect(table.textContent).not.toMatch(/disabled-by-default|No browser/);
    expect(screen.getByText("3단계 · 완료 2 · 건너뜀 1")).toBeTruthy();
    // No "P2" placeholder sentence any more: the table is the plan.
    expect(screen.queryByText(/P2/)).toBeNull();
  });
});

describe("검토 / 보고 stages (Q-IA-5)", () => {
  it("the review panel lists statuses with counts, bookmarks and tags as board filters", async () => {
    setRoute(`#/case/${RUN}/review/board/relevant`);
    installFetch({
      "/review-counts": () =>
        jsonResponse({
          run_id: RUN,
          database: "d",
          case_id: "c",
          exists: true,
          by_status: { relevant: 2, excluded: 1 },
          include_in_report: 1,
          case_json: { bookmarks: 4, include_in_report: 0 },
          report_candidates: 1,
        }),
      "/review-map": () =>
        jsonResponse({
          marks: [
            {
              collection: "files",
              kind: "",
              locator: "/candidates/1",
              status: "relevant",
              tags: ["악성"],
              note: "n",
            },
            {
              collection: "files",
              kind: "",
              locator: "/candidates/2",
              status: "",
              tags: ["북마크"],
              note: "",
            },
            {
              collection: "files",
              kind: "",
              locator: "/candidates/3",
              status: "",
              tags: ["북마크"],
              note: "",
            },
          ],
        }),
    });
    renderWithClient(<ReviewPanel />);
    const statuses = await screen.findByRole("list", { name: "판정" });
    await waitFor(() =>
      expect(within(statuses).getByRole("link", { name: /^관련 있음 ?\d+$/ }).textContent).toContain("2"),
    );
    expect(within(statuses).getByRole("link", { current: "page" }).textContent).toContain("관련 있음");
    // F12: a 판정 nobody made is not offered (재검토 0); 보고서 포함 counts include_in_report.
    expect(within(statuses).queryByRole("link", { name: /재검토/ })).toBeNull();
    expect(within(statuses).getByRole("link", { name: /보고서 포함/ }).textContent).toContain("1");
    // 판정자 filter: the people present (no name → 이름 없음), as a cf= column filter.
    const reviewers = await screen.findByRole("list", { name: "판정자" });
    const unnamed = within(reviewers).getByRole("link", { name: /이름 없음/ });
    expect(unnamed.textContent).toContain("3");
    expect(unnamed.getAttribute("href")).toContain("cf=reviewer");
    // 관련 있음 not in the report: a link to exactly those rows.
    expect(within(statuses).getByRole("link", { name: /관련 있음 중 보고서 미포함/ }).textContent).toContain(
      "1",
    );
    const tags = screen.getByRole("list", { name: "태그·북마크" });
    expect(
      within(tags)
        .getByRole("link", { name: /북마크/ })
        .getAttribute("href"),
    ).toBe(`#/case/${RUN}/review/board?tags=%EB%B6%81%EB%A7%88%ED%81%AC`);
    await waitFor(() => expect(within(tags).getByRole("link", { name: /#악성/ })).toBeTruthy());
    const notes = within(tags).getByRole("link", { name: /메모 있음/ });
    expect(notes.getAttribute("href")).toBe(`#/case/${RUN}/review/board?note=1`);
    expect(notes.textContent).toContain("1");
    // 북마크: the count comes from the same source as the link (review rows tagged 북마크),
    // not case.json's bookmark total (4).
    expect(within(tags).getByRole("link", { name: /북마크/ }).textContent).toContain("2");
  });

  it("the report page: checklist, the included items, one primary export, files folded (F16)", async () => {
    setRoute(`#/case/${RUN}/report/outputs`);
    useExportHistory.setState({
      records: [
        {
          runId: RUN,
          kind: "case-report",
          label: "보고서",
          fileName: "case-report.html",
          at: "2026-10-12T00:00:00Z",
        },
        {
          runId: "other",
          kind: "case-report",
          label: "보고서",
          fileName: "x.html",
          at: "2026-10-12T00:00:00Z",
        },
      ],
    });
    installFetch({
      "/review-counts": () =>
        jsonResponse({
          by_status: { relevant: 2 },
          include_in_report: 1,
          case_json: { bookmarks: 0, include_in_report: 0 },
          report_candidates: 1,
        }),
      "/review-map": () =>
        jsonResponse({
          marks: [
            {
              target_type: "event",
              target_id: "1",
              status: "relevant",
              tags: [],
              note: "송금 직전",
              include_in_report: true,
              reviewer: "김검사",
              updated_at: "2026-11-27T03:28:46+00:00",
              title: "Artifact event: browser-history https://bank.example.test/account",
              path: "C:/Users/a/History",
              timestamp: "2026-10-18T08:02:48Z",
              collection: "timeline",
              kind: "",
              locator: "/events/1",
            },
            {
              target_type: "event",
              target_id: "2",
              status: "relevant",
              tags: [],
              note: "",
              include_in_report: false,
              reviewer: "web-ui",
              updated_at: "2026-11-27T03:28:47+00:00",
              collection: "timeline",
              kind: "",
              locator: "/events/2",
            },
          ],
        }),
      "/output-files": () => jsonResponse({ files: [{ name: "a" }, { name: "b" }] }),
    });
    renderWithClient(<ReportPage />);
    const checklist = await screen.findByTestId("report-checklist");
    await waitFor(() => expect(checklist.textContent).toContain("보고서 포함1건"));
    expect(screen.getByTestId("report-check-left-out").textContent).toContain("1건");
    // X4: inclusion only by an explicit action that names the count.
    expect(screen.getByRole("button", { name: "관련 있음 1건 보고서에 포함" })).toBeTruthy();
    expect(checklist.textContent).toContain("판정자 이름 없는 판정1건");
    const preview = screen.getByRole("table", { name: "보고서에 들어갈 항목" });
    expect(preview.textContent).toContain("browser-history https://bank.example.test/account");
    expect(preview.textContent).not.toContain("Artifact event:");
    expect(preview.textContent).toContain("김검사");
    expect(preview.textContent).toContain("송금 직전");
    // ONE primary export; the other formats say who they are for.
    expect(screen.getAllByRole("button", { name: /^보고서 내보내기/ })).toHaveLength(1);
    expect(screen.getByText(/다른 검수자용/)).toBeTruthy();
    const history = screen.getByRole("table", { name: "내보내기 이력" });
    expect(within(history).getAllByRole("row")).toHaveLength(2);
    // The run's files are folded; the grid mounts only when opened.
    expect(screen.queryByTestId("grid-stub")).toBeNull();
    const summary = await screen.findByText("처리 결과 파일 (2)");
    const details = summary.closest("details") as HTMLDetailsElement;
    details.open = true;
    fireEvent(details, new Event("toggle"));
    expect(await screen.findByTestId("grid-stub")).toBeTruthy();
  });
});
