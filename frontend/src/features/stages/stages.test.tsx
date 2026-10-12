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
    ).toHaveLength(6);

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
    expect(screen.getAllByTestId(/^analysis-card-/)).toHaveLength(6);
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
    const statuses = await screen.findByRole("list", { name: "리뷰 상태" });
    await waitFor(() =>
      expect(within(statuses).getByRole("link", { name: /관련 있음/ }).textContent).toContain("2"),
    );
    expect(within(statuses).getByRole("link", { current: "page" }).textContent).toContain("관련 있음");
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

  it("the report page shows this session's export history for the run", () => {
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
    renderWithClient(<ReportPage />);
    const history = screen.getByRole("table", { name: "내보내기 이력" });
    expect(within(history).getAllByRole("row")).toHaveLength(2);
    expect(history.textContent).toContain("case-report.html");
    expect(screen.getByTestId("grid-stub")).toBeTruthy();
  });
});
