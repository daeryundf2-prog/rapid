// biome-ignore-all lint/a11y: tests drive the dialog / cards / panel through their DOM roles
// Real-data QA round 2 (2026-10-12, frontend): the 실행 button of kinds without a snapshot
// field, Korean plan steps, the results header of an older job, partial results of a
// cancelled job, run names, OCR engine failure, disabled-reason style, cross-case run
// grouping, MFT / volume-shadow row titles, cleared review marks.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, configure, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ReactElement } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AnalysisState } from "../../api/analyses";
import { fetchReviewRows, isClearedReviewMark } from "../../api/collections";
import type { RunWithProgress } from "../../api/runsProgress";
import { CommandButton } from "../../commands/CommandButton";
import { registerCommands, resetCommandRegistry } from "../../commands/registry";
import { EMPTY_ROUTE, parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import { analysisCollection } from "../grid/columns/analysis";
import { reviewCollection } from "../grid/columns/review";
import { installFetch, jsonResponse } from "../grid/testSupport";
import {
  ProcessPage,
  ProcessPanel,
  runNameParts,
  stepNameLabel,
  stepStatusLabel,
} from "../stages/ProcessStage";
import { domainNodeCount } from "../tree/model";
import { AnalysisDialog } from "./AnalysisDialog";
import { AnalysisPane, lastStateText } from "./AnalysisPane";
import { registerAnalysisCommands } from "./commands";
import { summaryNotes } from "./kinds";
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

describe("BLOCKER: 실행 of kinds without a snapshot field after a completed discover", () => {
  const discovered = () =>
    jsonResponse({
      analyses: [job({ analysis_id: "d1", kind: "vsc-discover", status: "completed", row_count: 1 })],
    });

  for (const kind of ["carve", "ntfs-meta", "ocr-batch", "memory-import", "cross-case"] as const) {
    it(`${kind}: the button is not stuck on "스냅샷 목록을 불러오는 중입니다"`, async () => {
      installFetch({ "/analyses": discovered });
      // The run's job list (with its completed discover) is already loaded by the 처리 page.
      useAnalysisStore.setState({
        runId: RUN,
        analyses: [job({ analysis_id: "d1", kind: "vsc-discover", status: "completed", row_count: 1 })],
      });
      renderWithClient(<AnalysisDialog kind={kind} runId={RUN} onClose={() => {}} />);
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(document.body.textContent).not.toContain("스냅샷 목록을 불러오는 중");
      const submit = screen.getByTestId("analysis-submit");
      // carve's defaults are valid: it is enabled. Others may still miss a field — but never
      // for the snapshot reason.
      if (kind === "carve") expect(submit.getAttribute("aria-disabled")).toBeNull();
      expect(submit.getAttribute("title") ?? "").not.toContain("스냅샷");
    });
  }
});

describe("2. processing plan steps in Korean", () => {
  it("maps step ids and warning levels; unknown ones still read as Korean", async () => {
    expect(stepNameLabel("silent-failure-detector")).toBe("누락 위험 점검");
    expect(stepNameLabel("artifacts-browser")).toBe("아티팩트 수집: browser");
    expect(stepStatusLabel("warning")).toBe("경고");
    expect(stepStatusLabel("failed_isolated")).toBe("일부 실패(격리됨)");
    expect(stepStatusLabel("weird-warn-level")).toBe("경고");
    expect(stepStatusLabel("zzz")).toBe("상태 미상(zzz)");
    setRoute(`#/case/${RUN}/process`);
    installFetch({
      "/summary": () =>
        jsonResponse({
          steps: [
            { name: "silent-failure-detector", status: "warning", warning_level: "warning" },
            { name: "timeline", status: "completed", warning_level: "notice" },
          ],
        }),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    renderWithClient(<ProcessPage />);
    const table = await screen.findByRole("table", { name: "처리 단계" });
    expect(table.textContent).toContain("누락 위험 점검");
    expect(table.textContent).toContain("경고");
    expect(table.textContent).toContain("완료 · 알림");
    expect(table.textContent).not.toMatch(/silent-failure-detector|warning|notice/);
  });
});

describe("3. results header describes the job being viewed", () => {
  it("an older capped compare shows its own truncated reason, the newest gets a short line", async () => {
    setRoute(`#/case/${RUN}/explore/analysis/vsc?id=old`);
    installFetch({
      "/analyses": () =>
        jsonResponse({
          analyses: [
            job({ analysis_id: "new", kind: "vsc-compare", status: "completed", row_count: 5 }),
            job({
              analysis_id: "old",
              kind: "vsc-compare",
              status: "completed",
              row_count: 10000,
              summary: { truncated: true, truncated_reason: "최대 변경 기록 수(10,000)에 도달" },
            }),
          ],
        }),
    });
    renderWithClient(<AnalysisPane />);
    await waitFor(() =>
      expect(screen.getByTestId("analysis-last").textContent).toContain(
        "일부만 처리: 최대 변경 기록 수(10,000)에 도달",
      ),
    );
    expect(screen.getByTestId("analysis-last").textContent).toMatch(/^보고 있는 실행: 완료/);
    expect(screen.getByTestId("analysis-last").textContent).toContain("10,000건");
    expect(screen.getByTestId("analysis-latest").textContent).toMatch(/^최신 실행: 완료 .*5건/);
    expect(screen.getByTestId("analysis-latest").textContent).not.toContain("일부만 처리");
  });
});

describe("4. cancelled carve with partial rows", () => {
  const cancelled = job({ analysis_id: "c9", kind: "carve", status: "cancelled", row_count: 37 });

  it("the 처리 card links its partial result instead of 결과 없음", async () => {
    setRoute(`#/case/${RUN}/process/carve`);
    installFetch({
      "/summary": () => jsonResponse({ steps: [] }),
      "/analyses": () => jsonResponse({ analyses: [cancelled] }),
    });
    off.push(registerAnalysisCommands(new QueryClient()));
    renderWithClient(<ProcessPage />);
    const card = await screen.findByTestId("analysis-card-carve");
    const link = await within(card).findByTestId("analysis-results-link");
    expect(link.textContent).toBe("부분 결과 37건 보기 → (취소됨)");
    expect(link.getAttribute("href")).toBe(`#/case/${RUN}/explore/analysis/carve?id=c9`);
    expect(card.textContent).not.toContain("결과 없음");
  });

  it("the tree node counts it and marks it partial", () => {
    const count = domainNodeCount({ analysis: "carve" } as never, { analyses: [cancelled] } as never);
    expect(count.count).toBe(37);
    expect(count.marker).toBe("취소됨 · 부분 결과");
  });
});

describe("5. 처리 run list names", () => {
  const runs = [
    { run_id: "2a942078-aaaa", created_at: "2026-10-12T11:26:00Z", request: { root: "C:/ev/bsh-subset" } },
    { run_id: "7f00beef-bbbb", created_at: "2026-10-11T09:00:00Z", request: { root: "C:/ev/bsh-subset" } },
  ];

  it("puts date · short id on its own line; the tooltip has name, date and full id", () => {
    const parts = runNameParts(runs, "utc").get("2a942078-aaaa");
    expect(parts).toEqual({
      name: "bsh-subset",
      detail: "2026-10-12 11:26 · 2a942078",
      tooltip: "bsh-subset · 2026-10-12 11:26 · 2a942078-aaaa",
    });
    useAppStore.setState({ runs: runs as unknown as RunWithProgress[] });
    setRoute(`#/case/${runs[0]?.run_id}/process`);
    installFetch({ "/analyses": () => jsonResponse({ analyses: [] }) });
    renderWithClient(<ProcessPanel />);
    const list = within(screen.getByTestId("process-panel")).getByRole("list", { name: "런" });
    const first = within(list).getAllByRole("link")[0] as HTMLElement;
    // (Rendered in the analyst's timezone.)
    expect(first.getAttribute("title")).toMatch(/^bsh-subset · 2026-10-1\d \d\d:26 · 2a942078-aaaa$/);
    expect(first.querySelector(".stage-link-title")?.textContent).toBe("bsh-subset");
    expect(first.querySelector(".stage-link-detail")?.textContent).toMatch(
      /^2026-10-1\d \d\d:26 · 2a942078$/,
    );
  });
});

describe("6. OCR engine-level failure", () => {
  it("shows only the failure reason, not 성공 0 · 실패 0", () => {
    const failed = job({
      analysis_id: "o1",
      kind: "ocr-batch",
      status: "failed",
      row_count: 0,
      error: "OCR 엔진(tesseract)을 찾을 수 없습니다",
      summary: { succeeded_count: 0, failed_count: 0 },
    });
    expect(summaryNotes(failed)).toEqual(["실패 사유: OCR 엔진(tesseract)을 찾을 수 없습니다"]);
    expect(lastStateText(failed, "utc")).not.toMatch(/성공 0/);
  });
});

describe("7. disabled reasons on 처리 cards share one style", () => {
  it("showReason prints the reason once, with no hover/focus box", () => {
    off.push(
      registerCommands([
        {
          id: "t.cmd",
          label: "비교 실행…",
          group: "case",
          disabledReason: () => "먼저 탐색하세요",
          run: () => {},
        },
      ]),
    );
    render(<CommandButton command="t.cmd" showReason />);
    const button = screen.getByRole("button", { name: "비교 실행…" });
    fireEvent.focus(button);
    fireEvent.mouseEnter(button.parentElement as HTMLElement);
    expect(screen.queryByRole("tooltip", { hidden: true })).toBeNull();
    expect(screen.getByTestId("command-disabled-reason").textContent).toBe("먼저 탐색하세요");
  });
});

describe("8. cross-case dialog groups the runs", () => {
  it("eligible first, ineligible folded behind a disclosure, the current case marked", () => {
    useAppStore.setState({
      runs: [
        { run_id: RUN, status: "completed", request: { root: "C:/ev/case1" } },
        { run_id: "run-ok", status: "completed", request: { root: "C:/ev/case2" } },
        ...Array.from({ length: 5 }, (_, i) => ({
          run_id: `run-bad${i}`,
          status: "failed",
          request: { root: `C:/ev/bad${i}` },
        })),
      ] as unknown as RunWithProgress[],
    });
    installFetch({ "/analyses": () => jsonResponse({ analyses: [] }) });
    renderWithClient(<AnalysisDialog kind="cross-case" runId={RUN} onClose={() => {}} />);
    const group = within(screen.getByRole("dialog")).getByRole("group", { name: "비교할 케이스" });
    expect(within(group).getByTestId("cross-case-current").textContent).toMatch(/현재 런.*case1/);
    expect(within(group).getAllByRole("checkbox")).toHaveLength(1);
    const more = within(group).getByRole("button", { name: "사용할 수 없는 런 5개 보기" });
    expect(more.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(more);
    const hidden = within(group).getByTestId("cross-case-ineligible");
    const boxes = within(hidden).getAllByRole("checkbox") as HTMLInputElement[];
    expect(boxes).toHaveLength(5);
    expect(boxes.every((b) => b.disabled)).toBe(true);
    expect(hidden.textContent).toContain("실패한 런이라 비교할 수 없습니다");
  });
});

describe("9 / 11. analysis row titles", () => {
  const map = (kind: string, details: Record<string, unknown>, path?: string) =>
    analysisCollection.mapRow({ details, _index: 12, ...(path ? { path } : {}) }, 12, {
      ref: { id: "analysis", kind, analysisId: "a" },
    }).title;

  it("an unnamed MFT record is titled by its entry number, not 결과 13", () => {
    expect(map("ntfs-meta", { entry_number: 13, in_use: false, name: "", path: "" })).toBe(
      "MFT 엔트리 13 (이름 없음, 삭제됨)",
    );
    expect(map("ntfs-meta", { entry_number: 5, in_use: true, directory: true, name: "" })).toBe(
      "MFT 엔트리 5 (이름 없음, 폴더)",
    );
    expect(map("ntfs-meta", { entry_number: 40, name: "secret.docx" })).toBe("secret.docx");
  });

  it("a volume-shadow compare row is titled by its file, not the snapshot folder", () => {
    expect(
      map(
        "vsc-compare",
        {
          status: "deleted",
          path: "Users/kim/Desktop/plan.xlsx",
          snapshot_root: "C:/ev/HarddiskVolumeShadowCopy1",
          source_path: "C:/ev/HarddiskVolumeShadowCopy1/Users/kim/Desktop/plan.xlsx",
        },
        "C:/ev/HarddiskVolumeShadowCopy1/Users/kim/Desktop/plan.xlsx",
      ),
    ).toBe("plan.xlsx");
  });
});

describe("12. review board after a mark is toggled off", () => {
  it("drops cleared marks (unreviewed, no note/tags/report) and keeps meaningful ones", async () => {
    expect(isClearedReviewMark({ status: "unreviewed", tags: [], note: "" })).toBe(true);
    expect(isClearedReviewMark({ status: "unreviewed", tags: ["북마크"], note: "" })).toBe(false);
    expect(isClearedReviewMark({ status: "unreviewed", tags: [], note: "확인" })).toBe(false);
    expect(isClearedReviewMark({ status: "", include_in_report: true })).toBe(false);
    installFetch({
      "/review-map": () =>
        jsonResponse({
          marks: [
            { target_type: "analysis_row", target_id: "x/1", status: "unreviewed", tags: [], note: "" },
            { target_type: "analysis_row", target_id: "x/2", status: "relevant", tags: [], note: "" },
          ],
          truncated: false,
        }),
      "/case": () => jsonResponse({ case: null }),
    });
    const page = await fetchReviewRows(RUN);
    expect(page.rows.map((r) => r.target_id)).toEqual(["x/2"]);
    expect(page.total).toBe(1);
  });

  it("the summary is the source row's label, never 'analysis_row <id>'", () => {
    const row = (raw: Record<string, unknown>) =>
      reviewCollection.mapRow({ _store: "case-db", status: "relevant", ...raw }, 0, {
        ref: { id: "review" },
      } as never);
    expect(
      row({ target_type: "analysis_row", target_id: "20261012T112630-2a942078/2", label: "plan.xlsx" }).title,
    ).toBe("plan.xlsx");
    const fallback = row({ target_type: "analysis_row", target_id: "20261012T112630-2a942078/2" }).title;
    expect(fallback).toBe("분석 결과 3 (2a942078)");
    expect(fallback).not.toContain("analysis_row");
  });
});

describe("10. analysis file picker starts at the run's allowed roots", () => {
  it("lists the roots first (scope + run_id, no home folder) and never goes above a root", async () => {
    const calls = installFetch({
      "/api/browse": (url) => {
        const path = url.searchParams.get("path");
        if (!path) {
          return jsonResponse({
            scope: "analysis-input",
            scope_label: "입력 허용 루트",
            path: "",
            parent: null,
            at_roots: true,
            roots: [],
            entries: [{ name: "D:evidence", path: "D:evidence", kind: "directory" }],
            entry_count: 1,
            truncated: false,
            hidden_count: 0,
          });
        }
        return jsonResponse({
          path: "D:evidence",
          parent: null,
          at_roots: false,
          roots: [],
          entries: [{ name: "vol", path: "D:evidence\vol", kind: "directory" }],
          entry_count: 1,
          truncated: false,
          hidden_count: 0,
        });
      },
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    renderWithClient(<AnalysisDialog kind="memory-import" runId={RUN} onClose={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "찾아보기" }));
    const roots = await screen.findByRole("list", { name: "허용 루트" });
    const first = calls.find((c) => c.url.startsWith("/api/browse")) as { url: string };
    const query = new URL(first.url, "http://x").searchParams;
    expect(query.get("scope")).toBe("analysis-input");
    expect(query.get("run_id")).toBe(RUN);
    expect(query.get("path")).toBeNull();
    expect(screen.getByTestId("browse-roots-title").textContent).toBe("입력 허용 루트");
    // The root list is not a folder to pick.
    expect(screen.queryByRole("button", { name: "이 폴더 선택" })).toBeNull();
    fireEvent.click(within(roots).getByRole("button", { name: /D:evidence/ }));
    await screen.findByRole("list", { name: "폴더 목록" });
    // At a root: back to the root list, never "상위 폴더" above it.
    expect(screen.queryByRole("button", { name: "상위 폴더" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "허용 루트 목록" }));
    expect(await screen.findByRole("list", { name: "허용 루트" })).toBeTruthy();
  });

  it("the extraction folder lists the output roots", async () => {
    const calls = installFetch({
      "/api/browse": () =>
        jsonResponse({ path: "", parent: null, at_roots: true, roots: [], entries: [], truncated: false }),
      "/analyses": () => jsonResponse({ analyses: [] }),
    });
    renderWithClient(<AnalysisDialog kind="vsc-extract" runId={RUN} onClose={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: "찾아보기" }));
    await screen.findByText("이 런에 허용된 루트가 없습니다.");
    const browse = calls.find((c) => c.url.startsWith("/api/browse")) as { url: string };
    expect(new URL(browse.url, "http://x").searchParams.get("scope")).toBe("analysis-output");
  });
});
