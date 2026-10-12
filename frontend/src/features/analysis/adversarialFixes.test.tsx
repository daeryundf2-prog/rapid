// biome-ignore-all lint/a11y: tests drive the dialog / cards / chip through their DOM roles
// Adversarial-review round 2 (analysis side): cross-case rule, OCR selection limits, card
// cancel target, chip "분석 보기", first-seen settled jobs, modal-safe and NumPad shortcuts.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  configure,
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import type { ReactElement, ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AnalysisState } from "../../api/analyses";
import type { RunWithProgress } from "../../api/runsProgress";
import { registerCommand, resetCommandRegistry } from "../../commands/registry";
import { EMPTY_ROUTE, parseHash } from "../../router";
import { dispatchShortcut, eventToShortcut } from "../../shortcuts";
import { useAppStore } from "../../state/store";
import { installFetch, jsonResponse } from "../grid/testSupport";
import { ProcessPage } from "../stages/ProcessStage";
import { registerStageCommands } from "../stages/stages";
import { AnalysisDialog } from "./AnalysisDialog";
import { AnalysisProgressChip } from "./AnalysisProgressChip";
import {
  type AnalysisFormState,
  buildAnalysisOptions,
  defaultForm,
  OCR_MAX_ITEMS,
  validateAnalysisForm,
} from "./analysisForm";
import { registerAnalysisCommands } from "./commands";
import { useAnalysisStore, useAnalysisTransitions } from "./store";

configure({ asyncUtilTimeout: 5000 });

const announceMock = vi.hoisted(() => vi.fn());
vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: announceMock,
}));
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
  return { client, ...render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>) };
}

function keydown(init: KeyboardEventInit, target: HTMLElement): KeyboardEvent {
  const event = new KeyboardEvent("keydown", { bubbles: true, cancelable: true, ...init });
  Object.defineProperty(event, "target", { value: target });
  return event;
}

let off: Array<() => void> = [];

beforeEach(() => {
  resetCommandRegistry();
  window.location.hash = "";
  document.body.innerHTML = "";
  useAppStore.setState({
    route: { ...EMPTY_ROUTE },
    runs: [
      { run_id: RUN, status: "completed", request: { root: "C:/ev/case1" } },
      { run_id: "run-2", status: "completed", request: { root: "C:/ev/case2" } },
    ] as unknown as RunWithProgress[],
    runsStatus: "ready" as never,
  });
  useAnalysisStore.setState({ runId: null, analyses: [], available: true, dialog: null });
  announceMock.mockReset();
});
afterEach(() => {
  cleanup();
  for (const fn of off) fn();
  off = [];
  vi.unstubAllGlobals();
  resetCommandRegistry();
});

// ---------------------------------------------------------------------------

describe("cross-case mirrors CrossCaseOptions / prepare_cross_case (11)", () => {
  const ctx = { runId: RUN };
  const ids = (n: number) => Array.from({ length: n }, (_, i) => `other-${i}`);
  it("one other case is enough; the current run is never counted or sent; at most 20 others", () => {
    const form = (caseIds: string[]) => ({ ...defaultForm("cross-case", ctx), case_ids: caseIds });
    expect(validateAnalysisForm("cross-case", form(["run-2"]), ctx).case_ids).toBeUndefined();
    // Only the current run checked = nothing to compare (the server answers 400).
    expect(validateAnalysisForm("cross-case", form([RUN]), ctx).case_ids).toMatch(/1개 이상/);
    expect(buildAnalysisOptions("cross-case", form([RUN, "run-2", "run-2"]), ctx).case_ids).toEqual([
      "run-2",
    ]);
    // 20 others (+ the current run the server adds) is the max_length; 21 is refused.
    expect(validateAnalysisForm("cross-case", form([RUN, ...ids(20)]), ctx).case_ids).toBeUndefined();
    expect(buildAnalysisOptions("cross-case", form([RUN, ...ids(20)]), ctx).case_ids).toHaveLength(20);
    expect(validateAnalysisForm("cross-case", form(ids(21)), ctx).case_ids).toMatch(/20개까지/);
  });

  it("the dialog offers only the other runs and posts with one of them checked", async () => {
    const calls = installFetch({
      "/analyses": (_url, init) =>
        init?.method === "POST"
          ? jsonResponse({ analysis_id: "x1", kind: "cross-case", status: "queued" }, 202)
          : jsonResponse({ analyses: [] }),
    });
    const onClose = vi.fn();
    renderWithClient(<AnalysisDialog kind="cross-case" runId={RUN} onClose={onClose} />);
    const dialog = screen.getByRole("dialog");
    const group = within(dialog).getByRole("group", { name: "비교할 케이스" });
    const boxes = within(group).getAllByRole("checkbox");
    expect(boxes).toHaveLength(1);
    expect(boxes[0]?.parentElement?.textContent).toContain("case2");
    fireEvent.click(boxes[0] as HTMLElement);
    const submit = within(dialog).getByTestId("analysis-submit");
    expect(submit.getAttribute("aria-disabled")).toBeNull();
    fireEvent.click(submit);
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({
      kind: "cross-case",
      options: { case_ids: ["run-2"], max_shared: 500 },
    });
  });
});

describe("OCR selection vs max_items (9)", () => {
  it("defaults max_items to the selection size and never sends more than the selection", () => {
    const locators = ["/candidates/1", "/candidates/2", "/candidates/3"];
    const form: AnalysisFormState = { ...defaultForm("ocr-batch", { locators }), locators };
    expect(form.max_items).toBe("3");
    expect(buildAnalysisOptions("ocr-batch", form)).toMatchObject({ max_items: 3, target: { locators } });
    // A selection larger than the old default (200) is not truncated by locators[:max_items].
    const many = Array.from({ length: 600 }, (_, i) => `/candidates/${i}`);
    expect(defaultForm("ocr-batch", { locators: many }).max_items).toBe("600");
    // A typed limit above the selection is clamped to it.
    expect(buildAnalysisOptions("ocr-batch", { ...form, max_items: "900" }).max_items).toBe(3);
    // Without a selection the backend default (50) applies.
    expect(defaultForm("ocr-batch").max_items).toBe("50");
  });

  it("warns and blocks when the selection exceeds the backend maximum (1,000)", () => {
    installFetch({ "/analyses": () => jsonResponse({ analyses: [] }) });
    const locators = Array.from({ length: OCR_MAX_ITEMS + 1 }, (_, i) => `/candidates/${i}`);
    expect(
      validateAnalysisForm("ocr-batch", { ...defaultForm("ocr-batch", { locators }), locators }).locators,
    ).toMatch(/1,000장까지/);
    renderWithClient(
      <AnalysisDialog kind="ocr-batch" runId={RUN} preset={{ locators }} onClose={() => undefined} />,
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByLabelText("최대 이미지 수")).toHaveProperty("value", "1000");
    expect(within(dialog).getByTestId("analysis-target-warning").textContent).toContain("1,000장까지");
    expect(within(dialog).getByTestId("analysis-submit").getAttribute("aria-disabled")).toBe("true");
  });

  it("says when a lowered limit processes only part of the selection", () => {
    installFetch({ "/analyses": () => jsonResponse({ analyses: [] }) });
    const locators = ["/artifacts/1", "/artifacts/2", "/artifacts/3"];
    renderWithClient(
      <AnalysisDialog kind="ocr-batch" runId={RUN} preset={{ locators }} onClose={() => undefined} />,
    );
    const input = screen.getByLabelText("최대 이미지 수");
    expect(input).toHaveProperty("value", "3");
    expect(screen.queryByTestId("analysis-target-warning")).toBeNull();
    fireEvent.change(input, { target: { value: "2" } });
    expect(screen.getByTestId("analysis-target-warning").textContent).toContain("앞의 2장만");
  });
});

describe("처리 card 분석 취소 cancels that card's job (2)", () => {
  it("cancels the OCR card's job while the route points at the carve card", async () => {
    setRoute(`#/case/${RUN}/process/carve`);
    const calls = installFetch({
      "/cancel": () => jsonResponse(job({ analysis_id: "o1", kind: "ocr-batch", status: "cancelled" })),
      "/summary": () => jsonResponse({ steps: [] }),
      "/analyses": () =>
        jsonResponse({
          analyses: [
            job({ analysis_id: "c2", kind: "carve", status: "running" }),
            job({ analysis_id: "o1", kind: "ocr-batch", status: "running" }),
          ],
        }),
    });
    const { client } = renderWithClient(<ProcessPage />);
    off.push(registerAnalysisCommands(client));
    const card = await screen.findByTestId("analysis-card-ocr-batch");
    const cancel = await within(card).findByTestId("analysis-cancel");
    fireEvent.click(cancel);
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    const posts = calls.filter((c) => c.method === "POST").map((c) => c.url);
    expect(posts).toEqual([`/api/runs/${RUN}/analyses/o1/cancel`]);
    await waitFor(() => expect(announceMock).toHaveBeenCalledWith("OCR 일괄 분석 취소를 요청했습니다"));
  });
});

describe("status chip 분석 보기 opens the job it names (7)", () => {
  it("opens the active job, not the newest completed one", async () => {
    setRoute(`#/case/${RUN}/explore/files`);
    installFetch({
      "/analyses": () =>
        jsonResponse({
          analyses: [
            job({ analysis_id: "c1", kind: "carve", status: "running" }),
            job({ analysis_id: "d1", kind: "vsc-discover", status: "completed", row_count: 2 }),
          ],
        }),
    });
    const { client } = renderWithClient(<AnalysisProgressChip />);
    off.push(registerAnalysisCommands(client));
    const chip = await screen.findByTestId("analysis-progress-chip");
    expect(chip.textContent).toContain("분석: 카빙");
    fireEvent.click(within(chip).getByRole("button", { name: "분석 보기" }));
    expect(window.location.hash).toBe(`#/case/${RUN}/explore/analysis/carve?id=c1`);
  });
});

describe("transitions: a job first seen already settled is news; history is not (6)", () => {
  it("announces and refreshes feeds for a new settled job, never for the first loaded snapshot", () => {
    const client = new QueryClient();
    const invalidate = vi.spyOn(client, "invalidateQueries");
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
    const history = job({ analysis_id: "h1", kind: "carve", status: "completed", row_count: 9 });
    const { rerender } = renderHook(
      ({ list, loaded }: { list: AnalysisState[]; loaded: boolean }) =>
        useAnalysisTransitions(RUN, list, { loaded }),
      { wrapper, initialProps: { list: [] as AnalysisState[], loaded: false } },
    );
    // Query resolves: the run's history is the baseline, not news.
    rerender({ list: [history], loaded: true });
    expect(announceMock).not.toHaveBeenCalled();
    expect(invalidate).not.toHaveBeenCalled();
    // A job that started and finished between two polls.
    const quick = job({ analysis_id: "n1", kind: "carve", status: "completed", row_count: 3 });
    rerender({ list: [quick, history], loaded: true });
    expect(announceMock).toHaveBeenCalledWith("카빙 분석 완료 · 3건", { politeness: "polite" });
    const keys = invalidate.mock.calls.map((c) => JSON.stringify(c[0]?.queryKey));
    expect(keys).toContain(JSON.stringify(["run-tree", RUN]));
    expect(keys).toContain(JSON.stringify(["collection", RUN, "files"]));
    // A new job that is still running is announced only when it settles.
    announceMock.mockReset();
    const running = job({ analysis_id: "r1", kind: "carve", status: "running" });
    rerender({ list: [running, quick, history], loaded: true });
    expect(announceMock).not.toHaveBeenCalled();
  });
});

describe("modal dialogs and NumPad digits do not switch stages (3, 5)", () => {
  it("Alt+1~5 inside an aria-modal dialog are ignored; Escape and Ctrl+K still act", () => {
    off.push(registerStageCommands());
    const close = vi.fn();
    const back = vi.fn();
    const palette = vi.fn();
    off.push(registerCommand({ id: "t.close", label: "닫기", group: "app", shortcut: "Escape", run: close }));
    off.push(
      registerCommand({ id: "t.palette", label: "팔레트", group: "app", shortcut: "Ctrl+K", run: palette }),
    );
    setRoute(`#/case/${RUN}/explore/files`);
    const dialog = document.createElement("div");
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    const button = document.createElement("button");
    dialog.append(button);
    document.body.append(dialog);
    act(() => {
      expect(dispatchShortcut(keydown({ key: "2", code: "Digit2", altKey: true }, button))).toBe(false);
    });
    expect(window.location.hash).toBe(`#/case/${RUN}/explore/files`);
    expect(document.activeElement).not.toBe(document.getElementById("stage-heading"));
    // Viewer history / view switches would also act behind the dialog.
    registerCommand({ id: "t.back", label: "뒤로", group: "viewer", shortcut: "Alt+ArrowLeft", run: back });
    expect(dispatchShortcut(keydown({ key: "ArrowLeft", altKey: true }, button))).toBe(false);
    expect(dispatchShortcut(keydown({ key: "Escape" }, button))).toBe(true);
    expect(dispatchShortcut(keydown({ key: "k", ctrlKey: true }, button))).toBe(true);
    expect(close).toHaveBeenCalledTimes(1);
    expect(back).not.toHaveBeenCalled();
    expect(palette).toHaveBeenCalledTimes(1);
    // Outside the dialog Alt+2 still switches.
    act(() => {
      expect(dispatchShortcut(keydown({ key: "2", code: "Digit2", altKey: true }, document.body))).toBe(true);
    });
    expect(window.location.hash).toBe(`#/case/${RUN}/process`);
  });

  it("Alt+NumPad digits (Windows Alt-codes) never match Alt+1~5", () => {
    off.push(registerStageCommands());
    setRoute(`#/case/${RUN}/explore/files`);
    const numpad = keydown({ key: "2", code: "Numpad2", altKey: true }, document.body);
    expect(eventToShortcut(numpad)).not.toBe("Alt+2");
    expect(dispatchShortcut(numpad)).toBe(false);
    expect(window.location.hash).toBe(`#/case/${RUN}/explore/files`);
    expect(eventToShortcut(keydown({ key: "2", code: "Digit2", altKey: true }, document.body))).toBe("Alt+2");
    // Plain NumPad digits keep meaning the 1–5 priority keys.
    expect(eventToShortcut(keydown({ key: "2", code: "Numpad2" }, document.body))).toBe("2");
  });
});
