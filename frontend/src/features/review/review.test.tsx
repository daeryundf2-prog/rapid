// AXIOM adoption E3 (plan §3.3): tag manager, digit tag keys, propagation, classic split,
// media blur persistence, baseline compare bars, selection CSV.
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CaseTag } from "../../api/reviewTools";
import { registerCommands, resetCommandRegistry, runCommand } from "../../commands/registry";
import { NO_ROW_REASON, reviewCommands } from "../../commands/review";
import type { ViewerTarget } from "../../contracts/viewer";
import { Layout } from "../../shell/Layout";
import { dispatchShortcut } from "../../shortcuts";
import { resetAppStore, useAppStore } from "../../state/store";
import { mockFetch, renderWithQuery } from "../case/testUtils";
import { makeRef, makeRow } from "../grid/columns/common";
import type { GridCommandHost } from "../grid/gridCommands";
import { resetCaseDbHandles } from "../grid/reviewActions";
import type { ColumnSpec } from "../grid/types";
import { CompareBars, deltaText } from "./BaselineHistogram";
import {
  CLASSIC_SPLIT_COMMAND,
  CLASSIC_STAGE_REASON,
  MEDIA_BLUR_COMMAND,
  reviewToolCommands,
} from "./commands";
import { buildSelectionCsv, CSV_BOM, csvCell, NONE, TRAILING_HEADERS } from "./csv";
import { NO_TAGS_TO_PROPAGATE, propagateReason, propagateTagsByHash } from "./gridTools";
import { visibleTagNodes } from "./ReviewTagNodes";
import { draftReason, SYSTEM_TAG_REASON, TagManagerDialog } from "./TagManagerDialog";
import { unboundKeyReason } from "./tagKeys";
import { loadCaseTags, resetCaseTagStore, sortTags } from "./tagStore";
import { CLASSIC_SPLIT_KEY, MEDIA_BLUR_KEY, reloadViewPrefs, useViewPrefs } from "./viewPrefs";

const announceMock = vi.hoisted(() => vi.fn());
vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: announceMock,
}));

function tag(partial: Partial<CaseTag> & { id: number; name: string }): CaseTag {
  return {
    case_id: "run-r1",
    kind: "user",
    color_token: "tag-5",
    shortcut: null,
    description: "",
    created_by: "검사관 A",
    created_at: "2026-10-17T00:00:00+00:00",
    updated_at: "2026-10-17T00:00:00+00:00",
    deleted_at: null,
    deleted_by: null,
    count: 0,
    ...partial,
  };
}

const SYSTEM: CaseTag[] = [
  tag({ id: 1, name: "북마크", kind: "system", color_token: "tag-3" }),
  ...[1, 2, 3, 4, 5].map((n) => tag({ id: n + 1, name: `우선순위 ${n}`, kind: "system", shortcut: n })),
];

function caseRoutes(tags: CaseTag[], extra: Record<string, unknown> = {}) {
  return {
    "GET /api/runs/r1/review-counts": { run_id: "r1", case_id: "run-r1", exists: true, by_status: {} },
    "GET /api/cases/run-r1/tags": { case_id: "run-r1", exists: true, tags },
    "POST /api/runs/r1/case-db/ensure": { database: "D:/out/rapidtriage-case.db", case_id: "run-r1" },
    ...extra,
  };
}

const target = (locator: string): ViewerTarget => ({
  ref: { collection: "files", locator },
  runId: "r1",
  sourcePath: `C:/e/file${locator.slice(-1)}.jpg`,
});

beforeEach(() => {
  resetCommandRegistry();
  resetCaseTagStore();
  resetCaseDbHandles();
  resetAppStore({ route: { runId: null, collection: null } });
  announceMock.mockReset();
  window.localStorage.clear();
  reloadViewPrefs();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("tag manager dialog", () => {
  it("lists tags in Korean order, creates one with colour + key, refuses taken keys, keeps system tags", async () => {
    const created = tag({ id: 20, name: "DLP 유출 후보", color_token: "tag-7", shortcut: 7, count: 0 });
    const { calls } = mockFetch(
      caseRoutes([...SYSTEM, tag({ id: 9, name: "하 태그", count: 2 }), tag({ id: 10, name: "가 태그" })], {
        "POST /api/cases/run-r1/tags": { tag: created },
      }),
    );
    const opener = document.createElement("button");
    document.body.append(opener);
    opener.focus();
    const onClose = vi.fn();
    const view = renderWithQuery(<TagManagerDialog runId="r1" onClose={onClose} />);
    const dialog = await screen.findByRole("dialog", { name: "태그 관리" });
    await waitFor(() => expect(within(dialog).getAllByTestId("tag-row")).toHaveLength(8));
    const names = within(dialog)
      .getAllByTestId("tag-row")
      .map((row) => row.querySelector("th span span:nth-child(2)")?.textContent);
    // System tags first (their own order), then user tags by Korean collation.
    expect(names.slice(-2)).toEqual(["가 태그", "하 태그"]);
    // System tags: delete is focusable but disabled with its reason.
    const systemDelete = within(dialog).getByRole("button", { name: "북마크 태그 삭제" });
    expect(systemDelete.getAttribute("aria-disabled")).toBe("true");
    expect(systemDelete.getAttribute("title")).toBe(SYSTEM_TAG_REASON);

    fireEvent.click(within(dialog).getByTestId("tag-new"));
    const form = within(dialog).getByRole("form", { name: "새 태그" });
    const save = within(form).getByTestId("tag-save");
    expect(save.getAttribute("title")).toBe("태그 이름을 입력하세요");
    fireEvent.change(within(form).getByLabelText("이름"), { target: { value: "  DLP   유출 후보 " } });
    fireEvent.click(within(form).getByLabelText("자주"));
    const keySelect = within(form).getByLabelText("단축키") as HTMLSelectElement;
    const taken = [...keySelect.options].find((option) => option.value === "3");
    expect(taken?.disabled).toBe(true);
    expect(taken?.textContent).toContain("우선순위 3");
    fireEvent.change(keySelect, { target: { value: "7" } });
    fireEvent.click(save);
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url.includes("/tags"))).toBe(true));
    const post = calls.find((c) => c.method === "POST" && c.url.includes("/tags"));
    expect(post?.url).toBe("/api/cases/run-r1/tags?run_id=r1");
    expect(post?.body).toMatchObject({
      name: "DLP 유출 후보",
      color_token: "tag-7",
      shortcut: 7,
      created_by: "web-ui",
    });
    await waitFor(() => expect(announceMock).toHaveBeenCalledWith("태그 'DLP 유출 후보'을(를) 만들었습니다"));

    // Esc closes the dialog; the shared Modal hands focus back to the opener on unmount.
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
    view.unmount();
    expect(document.activeElement).toBe(opener);
    opener.remove();
  });

  it("draft validation is Korean and case-insensitive", () => {
    const tags = [...SYSTEM, tag({ id: 9, name: "Alpha", shortcut: 8 })];
    const draft = {
      id: null,
      name: "alpha",
      color: "tag-1" as const,
      shortcut: null,
      description: "",
      system: false,
    };
    expect(draftReason(draft, tags)).toBe("같은 이름의 태그가 이미 있습니다: Alpha");
    expect(draftReason({ ...draft, name: "새 이름", shortcut: 8 }, tags)).toBe(
      "단축키 8은(는) 이미 'Alpha' 태그에 지정되어 있습니다",
    );
    expect(draftReason({ ...draft, name: " " }, tags)).toBe("태그 이름을 입력하세요");
    expect(draftReason({ ...draft, name: "새 이름", shortcut: 9 }, tags)).toBeUndefined();
  });

  it("tree nodes: user tags always, system tags once used, 북마크 apart, Korean order", () => {
    const tags = [
      ...SYSTEM.map((t) => (t.name === "우선순위 2" ? { ...t, count: 4 } : t)),
      tag({ id: 30, name: "하나", count: 0 }),
      tag({ id: 31, name: "가나", count: 3 }),
    ];
    expect(visibleTagNodes(tags).map((t) => t.name)).toEqual(["우선순위 2", "가나", "하나"]);
    expect(sortTags(tags)[0]?.kind).toBe("system");
  });
});

describe("digit tag keys", () => {
  beforeEach(() => registerCommands(reviewCommands(null)));

  it("apply the tag bound to the digit to the viewer row", async () => {
    const { calls } = mockFetch(
      caseRoutes([...SYSTEM, tag({ id: 20, name: "DLP", shortcut: 7 })], {
        "POST /api/case-db/review-batch": { updated_count: 1 },
      }),
    );
    useAppStore.getState().navigate({ runId: "r1", collection: "files" });
    useAppStore.getState().setViewerTarget(target("/candidates/2"));
    await loadCaseTags("r1");
    const row = document.createElement("div");
    row.setAttribute("role", "row");
    document.body.append(row);
    const event = new KeyboardEvent("keydown", { key: "7", code: "Digit7", bubbles: true, cancelable: true });
    Object.defineProperty(event, "target", { value: row });
    expect(dispatchShortcut(event)).toBe(true);
    await waitFor(() => expect(calls.some((c) => c.url === "/api/case-db/review-batch")).toBe(true));
    const batch = calls.find((c) => c.url === "/api/case-db/review-batch");
    expect(batch?.body).toMatchObject({
      add_tags: ["DLP"],
      targets: [{ collection: "files", locator: "/candidates/2" }],
    });
    row.remove();
  });

  it("an unbound digit says why; without a case DB 1–5 still mean 우선순위 n", async () => {
    mockFetch(caseRoutes([...SYSTEM]));
    useAppStore.getState().navigate({ runId: "r1", collection: "files" });
    expect(await runCommand("review.tagKey.6")).toEqual({ ok: false, reason: NO_ROW_REASON });
    useAppStore.getState().setViewerTarget(target("/candidates/2"));
    await loadCaseTags("r1");
    expect(await runCommand("review.tagKey.6")).toEqual({ ok: false, reason: unboundKeyReason(6) });

    resetCaseTagStore();
    const { calls } = mockFetch({
      "GET /api/runs/r1/review-counts": { run_id: "r1", case_id: "run-r1", exists: false, by_status: {} },
      "POST /api/runs/r1/case-db/ensure": { database: "D:/out/rapidtriage-case.db", case_id: "run-r1" },
      "POST /api/case-db/review-batch": { updated_count: 1 },
    });
    expect(await runCommand("review.priority.3")).toEqual({ ok: true });
    expect(calls.find((c) => c.url === "/api/case-db/review-batch")?.body).toMatchObject({
      add_tags: ["우선순위 3"],
    });
  });
});

function gridHost(
  rows: ReturnType<typeof makeRow>[],
  partial: Partial<GridCommandHost> = {},
): GridCommandHost {
  return {
    runId: "r1",
    collection: { id: "files" },
    getFocusedRow: () => rows[0],
    getSelectedRows: () => rows,
    openRow: vi.fn(),
    setFilter: vi.fn(),
    navigate: vi.fn(),
    patchRows: vi.fn(() => () => {}),
    toast: vi.fn(),
    refetch: vi.fn(),
    showExtract: vi.fn(),
    openTagPrompt: vi.fn(),
    runIsActive: false,
    ...partial,
  };
}

describe("같은 해시 행에 태그 전파", () => {
  it("sends the rows' tag ids with propagate_by_hash and reports the applied count", async () => {
    const { calls } = mockFetch(
      caseRoutes([...SYSTEM, tag({ id: 40, name: "같은 사진", count: 1 })], {
        "POST /api/case-db/review-batch": {
          applied_count: 23,
          changed_count: 22,
          created_count: 22,
          propagation: {
            hash_values: 1,
            matched_file_rows: 23,
            added_rows: 22,
            hashless_targets: 0,
            cap: 10000,
          },
        },
      }),
    );
    const row = makeRow(makeRef("files", "/candidates/4"), { title: "a.jpg", tags: ["같은 사진"] });
    const host = gridHost([row]);
    expect(propagateReason(host)).toBeUndefined();
    const text = await propagateTagsByHash(host);
    expect(text).toBe("같은 해시 행 23건에 태그 '같은 사진'을(를) 전파했습니다");
    const batch = calls.find((c) => c.url === "/api/case-db/review-batch");
    expect(batch?.body).toMatchObject({
      case_id: "run-r1",
      run_id: "r1",
      tag_ids: [40],
      propagate_by_hash: true,
      targets: [{ collection: "files", locator: "/candidates/4" }],
    });
    expect(propagateReason(gridHost([{ ...row, tags: [] }]))).toBe(NO_TAGS_TO_PROPAGATE);
  });

  it("surfaces the server's Korean refusal above the cap", async () => {
    mockFetch(
      caseRoutes([...SYSTEM, tag({ id: 40, name: "같은 사진" })], {
        "POST /api/case-db/review-batch": new Response(
          JSON.stringify({
            detail:
              "같은 해시 행이 12,000건으로 전파 상한 10,000건을 넘어 적용하지 않았습니다. 선택을 줄이세요.",
          }),
          { status: 422, headers: { "content-type": "application/json" } },
        ),
      }),
    );
    const row = makeRow(makeRef("files", "/candidates/4"), { title: "a.jpg", tags: ["같은 사진"] });
    await expect(propagateTagsByHash(gridHost([row]))).rejects.toThrow("전파 상한 10,000건");
  });
});

describe("classic split and media blur", () => {
  beforeEach(() => registerCommands(reviewToolCommands()));

  it("` toggles the classic split on 탐색·검토, persists it and says why elsewhere", async () => {
    useAppStore.getState().navigate({ runId: "r1", collection: "intake" });
    expect(await runCommand(CLASSIC_SPLIT_COMMAND)).toEqual({ ok: false, reason: CLASSIC_STAGE_REASON });
    useAppStore.getState().navigate({ runId: "r1", collection: "files" });
    const event = new KeyboardEvent("keydown", {
      key: "`",
      code: "Backquote",
      bubbles: true,
      cancelable: true,
    });
    Object.defineProperty(event, "target", { value: document.body });
    expect(dispatchShortcut(event)).toBe(true);
    await waitFor(() => expect(useViewPrefs.getState().classicSplit).toBe(true));
    expect(window.localStorage.getItem(CLASSIC_SPLIT_KEY)).toBe("1");
    // A reload reads it back.
    useViewPrefs.setState({ classicSplit: false });
    reloadViewPrefs();
    expect(useViewPrefs.getState().classicSplit).toBe(true);
    expect(announceMock).toHaveBeenCalledWith("클래식 분할 보기를 켰습니다. 격자 위, 세부 정보 아래");
  });

  it("Shift+B toggles media blur; storage failures never throw", async () => {
    const event = new KeyboardEvent("keydown", {
      key: "B",
      code: "KeyB",
      shiftKey: true,
      bubbles: true,
      cancelable: true,
    });
    Object.defineProperty(event, "target", { value: document.body });
    expect(dispatchShortcut(event)).toBe(true);
    await waitFor(() => expect(useViewPrefs.getState().mediaBlur).toBe(true));
    expect(window.localStorage.getItem(MEDIA_BLUR_KEY)).toBe("1");
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("QuotaExceeded");
    });
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(await runCommand(MEDIA_BLUR_COMMAND)).toEqual({ ok: true });
    expect(useViewPrefs.getState().mediaBlur).toBe(false);
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(() => reloadViewPrefs()).not.toThrow();
  });
});

describe("classic split layout", () => {
  it("renders the grid above and the viewer below while on, and the side viewer when off", () => {
    if (!("ResizeObserver" in window)) {
      class RO {
        observe() {}
        unobserve() {}
        disconnect() {}
      }
      Object.assign(window, { ResizeObserver: RO });
      Object.assign(globalThis, { ResizeObserver: RO });
    }
    useAppStore.getState().navigate({ runId: "r1", collection: "files" });
    useViewPrefs.getState().setClassicSplit(true);
    const view = render(<Layout />);
    expect(screen.getByTestId("workbench-shell").getAttribute("data-split")).toBe("classic");
    const viewer = screen.getByTestId("viewer-region");
    expect(viewer.getAttribute("aria-label")).toBe("뷰어 패널 (아래)");
    // Grid first, viewer second in the vertical group (DOM order = reading order).
    const grid = screen.getByTestId("grid-region");
    expect(grid.compareDocumentPosition(viewer) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    act(() => useViewPrefs.getState().setClassicSplit(false));
    expect(screen.getByTestId("workbench-shell").getAttribute("data-split")).toBeNull();
    expect(screen.getByTestId("viewer-region").getAttribute("aria-label")).toBe("뷰어 패널");
    // On 접수 (no viewer column) the preference does not apply.
    act(() => {
      useViewPrefs.getState().setClassicSplit(true);
      useAppStore.getState().navigate({ runId: "r1", collection: "intake" });
    });
    expect(screen.getByTestId("workbench-shell").getAttribute("data-split")).toBeNull();
    view.unmount();
  });
});

describe("baseline compare bars", () => {
  it("draw two bars per category with signed deltas, sorted by count then Korean label", () => {
    render(
      <CompareBars
        baselineName="처리 직후"
        bars={[
          { key: "kind:b", label: "나 종류", group: "artifact", count: 5, baseline_count: 8, delta: -3 },
          { key: "kind:a", label: "가 종류", group: "artifact", count: 5, baseline_count: 2, delta: 3 },
          {
            key: "collection:files",
            label: "파일",
            group: "collection",
            count: 40,
            baseline_count: 40,
            delta: 0,
          },
        ]}
      />,
    );
    const rows = screen.getAllByTestId("hist-compare-row");
    expect(rows.map((row) => row.getAttribute("aria-label"))).toEqual([
      "파일: 현재 40건, 기준선 40건, 증감 0",
      "나 종류: 현재 5건, 기준선 8건, 증감 −3",
      "가 종류: 현재 5건, 기준선 2건, 증감 +3",
    ]);
    expect(screen.getByText(/기준선 '처리 직후' 50건/)).toBeTruthy();
    expect(deltaText(-1200)).toBe("−1,200");
  });
});

describe("selection CSV", () => {
  it("BOM, leading 태그/메모, visible columns, then the seven trailing columns filled or 없음", () => {
    const columns: ColumnSpec[] = [
      { id: "title", header: "이름", width: 100, presets: ["analysis"], value: (r) => r.title },
      { id: "status", header: "태그", width: 60, presets: ["analysis"], value: () => "dup" },
    ];
    const parsed = makeRow(
      makeRef("artifacts", "/artifacts/3", "eventlog"),
      {
        title: '=cmd|"/c calc"!A1',
        sourcePath: "C:/Windows/System32/winevt/Security.evtx",
        tags: ["관심", "DLP"],
      },
      {
        note: "검토 메모, 두 줄\n둘째",
        details: { parser: "evtx", parser_version: "2.1" },
        sourceOffset: 4096,
        recoverySourceId: "carving",
      },
    );
    const bare = makeRow(makeRef("files", "/candidates/0"), { title: "-12", sourcePath: null });
    const csv = buildSelectionCsv([parsed, bare], columns, {
      case_id: "c",
      case_number: null,
      evidence_number: "RUN-EVID-000001",
      evidence_name: null,
    });
    expect(csv.startsWith(CSV_BOM)).toBe(true);
    const lines = csv.slice(1).split("\r\n");
    expect(lines[0]).toBe(["태그", "메모", "이름", ...TRAILING_HEADERS].join(","));
    expect(TRAILING_HEADERS).toEqual([
      "소스",
      "위치",
      "복구 방법",
      "증거 번호",
      "사건 번호",
      "항목 ID",
      "파서 버전",
    ]);
    expect(lines[1]).toBe(
      [
        "관심; DLP",
        '"검토 메모, 두 줄\n둘째"',
        `"'=cmd|""/c calc""!A1"`,
        "C:/Windows/System32/winevt/Security.evtx",
        "오프셋 4096 (0x1000)",
        "카빙",
        "RUN-EVID-000001",
        NONE,
        "artifacts:eventlog:/artifacts/3",
        "evtx v2.1",
      ].join(","),
    );
    // A number-like "-12" stays as is; empty trailing cells read 없음.
    expect(lines[2]).toBe(
      ["", "", "-12", NONE, NONE, NONE, "RUN-EVID-000001", NONE, "files:/candidates/0", NONE].join(","),
    );
    expect(csvCell("@SUM(1)")).toBe("'@SUM(1)");
    expect(csvCell("-cmd")).toBe("'-cmd");
  });
});

describe("act wrapper sanity", () => {
  it("store updates outside React do not warn", () => {
    act(() => useViewPrefs.getState().setMediaBlur(true));
    expect(useViewPrefs.getState().mediaBlur).toBe(true);
  });
});
