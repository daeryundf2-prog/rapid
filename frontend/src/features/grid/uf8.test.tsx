import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import {
  RECENT_RANGES_KEY,
  recentRanges,
  rememberRange,
  removeSavedCondition,
  SAVED_CONDITIONS_KEY,
  saveCondition,
  savedConditions,
} from "../filters/conditionMemory";
import { FilterBar } from "../filters/FilterBar";
import { EMPTY_FILTERS } from "../filters/filterModel";
import { useFilterStore } from "../filters/filterStore";
import { koreanLabel, normalizeCatalog } from "../flags/catalog";
import {
  flagsPartialNotice,
  flagsSectionNode,
  flagsUnavailableReason,
  treeFlagsSection,
} from "../tree/model";
import { EvidenceTail, TAIL_REASONS } from "../viewer/views/MetaView";
import { artifactColumnsForKind, isMixedGrid } from "./columns/artifacts";
import { rowMark } from "./DataGrid";

// viewer-families U-F8 (AXIOM observations): review stripe, mixed-family summary cells, the
// fixed evidence tail, and the condition line's applied label / save / recent ranges.

function artifactRow(type: string, details: Record<string, unknown>, extra: Partial<GridRow> = {}): GridRow {
  return {
    rowKey: `artifacts:k:/artifacts/1:${type}`,
    ref: { collection: "artifacts", kind: "k", locator: "/artifacts/1" },
    title: "행",
    sourcePath: "C:/e/x",
    timestamp: null,
    artifactType: type,
    tags: [],
    reviewStatus: null,
    fields: { details },
    ...extra,
  } as unknown as GridRow;
}

beforeEach(() => {
  window.localStorage.removeItem(RECENT_RANGES_KEY);
  window.localStorage.removeItem(SAVED_CONDITIONS_KEY);
  window.location.hash = "#/case/r1/explore/artifacts";
  useAppStore.setState({ route: parseHash(window.location.hash) });
  useFilterStore.setState({ filters: EMPTY_FILTERS, report: null });
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("review stripe (Q-F14)", () => {
  it("one stripe per mark: review status first, else a 북마크 tag; none when unmarked", () => {
    expect(rowMark(artifactRow("x", {}, { reviewStatus: "relevant" }))).toEqual({
      id: "relevant",
      label: "관련 있음",
    });
    expect(rowMark(artifactRow("x", {}, { reviewStatus: "excluded" }))?.id).toBe("excluded");
    expect(rowMark(artifactRow("x", {}, { tags: ["북마크"] }))).toEqual({ id: "bookmark", label: "북마크" });
    expect(rowMark(artifactRow("x", {}, { tags: ["악성"] }))).toBeNull();
  });
});

describe("mixed-family grid (Q-F13)", () => {
  it("every artifact / types spanning families → summary columns; one family → its catalogue columns", () => {
    expect(isMixedGrid(undefined)).toBe(true);
    expect(isMixedGrid("eventlog")).toBe(false);
    expect(isMixedGrid(undefined, ["eventlog-event"])).toBe(false);
    const ids = artifactColumnsForKind(undefined).map((c) => c.id);
    expect(ids).toEqual(expect.arrayContaining(["sum:main", "sum:support", "sum:extra", "sum:time"]));
    expect(artifactColumnsForKind(undefined, ["eventlog-event"]).map((c) => c.id)).not.toContain("sum:main");
  });

  it("cells carry their own label above the value, from the row's family", () => {
    const columns = artifactColumnsForKind(undefined);
    const main = columns.find((c) => c.id === "sum:main");
    const time = columns.find((c) => c.id === "sum:time");
    const event = artifactRow("eventlog-event", {
      channel: "Security",
      event_id: 4624,
      event_created_at: "2026-03-01T12:00:00Z",
    });
    render(<div>{main?.render?.(event)}</div>);
    const cell = document.querySelector(".sum-cell") as HTMLElement;
    expect(cell.querySelector(".sum-label")?.textContent).toBe("채널");
    expect(cell.querySelector(".sum-value")?.textContent).toBe("Security");
    expect(main?.format?.(event)).toBe("채널: Security");
    expect(time?.format?.(event)).toMatch(/^기록 시각: 2026-03-01/);
    // A row of no known family: an empty main cell, the row time under "시각".
    const other = artifactRow("zzz-unknown", {}, { timestamp: "2026-03-01T12:00:00Z" } as Partial<GridRow>);
    expect(main?.format?.(other)).toBe("");
    expect(time?.format?.(other)).toMatch(/^시각: /);
  });
});

describe("evidence tail (Q-F15)", () => {
  it("seven facts, each a value or 없음 with its reason", () => {
    const row = artifactRow("eventlog-event", { parser: "windows-eventlog", parser_version: "2.1" });
    render(
      <EvidenceTail
        target={{ runId: "r1", ref: row.ref, sourcePath: "C:/e/Security.evtx" }}
        row={row}
        onOpenHex={() => {}}
      />,
    );
    const block = screen.getByTestId("evidence-info");
    const terms = within(block)
      .getAllByRole("term")
      .map((t) => t.textContent);
    expect(terms).toEqual(["소스", "복구 방법", "삭제된 출처", "위치", "증거 번호", "파서 버전", "원본 행"]);
    const text = block.textContent ?? "";
    expect(text).toContain(TAIL_REASONS.recovery);
    expect(text).toContain(TAIL_REASONS.deletion);
    expect(text).toContain(TAIL_REASONS.offset);
    expect(text).toContain(TAIL_REASONS.partition);
    expect(text).toContain("windows-eventlog v2.1");
    expect(text).toContain(TAIL_REASONS.origin);
    for (const dd of within(block).getAllByRole("definition")) expect(dd.textContent?.trim()).not.toBe("—");
  });

  it("a timeline row links to its source artifact row", () => {
    const row = {
      ...artifactRow("timeline", {}),
      ref: { collection: "timeline", locator: "/events/3" },
      fields: { sourceRecord: { output: "rapidtriage-artifacts-browser.json", row_index: 7 } },
    } as unknown as GridRow;
    render(
      <EvidenceTail
        target={{ runId: "r1", ref: row.ref, sourcePath: null }}
        row={row}
        onOpenHex={() => {}}
      />,
    );
    const link = screen.getByRole("link", { name: "원본 아티팩트 행으로 이동" }) as HTMLAnchorElement;
    expect(decodeURIComponent(link.getAttribute("href") ?? "")).toContain("artifacts/browser");
    expect(screen.getByTestId("evidence-info").textContent).toContain(TAIL_REASONS.source);
  });
});

describe("condition line (U-F8)", () => {
  const bar = () =>
    render(<FilterBar filterRef={{ current: null }} query="" onQuery={() => {}} onReturnToGrid={() => {}} />);

  it("an applied condition becomes the bold button label; 조건 저장 keeps it for the panel", () => {
    bar();
    const trigger = screen.getByTestId("filter-popover-button");
    expect(trigger.textContent).toBe("조건");
    fireEvent.click(trigger);
    fireEvent.click(screen.getByRole("button", { name: "상태 필터: 재검토" }));
    expect(trigger.querySelector("strong")?.textContent).toBe("상태 재검토");
    expect(trigger.getAttribute("aria-label") ?? trigger.textContent).toMatch(/^조건/);
    fireEvent.click(screen.getByTestId("filter-save"));
    expect(savedConditions().map((s) => s.name)).toEqual(["상태 재검토"]);
    fireEvent.click(screen.getByRole("button", { name: "조건 지우기" }));
    expect(useFilterStore.getState().filters.statuses).toEqual([]);
    if (!screen.queryByRole("dialog", { name: "조건" })) fireEvent.click(trigger);
    const panel = screen.getByRole("dialog", { name: "조건" });
    fireEvent.click(within(panel).getByRole("button", { name: "상태 재검토" }));
    expect(useFilterStore.getState().filters.statuses).toEqual(["needs-review"]);
    fireEvent.click(within(panel).getByRole("button", { name: "상태 재검토 저장한 조건 삭제" }));
    expect(savedConditions()).toEqual([]);
  });

  it("keeps the three most recent time ranges; storage failures are harmless", () => {
    rememberRange({ from: "2026-01-01T00:00" });
    rememberRange({ from: "2026-02-01T00:00", to: "2026-02-02T00:00" });
    rememberRange({ from: "2026-01-01T00:00" });
    rememberRange({ to: "2026-03-01T00:00" });
    rememberRange({ from: "2026-04-01T00:00" });
    expect(recentRanges()).toEqual([
      { from: "2026-04-01T00:00" },
      { to: "2026-03-01T00:00" },
      { from: "2026-01-01T00:00" },
    ]);
    bar();
    fireEvent.click(screen.getByTestId("filter-popover-button"));
    fireEvent.click(screen.getByRole("button", { name: /^최근 시간 범위 적용: 2026-04-01 00:00 ~ …$/ }));
    expect(useFilterStore.getState().filters.from).toBe("2026-04-01T00:00");
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("quota");
    });
    expect(() => rememberRange({ from: "2026-05-01T00:00" })).not.toThrow();
  });
});

describe("adversarial review round 1", () => {
  const bar = (props: Partial<Parameters<typeof FilterBar>[0]> = {}) =>
    render(
      <FilterBar
        filterRef={{ current: null }}
        query=""
        onQuery={() => {}}
        onReturnToGrid={() => {}}
        {...props}
      />,
    );

  it("#2 mixed-grid time cells follow a timezone change (rows keep their identity)", () => {
    const time = artifactColumnsForKind(undefined).find((c) => c.id === "sum:time");
    const event = artifactRow("eventlog-event", { event_created_at: "2026-03-01T12:00:00Z" });
    useAppStore.setState({ timezone: "utc" });
    const utc = time?.format?.(event);
    useAppStore.setState({ timezone: "Asia/Seoul" });
    const seoul = time?.format?.(event);
    expect(utc).toContain("12:00");
    expect(seoul).toContain("21:00");
    useAppStore.setState({ timezone: null });
  });

  it("#4 a malformed saved condition is normalised, never crashes the panel", () => {
    window.localStorage.setItem(
      SAVED_CONDITIONS_KEY,
      JSON.stringify([
        { name: "옛 조건", filters: { types: ["x"], statuses: "bad", tags: null } },
        { nope: 1 },
      ]),
    );
    const [saved] = savedConditions();
    expect(saved?.filters.statuses).toEqual([]);
    expect(saved?.filters.tags).toEqual([]);
    expect(saved?.filters.ext).toEqual([]);
    bar();
    fireEvent.click(screen.getByTestId("filter-popover-button"));
    fireEvent.click(
      within(screen.getByRole("dialog", { name: "조건" })).getByRole("button", { name: "옛 조건" }),
    );
    expect(useFilterStore.getState().filters.types).toEqual(["x"]);
    expect(screen.getByRole("dialog", { name: "조건" })).toBeTruthy();
  });

  it("#5 same name, different conditions: unique names; delete removes one", () => {
    saveCondition("상태 재검토", { ...EMPTY_FILTERS, statuses: ["needs-review"] });
    saveCondition("상태 재검토", { ...EMPTY_FILTERS, statuses: ["needs-review"], tags: ["a"] });
    expect(savedConditions().map((s) => s.name)).toEqual(["상태 재검토 (2)", "상태 재검토"]);
    removeSavedCondition("상태 재검토");
    expect(savedConditions().map((s) => s.name)).toEqual(["상태 재검토 (2)"]);
  });

  it("#6 a half-typed range is not remembered; the range the panel closes with is", () => {
    bar();
    fireEvent.click(screen.getByTestId("filter-popover-button"));
    fireEvent.change(screen.getByLabelText("시작 시각"), { target: { value: "2026-01-0" } });
    fireEvent.change(screen.getByLabelText("시작 시각"), { target: { value: "2026-01-02T03:04" } });
    expect(recentRanges()).toEqual([]);
    fireEvent.keyDown(screen.getByRole("dialog", { name: "조건" }), { key: "Escape" });
    expect(recentRanges()).toEqual([{ from: "2026-01-02T03:04" }]);
  });

  it("#15 열 구성 / 밀도 are display settings: no count or bold label, their own chip list", () => {
    bar({
      display: { preset: "axiom", onPreset: () => {}, density: "compact", onDensity: () => {} },
    });
    const trigger = screen.getByTestId("filter-popover-button");
    expect(trigger.textContent).toBe("조건");
    expect(trigger.querySelector("strong")).toBeNull();
    expect(screen.queryByRole("list", { name: "적용된 조건" })).toBeNull();
    const display = screen.getByRole("list", { name: "표시 설정" });
    expect(within(display).getAllByRole("listitem")).toHaveLength(2);
  });

  it("#12 bare English catalogue labels read in Korean; Korean ones are kept", () => {
    expect(koreanLabel("SRUM")).toBe("시스템 자원 사용(SRUM)");
    expect(koreanLabel("AppID")).toBe("앱 ID");
    expect(koreanLabel("이벤트 로그")).toBe("이벤트 로그");
    const catalog = normalizeCatalog({
      version: "t",
      families: [
        { id: "srum", label: "SRUM", types: ["srum-x"], core_columns: [{ key: "app_id", label: "AppID" }] },
      ],
      rules: [],
    });
    expect(catalog?.families[0]?.label).toBe("시스템 자원 사용(SRUM)");
    expect(catalog?.families[0]?.core_columns[0]?.label).toBe("앱 ID");
  });

  it("#8 each unusable flag-set status has its own Korean reason", () => {
    const tree = (status: string, reason?: string) =>
      ({
        run_id: "r",
        root: {},
        nodes: [],
        flags: { total: 0, source: { status, ...(reason ? { reason } : {}) } },
      }) as never;
    expect(flagsUnavailableReason(tree("too_large"))).toMatch(/너무 커서/);
    expect(flagsUnavailableReason(tree("skipped"))).toMatch(/건너뛰었습니다/);
    expect(flagsUnavailableReason(tree("no_source"))).toMatch(/특이사항 분석을 실행하세요/);
    expect(flagsUnavailableReason(tree("weird", "디스크 오류"))).toBe(
      "특이사항 결과를 쓸 수 없습니다 — 상태: weird (디스크 오류)",
    );
    expect(flagsUnavailableReason({ run_id: "r", root: {}, nodes: [] } as never)).toMatch(/실행하세요/);
    expect(flagsUnavailableReason(tree("joined"))).toBeUndefined();
  });
});

describe("D1 follow-up: partial flag coverage and run-stage ids", () => {
  const partialTree = (source: Record<string, unknown>) =>
    ({
      run_id: "r",
      root: {},
      nodes: [
        {
          id: "artifacts",
          label: "아티팩트",
          collection: "artifacts",
          children: [
            {
              id: "artifacts:eventlog",
              label: "EVTX 이벤트 로그",
              collection: "artifacts",
              kind: "eventlog",
              count: 5,
            },
          ],
        },
      ],
      flags: { total: 3, by_grade: { B: 3 }, by_rule: [], source: { status: "joined", ...source } },
    }) as never;

  it("coverage=partial names the unread sources in Korean, the reason and skipped flags", () => {
    const tree = partialTree({
      coverage: "partial",
      incomplete_sources: ["eventlog", "files:candidates", "analysis:abc"],
      reason: "행 소스를 읽는 중 오류가 났습니다",
      skipped_flags: 2,
      analysis_id: "run-triage-flags-20261017T010203123456Z",
    });
    expect(flagsPartialNotice(tree)).toBe(
      "특이사항 분석이 일부 소스를 읽지 못했습니다 (EVTX 이벤트 로그, 파일 후보, 분석 결과(abc)) — 행 소스를 읽는 중 오류가 났습니다 · 손상된 지표 2개 제외",
    );
    // Still a usable (joined) set: not "unavailable", and the tree section carries the notice.
    expect(flagsUnavailableReason(tree)).toBeUndefined();
    expect(flagsSectionNode(tree).note).toBe(flagsPartialNotice(tree));
    expect(flagsSectionNode(tree).count).toBe(3);
  });

  it("a complete set has no notice; skipped flags alone are still reported", () => {
    expect(flagsPartialNotice(partialTree({ coverage: "complete" }))).toBeUndefined();
    expect(flagsPartialNotice(partialTree({}))).toBeUndefined();
    expect(flagsPartialNotice(partialTree({ skipped_flags: 4 }))).toBe("특이사항 · 손상된 지표 4개 제외");
  });

  it("a timestamped run-stage analysis id (run-triage-flags-<µs>) is an ordinary joined source", () => {
    const tree = partialTree({ source: "run-stage", analysis_id: "run-triage-flags-20261017T010203123456Z" });
    expect(treeFlagsSection(tree)?.total).toBe(3);
    expect(flagsUnavailableReason(tree)).toBeUndefined();
  });
});
