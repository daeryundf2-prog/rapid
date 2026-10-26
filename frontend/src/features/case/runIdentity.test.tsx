// R7 L1: one run identity on every screen — the representative start time (C-G3), the duration
// (C-G2), one time format (C-G4), "런" not "케이스" (C-G5 / C-L1 / C-L6), the quick mode label (P4),
// the evidence-zone option (P6), evidence-anchored date presets (C-D5) and the width-fitted,
// zone-labelled timeline histogram (C-V2).

import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type RunListItem,
  runCompletedAt,
  runDurationMs,
  runStartedAt,
  runTimeIsImport,
} from "../../api/runs";
import type { RunWithProgress } from "../../api/runsProgress";
import { RUN_MODE_LABEL } from "../../app/collections";
import { CasePickerCombobox } from "../../shell/CasePickerCombobox";
import { casePickerOptions } from "../../shell/casePicker";
import { runCountText, StatusBar, timezoneOptions } from "../../shell/StatusBar";
import { resetAppStore, useAppStore } from "../../state/store";
import { evidenceZoneOption, formatRunTime } from "../../utils/time";
import { formatTime } from "../dashboard/model";
import {
  activeRelativePreset,
  presetAnchor,
  relativePresetLabel,
  relativePresetRange,
} from "../filters/conditionValues";
import { timeWindow } from "../filters/rowConditions";
import { runNameParts } from "../stages/ProcessStage";
import {
  barSizeLabel,
  fitBuckets,
  maxBarsFor,
  type TimelineHistogramPayload,
  zonedBucketLabel,
} from "../views/histogram";
import { CasePicker } from "./CasePicker";
import { Landing } from "./Landing";
import { runChipText, runDurationText, runStartText } from "./runTime";
import { mockFetch, renderWithQuery } from "./testUtils";

const TZ = "Asia/Seoul";

/** af54-like: a run started here whose progress file is ~3 s after the job record. */
const WEB_RUN = {
  run_id: "af54ff24ed5f",
  status: "completed",
  origin: "web",
  created_at: "2026-10-17T11:18:42.781973+00:00",
  started_at: "2026-10-17T11:18:43.431790+00:00",
  completed_at: "2026-10-17T11:52:54.449812+00:00",
  updated_at: "2026-10-17T11:52:54.449812+00:00",
  request: { root: "D:\\rapid-qa\\bsh-subset", mode: "fraud" },
  run_times: {
    started_at: "2026-10-17T11:18:45.840606+00:00",
    completed_at: "2026-10-17T11:52:54.444485+00:00",
    source: "run-progress",
    imported_at: null,
  },
} satisfies RunListItem;

/** b5fa-like: imported two days after it ran; the progress file has the processing times. */
const IMPORTED_RUN = {
  run_id: "b5fabbe09f18",
  status: "completed",
  origin: "imported",
  created_at: "2026-10-16T23:52:52.682276+00:00",
  updated_at: "2026-10-18T07:25:05+00:00",
  request: { root: "D:\\rapid-qa\\bsh-subset", mode: "hacking" },
  run_times: {
    started_at: "2026-10-15T11:54:28.859703+00:00",
    completed_at: "2026-10-15T12:36:35.535364+00:00",
    source: "run-progress",
    imported_at: "2026-10-16T23:52:52.682276+00:00",
  },
} satisfies RunListItem;

/** An imported run without a progress file. */
const BARE_IMPORT = {
  run_id: "682636ce5605",
  status: "completed",
  origin: "imported",
  created_at: "2026-10-10T06:30:26Z",
  updated_at: "2026-10-11T03:01:20Z",
  request: { root: "C:\\rapid-qa\\bsh-subset", mode: "quick" },
  run_times: { started_at: null, completed_at: null, source: "none", imported_at: "2026-10-10T06:30:26Z" },
} satisfies RunListItem;

beforeEach(() => {
  resetAppStore();
  useAppStore.getState().setTimezone(TZ);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  useAppStore.getState().setTimezone(null);
});

describe("run identity helpers (C-G2 · C-G3)", () => {
  it("the representative start is the run's own processing start, never the import time", () => {
    expect(runStartedAt(WEB_RUN)).toBe(WEB_RUN.run_times.started_at);
    expect(runStartedAt(IMPORTED_RUN)).toBe(IMPORTED_RUN.run_times.started_at);
    expect(runTimeIsImport(IMPORTED_RUN)).toBe(false);
    // Without processing times: the import time, flagged.
    expect(runStartedAt(BARE_IMPORT)).toBe(BARE_IMPORT.created_at);
    expect(runTimeIsImport(BARE_IMPORT)).toBe(true);
    // Older servers (no run_times): the full progress, else the job record.
    expect(
      runStartedAt({ ...WEB_RUN, run_times: undefined, progress: { started_at: "2026-10-17T11:18:45Z" } }),
    ).toBe("2026-10-17T11:18:45Z");
    expect(runStartedAt({ ...WEB_RUN, run_times: undefined })).toBe(WEB_RUN.started_at);
  });

  it("소요 = completed − started; an import without times is — (not import → last update)", () => {
    expect(runDurationMs(IMPORTED_RUN)).toBe(
      Date.parse(IMPORTED_RUN.run_times.completed_at) - Date.parse(IMPORTED_RUN.run_times.started_at),
    );
    expect(runDurationText(IMPORTED_RUN)).toBe("42:06");
    expect(runDurationText(WEB_RUN)).toBe("34:08");
    expect(runDurationMs(BARE_IMPORT)).toBeNull();
    expect(runDurationText(BARE_IMPORT)).toBe("—");
    expect(runCompletedAt(BARE_IMPORT)).toBeNull();
    // A running run counts to now.
    const running = {
      ...WEB_RUN,
      status: "running",
      run_times: { ...WEB_RUN.run_times, completed_at: null },
    };
    expect(runDurationMs(running, Date.parse("2026-10-17T11:28:45.840606Z"))).toBe(600_000);
  });

  it("run chip: 모드 · 시작 시각 · 소요 · id8 (C-L1); quick reads 빠른 선별 (P4)", () => {
    expect(RUN_MODE_LABEL.quick).toBe("빠른 선별");
    expect(runChipText(WEB_RUN, TZ)).toBe("문서·부정 조사 · 2026-10-17 20:18 · 소요 34:08 · af54ff24");
    expect(runChipText(IMPORTED_RUN, TZ)).toBe("침해사고 · 2026-10-15 20:54 · 소요 42:06 · b5fabbe0");
    expect(runChipText(BARE_IMPORT, TZ)).toBe("빠른 선별 · 가져옴 2026-10-10 15:30 · 682636ce");
  });
});

describe("one timestamp string per run on 랜딩 · 처리 · 접수 · 선택기 (acceptance)", () => {
  it("prints the same start string on every screen", async () => {
    // Runs land in the store as the list poll sets them.
    act(() => useAppStore.getState().setRuns([WEB_RUN, IMPORTED_RUN] as unknown as RunWithProgress[]));
    const expected = { [WEB_RUN.run_id]: "2026-10-17 20:18", [IMPORTED_RUN.run_id]: "2026-10-15 20:54" };
    // 접수: the dashboard strip formats the full progress `started_at` of the run detail.
    expect(formatTime(WEB_RUN.run_times.started_at)).toBe(expected[WEB_RUN.run_id]);
    expect(formatTime(IMPORTED_RUN.run_times.started_at)).toBe(expected[IMPORTED_RUN.run_id]);
    // 처리 run list.
    const names = runNameParts([WEB_RUN, IMPORTED_RUN], TZ);
    expect(names.get(WEB_RUN.run_id)?.detail).toContain(expected[WEB_RUN.run_id]);
    expect(names.get(IMPORTED_RUN.run_id)?.detail).toContain(expected[IMPORTED_RUN.run_id]);
    // Top-bar picker.
    const options = casePickerOptions([WEB_RUN, IMPORTED_RUN], "", TZ);
    expect(options.map((o) => o.date)).toEqual([expected[WEB_RUN.run_id], expected[IMPORTED_RUN.run_id]]);
    // 처리 page "시작".
    expect(runStartText(WEB_RUN, TZ)).toBe(expected[WEB_RUN.run_id]);
    // 랜딩 "최근 런".
    mockFetch({ "GET /api/cases": { cases: [] } });
    renderWithQuery(<Landing />);
    expect(screen.getByRole("heading", { name: "최근 런" })).toBeTruthy();
    const links = screen.getAllByRole("link");
    expect(links[0]?.textContent).toContain(expected[WEB_RUN.run_id]);
    expect(links[1]?.textContent).toContain(expected[IMPORTED_RUN.run_id]);
    expect(links[1]?.getAttribute("title")).toContain("가져옴 2026-10-17 08:52 (처리 시각 아님)");
  });

  it("접수 card times never use the browser's toLocaleString (C-G4)", () => {
    expect(formatTime("2026-10-17T11:18:45Z", "utc")).toBe("2026-10-17 11:18");
    expect(formatTime("2026-10-17T11:18:45Z")).toBe("2026-10-17 20:18");
    expect(formatTime(null)).toBe("—");
    expect(formatTime("not a time")).toBe("not a time");
    expect(formatRunTime("2026-10-17T11:18:45Z", TZ)).toBe("2026-10-17 20:18");
  });
});

describe("런 / 케이스 wording (C-G5 · C-L1)", () => {
  it("status bar counts runs and cases apart", () => {
    expect(runCountText(40, 1)).toBe("런 40건 · 케이스 1건");
    expect(runCountText(40)).toBe("런 40건");
  });

  it("the status bar without an open run says 런 N건 · 케이스 M건", async () => {
    mockFetch({ "GET /api/cases": { cases: [{ case_id: "c1", case_number: "2026-1", evidence: [] }] } });
    act(() =>
      useAppStore.getState().setRuns([WEB_RUN, IMPORTED_RUN, BARE_IMPORT] as unknown as RunWithProgress[]),
    );
    renderWithQuery(<StatusBar />);
    expect(await screen.findByText("런 3건 · 케이스 1건")).toBeTruthy();
  });

  it("the top-bar picker is labelled 런: and lists run chips", () => {
    act(() => useAppStore.getState().setRuns([WEB_RUN, BARE_IMPORT] as unknown as RunWithProgress[]));
    act(() => useAppStore.getState().navigate({ runId: WEB_RUN.run_id, collection: "intake" }));
    render(<CasePickerCombobox />);
    const trigger = screen.getByTestId("case-picker");
    expect(trigger.getAttribute("aria-label")).toBe("런: bsh-subset · 문서·부정 조사");
    fireEvent.click(trigger);
    const list = screen.getByRole("listbox", { name: "런" });
    expect(within(list).getAllByRole("option")[0]?.textContent).toContain(
      "문서·부정 조사 · 2026-10-17 20:18 · 소요 34:08 · af54ff24",
    );
  });

  it("케이스 열기: the dialog title, run chips and delete in a ⋯ menu", async () => {
    mockFetch({
      "GET /api/runs": { runs: [WEB_RUN, BARE_IMPORT] },
      "GET /api/cases": { cases: [] },
    });
    const openDelete = vi.fn();
    const { useCaseDialogs } = await import("./dialogs");
    useCaseDialogs.setState({ confirmDelete: openDelete } as never);
    renderWithQuery(<CasePicker currentRunId={null} onClose={vi.fn()} />);
    expect(screen.getByRole("dialog", { name: "케이스 열기" })).toBeTruthy();
    const row = await screen.findByRole("button", {
      name: /^bsh-subset · 완료 · 문서·부정 조사 · 2026-10-17 20:18/,
    });
    expect(row.textContent).toContain("소요 34:08 · af54ff24");
    expect(screen.queryByRole("button", { name: /삭제$/ })).toBeNull();
    fireEvent.click(screen.getAllByRole("button", { name: /런 메뉴$/ })[0] as HTMLElement);
    fireEvent.click(screen.getByRole("menuitem", { name: /런 삭제/ }));
    expect(openDelete).toHaveBeenCalledWith(WEB_RUN.run_id);
  });
});

describe("evidence-system zone option (P6)", () => {
  it("maps the Windows zone to IANA and labels it with the bias", () => {
    expect(evidenceZoneOption({ name: "Korea Standard Time", bias_minutes: -540 })).toEqual({
      value: "Asia/Seoul",
      label: "증거 시스템(KST −540)",
    });
    // Unknown name: a fixed offset from the bias (Etc/GMT signs are inverted).
    expect(evidenceZoneOption({ name: "Nowhere Standard Time", bias_minutes: -180 })?.value).toBe(
      "Etc/GMT-3",
    );
    expect(evidenceZoneOption({ name: null, bias_minutes: 300 })?.value).toBe("Etc/GMT+5");
    expect(evidenceZoneOption(null)).toBeNull();
    expect(evidenceZoneOption({ name: "Nowhere", bias_minutes: -330 })).toBeNull();
  });

  it("the status bar select gains the evidence option first, without a duplicate value", () => {
    const options = timezoneOptions({ name: "Korea Standard Time", bias_minutes: -540 }, "utc");
    expect(options[0]).toEqual(["Asia/Seoul", "증거 시스템(KST −540)"]);
    expect(options.filter(([value]) => value === "Asia/Seoul")).toHaveLength(1);
    expect(timezoneOptions(null, "utc").some(([, label]) => label.startsWith("증거 시스템"))).toBe(false);
  });
});

describe("relative date presets anchored on the evidence (C-D5)", () => {
  const EVIDENCE_MAX = "2025-05-30T04:11:48.546071+00:00";
  /** Row times of 2025 evidence (the last week of May 2025) opened in 2026. */
  const ROWS = [
    "2025-05-24T01:00:00Z",
    "2025-05-29T23:25:26Z",
    "2025-05-30T04:11:48Z",
    "2024-12-01T00:00:00Z",
  ];

  it("counts back from timeline_max_ts and says so; rows of 2025 evidence match", () => {
    const anchor = presetAnchor(EVIDENCE_MAX, "2026-10-17T11:18:45Z", Date.parse("2026-10-26T00:00:00Z"));
    expect(anchor.source).toBe("evidence");
    expect(relativePresetLabel("7d", anchor)).toBe("증거 기준 최근 7일");
    expect(relativePresetLabel("today", anchor)).toBe("증거 기준 마지막 날");
    const range = relativePresetRange("7d", anchor);
    const window = timeWindow(range.from, range.to);
    const hits = ROWS.filter((row) => {
      const ms = Date.parse(row);
      return ms >= (window.from ?? 0) && ms < (window.until ?? Number.POSITIVE_INFINITY);
    });
    expect(hits.length).toBe(3);
    expect(activeRelativePreset(range, anchor)).toBe("7d");
    // The wall clock (the old behaviour) finds nothing in that evidence.
    const clock = presetAnchor(null, null, Date.parse("2026-10-26T00:00:00Z"));
    const old = timeWindow(relativePresetRange("7d", clock).from, relativePresetRange("7d", clock).to);
    expect(ROWS.filter((row) => Date.parse(row) >= (old.from ?? 0))).toHaveLength(0);
    expect(relativePresetLabel("7d", clock)).toBe("최근 7일");
  });

  it("falls back to the run start when the evidence time is unknown", () => {
    const anchor = presetAnchor(null, "2026-10-15T11:54:28Z");
    expect(anchor).toEqual({ ms: Date.parse("2026-10-15T11:54:28Z"), source: "run-start" });
    expect(relativePresetLabel("30d", anchor)).toBe("런 시작 기준 최근 30일");
  });
});

describe("timeline histogram fitted to the width, in the display zone (C-V2)", () => {
  /** 482 hourly server buckets (~20 days) — 482 bars in 460 px before. */
  function hourly(count: number, start = Date.parse("2025-05-10T00:00:00Z")): TimelineHistogramPayload {
    const buckets = Array.from({ length: count }, (_, index) => ({
      index,
      start: new Date(start + index * 3_600_000).toISOString(),
      end: new Date(start + (index + 1) * 3_600_000).toISOString(),
      count: 1 + (index % 5),
    }));
    return {
      total_events: 0,
      parsed_events: 0,
      unparsed_events: 0,
      bucket_seconds: 3600,
      bucket_count: count,
      range_start: buckets[0]?.start ?? null,
      range_end: buckets.at(-1)?.end ?? null,
      sources: [],
      buckets,
    };
  }

  it("bar count ≤ width / 4 px", () => {
    expect(maxBarsFor(460)).toBe(115);
    expect(maxBarsFor(0)).toBe(240);
    const fitted = fitBuckets(hourly(482), { maxBars: maxBarsFor(460), offsetMinutes: 540 });
    expect(fitted.buckets.length).toBeLessThanOrEqual(115);
    expect(fitted.sizeMs).toBe(6 * 3_600_000);
    expect(barSizeLabel(fitted.sizeMs)).toBe("막대 6시간");
    // Nothing is lost by merging.
    const total = hourly(482).buckets.reduce((sum, b) => sum + b.count, 0);
    expect(fitted.buckets.reduce((sum, b) => sum + b.count, 0)).toBe(total);
  });

  it("day bars start at the display zone's midnight and are labelled in it", () => {
    const fitted = fitBuckets(hourly(482), { maxBars: 30, offsetMinutes: 540 });
    expect(fitted.sizeMs).toBe(86_400_000);
    const first = fitted.buckets[0];
    expect(new Date(first?.startMs ?? 0).toISOString()).toBe("2025-05-09T15:00:00.000Z"); // 00:00 KST
    expect(zonedBucketLabel(first?.startMs ?? 0, fitted.sizeMs, 540)).toBe("2025-05-10");
    expect(zonedBucketLabel(Date.parse("2025-05-10T05:00:00Z"), 3_600_000, 540)).toBe("05-10 14시");
  });

  it("the range condition limits the bars", () => {
    const payload = hourly(482);
    const from = Date.parse("2025-05-12T00:00:00Z");
    const until = Date.parse("2025-05-13T00:00:00Z");
    const fitted = fitBuckets(payload, { maxBars: 240, offsetMinutes: 0, fromMs: from, untilMs: until });
    expect(fitted.clipped).toBe(true);
    expect(fitted.buckets).toHaveLength(24);
    expect(fitted.buckets[0]?.startMs).toBe(from);
  });
});
