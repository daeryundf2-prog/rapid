// biome-ignore-all lint/a11y: tests drive the condition panel through its DOM roles
/** r4 §2.3 V3 필터: relative dates, 요일·업무 외 시간, 부분 결과, 콘텐츠 유형 — model, URL, server params, panel. */
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { artifactsQueryString } from "../../api/runs";
import type { GridRow } from "../../contracts/collection";
import { parseHash, serializeRoute } from "../../router";
import { resetAppStore, useAppStore } from "../../state/store";
import { useAnalysisStore } from "../analysis/store";
import { collectionQueryKey } from "../grid/useCollectionQuery";
import { ClockSection, IncidentRange, ResultSection } from "./ConditionSections";
import { normalizeFilters, saveCondition, savedConditions } from "./conditionMemory";
import { pathExtension, rowContentTypes } from "./contentTypes";
import {
  activeChips,
  applyFiltersToQuery,
  clientOnlyFilters,
  EMPTY_FILTERS,
  type FilterState,
  filtersEqual,
  filtersFromRoute,
  filtersToRoutePatch,
  partitionFilters,
  presetRange,
  removeChip,
  rowMatchesFilters,
  TIME_PRESET_LABELS,
} from "./filterModel";
import { useFilterStore } from "./filterStore";
import {
  clockLabel,
  clockMatches,
  conditionQueryString,
  incidentFromAnalyses,
  incidentRange,
  localClock,
  parseHours,
  rowIsPartial,
  serverConditionParams,
} from "./rowConditions";

const f = (patch: Partial<FilterState>): FilterState => ({ ...EMPTY_FILTERS, ...patch });

function row(partial: Partial<GridRow> & { rowKey: string }): GridRow {
  return {
    ref: { collection: "artifacts", locator: partial.rowKey },
    title: partial.rowKey,
    sourcePath: null,
    timestamp: null,
    artifactType: null,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: {},
    ...partial,
  };
}

beforeEach(() => {
  resetAppStore();
  try {
    window.localStorage.clear();
  } catch {
    // storage unavailable: nothing to clear
  }
});

afterEach(() => cleanup());

describe("URL round-trip", () => {
  it("serialises and parses wd / hours / offhours / partial / content / geo", () => {
    const hash = serializeRoute({
      runId: "r",
      collection: "artifacts",
      kind: "eventlog",
      weekdays: ["sat", "sun"],
      hours: "18-09",
      offhours: true,
      partial: true,
      content: ["document", "image"],
      geo: "37.48,126.94,37.49,126.95",
    });
    expect(hash).toContain("wd=sat,sun");
    expect(hash).toContain("hours=18-09");
    expect(hash).toContain("offhours=1");
    expect(hash).toContain("partial=1");
    expect(hash).toContain("content=document,image");
    expect(hash).toContain("geo=37.48,126.94,37.49,126.95");
    const route = parseHash(hash);
    expect(route).toMatchObject({
      weekdays: ["sat", "sun"],
      hours: "18-09",
      offhours: true,
      partial: true,
      content: ["document", "image"],
      geo: "37.48,126.94,37.49,126.95",
    });
    expect(serializeRoute(route)).toBe(hash);
    // Junk values are dropped, never half-applied.
    const junk = parseHash("#/case/r/explore/artifacts?wd=funday,mon&hours=evening&offhours=yes&geo=a,b,c,d");
    expect(junk.weekdays).toEqual(["mon"]);
    expect(junk.hours).toBeUndefined();
    expect(junk.offhours).toBeUndefined();
    expect(junk.geo).toBeUndefined();
  });

  it("maps route ↔ filter state and compares the new fields", () => {
    const filters = filtersFromRoute({
      runId: "r",
      collection: "files",
      weekdays: ["mon"],
      hours: "09-18",
      partial: true,
      content: ["archive"],
    });
    expect(filters).toMatchObject({ weekdays: ["mon"], hours: "09-18", partial: true, content: ["archive"] });
    const patch = filtersToRoutePatch(filters);
    expect(patch).toMatchObject({
      weekdays: ["mon"],
      hours: "09-18",
      partial: true,
      content: ["archive"],
      offhours: undefined,
    });
    expect(filtersEqual(filters, { ...filters })).toBe(true);
    expect(filtersEqual(filters, { ...filters, offhours: true })).toBe(false);
    expect(filtersEqual(filters, { ...filters, content: ["image"] })).toBe(false);
  });
});

describe("relative ranges", () => {
  it("offers 최근 1 / 7 / 30일 and incident ± n hours", () => {
    expect(TIME_PRESET_LABELS["1d"]).toBe("최근 1일");
    const now = new Date(2026, 9, 18, 12, 0);
    const day = presetRange("1d", now);
    expect(Date.parse(day.to) - Date.parse(day.from)).toBe(86_400_000);
    expect(incidentRange("2025-05-30T12:00", 6)).toEqual({
      from: "2025-05-30T06:00",
      to: "2025-05-30T18:00",
    });
    expect(incidentRange("2025-05-30T12:00", 1, "2025-05-30T14:00")).toEqual({
      from: "2025-05-30T11:00",
      to: "2025-05-30T15:00",
    });
    expect(incidentRange("not a time", 1)).toBeNull();
    const incident = incidentFromAnalyses([
      {
        kind: "triage-flags",
        status: "completed",
        created_at: "2026-01-01",
        options: { incident_start: null },
      },
      {
        kind: "triage-flags",
        status: "completed",
        created_at: "2026-01-02",
        options: { incident_start: "2025-05-30T03:00:00Z", incident_end: "2025-05-30T05:00:00Z" },
      },
      {
        kind: "triage-flags",
        status: "running",
        created_at: "2026-01-03",
        options: { incident_start: "2020-01-01T00:00:00Z" },
      },
    ]);
    expect(incident?.start.toISOString()).toBe("2025-05-30T03:00:00.000Z");
    expect(incident?.end).toBe("2025-05-30T05:00:00Z");
    expect(incidentFromAnalyses([])).toBeNull();
  });
});

describe("clock conditions", () => {
  // 2025-05-26 is a Monday. 10:30Z = 19:30 KST.
  const at = new Date("2025-05-26T10:30:00Z");

  it("evaluates weekday / hours / 업무 외 시간 in the display timezone", () => {
    expect(localClock(at, "Asia/Seoul")).toEqual({ weekday: "mon", hour: 19 });
    expect(localClock(at, "utc")).toEqual({ weekday: "mon", hour: 10 });
    expect(clockMatches(at, { offhours: true }, "Asia/Seoul")).toBe(true);
    expect(clockMatches(at, { offhours: true }, "utc")).toBe(false);
    expect(clockMatches(at, { hours: "18-09" }, "Asia/Seoul")).toBe(true);
    expect(clockMatches(at, { weekdays: ["sat"] }, "Asia/Seoul")).toBe(false);
    expect(clockMatches(new Date("2025-05-31T02:00:00Z"), { offhours: true }, "Asia/Seoul")).toBe(true);
    expect(parseHours("9-9")).toBeNull();
    expect(parseHours("24-6")).toEqual([0, 6]);
    expect(clockLabel({ offhours: true })).toBe("업무 외 시간 18–09시·토·일");
    expect(clockLabel({ weekdays: ["mon", "tue"], hours: "09-18" })).toBe("요일 월·화 · 시간 09–18시");
  });
});

describe("partition and server params", () => {
  const conditions = f({
    from: "2025-05-26T00:00",
    weekdays: ["sat"],
    offhours: true,
    partial: true,
    content: ["document"],
    geo: "37.48,126.94,37.49,126.95",
  });

  it("artifacts · files · timeline get them on the server; other listings on loaded rows", () => {
    const artifacts = partitionFilters({ id: "artifacts", kind: "eventlog" }, conditions, [], "Asia/Seoul");
    expect(artifacts.serverLabels).toEqual(["시간 범위", "업무 외 시간", "부분 결과", "콘텐츠 유형", "위치"]);
    expect(artifacts.clientLabels).toEqual([]);
    expect(artifacts.server.conditions).toEqual({
      from: new Date(Date.parse("2025-05-26T00:00")).toISOString(),
      tz: "Asia/Seoul",
      weekday: ["sat"],
      offhours: "1",
      partial: "1",
      content: ["document"],
      geo: "37.48,126.94,37.49,126.95",
    });
    const files = partitionFilters({ id: "files" }, conditions, [], "utc");
    expect(files.server.conditions?.geo).toBeUndefined();
    expect(files.server.conditions?.tz).toBe("UTC");
    expect(files.clientLabels).toEqual(["위치"]);
    expect(clientOnlyFilters(conditions, files)).toMatchObject({
      from: undefined,
      offhours: undefined,
      partial: undefined,
      content: undefined,
      geo: conditions.geo,
    });
    const docs = partitionFilters({ id: "docs" }, conditions);
    expect(docs.server.conditions).toBeUndefined();
    expect(docs.clientLabels).toContain("업무 외 시간");
    const query = applyFiltersToQuery(
      { ref: { id: "timeline" }, offset: 0, limit: 250 },
      conditions,
      [],
      "utc",
    );
    expect(query.rowConditions?.partial).toBe("1");
    // A view's own condition (지도 world box) survives, the bar wins on a clash.
    const map = applyFiltersToQuery(
      { ref: { id: "artifacts" }, offset: 0, limit: 250, rowConditions: { geo: "-90,-180,90,180" } },
      f({ partial: true }),
    );
    expect(map.rowConditions).toEqual({ geo: "-90,-180,90,180", partial: "1" });
    expect(serverConditionParams(f({ hours: "18-09" }), "local", { time: true, geo: false }).tz).toBeTruthy();
  });

  it("puts the params on the wire and in the cache key", () => {
    const params = serverConditionParams(conditions, "Asia/Seoul", { time: true, geo: true });
    const text = artifactsQueryString({ kind: ["eventlog"], limit: 10, conditions: params });
    const search = new URLSearchParams(text);
    expect(search.getAll("weekday")).toEqual(["sat"]);
    expect(search.get("offhours")).toBe("1");
    expect(search.get("tz")).toBe("Asia/Seoul");
    expect(search.getAll("content")).toEqual(["document"]);
    expect(conditionQueryString({ content: ["a", "b"], partial: "1" })).toBe(
      "&content=a&content=b&partial=1",
    );
    const key = (rowConditions?: Record<string, string | string[]>) =>
      JSON.stringify(
        collectionQueryKey("r", { ref: { id: "files" }, offset: 0, limit: 250, rowConditions }, 250),
      );
    expect(key({ partial: "1" })).not.toBe(key(undefined));
  });
});

describe("client predicates", () => {
  it("content types follow files categories and artifact types / target extensions", () => {
    const file = row({
      rowKey: "f",
      ref: { collection: "files", locator: "/candidates/0" },
      sourcePath: "C:/a/x.MP4",
      fields: { categories: ["other"] },
    });
    expect([...rowContentTypes(file)]).toEqual(["video"]);
    const doc = row({
      rowKey: "d",
      ref: { collection: "files", locator: "/candidates/1" },
      fields: { categories: ["documents"] },
    });
    expect([...rowContentTypes(doc)]).toEqual(["document"]);
    const lnk = row({
      rowKey: "l",
      artifactType: "recent-shortcut",
      sourcePath: "C:/r/a.lnk",
      fields: { details: { target_path: "C:/Docs/a.hwp" } },
    });
    expect([...rowContentTypes(lnk)]).toEqual(["document"]);
    const media = row({ rowKey: "m", artifactType: "media-image", sourcePath: "C:/p/a.heic" });
    expect([...rowContentTypes(media)]).toEqual(["image"]);
    // R5 L1 media player rows: the played file (media_path) is the content, never the ini path.
    const played = row({
      rowKey: "p",
      artifactType: "media-player-recent",
      sourcePath: "C:/Users/a/AppData/Roaming/vlc/vlc-qt-interface.ini",
      fields: { details: { media_path: "D:/movies/clip.mkv" } },
    });
    expect([...rowContentTypes(played)]).toEqual(["video"]);
    const urlOnly = row({
      rowKey: "q",
      artifactType: "media-player-recent",
      // The row's own path (a .db the player keeps) is not its content.
      sourcePath: "C:/Users/a/AppData/Roaming/player/history.db",
      fields: { details: { media_url: "https://example.com/stream" } },
    });
    expect([...rowContentTypes(urlOnly)]).toEqual([]);
    expect(pathExtension("C:/a/.hidden")).toBe("");
    expect(pathExtension("C:/a/b.tar.gz")).toBe("gz");
  });

  it("partial rows: parser_error, truncation flags, failing parse / decrypt status, invalid types", () => {
    expect(rowIsPartial(row({ rowKey: "a", fields: { details: { parser_error: true } } }))).toBe(true);
    // A display cap is no 부분 결과; a read / scan cap is (r4 V3 review B4).
    expect(rowIsPartial(row({ rowKey: "b", fields: { details: { event_data_truncated: true } } }))).toBe(
      false,
    );
    expect(rowIsPartial(row({ rowKey: "b2", fields: { details: { scan_truncated: true } } }))).toBe(true);
    expect(rowIsPartial(row({ rowKey: "c", fields: { details: { parse_status: "truncated-item" } } }))).toBe(
      true,
    );
    expect(rowIsPartial(row({ rowKey: "d", fields: { details: { decrypt_status: "failed" } } }))).toBe(true);
    expect(rowIsPartial(row({ rowKey: "e", artifactType: "prefetch-invalid-content" }))).toBe(true);
    expect(
      rowIsPartial(
        row({ rowKey: "f", fields: { details: { parse_status: "parsed", decrypt_status: "success" } } }),
      ),
    ).toBe(false);
  });

  it("rowMatchesFilters applies them in the display timezone", () => {
    const evening = row({ rowKey: "e", timestamp: "2025-05-26T10:30:00Z" });
    const morning = row({ rowKey: "m", timestamp: "2025-05-26T01:00:00Z" });
    expect(rowMatchesFilters(evening, f({ offhours: true }), "Asia/Seoul")).toBe(true);
    expect(rowMatchesFilters(morning, f({ offhours: true }), "Asia/Seoul")).toBe(false);
    expect(rowMatchesFilters(row({ rowKey: "n" }), f({ offhours: true }), "Asia/Seoul")).toBe(false);
    const geo = row({ rowKey: "g", fields: { details: { gps_latitude: 37.485, gps_longitude: 126.945 } } });
    expect(rowMatchesFilters(geo, f({ geo: "37.48,126.94,37.49,126.95" }))).toBe(true);
    expect(rowMatchesFilters(geo, f({ geo: "35,129,36,130" }))).toBe(false);
  });
});

describe("chips and saved condition sets", () => {
  it("shows Korean chips that remove one condition each", () => {
    const filters = f({
      offhours: true,
      partial: true,
      content: ["document", "mail"],
      geo: "37.48,126.94,37.49,126.95",
    });
    const chips = activeChips(filters, (s) => s);
    expect(chips.map((chip) => chip.label)).toEqual([
      "업무 외 시간 18–09시·토·일",
      "부분 결과만",
      "콘텐츠 문서",
      "콘텐츠 메일",
      "위치 37.485, 126.945 부근",
    ]);
    const content = chips.find((chip) => chip.value === "document");
    expect(removeChip(filters, content as never).content).toEqual(["mail"]);
    expect(removeChip(filters, chips[0] as never).offhours).toBeUndefined();
    expect(removeChip(filters, chips[1] as never).partial).toBeUndefined();
    expect(removeChip(filters, chips[4] as never).geo).toBeUndefined();
  });

  it("saved condition sets keep the row conditions", () => {
    const filters = f({
      weekdays: ["sat"],
      hours: "18-09",
      offhours: true,
      partial: true,
      content: ["image"],
    });
    saveCondition("주말 이미지", filters);
    const saved = savedConditions()[0];
    expect(saved?.filters).toMatchObject({
      weekdays: ["sat"],
      hours: "18-09",
      offhours: true,
      partial: true,
      content: ["image"],
    });
    // Unknown content ids are dropped (r4 V3 review F5).
    expect(normalizeFilters({ hours: "bad", offhours: "yes", content: [1, "x", "image"] })).toMatchObject({
      content: ["image"],
    });
    expect(normalizeFilters({ hours: "bad" }).hours).toBeUndefined();
  });
});

describe("condition panel sections", () => {
  it("writes weekday, 업무 외 시간, hours, content and 부분 결과 to the URL", () => {
    useAppStore.getState().patchRoute({ runId: "run-1", collection: "artifacts" });
    render(
      <>
        <ClockSection />
        <ResultSection />
      </>,
    );
    fireEvent.click(screen.getByRole("checkbox", { name: /업무 외 시간/ }));
    fireEvent.click(screen.getByRole("button", { name: "토요일" }));
    fireEvent.change(screen.getByRole("combobox", { name: "시작 시" }), { target: { value: "20" } });
    fireEvent.click(
      within(screen.getByRole("group", { name: "콘텐츠 유형" })).getByRole("button", { name: "압축" }),
    );
    fireEvent.click(screen.getByRole("checkbox", { name: /부분 결과만/ }));
    const route = useAppStore.getState().route;
    expect(route).toMatchObject({
      offhours: true,
      weekdays: ["sat"],
      hours: "20-09",
      content: ["archive"],
      partial: true,
    });
    expect(useFilterStore.getState().filters.content).toEqual(["archive"]);
    expect(screen.getByRole("button", { name: "압축" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("prefills the incident time from the 특이사항 analysis and applies ± n hours", () => {
    useAppStore.getState().patchRoute({ runId: "run-1", collection: "artifacts" });
    useAnalysisStore.getState().setSnapshot(
      "run-1",
      [
        {
          analysis_id: "a",
          kind: "triage-flags",
          status: "completed",
          options: { incident_start: "2025-05-30T03:00:00Z" },
          created_at: "2026-01-01T00:00:00Z",
          progress: {} as never,
          row_count: 0,
        },
      ],
      true,
    );
    render(<IncidentRange />);
    fireEvent.change(screen.getByRole("combobox", { name: "앞뒤 시간" }), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: /사건 시각 ±1시간 적용/ }));
    const { from, to } = useAppStore.getState().route;
    expect(Date.parse(to as string) - Date.parse(from as string)).toBe(2 * 3_600_000);
    expect(new Date(Date.parse(from as string)).toISOString()).toBe("2025-05-30T02:00:00.000Z");
  });
});
