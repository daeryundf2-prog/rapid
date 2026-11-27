import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SESSION_ID, setAuthToken } from "../api/client";
import {
  codeId,
  countBucket,
  emit,
  gridLoaded,
  gridSorted,
  sessionStarted,
  setTelemetryEnabled,
  stageEntered,
  type TelemetryEvent,
  tagApplied,
} from "./telemetry";

const PATH = "C:\\Users\\analyst\\evidence\\계약서.docx";

/** Props each event may carry (server whitelist, docs/telemetry.md). */
const ALLOWED: Record<TelemetryEvent["event"], readonly string[]> = {
  app_session_started: ["viewport_bucket", "locale"],
  grid_loaded: [
    "surface",
    "artifact_type",
    "row_count_bucket",
    "latency_ms",
    "server_ms",
    "total_known",
    "truncated",
  ],
  grid_sorted: ["surface", "column_kind", "direction", "scope", "loaded_rows_bucket", "total_rows_bucket"],
  review_stage_entered: ["stage"],
  review_tag_applied: ["action", "row_count", "source_surface", "artifact_type"],
};

describe("countBucket", () => {
  it("puts counts on the shared log scale", () => {
    expect([0, 1, 9, 10, 999, 1000, 99_999, 100_000, 5_000_000].map(countBucket)).toEqual([
      "0",
      "1-9",
      "1-9",
      "10-99",
      "100-999",
      "1k-9k",
      "10k-99k",
      "100k-999k",
      "1m+",
    ]);
    expect([null, undefined, -1, Number.NaN].map(countBucket)).toEqual([
      "unknown",
      "unknown",
      "unknown",
      "unknown",
    ]);
  });
});

describe("event builders", () => {
  it("build exactly the approved props", () => {
    expect(sessionStarted(1280, "ko-KR")).toEqual({
      event: "app_session_started",
      props: { viewport_bucket: "md", locale: "ko" },
    });
    expect(
      gridLoaded({
        runId: "r1",
        surface: "tree",
        artifactType: "evtx",
        total: 360_000,
        latencyMs: 1999.6,
        serverMs: 120,
        truncated: false,
      }),
    ).toEqual({
      event: "grid_loaded",
      run_id: "r1",
      props: {
        surface: "tree",
        artifact_type: "evtx",
        row_count_bucket: "100k-999k",
        latency_ms: 2000,
        server_ms: 120,
        total_known: true,
        truncated: false,
      },
    });
    expect(stageEntered("r1", "review")).toEqual({
      event: "review_stage_entered",
      run_id: "r1",
      props: { stage: "review" },
    });
  });

  it("never carry paths, file names or free text", () => {
    const events: TelemetryEvent[] = [
      gridLoaded({
        runId: "r1",
        surface: "search",
        artifactType: PATH,
        total: null,
        latencyMs: 5,
        serverMs: null,
        truncated: true,
      }),
      gridSorted({
        runId: "r1",
        surface: "timeline",
        columnKind: "time",
        direction: "desc",
        scope: "loaded",
        loadedRows: 250,
        totalRows: null,
      }),
      tagApplied({
        runId: "r1",
        action: "tag",
        rowCount: 3,
        surface: "grid",
        artifactType: PATH,
        tag: "중요",
      }),
    ];
    for (const event of events) {
      expect(Object.keys(event.props).every((key) => ALLOWED[event.event].includes(key))).toBe(true);
      for (const value of Object.values(event.props)) {
        expect(String(value)).not.toMatch(/[\\/]|계약서|analyst/);
      }
    }
    expect(codeId("windows.prefetch")).toBe("windows.prefetch");
    expect(codeId(PATH)).toBe("other");
  });
});

describe("emit", () => {
  const fetchMock = vi.fn(
    async () => new Response("{}", { status: 202, headers: { "content-type": "application/json" } }),
  );

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    setAuthToken("t");
    setTelemetryEnabled(true);
  });
  afterEach(() => {
    setTelemetryEnabled(false);
    vi.unstubAllGlobals();
    fetchMock.mockClear();
    window.sessionStorage.clear();
  });

  it("posts the event to the local server with the session header", () => {
    // api() calls fetch synchronously when emit() starts it.
    emit(stageEntered("r1", "explore"));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [path, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(path).toBe("/api/telemetry/events");
    expect(JSON.parse(String(init.body))).toEqual({
      event: "review_stage_entered",
      run_id: "r1",
      props: { stage: "explore" },
    });
    expect((init.headers as Record<string, string>)["X-RapidTriage-Session"]).toBe(SESSION_ID);
  });

  it("sends nothing while disabled", () => {
    setTelemetryEnabled(false);
    emit(stageEntered("r1", "explore"));
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
