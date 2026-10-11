import { describe, expect, it } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { parseHighlightTerms } from "./adapter";
import { bookmarkPointer, bookmarkSource, buildCitation, markDisabledReason } from "./citation";
import { bytesFromHexRows, formatOffset, parseOffsetInput, scanSignatures } from "./hex";
import { TargetHistory } from "./history";
import { groupRecordFields, recordByteRange } from "./record";
import { target } from "./testSupport";
import { parseCueTime } from "./views/MediaView";

describe("hex helpers", () => {
  it("parses hex and decimal offsets", () => {
    expect(parseOffsetInput("0x1f0")).toBe(0x1f0);
    expect(parseOffsetInput("1F0")).toBe(0x1f0);
    expect(parseOffsetInput("496")).toBe(496);
    expect(parseOffsetInput("0x")).toBeNull();
    expect(parseOffsetInput("12z")).toBeNull();
    expect(parseOffsetInput("")).toBeNull();
  });

  it("parses API rows into bytes", () => {
    expect(Array.from(bytesFromHexRows([{ hex: "4d 5a 00" }, { hex: "ff" }]))).toEqual([0x4d, 0x5a, 0, 0xff]);
  });

  it("finds magic-byte signatures at absolute offsets", () => {
    const bytes = Uint8Array.from([0, 0x4d, 0x5a, 0, 0x72, 0x65, 0x67, 0x66]);
    expect(scanSignatures(bytes, 0x1000)).toEqual([
      { name: "PE/MZ", offset: 0x1001, length: 2 },
      { name: "regf", offset: 0x1004, length: 4 },
    ]);
  });

  it("widens offsets for files above 4 GiB", () => {
    expect(formatOffset(16)).toBe("0x00000010");
    expect(formatOffset(16, 2 ** 33)).toBe("0x000000000010");
  });
});

describe("citation + marks", () => {
  it("builds a one-line citation with path, sha256, locator and run", () => {
    const text = buildCitation(target({ highlight: { offset: 32, length: 4 } }), "abc123");
    expect(text).toBe(
      "원본=C:/evidence/file.bin; sha256=abc123; 위치=files:/candidates/7; 런=run-1; 바이트=0x00000020-0x00000023",
    );
  });

  it("maps artifact/doc locators to bookmark JSON pointers", () => {
    const artifact = target({
      ref: { collection: "artifacts", kind: "eventlog", locator: "artifacts_eventlog:row:12" },
    });
    expect(bookmarkSource(artifact)).toBe("artifacts:eventlog");
    expect(bookmarkPointer(artifact)).toBe("/artifacts/12");
    const doc = target({ ref: { collection: "docs", locator: "doc:17" } });
    expect(bookmarkPointer(doc)).toBe("/results/17");
  });

  it("explains why a row cannot be marked", () => {
    expect(markDisabledReason(null, "relevant")).toContain("행이 없습니다");
    const search = target({ ref: { collection: "search", locator: "hit:3" } });
    expect(markDisabledReason(search, "relevant")).toContain("locator");
    expect(markDisabledReason(target(), "relevant")).toBeUndefined();
    expect(markDisabledReason({ ...search, ref: { ...search.ref, caseDbId: 4 } }, "bookmark")).toContain(
      "북마크",
    );
  });
});

describe("history", () => {
  it("is bounded to 50 entries with back/forward", () => {
    const history = new TargetHistory();
    for (let i = 0; i < 60; i++)
      history.visit(target({ ref: { collection: "files", locator: `/candidates/${i}` } }));
    expect(history.size).toBe(50);
    expect(history.back()?.ref.locator).toBe("/candidates/58");
    expect(history.forward()?.ref.locator).toBe("/candidates/59");
    expect(history.canForward()).toBe(false);
    let steps = 0;
    while (history.back()) steps++;
    expect(steps).toBe(49);
  });

  it("revisiting the current entry is a no-op; a new visit drops the forward stack", () => {
    const history = new TargetHistory();
    history.visit(target({ ref: { collection: "files", locator: "/a" } }));
    history.visit(target({ ref: { collection: "files", locator: "/b" } }));
    history.back();
    history.visit(target({ ref: { collection: "files", locator: "/a" } }));
    expect(history.canForward()).toBe(true);
    history.visit(target({ ref: { collection: "files", locator: "/c" } }));
    expect(history.canForward()).toBe(false);
    expect(history.size).toBe(2);
  });
});

describe("misc", () => {
  it("reads q= keywords from the hash route", () => {
    expect(parseHighlightTerms("#/case/r1/search?q=powershell%20mimikatz&row=x")).toEqual([
      "powershell",
      "mimikatz",
    ]);
    expect(parseHighlightTerms("#/case/r1/files")).toEqual([]);
  });

  it("parses cue timestamps", () => {
    expect(parseCueTime("00:01:02.500")).toBe(62.5);
    expect(parseCueTime("01:02,5")).toBe(62.5);
    expect(parseCueTime("x")).toBeNull();
  });
});

function row(details: Record<string, unknown>): GridRow {
  return {
    rowKey: "artifacts:/artifacts/0",
    ref: { collection: "artifacts", kind: "x", locator: "/artifacts/0" },
    title: "",
    sourcePath: null,
    timestamp: null,
    artifactType: null,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: { details },
  };
}

describe("decoded record", () => {
  it("finds the record byte range from artifact detail fields", () => {
    expect(recordByteRange(row({ evtx_record_offset: 4608, evtx_record_size: 1568 }))).toEqual({
      offset: 4608,
      length: 1568,
    });
    expect(recordByteRange(row({ source_offset: "0x200" }))).toEqual({ offset: 512 });
    expect(recordByteRange(row({ evtx_chunk_index: 2 }))).toEqual({
      offset: 0x1000 + 2 * 0x10000,
      length: 0x10000,
    });
    expect(recordByteRange(row({ size: 10 }))).toBeNull();
    expect(recordByteRange(null)).toBeNull();
  });

  it("groups fields into 핵심/출처/검증/기타", () => {
    const groups = groupRecordFields(
      row({
        event_id: "4624",
        timestamp: "t",
        source_path: "C:/x",
        source_hashes: { sha256: "abc" },
        prefetch_parse_status: "parsed",
        run_count: 3,
        volume_candidate_count: 1,
        empty: "",
      }),
    );
    expect(groups.core.map((f) => f.key)).toEqual(["timestamp", "event_id", "run_count"]);
    expect(groups.source.map((f) => f.key)).toEqual(["source_path", "source_hashes"]);
    expect(groups.source[1]?.value).toBe('{"sha256":"abc"}');
    expect(groups.validation.map((f) => f.key)).toEqual(["prefetch_parse_status"]);
    expect(groups.other.map((f) => f.key)).toEqual(["volume_candidate_count"]);
  });
});

describe("record long values (U-C3)", () => {
  it("clips the display value at 600 chars but keeps the full text, and marks details keys", () => {
    const long = "가".repeat(5000);
    const groups = groupRecordFields({
      rowKey: "artifacts:eventlog:/artifacts/1",
      ref: { collection: "artifacts", kind: "eventlog", locator: "/artifacts/1" },
      title: "t",
      sourcePath: null,
      timestamp: null,
      artifactType: "eventlog-event",
      provider: null,
      sha256: null,
      reviewStatus: null,
      tags: [],
      fields: { detail: "summary", details: { event_message: long, level: 4 } },
    });
    const message = groups.core.find((f) => f.key === "event_message");
    expect(message?.truncated).toBe(true);
    expect(message?.value).toHaveLength(601);
    expect(message?.value.endsWith("…")).toBe(true);
    expect(message?.full).toBe(long);
    expect(message?.fromDetails).toBe(true);
    const level = groups.core.find((f) => f.key === "level");
    expect(level).toMatchObject({ value: "4", full: "4", truncated: false, fromDetails: true });
    // `detail` is a grid summary field, not a details key: never promotable.
    expect(groups.other.find((f) => f.key === "detail")?.fromDetails).toBeUndefined();
  });
});
