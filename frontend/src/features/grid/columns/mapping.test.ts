import { describe, expect, it } from "vitest";
import type { CollectionId } from "../../../contracts/collection";
import { buildViewerTarget } from "../gridCommands";
import { bookmarkTarget } from "../reviewActions";
import { COLLECTIONS, presetColumnIds } from "./index";

const SHA = "a".repeat(64);

function map(id: CollectionId, raw: Record<string, unknown>, index = 0, kind?: string) {
  return COLLECTIONS[id].mapRow(raw, index, { ref: kind ? { id, kind } : { id } });
}

describe("API row -> GridRow mapping", () => {
  it("files: locator is /candidates/{global index}", () => {
    const row = map(
      "files",
      {
        path: "C:/ev/a.docx",
        name: "a.docx",
        extension: ".docx",
        size: 2048,
        modified_at: "2026-02-01T10:00:00Z",
        sha256: SHA,
      },
      894,
    );
    expect(row.rowKey).toBe("files:/candidates/894");
    expect(row.ref).toEqual({ collection: "files", locator: "/candidates/894" });
    expect(row.title).toBe("a.docx");
    expect(row.sourcePath).toBe("C:/ev/a.docx");
    expect(row.timestamp).toBe("2026-02-01T10:00:00Z");
    expect(row.sha256).toBe(SHA);
    expect(row.fields.size).toBe(2048);
  });

  it("docs: /results/{index}, title from the path, keywords joined", () => {
    const row = map(
      "docs",
      { path: "C:/ev/x/report.pdf", kind: "pdf", matched_keywords: ["a", "b"], preview: "hi", size: 5 },
      3,
    );
    expect(row.rowKey).toBe("docs:/results/3");
    expect(row.title).toBe("report.pdf");
    expect(row.fields.keywords).toBe("a, b");
    expect(row.fields.keywordCount).toBe(2);
  });

  it("timeline: /events/{index}, summary is the title", () => {
    const row = map(
      "timeline",
      {
        timestamp: "2026-01-02T00:00:00Z",
        source: "artifacts",
        event_type: "evtx",
        path: "C:/a.evtx",
        summary: "로그온",
      },
      278261,
    );
    expect(row.rowKey).toBe("timeline:/events/278261");
    expect(row.title).toBe("로그온");
    expect(row.provider).toBe("artifacts");
    expect(row.artifactType).toBe("evtx");
  });

  it("indicators: /indicators/{index}, value is the title, first source path", () => {
    const row = map(
      "indicators",
      {
        type: "domain",
        value: "evil.example",
        count: 4,
        classification: "suspicious",
        sources: [{ path: "C:/x.db" }],
      },
      7,
    );
    expect(row.rowKey).toBe("indicators:/indicators/7");
    expect(row.title).toBe("evil.example");
    expect(row.sourcePath).toBe("C:/x.db");
    expect(row.fields.count).toBe(4);
  });

  it("artifacts: /artifacts/{kind-local index} with kind; hoisted details and record hash used", () => {
    const row = map(
      "artifacts",
      {
        provider: "windows-eventlog",
        artifact_type: "evtx_event",
        path: "C:/Windows/System32/winevt/Security.evtx",
        details: { message: "An account was logged on", timestamp: "2026-03-01T01:02:03Z" },
        artifact_record: { source: { source_path: "C:/x", hashes: { sha256: SHA } }, confidence: 0.9 },
        _kind: "eventlog",
        _index: 12345,
      },
      0,
    );
    expect(row.rowKey).toBe("artifacts:eventlog:/artifacts/12345");
    expect(row.ref).toEqual({ collection: "artifacts", kind: "eventlog", locator: "/artifacts/12345" });
    expect(row.title).toBe("An account was logged on");
    expect(row.timestamp).toBe("2026-03-01T01:02:03Z");
    expect(row.provider).toBe("windows-eventlog");
    expect(row.sha256).toBe(SHA);
  });

  it("artifacts: provider objects ({name}) and missing details fall back to type/path", () => {
    const row = map(
      "artifacts",
      {
        provider: { name: "p" },
        artifact_type: "prefetch",
        path: "C:/a/B.pf",
        details: {},
        _kind: "prefetch",
      },
      4,
    );
    expect(row.provider).toBe("p");
    expect(row.title).toBe("B.pf");
    expect(row.rowKey).toBe("artifacts:prefetch:/artifacts/4");
  });

  it("search: locator is source-qualified so identical pointers do not collide", () => {
    const a = map(
      "search",
      {
        source: "artifacts",
        kind: "eventlog",
        pointer: "/artifacts/3",
        path: "C:/a.evtx",
        title: "t",
        preview: "p",
        matched_keywords: ["k"],
      },
      0,
    );
    const b = map(
      "search",
      {
        source: "artifacts",
        kind: "browser",
        pointer: "/artifacts/3",
        path: "C:/b.db",
        title: "t",
        preview: "p",
      },
      1,
    );
    const c = map("search", { source: "files", pointer: "/candidates/3", path: "C:/c.txt", title: "t" }, 2);
    expect(a.rowKey).toBe("search:artifacts:eventlog:/artifacts/3");
    expect(a.rowKey).not.toBe(b.rowKey);
    expect(c.rowKey).toBe("search:files:/candidates/3");
    expect(a.fields.pointer).toBe("/artifacts/3");
    expect(a.fields.keywords).toBe("k");
  });

  it("search hits keep the verbatim API pointer as ref.locator so they can be marked", () => {
    const hit = map(
      "search",
      { source: "artifacts", kind: "eventlog", pointer: "/artifacts/3", path: "C:/a.evtx", title: "t" },
      0,
    );
    expect(hit.ref).toEqual({
      collection: "search",
      kind: "eventlog",
      locator: "/artifacts/3",
      source: "artifacts",
    });
    expect(bookmarkTarget(hit)).toEqual({ source: "artifacts:eventlog", pointer: "/artifacts/3" });
    const file = map(
      "search",
      { source: "files", pointer: "/candidates/894", path: "C:/f.txt", title: "f" },
      1,
    );
    expect(file.ref.locator).toBe("/candidates/894");
    expect(bookmarkTarget(file)).toEqual({ source: "files", pointer: "/candidates/894" });
    const docs = map(
      "search",
      { source: "docs-index", pointer: "docs-index:/results/7", path: "C:/d.pdf", title: "d" },
      2,
    );
    expect(docs.ref.locator).toBe("/results/7");
    expect(bookmarkTarget(docs)).toEqual({ source: "docs", pointer: "/results/7" });
  });

  it("review: bookmark id locator, status mapping, tags", () => {
    const row = map(
      "review",
      {
        bookmark_id: "bm-1",
        summary: "의심 파일",
        tags: ["a", "b"],
        note: "메모",
        review: { status: "not-relevant", include_in_report: false },
        reference: { command: "files", file: "files.json", pointer: "/candidates/5" },
        snapshot: { path: "C:/x", hash: SHA, timestamp: "2026-01-01T00:00:00Z", summary: "s" },
      },
      0,
    );
    expect(row.rowKey).toBe("review:bookmark:bm-1");
    expect(row.reviewStatus).toBe("excluded");
    expect(row.tags).toEqual(["a", "b"]);
    expect(row.sha256).toBe(SHA);
    expect(row.fields.pointer).toBe("/candidates/5");
    expect(bookmarkTarget(row)).toEqual({ source: "files", pointer: "/candidates/5" });
    const included = map("review", {
      bookmark_id: "b2",
      review: { status: "unreviewed", include_in_report: true },
    });
    expect(included.reviewStatus).toBe("include-in-report");
  });

  it("outputs: output:{name} locator, path and size", () => {
    const row = map("outputs", {
      name: "timeline",
      path: "C:/out/timeline.json",
      exists: true,
      size: 10,
      download_url: "/api/runs/r/outputs/timeline/file",
    });
    expect(row.rowKey).toBe("outputs:output:timeline");
    expect(row.sourcePath).toBe("C:/out/timeline.json");
    expect(row.fields.exists).toBe(true);
  });

  it("every collection defines columns, the first one is the title and visible in every preset", () => {
    for (const def of Object.values(COLLECTIONS)) {
      expect(def.columns.length).toBeGreaterThan(0);
      for (const preset of ["analysis", "compact", "source"] as const) {
        expect(presetColumnIds(def.columns, preset).length).toBeGreaterThan(0);
      }
    }
    expect(presetColumnIds(COLLECTIONS.artifacts.columns, "compact")).not.toEqual(
      presetColumnIds(COLLECTIONS.artifacts.columns, "source"),
    );
  });
});

describe("artifact-kind-aware summaries and record locators", () => {
  const evtx = {
    provider: "windows-eventlog",
    artifact_type: "eventlog-event",
    path: "C:/Windows/System32/winevt/Logs/Application.evtx",
    details: {
      event_id: "1531",
      provider_name: "Microsoft-Windows-User Profiles Service",
      event_tags: ["category:event", "channel:application"],
      event_message:
        "provider=X | channel=Application | computer=PC | user=u | 4 | 0 | 1531 | body text here",
      evtx_record_offset: 4608,
      evtx_record_size: 1568,
    },
    _kind: "eventlog",
    _index: 0,
  };

  it("eventlog: title is id channel provider, type stays separate, message preview is its own field", () => {
    const row = map("artifacts", evtx, 0, "eventlog");
    expect(row.title).toBe("1531 application Microsoft-Windows-User Profiles Service");
    expect(row.artifactType).toBe("eventlog-event");
    expect(row.fields.eventId).toBe("1531");
    expect(row.fields.channel).toBe("application");
    expect(String(row.fields.detail)).toBe("4 | 0 | 1531 | body text here");
    const cols = COLLECTIONS.artifacts.columnsFor?.({ id: "artifacts", kind: "eventlog" }) ?? [];
    expect(cols.map((c) => c.header)).toEqual(expect.arrayContaining(["이벤트ID", "채널", "메시지", "유형"]));
  });

  it("prefetch / registry / recent-files / media titles come from the record", () => {
    const pf = map(
      "artifacts",
      {
        artifact_type: "prefetch-file",
        path: "C:/Prefetch/A.pf",
        details: { executable_hint: "ADOBEARM.EXE", run_count: 3, last_run_at: "2025-05-29T23:26:25Z" },
      },
      0,
      "windows-prefetch",
    );
    expect(pf.title).toBe("ADOBEARM.EXE");
    expect(pf.fields.detail).toBe("실행 3회 · 최근 2025-05-29T23:26:25Z");
    expect(pf.timestamp).toBe("2025-05-29T23:26:25Z");
    const reg = map(
      "artifacts",
      {
        artifact_type: "registry-key-tree-node",
        path: "C:/NTUSER.DAT",
        details: { key_path: "ROOT/Software/X", name: "Run" },
      },
      0,
      "windows-registry",
    );
    expect(reg.title).toBe(`ROOT/Software/X ${String.fromCharCode(92)} Run`);
    const rf = map(
      "artifacts",
      {
        artifact_type: "recent-shortcut",
        path: "C:/Recent/a.lnk",
        details: { target_path: "F:/x/y.txt", entry_name: "a.lnk" },
      },
      0,
      "recent-files",
    );
    expect(rf.title).toBe("F:/x/y.txt");
    const img = map(
      "artifacts",
      {
        artifact_type: "media-image",
        path: "C:/p/128.png",
        details: { entry_name: "128.png", width: 128, height: 64 },
      },
      0,
      "media-image",
    );
    expect(img.title).toBe("128.png");
    expect(img.fields.detail).toBe("128×64");
  });

  it("record locator goes into the ViewerTarget highlight and artifact rows open on meta", () => {
    const row = map("artifacts", evtx, 0, "eventlog");
    expect(row.fields.highlight).toEqual({ offset: 4608, length: 1568 });
    const target = buildViewerTarget("r1", row);
    expect(target.highlight).toEqual({ offset: 4608, length: 1568 });
    expect(target.preferredMode).toBe("meta");
    expect(buildViewerTarget("r1", row, "hex").preferredMode).toBe("hex");
    const sqlite = map(
      "artifacts",
      {
        artifact_type: "notification-row-candidate",
        path: "C:/n.db",
        details: { table: "Notification", rowid: 7 },
      },
      0,
      "windows-system",
    );
    expect(sqlite.fields.highlight).toEqual({ table: "Notification", rowid: 7 });
    const file = map("files", { path: "C:/a.txt" }, 0);
    expect(buildViewerTarget("r1", file).preferredMode).toBeUndefined();
  });
});

describe("bookmarkTarget", () => {
  it("maps locator prefixes to the bookmark source alias", () => {
    expect(bookmarkTarget(map("docs", { path: "C:/a.pdf" }, 2))).toEqual({
      source: "docs",
      pointer: "/results/2",
    });
    expect(bookmarkTarget(map("timeline", { summary: "x" }, 9))).toEqual({
      source: "timeline",
      pointer: "/events/9",
    });
    expect(bookmarkTarget(map("artifacts", { _kind: "eventlog", _index: 5, details: {} }))).toEqual({
      source: "artifacts:eventlog",
      pointer: "/artifacts/5",
    });
    expect(bookmarkTarget(map("outputs", { name: "x" }))).toBeNull();
  });
});
