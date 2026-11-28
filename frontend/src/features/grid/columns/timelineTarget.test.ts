/**
 * F10: the 대상 of a timeline event. One case per event family of the synthetic run
 * (ce781cdd7fc7: amcache / bam / jumplist / srum / windows-search-index synthetic rows, browser
 * history / download / AI usage, file and document events) and per build_artifact_summary branch
 * (core/timeline.py: url, source_url, target_path, executable_path, key_path, entry_name,
 * EventLog, inventory). Event shapes copy the server's.
 */
import { describe, expect, it } from "vitest";
import { timelineCollection } from "./timeline";
import { keyTarget, stripSummaryPrefix, timelineTarget, urlTarget } from "./timelineTarget";

const lnk = "/tmp/rd-data/evidence/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/Invoice Review.lnk";
const history = "/tmp/rd-data/evidence/Users/alice/AppData/Local/Google/Chrome/User Data/Default/History";

function synthetic(artifactType: string, eventType: string, summary: string) {
  return {
    event_type: eventType,
    source: "artifacts",
    summary,
    path: lnk,
    details: {
      kind: "synthetic",
      artifact_type: artifactType,
      field_path: "details.timestamp",
      synthetic: true,
    },
  };
}

describe("timelineTarget — synthetic run families (summary basis, prefix removed)", () => {
  it.each([
    ["amcache-entry", "artifact-amcache-entry-last-written", "incident-notes.log (합성 12)"],
    ["bam-entry", "artifact-bam-entry-run", "payload-installer.exe (합성 14)"],
    ["jumplist-automatic", "artifact-jumplist-automatic-target-accessed", "incident-notes.log (합성 57)"],
    ["srum-app-usage", "artifact-srum-app-usage-srum-record", "attacker-activity.pdf (합성 2)"],
    [
      "windows-search-index-entry",
      "artifact-windows-search-index-entry-indexed-created",
      "payload-installer.exe (합성 50)",
    ],
  ])("%s → the named file, not 'Artifact event: …'", (type, eventType, target) => {
    const summary = `Artifact event: ${type} ${target}`;
    const result = timelineTarget(synthetic(type, eventType, summary));
    expect(result).toEqual({ text: target, title: summary, basis: "summary" });
  });

  it("file events drop '파일 <kind>: ' (kind stays in the 이벤트 column)", () => {
    for (const kind of ["accessed", "created", "modified"]) {
      const raw = {
        event_type: `file-${kind}`,
        source: "files",
        summary: `파일 ${kind}: breach-summary.docx (합성 1)`,
        path: "/tmp/rd-data/evidence/Users/alice/Documents/breach-summary.docx",
        details: { synthetic: true },
      };
      expect(timelineTarget(raw).text).toBe("breach-summary.docx (합성 1)");
    }
  });

  it("a real file event reads details.name (structured field first)", () => {
    const raw = {
      event_type: "file-modified",
      source: "files",
      summary: "파일 modified: report.docx",
      path: "C:\\Users\\a\\report.docx",
      details: { name: "report.docx", extension: ".docx", field: "fs_modified_at" },
    };
    expect(timelineTarget(raw)).toMatchObject({ text: "report.docx", basis: "field" });
  });

  it("a document event reads the document's file name", () => {
    const raw = {
      event_type: "document-modified",
      source: "docs",
      summary: "문서 수정: screen-capture.png (합성 16)",
      path: "/tmp/rd-data/evidence/Users/alice/Desktop/screen-capture.png",
      details: { synthetic: true },
    };
    expect(timelineTarget(raw)).toMatchObject({ text: "screen-capture.png", basis: "field" });
  });
});

describe("timelineTarget — structured fields (build_artifact_summary branches)", () => {
  it("browser history: URL host + path, the full URL and summary on hover", () => {
    const raw = {
      event_type: "artifact-browser-history-last-visited",
      source: "artifacts",
      summary: "Artifact event: browser-history https://bank.example.test/account (합성 0)",
      path: history,
      details: {
        artifact_type: "browser-history",
        url: "https://bank.example.test/account",
        title: "Sample Bank Account",
        domain: "bank.example.test",
      },
    };
    const result = timelineTarget(raw);
    expect(result.text).toBe("bank.example.test/account");
    expect(result.basis).toBe("field");
    expect(result.title).toContain("https://bank.example.test/account");
    expect(result.title).toContain(raw.summary);
  });

  it("browser download: the downloaded file (target_path) before its source URL", () => {
    const raw = {
      event_type: "artifact-browser-download-started",
      source: "artifacts",
      summary: "Artifact event: browser-download https://example.test/tools/payload-installer.exe (합성 8)",
      path: history,
      details: {
        artifact_type: "browser-download",
        source_url: "https://example.test/tools/payload-installer.exe",
        target_path: "C:\\Users\\alice\\Downloads\\payload-installer.exe",
      },
    };
    expect(timelineTarget(raw)).toMatchObject({ text: "payload-installer.exe", basis: "field" });
    expect(timelineTarget(raw).title).toContain("C:\\Users\\alice\\Downloads\\payload-installer.exe");
  });

  it("a source_url alone reads as host + path", () => {
    const raw = {
      event_type: "x",
      details: { artifact_type: "x", source_url: "https://cdn.test/a/b.zip?x=1" },
    };
    expect(timelineTarget(raw).text).toBe("cdn.test/a/b.zip");
  });

  it("AI usage: the query first, the service after", () => {
    const raw = {
      event_type: "artifact-browser-ai-usage-ai-usage-visited",
      source: "artifacts",
      summary: "AI usage: ChatGPT windows event log timeline (합성 9)",
      details: {
        artifact_type: "browser-ai-usage",
        ai_service: "ChatGPT",
        url: "https://chatgpt.com/?q=windows%20event%20log%20timeline",
        query_hint: "windows event log timeline",
      },
    };
    expect(timelineTarget(raw).text).toBe("windows event log timeline (ChatGPT)");
  });

  it("executable, registry key and entry name", () => {
    expect(
      timelineTarget({ event_type: "e", details: { executable_path: "C:\\Windows\\System32\\cmd.exe" } })
        .text,
    ).toBe("cmd.exe");
    expect(
      timelineTarget({
        event_type: "e",
        details: { key_path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
      }).text,
    ).toBe("…\\CurrentVersion\\Run");
    expect(timelineTarget({ event_type: "e", details: { entry_name: "evil.lnk" } }).text).toBe("evil.lnk");
  });

  it("EventLog and inventory summaries lose their English / type prefix", () => {
    expect(
      timelineTarget({
        event_type: "eventlog-logon-success",
        summary: "EventLog event: id=4624 logon-success channel=Security user=bob",
        details: { artifact_type: "eventlog-event" },
      }).text,
    ).toBe("id=4624 logon-success channel=Security user=bob");
    expect(
      timelineTarget({
        event_type: "artifact-registry-key-last-written",
        summary: "registry-key: SYSTEM 인벤토리 키 12개 최종 수정(대표 시각, 서로 다른 시각 3개)",
        details: { artifact_type: "registry-key", scope: "inventory" },
      }).text,
    ).toBe("SYSTEM 인벤토리 키 12개 최종 수정(대표 시각, 서로 다른 시각 3개)");
  });

  it("a summary of an unknown shape stays whole; an empty one falls back to the event type", () => {
    expect(timelineTarget({ event_type: "x", summary: "Something else happened" }).text).toBe(
      "Something else happened",
    );
    expect(timelineTarget({ event_type: "custom-event" }).text).toBe("custom-event");
  });
});

describe("helpers", () => {
  it("urlTarget / keyTarget / stripSummaryPrefix", () => {
    expect(urlTarget("https://example.test/")).toBe("example.test");
    expect(urlTarget("not a url")).toBe("not a url");
    expect(keyTarget("HKCU\\Run")).toBe("HKCU\\Run");
    expect(stripSummaryPrefix("Artifact event: other-type x", "amcache-entry")).toBe(
      "Artifact event: other-type x",
    );
  });

  it("the timeline 대상 column shows the target; its tooltip keeps the original summary", () => {
    const summary = "Artifact event: bam-entry payload-installer.exe (합성 14)";
    const row = timelineCollection.mapRow(synthetic("bam-entry", "artifact-bam-entry-run", summary), 3, {
      ref: { id: "timeline" },
    });
    const column = timelineCollection.columns.find((c) => c.id === "title");
    expect(column?.header).toBe("대상");
    expect(row.title).toBe("payload-installer.exe (합성 14)");
    expect(column?.tooltip?.(row)).toBe(summary);
    expect(row.fields.summary).toBe(summary);
  });
});
