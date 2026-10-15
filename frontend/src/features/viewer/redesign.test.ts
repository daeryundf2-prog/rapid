import { describe, expect, it } from "vitest";
import type { GridRow } from "../../contracts/collection";
import {
  evidenceTime,
  evidenceTimeTooltip,
  filetimeOf,
  formatEvidenceTime,
  formatGridTime,
  fractionDigits,
  zoneLabel,
} from "../../utils/time";
import { timestampKindLabel } from "../../utils/timeKinds";
import { artifactColumnsForKind, artifactTypeFamily } from "../grid/columns/artifacts";
import { citationText } from "../grid/gridCommands";
import { recordBanners } from "./banners";
import { bytesOfHex, filterUtf16Strings, hexDump, isReadableString, utf16Strings } from "./binaryValue";
import { buildCitation } from "./citation";
import { eventLevelLabel, logonTypeLabel, severityLabel } from "./fieldFormat";
import { recordPivots } from "./pivots";
import { eventRecordXml, hasEventRecord } from "./recordXml";
import { resolveSid, wellKnownSid } from "./sidNames";

function artifact(
  type: string,
  details: Record<string, unknown>,
  kind = "eventlog",
  extra: Partial<GridRow> = {},
): GridRow {
  return {
    rowKey: `artifacts:${kind}:/artifacts/3`,
    ref: { collection: "artifacts", kind, locator: "/artifacts/3" },
    title: "t",
    sourcePath: "C:/e/Security.evtx",
    timestamp: null,
    artifactType: type,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: { details },
    ...extra,
  };
}

describe("evidence timestamps (§2)", () => {
  const iso = "2025-05-29T14:25:26.427+00:00";
  it("local (zone) · UTC, sub-second kept", () => {
    expect(formatEvidenceTime(iso, "Asia/Seoul")).toBe(
      "2025-05-29 23:25:26.427 (KST+09:00) · UTC 14:25:26.427",
    );
    expect(formatEvidenceTime(iso, "utc")).toBe("2025-05-29 14:25:26.427 (UTC)");
    // Date differs between local and UTC: the UTC side carries its date.
    expect(evidenceTime("2025-05-29T20:00:00Z", "Asia/Seoul")?.utc).toBe("UTC 2025-05-29 20:00:00");
  });
  it("keeps the source precision: none, µs, 100 ns", () => {
    expect(fractionDigits("2024-04-01T12:34:56.000000+00:00")).toBe("");
    expect(fractionDigits("2024-04-01T12:34:56.123400+00:00")).toBe("123400");
    expect(fractionDigits("2024-04-01T12:34:56.1234567Z")).toBe("1234567");
    expect(evidenceTime("2024-04-01T12:34:56.1234567Z", "utc")?.local).toBe("2024-04-01 12:34:56.1234567");
  });
  it("names zones with daylight saving", () => {
    expect(zoneLabel("America/New_York", new Date("2025-01-15T00:00:00Z"))).toBe("EST-05:00");
    expect(zoneLabel("America/New_York", new Date("2025-07-15T00:00:00Z"))).toBe("EDT-04:00");
    expect(zoneLabel("Asia/Kolkata", new Date("2025-07-15T00:00:00Z"))).toBe("UTC+05:30");
  });
  it("FILETIME in the tooltip: raw when known, else converted", () => {
    expect(filetimeOf("1601-01-01T00:00:00Z")).toBe("0");
    expect(filetimeOf("2024-04-01T12:34:56.1234567Z")).toBe("133564484961234567");
    expect(evidenceTimeTooltip(iso, "utc", "133")).toContain("FILETIME 원문 133");
    expect(evidenceTimeTooltip(iso, "utc")).toContain("FILETIME(환산)");
  });
  it("grid cells: seconds + zone name", () => {
    expect(formatGridTime(iso, "Asia/Seoul")).toBe("2025-05-29 23:25:26 KST");
    expect(formatGridTime(iso, "utc")).toBe("2025-05-29 14:25:26 UTC");
    expect(formatGridTime("junk", "utc")).toBe("junk");
  });
  it("time-kind chip labels", () => {
    expect(timestampKindLabel("run-3")).toBe("실행 3회차");
    expect(timestampKindLabel("last_written")).toBe("키 마지막 기록");
    expect(timestampKindLabel("visited")).toBe("방문");
  });
});

describe("coded values (§4)", () => {
  it("EVTX level, logon type, detection severity", () => {
    expect(eventLevelLabel("0")).toBe("로그 항상(0)");
    expect(eventLevelLabel(4)).toBe("정보(4)");
    expect(logonTypeLabel("10")).toBe("10 — 원격 대화형(RDP)");
    expect(logonTypeLabel("3")).toBe("3 — 네트워크");
    expect(severityLabel("medium")).toBe("중간(medium)");
  });
});

describe("record banners (§3)", () => {
  const ids = (row: GridRow) => recordBanners(row).map((b) => b.id);
  it("string candidates, invalid content and synthetic media are flagged as not evidence", () => {
    expect(ids(artifact("amcache-string-candidate", {}))).toContain("string-candidate");
    expect(
      recordBanners(artifact("recent-shortcut-invalid-content", { detected_content_label: "ZIP" }))[0]?.title,
    ).toBe("내용 불일치 — 아티팩트로 해석되지 않음");
    expect(recordBanners(artifact("synthetic-media-image", {}, "synthetic-media"))[0]?.title).toBe(
      "진위 판정 아님",
    );
  });
  it("record state, template names, decode errors, truncation, acquisition copy, cautions", () => {
    expect(ids(artifact("eventlog-record-candidate", { evtx_record_state: "slack-recovered" }))).toContain(
      "state-slack-recovered",
    );
    expect(ids(artifact("eventlog-event", { evtx_record_id_position: "stale-below-first" }))).toContain(
      "state-stale-below-first",
    );
    expect(ids(artifact("eventlog-event", { event_data_key_status: "template-undecoded" }))).toContain(
      "template-undecoded",
    );
    expect(ids(artifact("eventlog-event", { evtx_decode_error: "bad token" }))).toContain("decode-error");
    const cut = recordBanners(
      artifact("jumplist-automatic", {
        destinations_truncated: true,
        destinations_total: 40,
        destinations: [1, 2],
      }),
    ).find((b) => b.id === "truncated");
    expect(cut?.detail).toContain("40개 중 2개");
    expect(ids(artifact("prefetch-file", { source_file_mtime: "2026-01-01T00:00:00Z" }))).toContain(
      "acquisition-copy",
    );
    expect(ids(artifact("eventlog-event", { caution_labels: ["timestamp-out-of-range-future"] }))).toContain(
      "caution",
    );
    expect(ids(artifact("eventlog-event", { event_id: "1" }))).toEqual([]);
  });
  it("one note when the two confidence values disagree", () => {
    const row = artifact("prefetch-file", { parser_confidence: "medium" }, "windows-prefetch", {
      fields: { details: { parser_confidence: "medium" }, artifact_record: { confidence: 0.95 } },
    });
    expect(recordBanners(row).filter((b) => b.id === "confidence")).toHaveLength(1);
    const agree = artifact("prefetch-file", { parser_confidence: 0.9 }, "windows-prefetch", {
      fields: { details: { parser_confidence: 0.9 }, artifact_record: { confidence: 0.9 } },
    });
    expect(recordBanners(agree).some((b) => b.id === "confidence")).toBe(false);
  });
});

describe("pivots (§5)", () => {
  const byId = (row: GridRow | null) => new Map(recordPivots(row, "r1").map((p) => [p.id, p]));
  it("field filters on the same kind for direct keys; search for derived values", () => {
    const pivots = byId(
      artifact("eventlog-event", {
        user_sid: "S-1-5-21-1-2-3-1001",
        timestamp: "2024-04-01T12:34:56Z",
        event_data: { TargetLogonId: "0x3e7" },
      }),
    );
    expect(pivots.get("same-user")?.route).toMatchObject({
      collection: "artifacts",
      kind: "eventlog",
      cf: [{ col: "f:user_sid", op: ":", value: "S-1-5-21-1-2-3-1001" }],
    });
    expect(pivots.get("same-logon")?.route).toMatchObject({ collection: "search", q: "0x3e7" });
    expect(pivots.get("timeline-window")?.route).toMatchObject({
      collection: "timeline",
      from: "2024-04-01T12:29:56.000Z",
      to: "2024-04-01T12:39:56.000Z",
    });
    expect(pivots.get("same-source")?.route).toMatchObject({ path: "C:/e/Security.evtx" });
  });
  it("absent fields give a reason (DisabledReason) instead of a route", () => {
    const pivots = byId(artifact("prefetch-file", { executable_hint: "CMD.EXE" }, "windows-prefetch"));
    expect(pivots.get("same-logon")?.reason).toBe("이 레코드에 로그온 ID가 없습니다.");
    expect(pivots.get("same-key")?.reason).toContain("레지스트리 키");
    expect(pivots.get("matched-event")?.reason).toContain("matched_event");
    expect(pivots.get("source-artifact")?.reason).toContain("source_record");
    expect(pivots.get("same-target")?.route).toBeTruthy();
    expect([...byId(null).values()].every((p) => p.reason === "뷰어에 표시된 행이 없습니다.")).toBe(true);
  });
  it("detection → original event; timeline event → source artifact", () => {
    const detection = byId(
      artifact("eventlog-detection", { matched_event: { record_id: "1001", path: "C:/e/Security.xml" } }),
    );
    expect(detection.get("matched-event")?.route).toMatchObject({
      collection: "artifacts",
      kind: "eventlog",
      types: ["eventlog-event"],
      cf: [{ col: "f:record_id", op: ":", value: "1001" }],
    });
    const event: GridRow = {
      ...artifact("x", {}),
      ref: { collection: "timeline", locator: "/events/4" },
      fields: { sourceRecord: { output: "artifacts_windows-prefetch", row_index: 7 } },
    };
    expect(byId(event).get("source-artifact")?.route).toEqual({
      runId: "r1",
      collection: "artifacts",
      kind: "windows-prefetch",
      row: { collection: "artifacts", kind: "windows-prefetch", locator: "/artifacts/7" },
    });
  });
  it("SID names: well-known locally, machine accounts from the run's SAM rows", () => {
    expect(wellKnownSid("S-1-5-18")?.name).toContain("SYSTEM");
    const sam = { bySid: new Map([["S-1-5-21-1-2-3-1001", "alice"]]), byRid: new Map([["1002", "bob"]]) };
    expect(resolveSid("S-1-5-21-1-2-3-1001", sam)).toEqual({ name: "alice", source: "sam" });
    expect(resolveSid("S-1-5-21-9-9-9-1002", sam)?.name).toBe("bob");
    expect(resolveSid("S-1-5-21-9-9-9-500", null)?.source).toBe("rid");
    expect(resolveSid("S-1-5-21-9-9-9-1500", null)).toBeNull();
  });
});

describe("grid presets per family (§7)", () => {
  const visible = (kind: string, types?: string[]) =>
    artifactColumnsForKind(kind, types)
      .filter((c) => c.id.startsWith("d:") && c.presets.includes("analysis"))
      .map((c) => c.header);
  it("kind presets", () => {
    expect(visible("windows-registry")).toEqual(["키 경로", "값 이름", "값 종류", "마지막 기록"]);
    expect(visible("browser")).toEqual(["URL", "제목", "방문 수", "전환"]);
    expect(visible("windows-shellbags")).toEqual(["경로", "MRU", "키 기록 시각"]);
    expect(visible("windows-prefetch")).toEqual(["실행 파일", "실행 횟수", "최근 실행", "볼륨"]);
    expect(visible("recent-files")).toEqual(["대상", "대상 수정", "볼륨 시리얼", "머신 ID"]);
    expect(visible("windows-os-account")).toEqual(["계정", "RID", "마지막 로그온", "로그온 수"]);
  });
  it("type-family presets follow the 유형 filter", () => {
    expect(artifactTypeFamily(["browser-download"])).toBe("browser-download");
    expect(artifactTypeFamily(["browser-download", "browser-visit"])).toBeUndefined();
    expect(visible("browser", ["browser-download"])).toEqual(["URL", "대상 경로", "크기", "상태"]);
    expect(visible("windows-registry", ["windows-usb-device"])).toEqual([
      "장치명",
      "시리얼",
      "VID/PID",
      "마지막 연결",
    ]);
    expect(visible("windows-os-account", ["windows-sam-account"])).toEqual([
      "계정",
      "RID",
      "마지막 로그온",
      "로그온 수",
    ]);
    expect(visible("windows-system", ["task-scheduler-task"])).toEqual([
      "작업 경로",
      "명령",
      "작성자",
      "트리거",
    ]);
  });
});

describe("citation (§8)", () => {
  const row = artifact("eventlog-event", {
    record_id: "1001",
    event_id: "4624",
    timestamp: "2024-04-01T12:34:56.000000+00:00",
  });
  it("viewer citation carries the record id, the record time and the container hash label", () => {
    const text = buildCitation(
      { ref: row.ref, runId: "r1", sourcePath: "C:/e/Security.evtx" },
      "abc",
      row,
      "Asia/Seoul",
    );
    expect(text).toContain("컨테이너 sha256=abc");
    expect(text).toContain("레코드=EventRecordID 1001");
    expect(text).toContain("시각=생성 시각: 2024-04-01 21:34:56 (KST+09:00) · UTC 12:34:56");
    expect(text.indexOf("레코드=")).toBeLessThan(text.indexOf("런=r1"));
  });
  it("grid citation too", () => {
    const text = citationText({ ...row, sha256: "abc" });
    expect(text).toContain("컨테이너 sha256=abc");
    expect(text).toContain("레코드=EventRecordID 1001");
    expect(text).toContain("시각=생성 시각: 2024-04-01");
  });
});

describe("EVTX record reconstruction (§6) and registry binary values (§9)", () => {
  it("rebuilds Event XML from System + EventData, escaping values", () => {
    const fields = {
      provider_name: "Microsoft-Windows-Security-Auditing",
      event_id: "4624",
      level: "0",
      timestamp: "2024-04-01T12:34:56Z",
      record_id: "1001",
      channel: "Security",
      computer: "WIN<1>",
      event_data: { TargetUserName: "alice", IpAddress: "10.0.0.5" },
    };
    expect(hasEventRecord("eventlog-event", fields)).toBe(true);
    expect(hasEventRecord("prefetch-file", fields)).toBe(false);
    const xml = eventRecordXml(fields);
    expect(xml).toContain('<Provider Name="Microsoft-Windows-Security-Auditing" />');
    expect(xml).toContain("<EventID>4624</EventID>");
    expect(xml).toContain('<TimeCreated SystemTime="2024-04-01T12:34:56Z" />');
    expect(xml).toContain("<EventRecordID>1001</EventRecordID>");
    expect(xml).toContain("<Computer>WIN&lt;1&gt;</Computer>");
    expect(xml).toContain('<Data Name="IpAddress">10.0.0.5</Data>');
  });
  it("parses .reg hex text, dumps it and extracts UTF-16 strings", () => {
    const bytes = bytesOfHex("hex:43,00,3a,00,5c,00,57,00,69,00,6e,00,00,00");
    expect(bytes?.length).toBe(14);
    expect(utf16Strings(bytes as Uint8Array)).toEqual(["C:\\Win"]);
    expect(hexDump(bytes as Uint8Array)[0]?.offset).toBe("00000000");
    expect(bytesOfHex("hex(7):41,00,\\\n  42,00")).toEqual(new Uint8Array([0x41, 0, 0x42, 0]));
    expect(bytesOfHex("not hex")).toBeNull();
  });
  it("hides garbage UTF-16 strings (binary read as text) and counts them", () => {
    expect(isReadableString("C:\\Users\\alice\\Desktop")).toBe(true);
    expect(isReadableString("한글 문서.docx")).toBe(true);
    expect(isReadableString("\u4e00\u9fa5\ua000\u4e8c\u4e09")).toBe(false);
    expect(isReadableString("\u0001\u0002ab")).toBe(false);
    expect(filterUtf16Strings(["report.pdf", "\u4e00\u9fa5\ua000\u4e8c\u4e09"])).toEqual({
      shown: ["report.pdf"],
      hidden: 1,
    });
  });
});
