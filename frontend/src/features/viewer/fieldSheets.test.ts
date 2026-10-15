import { describe, expect, it } from "vitest";
import type { GridRow } from "../../contracts/collection";
import {
  FIELD_SHEETS,
  type FieldSheet,
  fieldLabel,
  humanizeKey,
  isGovernanceKey,
  recordIdentifier,
  recordLayout,
  sheetForType,
} from "./fieldSheets";

function artifact(
  type: string,
  details: Record<string, unknown>,
  kind = "k",
  extra: Record<string, unknown> = {},
): GridRow {
  return {
    rowKey: `artifacts:${kind}:/artifacts/1`,
    ref: { collection: "artifacts", kind, locator: "/artifacts/1" },
    title: "t",
    sourcePath: "C:/e/src.bin",
    timestamp: null,
    artifactType: type,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: { details, ...extra },
  };
}

/** A type the sheet resolves for: its first exact type, else prefix + "x", else "x" + suffix. */
function typeOf(sheet: FieldSheet): string {
  if (sheet.types?.length) return sheet.types[0] as string;
  if (sheet.prefixes?.length) return `${sheet.prefixes[0]}x`;
  return `x${sheet.suffixes?.[0] ?? ""}`;
}

const keysOf = (key: string | readonly string[]) => (typeof key === "string" ? [key] : [...key]);

describe("field sheets: every family", () => {
  it("resolves each sheet from its types / prefixes / suffixes", () => {
    for (const sheet of FIELD_SHEETS) {
      expect(sheetForType(typeOf(sheet))?.id, sheet.id).toBe(sheet.id);
    }
    // String scans of amcache/bam/shimcache are string candidates, not their families.
    expect(sheetForType("amcache-string-candidate")?.id).toBe("string-candidate");
    expect(sheetForType("windows-usb-device")?.id).toBe("usb");
    expect(sheetForType("registry-usb")?.id).toBe("usb");
    expect(sheetForType("registry-key-tree-node")?.id).toBe("registry");
    expect(sheetForType("unknown-type", "windows-registry")?.id).toBe("registry");
    expect(sheetForType("unknown-type")).toBeNull();
  });

  it("puts every core key of every family in 핵심, in sheet order", () => {
    for (const sheet of FIELD_SHEETS) {
      const details: Record<string, unknown> = {};
      const expected: string[] = [];
      for (const def of sheet.core) {
        const key = keysOf(def.key).find((k) => !(k in details));
        if (!key || expected.includes(key)) continue;
        details[key] = def.format === "time" ? "2025-05-29T14:25:26.427+00:00" : `값-${key}`;
        expected.push(key);
      }
      const layout = recordLayout(artifact(typeOf(sheet), details));
      expect(layout.sheet.id, sheet.id).toBe(sheet.id);
      const core = layout.core.map((entry) => entry.key);
      // Ordered, and nothing of the sheet falls out of 핵심.
      expect(core, sheet.id).toEqual(expected.filter((key) => core.includes(key)));
      expect(core.length, sheet.id).toBeGreaterThanOrEqual(Math.min(expected.length, sheet.core.length) - 2);
      for (const key of expected) {
        const placed = [...layout.core, ...layout.provenance, ...layout.other, ...layout.governance].some(
          (entry) => entry.key === key || entry.aliases.includes(key),
        );
        const inTable = layout.table?.key === key;
        expect(placed || inTable, `${sheet.id}/${key}`).toBe(true);
      }
    }
  });

  it("never hides unknown keys: they are listed under 기타 필드 with a humanised label", () => {
    const layout = recordLayout(
      artifact("eventlog-event", { event_id: "4624", danger_type_name: "x", visit_total_count: 3 }),
    );
    const other = layout.other.map((entry) => entry.key);
    expect(other).toContain("danger_type_name");
    expect(other).toContain("visit_total_count");
    expect(layout.other.find((e) => e.key === "visit_total_count")?.label).toBe("방문 합계 건수");
    expect(humanizeKey("last_visit_at")).toBe("마지막 방문 시각");
    expect(humanizeKey("payload_sha256")).toBe("payload SHA-256");
    expect(fieldLabel("source_path")).toBe("원본 경로");
  });

  it("folds only governance keys (commercial_* · validation_* · blockers · *_plan* · readiness · grade)", () => {
    const layout = recordLayout(
      artifact("prefetch-file", {
        executable_hint: "CMD.EXE",
        commercial_grade_ready: false,
        commercial_grade_blockers: ["x"],
        validation_required: true,
        prefetch_validation_matrix: {},
        browser_validation_checks: { a: 1 },
        recommended_validation: "diff",
        m365_export_report_grade_validation_plan: { a: 1 },
        court_report_ready: false,
        readiness: "blocked",
        grade: "B",
        blockers: ["y"],
        volume_count: 1,
      }),
    );
    const governance = layout.governance.map((e) => e.key);
    expect(governance).toEqual(
      expect.arrayContaining([
        "commercial_grade_ready",
        "commercial_grade_blockers",
        "validation_required",
        "browser_validation_checks",
        "recommended_validation",
        "m365_export_report_grade_validation_plan",
        "court_report_ready",
        "readiness",
        "grade",
        "blockers",
      ]),
    );
    // Evidence never lands in the governance fold.
    expect(governance).not.toContain("volume_count");
    expect(isGovernanceKey("source_path")).toBe(false);
    expect(isGovernanceKey("event_id")).toBe(false);
  });

  it("shows aliases once: event_id/eventId, detail vs message, sha256 vs source_hashes", () => {
    const layout = recordLayout(
      artifact(
        "eventlog-event",
        {
          event_id: "4624",
          event_message: "An account successfully logged on.",
          sha256: "AB",
          source_hashes: { sha256: "ab" },
        },
        "eventlog",
        { eventId: "4624", detail: "An account successfully logged on." },
      ),
    );
    const all = [...layout.core, ...layout.provenance, ...layout.other, ...layout.governance].map(
      (e) => e.key,
    );
    expect(all.filter((k) => k === "event_id")).toHaveLength(1);
    expect(all).not.toContain("eventId");
    expect(all).not.toContain("detail");
    expect(all).not.toContain("sha256");
    expect(layout.core.find((e) => e.key === "event_id")?.aliases).toContain("eventId");
    expect(layout.provenance.find((e) => e.key === "source_hashes")?.label).toBe("컨테이너 파일 해시");
  });

  it("EVTX: EventData is a table; top-level copies of its names are not listed twice", () => {
    const layout = recordLayout(
      artifact("eventlog-event", {
        event_id: "4624",
        logon_type: "10",
        event_data: { TargetUserName: "alice", IpAddress: "10.0.0.5", TargetLogonId: "0x3e7" },
        TargetUserName: "alice",
      }),
    );
    expect(layout.table?.label).toBe("EventData");
    expect(layout.table?.rows.map((r) => r.name)).toEqual(["TargetUserName", "IpAddress", "TargetLogonId"]);
    expect(layout.other.map((e) => e.key)).not.toContain("TargetUserName");
    // Fields only present in EventData are read from it (logon ID, source IP).
    const core = new Map(layout.core.map((e) => [e.label, e]));
    expect(core.get("로그온 ID")?.raw).toBe("0x3e7");
    expect(core.get("로그온 ID")?.key).toBe("event_data.TargetLogonId");
    expect(core.get("출발지 IP")?.raw).toBe("10.0.0.5");
    expect(core.get("로그온 유형")?.format).toBe("logonType");
  });

  it("detection: the rule object feeds 탐지 규칙 · 탐지 심각도 · MITRE, distinct from the event level", () => {
    const layout = recordLayout(
      artifact("eventlog-detection", {
        event_id: "4624",
        level: "0",
        rule: {
          title: "Remote interactive logon",
          id: "RT-1",
          level: "medium",
          mitre_tags: ["attack.t1021.001"],
        },
      }),
    );
    const byLabel = new Map(layout.core.map((e) => [e.label, e]));
    expect(byLabel.get("탐지 규칙")?.raw).toBe("Remote interactive logon");
    expect(byLabel.get("탐지 심각도")?.raw).toBe("medium");
    expect(byLabel.get("탐지 심각도")?.format).toBe("detectionSeverity");
    expect(byLabel.get("레벨")?.raw).toBe("0");
    expect(byLabel.get("레벨")?.format).toBe("eventLevel");
  });

  it("record identifiers for citations", () => {
    expect(recordIdentifier(artifact("eventlog-event", { record_id: "1001" }))).toEqual({
      label: "EventRecordID",
      value: "1001",
    });
    expect(recordIdentifier(artifact("registry-key", { key: "HKLM\\Run" }))).toEqual({
      label: "키 경로",
      value: "HKLM\\Run",
    });
    expect(recordIdentifier(artifact("task-scheduler-task", { task_uri: "\\Evil" }))?.value).toBe("\\Evil");
  });
  it("a 4624 without a logon ID still lists 로그온 ID as missing (absence is visible)", () => {
    const layout = recordLayout(artifact("eventlog-event", { event_id: "4624", logon_type: "10" }));
    const logonId = layout.core.find((e) => e.label === "로그온 ID");
    expect(logonId?.missing).toBe(true);
    expect(layout.core.find((e) => e.label === "출발지 IP")?.missing).toBe(true);
    expect(layout.core.find((e) => e.label === "로그온 유형")?.missing).toBeUndefined();
    // Not a logon event: nothing is invented.
    const other = recordLayout(artifact("eventlog-event", { event_id: "7045" }));
    expect(other.core.some((e) => e.missing)).toBe(false);
  });
});
