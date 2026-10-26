/**
 * R7 stage 1 L3: the value-label table (C-D9), unique histogram labels (C-V1), legacy timeline
 * summary prefixes (C-D13) and the card title (C-V3).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { RunTree } from "../../api/runs";
import type { GridRow } from "../../contracts/collection";
import { FALLBACK_CATALOG, familyById, setCatalog } from "../flags/catalog";
import { barsFromRows, barsFromTree } from "../views/histogram";
import { uniqueLabels } from "./columns/families";
import { stripLegacySummaryPrefix } from "./columns/timeline";
import {
  evidenceFieldLabel,
  evidenceValueText,
  keyValueReading,
  labelledCell,
  typeDisplayLabel,
  valueLabel,
  valueListLabel,
} from "./valueLabels";

beforeEach(() => setCatalog(FALLBACK_CATALOG, "server"));
afterEach(() => setCatalog(null));

function row(fields: Record<string, unknown>, artifactType: string | null = null): GridRow {
  return {
    rowKey: "r0",
    ref: { collection: "indicators", locator: "/indicators/0" },
    title: "x",
    sourcePath: null,
    timestamp: null,
    artifactType,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields,
  };
}

describe("value labels (C-D9)", () => {
  it("reads indicator type, scope and risk tags in Korean; the raw value is the tooltip", () => {
    expect(valueLabel("indicatorType", "ip")).toBe("IP");
    expect(valueLabel("indicatorType", "url")).toBe("URL");
    expect(valueLabel("indicatorScope", "global")).toBe("공인");
    expect(valueLabel("indicatorScope", "private")).toBe("사설망");
    // `network` is the class of URL/domain indicators (indicators.py classify_indicator), not 내부망.
    expect(valueLabel("indicatorScope", "network")).toBe("네트워크");
    expect(valueListLabel("riskTag", "network-indicator, cleartext-url")).toBe("네트워크 지표, 평문 URL");
    expect(valueListLabel("riskTag", ["global-ip"])).toBe("공인 IP");
    const cell = labelledCell("indicatorScope", (r) => String(r.fields.classification ?? ""));
    const r = row({ classification: "global" });
    expect(cell.format?.(r)).toBe("공인");
    expect(cell.tooltip?.(r)).toBe("공인 (원래 값: global)");
  });

  it("covers browser, source, document kind and the shared record keys", () => {
    expect(valueLabel("browser", "edge")).toBe("Edge");
    expect(valueLabel("source", "documents")).toBe("문서");
    expect(valueLabel("source", "artifacts")).toBe("아티팩트");
    expect(valueLabel("source", "path")).toBe("경로");
    expect(valueLabel("docKind", "log")).toBe("로그(LOG)");
    expect(keyValueReading("evidence_nature", "registry-string-trace")).toBe("레지스트리 문자열 흔적");
    expect(keyValueReading("drive_type_name", "fixed")).toBe("고정 디스크");
    expect(keyValueReading("item_kind", "directory")).toBe("폴더");
    expect(keyValueReading("binary_type", "pe64_amd64")).toBe("PE64(x64)");
    expect(keyValueReading("content_format", "png")).toBe("PNG");
    expect(keyValueReading("danger_type", "POTENTIALLY_UNWANTED")).toBe("원치 않는 프로그램 가능성");
    expect(keyValueReading("browser", "edge")).toBe("Edge");
    // A key without a domain, or a value the table does not know, has no reading (shown as written).
    expect(keyValueReading("comment", "edge")).toBeUndefined();
    expect(valueLabel("browser", "netscape")).toBe("netscape");
  });

  it("names types by the tree / family, never the raw id when a name exists", () => {
    expect(typeDisplayLabel("browser-history")).not.toBe("browser-history");
    expect(typeDisplayLabel("")).toBe("");
    expect(typeDisplayLabel("zz-unknown-type")).toBe("zz-unknown-type");
  });

  it("names flag evidence fields by the family column (C-R4) and reads their values", () => {
    const browser = familyById("browser-download");
    const label = evidenceFieldLabel(browser, "danger_type");
    expect(label).not.toBeNull();
    expect(label).not.toBe("danger_type");
    expect(evidenceValueText("browser-download", "danger_type", "USER_VALIDATED")).toBe("사용자가 허용함");
    expect(evidenceFieldLabel(undefined, "zz_unknown_key")).toBeNull();
  });
});

describe("unique histogram labels (C-V1)", () => {
  it("qualifies a shared label by its group, then numbers what still collides", () => {
    const out = uniqueLabels([
      { label: "실행 흔적", context: "운영체제·계정" },
      { label: "실행 흔적", context: "실행 흔적" },
      { label: "실행 흔적", context: "연결 장치·원격" },
      { label: "Prefetch", context: "실행 흔적" },
      { label: "A", context: "g" },
      { label: "A", context: "g" },
    ]).map((entry) => entry.label);
    expect(out).toEqual([
      "실행 흔적 · 운영체제·계정",
      "실행 흔적",
      "실행 흔적 · 연결 장치·원격",
      "Prefetch",
      "A · g",
      "A · g (2)",
    ]);
    expect(new Set(out).size).toBe(out.length);
  });

  it("barsFromTree: a kind split over three groups yields three distinct labels", () => {
    const kindNode = (id: string, kind: string, label: string, count: number) => ({
      id,
      label,
      count,
      kind,
      collection: "artifacts",
      children: [],
    });
    const tree = {
      run_id: "r",
      nodes: [
        {
          id: "artifacts",
          label: "아티팩트",
          count: 0,
          collection: "artifacts",
          children: [
            {
              id: "artifacts-group:os",
              label: "운영체제·계정",
              count: 0,
              children: [
                kindNode("artifacts:windows-execution@os", "windows-execution", "실행 흔적", 16),
                kindNode("artifacts:windows-registry@os", "windows-registry", "레지스트리 하이브", 863),
              ],
            },
            {
              id: "artifacts-group:execution",
              label: "실행 흔적",
              count: 0,
              children: [kindNode("artifacts:windows-execution", "windows-execution", "실행 흔적", 4283)],
            },
            {
              id: "artifacts-group:registry",
              label: "레지스트리",
              count: 0,
              children: [
                kindNode("artifacts:windows-registry", "windows-registry", "레지스트리 하이브", 250226),
              ],
            },
            {
              id: "artifacts-group:devices",
              label: "연결 장치·원격",
              count: 0,
              children: [
                kindNode("artifacts:windows-execution@devices", "windows-execution", "실행 흔적", 193),
                kindNode("artifacts:windows-registry@devices", "windows-registry", "레지스트리 하이브", 49),
              ],
            },
          ],
        },
      ],
    } as unknown as RunTree;
    const labels = barsFromTree(tree, undefined).map((bar) => bar.label);
    expect(labels).toHaveLength(6);
    expect(new Set(labels).size).toBe(6);
    expect(labels).toContain("레지스트리 하이브 · 운영체제·계정");
    expect(labels).toContain("실행 흔적");
  });

  it("barsFromRows names artifact types in Korean", () => {
    const rows = [row({}, "browser-history"), row({}, "browser-history"), row({}, "zz-type")];
    const bars = barsFromRows(rows, "artifacts");
    expect(bars[0]?.label).toBe(typeDisplayLabel("browser-history"));
    expect(bars[0]?.artifactType).toBe("browser-history");
  });
});

describe("timeline legacy summary prefixes (C-D13)", () => {
  it("strips 'Artifact event: <type> ' and 'EventLog event: ' at display", () => {
    expect(stripLegacySummaryPrefix("Artifact event: jumplist-automatic C:\\a.lnk")).toBe("C:\\a.lnk");
    expect(stripLegacySummaryPrefix("EventLog event: 4624 로그온")).toBe("4624 로그온");
    expect(stripLegacySummaryPrefix("일반 요약")).toBe("일반 요약");
    expect(stripLegacySummaryPrefix(null)).toBeNull();
  });
});
