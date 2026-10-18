/**
 * R3 console fix (adversarial review of the R3 surface): analysis grids take their catalogue family
 * (타임스탬프 불일치 · $LogFile · 카빙), Prefetch volumes / run times, PCA and Office MRU time kinds,
 * Korean value readings of the R3 families. Uses the real catalogue (families.fallback.json).
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ColumnFilter, GridRow } from "../../contracts/collection";
import { useAppStore } from "../../state/store";
import { formatGridTime } from "../../utils/time";
import { artifactTypeLabel } from "../filters/typeLabels";
import { type CatalogFamily, FALLBACK_CATALOG, familyById, setCatalog } from "../flags/catalog";
import { analysisCollection, analysisColumnsForKind, analysisFamily } from "./columns/analysis";
import { makeRef, makeRow } from "./columns/common";
import { catalogColumn, cellTsKind, familyColumnId, readKey } from "./columns/families";
import type { ColumnSpec } from "./types";

const SOURCE = (value: string): ColumnFilter[] => [{ col: "f:source", op: ":", value }];

function row(details: Record<string, unknown>, artifactType = "x"): GridRow {
  return makeRow(makeRef("analysis", "/rows/0", "a1"), { title: "t", artifactType }, { details });
}

function family(id: string): CatalogFamily {
  const found = familyById(id);
  if (!found) throw new Error(`family ${id} missing from the catalogue`);
  return found;
}

function column(columns: ColumnSpec[], key: string): ColumnSpec {
  const found = columns.find((c) => c.id === familyColumnId(key));
  if (!found) throw new Error(`column ${key} missing`);
  return found;
}

function catalogCol(familyId: string, key: string): ColumnSpec {
  const fam = family(familyId);
  const def = [...fam.core_columns, ...fam.aux_columns].find((c) => c.key === key);
  if (!def) throw new Error(`${familyId}.${key} missing`);
  return catalogColumn(def);
}

beforeEach(() => {
  setCatalog(FALLBACK_CATALOG, "server");
  useAppStore.setState({ timezone: "Asia/Seoul" });
});
afterEach(() => {
  setCatalog(null);
  useAppStore.setState({ timezone: null });
});

describe("#1 analysis grids take their catalogue family", () => {
  it("resolves the family from the node's f:source, the carve job, or the rows' one type", () => {
    expect(analysisFamily("ntfs-meta", SOURCE("timestamp-mismatch"))?.id).toBe("ntfs-timestamp-mismatch");
    expect(analysisFamily("ntfs-meta", SOURCE("logfile-transaction"))?.id).toBe("ntfs-logfile-transaction");
    expect(analysisFamily("carve", [])?.id).toBe("carved-file");
    // MFT/USN (and several sources) keep the kind's own columns.
    expect(analysisFamily("ntfs-meta", SOURCE("mft,usn"))).toBeUndefined();
    expect(analysisFamily("ntfs-meta", SOURCE("mft,timestamp-mismatch"))).toBeUndefined();
    expect(analysisFamily("ntfs-meta", [], ["ntfs-timestamp-mismatch"])?.id).toBe("ntfs-timestamp-mismatch");
    expect(analysisFamily("ntfs-meta", [], ["ntfs-meta-row", "ntfs-timestamp-mismatch"])).toBeUndefined();
  });

  it("타임스탬프 불일치: all 8 SI/FN times with their kinds + 사유, no USN columns", () => {
    const columns = analysisCollection.columnsFor?.(
      { id: "analysis", kind: "ntfs-meta", analysisId: "a1" },
      [],
      { columnFilters: SOURCE("timestamp-mismatch") },
    ) as ColumnSpec[];
    const headers = columns.filter((c) => c.presets.includes("analysis")).map((c) => c.header);
    for (const header of [
      "사유",
      "$SI 생성",
      "$SI 수정",
      "$SI 접근",
      "$SI MFT 수정",
      "$FN 생성",
      "$FN 수정",
      "$FN 접근",
      "$FN MFT 수정",
    ])
      expect(headers).toContain(header);
    expect(columns.map((c) => c.header)).not.toContain("USN 사유");
    expect(columns.map((c) => c.header)).not.toContain("USN 시각");
    const fnAccessed = column(columns, "fn_accessed_at");
    const mismatch = row(
      { fn_accessed_at: "2024-01-02T03:04:05Z", in_use: false, reason: "$SI 생성 < $FN 생성" },
      "ntfs-timestamp-mismatch",
    );
    expect(fnAccessed.tooltip?.(mismatch)).toContain("FN 접근(fn-accessed)");
    expect(
      column(columns, "si_created_at").tooltip?.(row({ si_created_at: "2024-01-01T00:00:00Z" })),
    ).toContain("SI 생성(si-created)");
    // 유형 reads Korean; 사용 중 reads 예/아니요.
    const type = columns.find((c) => c.id === "type") as ColumnSpec;
    expect(type.format?.(mismatch)).toBe("NTFS 타임스탬프 불일치");
    expect(column(columns, "in_use").format?.(mismatch)).toBe("아니요(삭제된 레코드)");
  });

  it("$LogFile: LSN · 시각 추정 · 작업 · 대상 MFT · 파일 이름 후보", () => {
    const columns = analysisColumnsForKind("ntfs-meta", family("ntfs-logfile-transaction"));
    const shown = columns.filter((c) => c.presets.includes("analysis")).map((c) => c.id);
    for (const key of ["lsn", "time_estimate", "redo_op_label", "target_mft_entry", "file_name"])
      expect(shown).toContain(familyColumnId(key));
    const estimate = column(columns, "time_estimate");
    expect(estimate.header).toBe("시각 추정");
    expect(estimate.tooltip?.(row({ time_estimate: "2024-01-01T00:00:00Z" }))).toContain("FN 생성");
    expect(column(columns, "file_name").format?.(row({ file_name_candidates: ["a.txt", "b.txt"] }))).toBe(
      "a.txt, b.txt",
    );
  });

  it("카빙: status / boundary_method / recovery_method read Korean, offsets read hex", () => {
    const columns = analysisCollection.columnsFor?.({ id: "analysis", kind: "carve", analysisId: "c1" }, [], {
      columnFilters: [],
    }) as ColumnSpec[];
    const carved = row(
      {
        status: "footer-validated",
        boundary_method: "box-walk",
        recovery_method: "carved",
        offset: 512,
        confidence: "high",
      },
      "carve-row",
    );
    expect(column(columns, "status").format?.(carved)).toBe("끝 표식 확인");
    expect(column(columns, "status").tooltip?.(carved)).toContain("원래 값: footer-validated");
    expect(column(columns, "boundary_method").format?.(carved)).toBe("박스 순회(MP4/M4A)");
    expect(column(columns, "recovery_method").format?.(carved)).toBe("카빙");
    expect(column(columns, "offset").format?.(carved)).toBe("0x200");
    expect(column(columns, "confidence").format?.(carved)).toBe("높음");
  });

  it("analysis row types have Korean names (유형)", () => {
    expect(artifactTypeLabel("ntfs-timestamp-mismatch")).toBe("NTFS 타임스탬프 불일치");
    expect(artifactTypeLabel("ntfs-logfile-transaction")).toBe("$LogFile 트랜잭션");
    expect(artifactTypeLabel("carve-row")).toBe("카빙 결과");
    expect(artifactTypeLabel("ntfs-meta-row")).toBe("MFT/USN 레코드");
  });
});

describe("#3 Prefetch volumes and run times", () => {
  it("volumes read 장치 · VSN · 생성 시각 (display timezone), never JSON", () => {
    const volumes = catalogCol("prefetch-file", "volumes");
    const created = "2023-05-06T07:08:09Z";
    const text = volumes.format?.(
      row({
        volumes: [
          {
            volume_device_path: "\\VOLUME{01d8}",
            volume_serial_number: "1234ABCD",
            volume_created_at: created,
            directory_strings: ["\\WINDOWS"],
          },
        ],
      }),
    );
    expect(text).toBe(`\\VOLUME{01d8} · VSN 1234ABCD · 생성 ${formatGridTime(created, "Asia/Seoul")}`);
    expect(text).not.toContain('{"');
  });

  it("the run-time list is shown in the display timezone; 실행 1회차…8회차 columns", () => {
    const times = ["2024-03-01T10:00:00Z", "2024-02-01T10:00:00Z"];
    const list = catalogCol("prefetch-file", "last_run_times");
    expect(list.format?.(row({ last_run_times: times }))).toBe(
      times.map((t) => formatGridTime(t, "Asia/Seoul")).join(", "),
    );
    const fam = family("prefetch-file");
    const runCols = fam.aux_columns.filter((c) => c.key.startsWith("run_time_"));
    expect(runCols.map((c) => c.label)).toEqual([1, 2, 3, 4, 5, 6, 7, 8].map((n) => `실행 ${n}회차`));
    expect(runCols.map((c) => c.ts_kind)).toEqual([1, 2, 3, 4, 5, 6, 7, 8].map((n) => `run-${n}`));
    // Older rows without run_time_N: the list index alias reads the slot.
    const second = catalogCol("prefetch-file", "run_time_2");
    const older = row({ last_run_times: times });
    expect(second.format?.(older)).toBe(formatGridTime(times[1] as string, "Asia/Seoul"));
    expect(second.tooltip?.(older)).toContain("실행 2회차(run-2)");
    expect(readKey({ last_run_times: times }, "last_run_times.1")).toBe(times[1]);
    expect(readKey({ last_run_times: times }, "last_run_times.7")).toBeUndefined();
  });
});

describe("#6 / m PCA and Office MRU time kinds", () => {
  it("PCA rows use their own kind (timestamp_kind, else timestamp_label)", () => {
    const pca = family("pca");
    const def = pca.core_columns.find((c) => c.key === "timestamp");
    if (!def) throw new Error("pca timestamp column missing");
    expect(def.ts_kind).not.toBe("run");
    expect(cellTsKind(def, { timestamp_label: "last_run" }, "timestamp")).toBe("run");
    expect(cellTsKind(def, { timestamp_label: "pca_event" }, "timestamp")).toBe("pca-event");
    expect(cellTsKind(def, { timestamp_label: "last_written" }, "last_run_at")).toBe("last-written");
    expect(cellTsKind(def, { timestamp_kind: "run", timestamp_label: "pca_event" }, "timestamp")).toBe("run");
    const cell = catalogColumn(def);
    expect(
      cell.tooltip?.(row({ timestamp: "2024-01-01T00:00:00Z", timestamp_label: "pca_event" })),
    ).toContain("PCA 이벤트(pca-event)");
  });

  it("Office MRU 마지막 열기 is last-opened (same kind as the timeline)", () => {
    const def = family("office-mru").core_columns[0];
    expect(def?.ts_kind).toBe("last-opened");
  });
});

describe("m value labels of the R3 registry / BitLocker families", () => {
  it.each([
    ["known-dll", "in_default_baseline", true, "예"],
    ["known-dll", "in_default_baseline", false, "아니요"],
    ["known-dll", "entry_kind", "directory", "디렉터리(DllDirectory)"],
    ["network-profile", "signature_scope", "Managed", "관리됨(도메인)"],
    ["network-profile", "profile_key_missing", true, "예(서명만 남음)"],
    ["antiforensics", "key_format_valid", false, "유효하지 않음"],
    ["antiforensics", "identifier_matches_file_name", true, "일치"],
  ] as const)("%s.%s %s → %s", (familyId, key, raw, text) => {
    expect(catalogCol(familyId, key).format?.(row({ [key]: raw }))).toBe(text);
  });
});
