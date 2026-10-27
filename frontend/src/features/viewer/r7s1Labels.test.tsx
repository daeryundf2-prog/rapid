// R7 stage 1 re-review R-10: raw machine values left on screen read in Korean — the registry
// citation line, the SQLite sidecar banner, the grid footer total and the record view's
// 핵심 / 출처 ids (collection, output name, profile keys).
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { citationDisplay } from "../explorers/RegistryExplorer";
import { KIND_COLUMNS } from "../grid/columns/artifacts";
import { GridFooter } from "../grid/GridToolbar";
import { outputNameLabel, sourceRecordLabel, valueReading } from "./fieldSheets";
import { metaLabel } from "./views/metaLabels";
import { sidecarLabel, walHeaderStatusLabel } from "./views/SqliteView";

afterEach(cleanup);

describe("R-10: registry citation line", () => {
  it("formats the last-written time and names the cell offset in hex and decimal", () => {
    const line = citationDisplay(
      {
        text: "D:\\ev\\BBI › HKLM\\BBI › 마지막 기록 2025-02-23T13:47:27.7191191+00:00 › 셀 오프셋 0x1020",
        hive_path: "D:\\ev\\BBI",
        key_path: "HKLM\\BBI",
        last_written_at: "2025-02-23T13:47:27.7191191+00:00",
        cell_offset: 0x1020,
        kind: "windows-registry",
        record_index: null,
        locator: null,
      },
      "Asia/Seoul",
    );
    expect(line).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
    expect(line).toContain("마지막 기록 2025-02-23 22:47:27");
    expect(line).toContain("셀 오프셋 0x1020 (4,128)");
    expect(line.startsWith("D:\\ev\\BBI › HKLM\\BBI")).toBe(true);
  });
});

describe("R-10: SQLite sidecar banner", () => {
  it("sidecar ids and WAL header states read in Korean", () => {
    expect(sidecarLabel("rollback_journal")).toBe("롤백 저널");
    expect(sidecarLabel("wal")).toBe("WAL");
    expect(walHeaderStatusLabel("parsed")).toBe("해석됨");
    expect(walHeaderStatusLabel("unknown-magic")).toBe("알 수 없는 형식(매직 불일치)");
    expect(walHeaderStatusLabel(undefined)).toBe("미해석");
    expect(walHeaderStatusLabel("weird")).toBe("미분류 상태(weird)");
  });
});

describe("R-10: grid footer total", () => {
  const props = {
    page: 1,
    pageCount: null,
    total: null,
    shown: 0,
    backend: "",
    elapsedMs: 0,
    truncated: false,
    filtering: false,
    sorting: false,
    loadedCount: 0,
    canLoadMore: false,
    onLoadMore: () => {},
    loading: false,
  };
  it("an uncounted total reads 전체 건수 미확정, never 총 알 수 없음", () => {
    render(<GridFooter {...props} />);
    expect(screen.getByTestId("grid-footer-total").textContent).toBe("전체 건수 미확정");
  });
  it("a counted total still reads 총 N건", () => {
    render(<GridFooter {...props} total={4770} />);
    expect(screen.getByTestId("grid-footer-total").textContent).toBe("총 4,770건");
  });
});

describe("R-10: record view ids", () => {
  it("collection, output name, source row, collector and platform read in Korean", () => {
    expect(valueReading(null, "source", "artifacts")).toBe("아티팩트 출력");
    expect(outputNameLabel("artifacts_windows-execution")).toBe("실행 흔적 출력");
    expect(valueReading(null, "output", "artifacts_windows-execution")).toBe("실행 흔적 출력");
    expect(sourceRecordLabel({ output: "artifacts_windows-execution", row_index: 3358 })).toBe(
      "실행 흔적 출력 · 행 3,358",
    );
    expect(valueReading(null, "sourceRecord", { output: "artifacts_recent-files", row_index: 2747 })).toBe(
      "최근 파일·LNK 출력 · 행 2,747",
    );
    expect(valueReading(null, "kind", "windows-execution")).toBe("실행 흔적");
    expect(valueReading(null, "provider", "windows-recent-files")).toBe("최근 파일·LNK");
    expect(valueReading(null, "source_platform", "windows")).toBe("Windows");
    // An unknown id stays as written (no invented reading).
    expect(valueReading(null, "kind", "no-such-kind")).toBeUndefined();
  });

  it("profile keys have Korean labels", () => {
    expect(metaLabel("source_database")).toBe("원본 데이터베이스");
    expect(metaLabel("profile_dir")).toBe("프로필 폴더");
    expect(metaLabel("source_platform")).toBe("원본 플랫폼");
  });

  it("the windows-execution 키 기록 column is a time column (no raw ISO)", () => {
    const column = (KIND_COLUMNS["windows-execution"] ?? []).find((c) => c.header === "키 기록");
    expect(column?.time).toBe(true);
  });
});
