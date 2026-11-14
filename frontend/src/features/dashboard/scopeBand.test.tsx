import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { normalizeDashboard } from "../../api/dashboard";
import { koCount, ScopeBand } from "./scopeBand";

/** IMG-B-like `/dashboard` `scope` (T-023 server shape; counts only). */
const IMG_B_SCOPE = {
  profile_version: "rapidtriage-run-scope-v1",
  basis: "inferred",
  partitions: { total: 4, supported: 2, processed: 1 },
  allocated: {
    listed_pct: 100.0,
    content_pct: 99.9,
    basis: "inferred",
    records: null,
    copies: 145307,
    read_errors: 5,
  },
  deleted: {
    records: 486915,
    records_source: "extraction_stats",
    attempted: 56863,
    attempted_pct: 11.6,
    listed: 54693,
    listed_pct: 11.2,
    not_attempted: 430052,
    read_errors: 2170,
    directories: null,
  },
  unallocated: { scanned_pct: null, measured: false },
  caps: [
    { code: "native_extract_file_limit", limit: 200000, reached: true, skipped: 430052, axis: "deleted" },
  ],
  mft: null,
  partial: true,
  notes: [
    "추정: 처리 범위는 추출 통계와 $MFT 사본 머리 집계로 추론한 값입니다. Sleuth Kit fls·ils 대조 전까지 확정 수치가 아닙니다.",
    "지원 파일시스템 파티션 2개 중 1개만 처리했습니다.",
    "비할당 영역은 측정하지 않았습니다.",
  ],
};

const COMPLETE_SCOPE = {
  ...IMG_B_SCOPE,
  partitions: { total: 1, supported: 1, processed: 1 },
  allocated: { listed_pct: 100.0, content_pct: 100.0, basis: "inferred" },
  deleted: { records: 2, attempted: 2, attempted_pct: 100.0, listed_pct: 100.0, not_attempted: 0 },
  caps: [],
  partial: false,
  notes: ["추정: …", "비할당 영역은 측정하지 않았습니다."],
};

const UNAVAILABLE_SCOPE = {
  basis: "unavailable",
  partitions: { total: null, supported: null, processed: null },
  allocated: { listed_pct: null, content_pct: null, basis: "unavailable" },
  deleted: { records: null, attempted: null, attempted_pct: null, listed_pct: null },
  unallocated: { scanned_pct: null, measured: false },
  caps: [],
  mft: null,
  partial: null,
  notes: ["이 결과에는 추출 통계가 없어 처리 범위를 계산하지 않았습니다(폴더 증거 또는 이전 결과)."],
};

const scopeOf = (raw: unknown) => normalizeDashboard("r1", { scope: raw } as never).scope;

afterEach(cleanup);

describe("ScopeBand (T-024 processing-scope band)", () => {
  it("IMG-B: four axes on one amber line, server percentages as-is, cap and basis notes", () => {
    render(<ScopeBand scope={scopeOf(IMG_B_SCOPE)} />);
    const band = screen.getByTestId("dash-scope");
    const axes = [...band.querySelectorAll<HTMLElement>("[data-count]")];
    expect(axes.map((el) => el.dataset.axis)).toEqual(["partitions", "allocated", "deleted", "unallocated"]);
    expect(axes.map((el) => el.dataset.count)).toEqual(["1/2", "100", "430052", ""]);
    expect(axes.map((el) => el.textContent)).toEqual([
      "파티션 1/2",
      " · 할당 파일 목록화 100%(추정)",
      " · 삭제 레코드 43만 건 내용 미시도(시도 11.6%)",
      " · 비할당 측정하지 않음",
    ]);
    const extras = [...band.querySelectorAll(".dash-scope-extra")].map((el) => el.textContent);
    expect(extras).toEqual(["추출 상한 200,000개 도달", "Sleuth Kit 대조 전 추정"]);
    expect(band.textContent).not.toMatch(/볼륨의/);
    expect(screen.getByText("자세히")).toBeTruthy();
    expect(screen.getByText("지원 파일시스템 파티션 2개 중 1개만 처리했습니다.")).toBeTruthy();
  });

  it("complete image: every axis complete → no band", () => {
    const { container } = render(<ScopeBand scope={scopeOf(COMPLETE_SCOPE)} />);
    expect(container.innerHTML).toBe("");
  });

  it("no stats (folder evidence, older result): neutral note, no band", () => {
    render(<ScopeBand scope={scopeOf(UNAVAILABLE_SCOPE)} />);
    expect(screen.queryByTestId("dash-scope")).toBeNull();
    expect(screen.getByTestId("dash-scope-note").textContent).toContain("추출 통계가 없어");
  });

  it("server without scope: nothing", () => {
    const { container } = render(<ScopeBand scope={scopeOf(undefined)} />);
    expect(container.innerHTML).toBe("");
  });

  it("deleted axis without a cap falls back to the attempted percent; unknown axes say so", () => {
    render(
      <ScopeBand
        scope={scopeOf({
          ...IMG_B_SCOPE,
          partitions: { total: null, supported: null, processed: 1 },
          allocated: { listed_pct: null, content_pct: null, basis: "inferred" },
          deleted: { records: 10, attempted: 9, attempted_pct: 90.0, listed_pct: 80.0, not_attempted: 0 },
          caps: [],
        })}
      />,
    );
    const text = screen.getByTestId("dash-scope").querySelector(".dash-scope-line")?.textContent ?? "";
    expect(text).toContain("파티션 확인 못 함");
    expect(text).toContain("할당 파일 목록화 확인 못 함");
    expect(text).toContain("삭제 레코드 시도 90%");
    expect(text).not.toContain("상한");
  });

  it("koCount floors to 만/억 units", () => {
    expect(koCount(430_052)).toBe("43만");
    expect(koCount(9_999)).toBe("9,999");
    expect(koCount(19_999)).toBe("1만");
    expect(koCount(250_000_000)).toBe("2억");
  });
});
