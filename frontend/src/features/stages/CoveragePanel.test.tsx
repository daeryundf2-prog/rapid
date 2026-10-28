import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { CoverageEntry } from "../../api/runs";
import { CoveragePanel, formatCoverageValue } from "./CoveragePanel";

const entry = (over: Partial<CoverageEntry>): CoverageEntry => ({
  area: "carving",
  reason_code: "scan_bytes_cap",
  limit: 1024 * 1024,
  observed: 5 * 1024 * 1024 * 1024,
  unit: "bytes",
  ...over,
});

describe("CoveragePanel (복구 범위)", () => {
  afterEach(cleanup);

  it("renders each entry as one Korean sentence", () => {
    render(
      <CoveragePanel
        coverage={[
          entry({}),
          entry({ area: "partition", reason_code: "unsupported-filesystem", limit: null, observed: null }),
          entry({
            area: "carving",
            reason_code: "candidate_cap",
            limit: 5000,
            observed: 12345,
            unit: "candidates",
          }),
        ]}
      />,
    );
    expect(screen.getByRole("heading", { name: "복구 범위" })).toBeTruthy();
    const items = screen.getAllByTestId("coverage-item");
    expect(items.map((li) => li.textContent)).toEqual([
      "카빙: 스캔 용량 상한에 걸려 일부만 처리됨 — 확인 5.0 GB / 상한 1.0 MB",
      "파티션: 지원하지 않는 파일시스템이라 처리하지 않음",
      "카빙: 후보 수 상한에 걸려 일부만 처리됨 — 확인 12,345 후보 / 상한 5,000 후보",
    ]);
  });

  it("shows unknown codes as 기타 제한 with the code in a title", () => {
    render(<CoveragePanel coverage={[entry({ reason_code: "weird_new_cap", area: "novel" })]} />);
    const item = screen.getByTestId("coverage-item");
    expect(item.textContent).toContain("기타 제한");
    expect(item.textContent).not.toContain("weird_new_cap");
    expect(item.querySelector('[title="weird_new_cap"]')).not.toBeNull();
    expect(item.querySelector('[title="novel"]')?.textContent).toBe("기타 영역");
  });

  it("states the empty list", () => {
    render(<CoveragePanel coverage={[]} />);
    expect(screen.getByText("제한 없이 처리됨")).toBeTruthy();
  });

  it("states a missing key (older runs)", () => {
    render(<CoveragePanel coverage={undefined} />);
    expect(screen.getByText("이 런은 복구 범위 기록 이전에 만들어졌습니다")).toBeTruthy();
    cleanup();
    render(<CoveragePanel coverage={null} />);
    expect(screen.getByText("이 런은 복구 범위 기록 이전에 만들어졌습니다")).toBeTruthy();
  });

  it("formats bytes and counts", () => {
    expect(formatCoverageValue(512, "bytes")).toBe("512 B");
    expect(formatCoverageValue(2048, "bytes")).toBe("2.0 KB");
    expect(formatCoverageValue(3 * 1024 * 1024, "bytes")).toBe("3.0 MB");
    expect(formatCoverageValue(1234567, "records")).toBe("1,234,567 레코드");
    expect(formatCoverageValue(null, "bytes")).toBe("");
  });
});
