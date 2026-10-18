import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { StatusBadge, statusLabel, statusTone } from "./Badge";

afterEach(cleanup);

describe("status badge labels (R4 V1)", () => {
  it("reads run / group / task states in Korean, canceled as 취소됨", () => {
    expect(statusLabel("partial")).toBe("일부 완료");
    expect(statusLabel("interrupted")).toBe("중단됨");
    expect(statusLabel("skipped")).toBe("건너뜀");
    expect(statusLabel("cancelled")).toBe("취소됨");
    expect(statusLabel("canceled")).toBe("취소됨");
    expect(statusLabel("queued")).toBe("대기");
    expect(statusLabel("running")).toBe("실행 중");
    expect(statusLabel("whatever")).toBe("whatever");
    expect(statusTone("canceled")).toBe("warn");
    expect(statusTone("interrupted")).toBe("warn");
    expect(statusTone("skipped")).toBe("muted");
  });

  it("renders the chip with the normalized tone", () => {
    render(<StatusBadge status="canceled" />);
    const chip = screen.getByText("취소됨");
    expect(chip.getAttribute("data-tone")).toBe("warn");
    cleanup();
    render(<StatusBadge status="interrupted" />);
    expect(screen.getByText("중단됨").getAttribute("data-tone")).toBe("warn");
  });
});
