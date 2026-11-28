import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { isChipStatus, STATUS_META, StatusChip } from "./StatusChip";

afterEach(cleanup);

describe("StatusChip", () => {
  const css = readFileSync(resolve(__dirname, "../tokens/tokens.css"), "utf8");

  it("defines every status token and its -on foreground in dark, light and print blocks", () => {
    for (const meta of Object.values(STATUS_META)) {
      for (const token of [meta.token, meta.onToken]) {
        const count = css.split(`${token}:`).length - 1;
        expect(count, token).toBe(3);
      }
    }
  });

  it("renders the verdict glyph and short word with the status data attribute (F2)", () => {
    const { container } = render(<StatusChip status="include-in-report" />);
    const chip = container.querySelector(".status-chip") as HTMLElement;
    expect(chip.getAttribute("data-status")).toBe("include-in-report");
    expect(chip.getAttribute("title")).toBe("보고서 포함");
    expect(screen.getByText("보고서")).toBeTruthy();
    const shape = chip.querySelector("svg.verdict-shape");
    expect(shape?.getAttribute("aria-hidden")).toBe("true");
    expect(shape?.getAttribute("data-verdict")).toBe("include-in-report");
  });

  it("keeps the full label in STATUS_META and accepts a tag label", () => {
    expect(STATUS_META.relevant).toMatchObject({
      label: "관련 있음",
      short: "관련",
      token: "--status-relevant",
    });
    render(<StatusChip status="bookmark" label="bookmark" />);
    expect(screen.getByText("bookmark")).toBeTruthy();
    expect(isChipStatus("needs-review")).toBe(true);
    expect(isChipStatus("cleared")).toBe(false);
  });
});
