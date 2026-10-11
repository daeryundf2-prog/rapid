import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { STATUS_META, StatusChip } from "./StatusChip";

afterEach(cleanup);

describe("StatusChip", () => {
  const css = readFileSync(resolve(__dirname, "../tokens/tokens.css"), "utf8");

  it("defines every status token and its -on foreground in dark, light and OS-light blocks", () => {
    for (const meta of Object.values(STATUS_META)) {
      for (const token of [meta.token, meta.onToken]) {
        const count = css.split(`${token}:`).length - 1;
        expect(count, token).toBe(3);
      }
    }
  });

  it("renders the Korean label with the status data attribute", () => {
    render(<StatusChip status="include-in-report" />);
    const chip = screen.getByText("보고서 포함");
    expect(chip.getAttribute("data-status")).toBe("include-in-report");
  });
});
