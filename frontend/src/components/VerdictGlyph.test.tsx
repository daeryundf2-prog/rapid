import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { VERDICT_META, VerdictGlyph, VerdictShape, type VerdictStatus } from "./VerdictGlyph";

afterEach(cleanup);

const STATUSES = Object.keys(VERDICT_META) as VerdictStatus[];

describe("VerdictGlyph (F2)", () => {
  it("draws a different shape for every verdict, hidden from assistive tech", () => {
    const shapes = STATUSES.map((status) => {
      const { container } = render(<VerdictShape status={status} />);
      const svg = container.querySelector("svg") as SVGElement;
      expect(svg.getAttribute("aria-hidden")).toBe("true");
      expect(svg.getAttribute("focusable")).toBe("false");
      expect(svg.getAttribute("data-verdict")).toBe(status);
      const markup = svg.innerHTML;
      cleanup();
      return markup;
    });
    expect(new Set(shapes).size).toBe(STATUSES.length);
  });

  it("uses short words that differ from each other and fit the chip", () => {
    const words = STATUSES.map((s) => VERDICT_META[s].short);
    expect(words).toEqual(["관련", "재검토", "제외", "북마크", "보고서"]);
    expect(new Set(words).size).toBe(words.length);
    for (const word of words) expect(word.length).toBeLessThanOrEqual(3);
  });

  it("shape only: the full label is screen-reader text and the tooltip", () => {
    const { container } = render(<VerdictGlyph status="relevant" />);
    const label = screen.getByText("관련 있음");
    expect(label.className).toBe("visually-hidden");
    expect(container.querySelector(".verdict")?.getAttribute("title")).toBe("관련 있음");
  });

  it("with label: the short word is visible text", () => {
    const { container } = render(<VerdictGlyph status="needs-review" withLabel />);
    expect(screen.getByText("재검토").className).toBe("verdict-word");
    expect(container.querySelector(".verdict")?.getAttribute("data-verdict")).toBe("needs-review");
  });
});
