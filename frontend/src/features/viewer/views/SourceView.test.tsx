import { describe, expect, it } from "vitest";
import { looksBinary } from "./SourceView";

describe("looksBinary (r8 T-086: never print binary bytes as text)", () => {
  it("flags NUL bytes and dense control characters", () => {
    expect(looksBinary("MZ\u0000\u0000\u0003")).toBe(true);
    expect(looksBinary("\u0001\u0002\u0003\u0004abc")).toBe(true);
    expect(looksBinary("����ab")).toBe(true);
  });

  it("keeps ordinary text, Korean and tabs / newlines", () => {
    expect(looksBinary("")).toBe(false);
    expect(looksBinary("line 1\r\nline\t2\n한글 텍스트\f")).toBe(false);
  });
});
