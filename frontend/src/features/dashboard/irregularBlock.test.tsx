// 접수 › 증거 › 예외 항목 block (R7 갈래 A, Q-A5): per-category counts whose links list exactly
// that many rows (files / 전체 파일 / artifacts with irregular=<id>), the total = their sum.

import { cleanup, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockFetch, renderWithQuery } from "../case/testUtils";
import { IRREGULAR_IDS } from "../filters/conditionValues";
import { IrregularBlock } from "./caseCards";

const categories = IRREGULAR_IDS.map((id) => ({
  id,
  label: "서버 라벨",
  help: "도움말",
  count: id === "encrypted" ? 3 : id === "unrecognized" ? 1 : 0,
  files: id === "encrypted" ? 1 : id === "unrecognized" ? 1 : 0,
  candidates: id === "encrypted" ? 1 : 0,
  inventory: id === "unrecognized" ? 1 : 0,
  artifacts: id === "encrypted" ? 2 : 0,
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("IrregularBlock", () => {
  it("lists the nine categories in Korean with links per list", async () => {
    mockFetch({
      "GET /api/runs/r1/irregular/summary": { categories, total: 4, unique_items: 4 },
    });
    renderWithQuery(<IrregularBlock runId="r1" />);
    const block = await screen.findByTestId("case-irregular");
    expect((await screen.findByTestId("irregular-total")).textContent).toBe("합계 4건 · 항목 4개");
    const rows = within(block).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(9);
    expect(rows.map((row) => row.querySelector("th")?.textContent)).toEqual([
      "확장자 불일치",
      "손상·부분 읽기",
      "삭제됨",
      "빈 파일",
      "암호화",
      "검색 불가 PDF",
      "본문 제외(바이너리)",
      "형식 미상",
      "미지원 형식",
    ]);
    const encrypted = within(block).getByRole("link", { name: "암호화 아티팩트 2건 보기" });
    expect(encrypted.getAttribute("href")).toBe("#/case/r1/explore/artifacts?irregular=encrypted");
    expect(within(block).getByRole("link", { name: "암호화 파일 1건 보기" }).getAttribute("href")).toBe(
      "#/case/r1/explore/files?irregular=encrypted",
    );
    expect(
      within(block).getByRole("link", { name: "형식 미상 전체 파일 1건 보기" }).getAttribute("href"),
    ).toBe("#/case/r1/explore/files?category=inventory&irregular=unrecognized");
    // A zero category has no link; no raw category id is ever shown.
    expect(within(rows[0] as HTMLElement).queryByRole("link")).toBeNull();
    expect(block.textContent).not.toMatch(/encrypted|bad-extension|unrecognized/);
  });

  it("says why the block is empty (live run)", async () => {
    mockFetch({
      "GET /api/runs/r1/irregular/summary": new Response(
        JSON.stringify({ detail: "런이 끝난 뒤에 계열·중복·예외 항목을 볼 수 있습니다" }),
        { status: 409, headers: { "content-type": "application/json" } },
      ),
    });
    renderWithQuery(<IrregularBlock runId="r1" />);
    expect(await screen.findByText(/런이 끝난 뒤에/)).toBeTruthy();
  });
});
