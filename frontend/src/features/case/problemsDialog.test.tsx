// R7 stage 1 re-review R-7: the 처리 문제 "전체 보기" table still showed the raw cap keys
// ("…결과가 전수가 아님: summary.size_caps.truncated") and raw step ids; both now go through
// the key→reason table (problemMessageKo) and stepLabelKo, the raw text stays the tooltip.
import { cleanup, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ProblemsDialog } from "./CaseDialogs";
import { mockFetch, renderWithQuery } from "./testUtils";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("R-7: problems dialog reads Korean reasons", () => {
  it("routes the cap-flag line through the key→reason table", async () => {
    const raw = "상한/절단 적용 — 결과가 전수가 아님: summary.size_caps.truncated";
    mockFetch({
      "GET /api/runs/r7/problems": {
        run_id: "r7",
        total: 2,
        groups: [
          {
            reason_id: "caps",
            label_ko: "상한·절단",
            level: "warning",
            count: 2,
            steps: ["docs", "artifacts-recent-files"],
            items: [
              { reason_id: "caps", source: "warning", step: "docs", level: "warning", message: raw },
              {
                reason_id: "caps",
                source: "warning",
                step: "artifacts-recent-files",
                level: "warning",
                message:
                  "recent-files: 행 단위 절단 10행 — 원문 일부만 보존됨 (jumplist-automatic.ole_streams_truncated 10행)",
              },
            ],
          },
        ],
      },
    });
    renderWithQuery(<ProblemsDialog runId="r7" reasonId="caps" reasonLabel="상한·절단" onClose={() => {}} />);
    const table = await screen.findByRole("table", { name: "상한·절단 전체 목록" });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows[0]?.textContent).toContain("결과가 전수가 아님: 문서 크기 상한 초과");
    expect(table.textContent).not.toContain("summary.size_caps.truncated");
    expect(table.textContent).not.toContain("ole_streams_truncated");
    expect(rows[1]?.textContent).toContain("아티팩트 수집: 최근 파일·LNK");
    // The raw message stays available as the cell's tooltip.
    expect(rows[0]?.querySelector("td[title]:last-child")?.getAttribute("title")).toBe(raw);
  });
});
