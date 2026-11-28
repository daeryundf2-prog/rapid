import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReviewMapMark } from "../../api/caseDb";
import { makeRef, makeRow } from "../grid/columns/common";
import { resetCaseDbHandles } from "../grid/reviewActions";
import { installFetch, jsonResponse, renderWithClient } from "../grid/testSupport";
import { rememberReviewMarks, resetMarkVersions } from "./markVersions";
import { NotePanel } from "./NotePanel";
import { ReviewConflictDialog } from "./ReviewConflictDialog";
import { type ConflictPrompt, useReviewConflict } from "./reviewConflict";

const RUN = "run-ui";

const row = makeRow(
  makeRef("files", "/candidates/1"),
  { title: "wallet.txt", sourcePath: "C:/x/wallet.txt" },
  { pointer: "/candidates/1", note: "처음 메모", markVersion: 1 },
);

function mapMark(version: number, note: string): ReviewMapMark {
  return {
    citation_id: "c",
    target_type: "file_record",
    target_id: "1",
    status: "relevant",
    tags: [],
    note,
    include_in_report: false,
    updated_at: "2026-11-28T01:00:00+00:00",
    version,
    collection: "files",
    kind: "",
    locator: "/candidates/1",
  };
}

beforeEach(() => {
  resetMarkVersions();
  resetCaseDbHandles();
  useReviewConflict.setState({ prompt: null, seq: 0 });
});
afterEach(() => vi.unstubAllGlobals());

describe("메모·이력 panel (P1-1)", () => {
  it("expects the version it showed when it opened, even after the review map reloads", async () => {
    const bodies: Array<{ targets: Array<{ expected_version?: number }> }> = [];
    installFetch({
      "/review-history": () => jsonResponse({ entries: [] }),
      "/case-db/ensure": () => jsonResponse({ database: "/d.db", case_id: "c" }),
      "/case-db/review-batch": (_url, init) => {
        bodies.push(JSON.parse(String(init?.body)));
        return jsonResponse({ updated_count: 1, targets: [], marks: [] });
      },
    });
    rememberReviewMarks(RUN, [mapMark(1, "처음 메모")], false);
    renderWithClient(<NotePanel target={{ runId: RUN, row }} onClose={() => {}} />);
    // While the panel is open, lee saves a note and the console reloads the review map.
    act(() => rememberReviewMarks(RUN, [mapMark(2, "lee의 메모")], false));
    fireEvent.change(screen.getByLabelText("메모"), { target: { value: "kim의 메모" } });
    fireEvent.click(screen.getByTestId("note-save"));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]?.targets[0]?.expected_version).toBe(1);
  });

  it("says which verdict a Z write undid (re-review P2)", async () => {
    const entry = (version: number, author: string, over: Record<string, unknown>) => ({
      version,
      changed_at: "2026-11-28T02:00:00+00:00",
      author,
      changed_fields: ["status", "reviewer"],
      note_before: "",
      note_after: "",
      tags_before: [],
      tags_after: [],
      ...over,
    });
    installFetch({
      "/review-history": () =>
        jsonResponse({
          entries: [
            entry(4, "kim", {
              status_before: "relevant",
              status_after: "unreviewed",
              kind: "undo",
              undone_version: 3,
              undone_reviewer: "lee",
            }),
            entry(3, "lee", { status_before: "", status_after: "relevant", kind: "", undone_version: null }),
          ],
        }),
    });
    renderWithClient(<NotePanel target={{ runId: RUN, row }} onClose={() => {}} />);
    const items = await screen.findAllByTestId("note-history-item");
    expect(items).toHaveLength(2);
    expect(items[0]?.textContent).toContain("kim");
    expect(items[0]?.textContent).toContain("되돌림 (원래 판정: lee v3)");
    expect(items[1]?.textContent).not.toContain("되돌림");
  });
});

describe("conflict prompt (P3-4)", () => {
  it("shows the stored mark (verdict and who set it, tags) and both notes side by side", () => {
    const prompt: ConflictPrompt = {
      runId: RUN,
      conflicts: [
        {
          target_type: "file_record",
          target_id: "1",
          expected_version: 1,
          current: {
            exists: true,
            status: "relevant",
            include_in_report: false,
            note: "lee: 지갑 메모 원본 확인함",
            tags: ["지갑"],
            reviewer: "lee",
            updated_at: "2026-11-28T05:30:00+00:00",
            status_by: "kim",
            status_at: "2026-11-28T05:00:00+00:00",
            version: 2,
            changes: [
              { version: 2, actor: "lee", changed_at: "2026-11-28T05:30:00+00:00", fields: ["note"] },
            ],
          },
        },
      ],
      titles: ["wallet.txt"],
      others: 0,
      action: "메모",
      mine: { note: "kim: 이 파일은 관련 없음" },
      resolve: async () => {},
    };
    render(<ReviewConflictDialog prompt={prompt} />);
    const dialog = screen.getByRole("alertdialog");
    expect(dialog.textContent).toMatch(/lee가 .*메모를 바꿈/);
    const current = screen.getByTestId("review-conflict-current");
    expect(current.textContent).toContain("관련 있음 · kim");
    expect(current.textContent).toContain("지갑");
    const notes = screen.getByTestId("review-conflict-notes");
    expect(within(notes).getByRole("region", { name: "지금 저장된 메모" }).textContent).toContain(
      "lee: 지갑 메모 원본 확인함",
    );
    expect(within(notes).getByRole("region", { name: "내 메모 (저장 안 됨)" }).textContent).toContain(
      "kim: 이 파일은 관련 없음",
    );
    expect(dialog.textContent).toContain("내 메모는 입력 창에 그대로 남습니다");
  });
});
