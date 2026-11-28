/** X7 / F27: uniform and empty columns hide by default and keep their information in one note. */
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ColumnNote, columnNoteScope } from "./ColumnNote";
import { col, makeRef, makeRow } from "./columns/common";
import { modifiedCell } from "./columns/FileCells";
import { copyTimeHeaderNote } from "./columns/files";
import { emptyColumnIds, UNIFORM_MIN_ROWS, uniformColumns } from "./gridUtils";
import type { ColumnSpec } from "./types";

function rows(values: { kw: string; state: string; when?: string; empty?: string }[]) {
  return values.map((v, i) =>
    makeRow(makeRef("search", `/r/${i}`), { title: `r${i}`, timestamp: v.when ?? null }, { ...v }),
  );
}

const columns: ColumnSpec[] = [
  col.title(),
  col.field("kw", "일치", 100, ["analysis"], (r) => String(r.fields.kw)),
  col.field("state", "상태", 100, ["analysis"], (r) => String(r.fields.state)),
  col.field("empty", "NTFS 생성", 100, ["analysis"], (r) => (r.fields.empty as string) ?? null, {
    emptyHint: {
      text: "NTFS 메타 분석을 실행하면 채워집니다",
      command: "x",
      commandLabel: "NTFS 메타 분석 실행",
    },
  }),
  col.timestamp(),
  col.review(),
];
const ids = columns.slice(1).map((c) => c.id);

describe("uniformColumns", () => {
  it("names the shared value of every column whose loaded rows all read the same", () => {
    const loaded = rows([
      { kw: "invoice", state: "있음" },
      { kw: "invoice", state: "없음" },
      { kw: "invoice", state: "있음" },
    ]);
    expect([...uniformColumns(columns, loaded, { candidates: ids })]).toEqual([["kw", "invoice"]]);
  });

  it("never the title, the verdict or a time column; never below the row minimum or a kept column", () => {
    const same = { kw: "a", state: "b", when: "2026-01-01T00:00:00Z" };
    const loaded = rows(Array.from({ length: UNIFORM_MIN_ROWS }, () => same));
    const found = uniformColumns(columns, loaded, { candidates: ids });
    expect(found.has("timestamp")).toBe(false);
    expect(found.has("review")).toBe(false);
    expect(found.has("title")).toBe(false);
    expect(uniformColumns(columns, loaded.slice(0, UNIFORM_MIN_ROWS - 1), { candidates: ids }).size).toBe(0);
    expect(uniformColumns(columns, loaded, { candidates: ids, keep: new Set(["kw"]) }).has("kw")).toBe(false);
  });

  it("empty columns hide too, even with an analysis hint (the note carries the hint, F27)", () => {
    const loaded = rows([
      { kw: "a", state: "b" },
      { kw: "c", state: "d" },
    ]);
    expect(emptyColumnIds(columns, loaded, { candidates: ids })).toEqual(["empty", "timestamp", "review"]);
  });
});

describe("ColumnNote", () => {
  it("one line: the shared values, the empty columns, the hint and the basis; a click re-shows", () => {
    const onShow = vi.fn();
    render(
      <ColumnNote
        notes={[
          { id: "kw", header: "일치", kind: "uniform", value: "invoice" },
          { id: "ntfsCreated", header: "NTFS 생성", kind: "empty" },
        ]}
        scope={columnNoteScope(110, 110)}
        hint={{
          text: "NTFS 메타 분석을 실행하면 채워집니다",
          command: "x",
          commandLabel: "NTFS 메타 분석 실행",
        }}
        onShow={onShow}
      />,
    );
    const note = screen.getByTestId("grid-column-note");
    expect(note.textContent).toContain("모든 행 같은 값");
    expect(note.textContent).toContain("일치 = invoice");
    expect(note.textContent).toContain("값 없는 열");
    expect(note.textContent).toContain("NTFS 메타 분석을 실행하면 채워집니다");
    expect(note.textContent).toContain("110행 전체 기준");
    expect(note.textContent).not.toContain("→");
    fireEvent.click(screen.getByRole("button", { name: "일치 열 다시 표시 (모든 행 invoice)" }));
    expect(onShow).toHaveBeenCalledWith("kw");
  });

  it("a paged collection says the decision rests on the loaded rows", () => {
    expect(columnNoteScope(300, 720)).toBe("불러온 300행 기준");
    expect(columnNoteScope(9, null)).toBe("9행 전체 기준");
  });

  it("renders nothing without notes or hint", () => {
    const { container } = render(<ColumnNote notes={[]} scope="" onShow={() => {}} />);
    expect(container.textContent).toBe("");
  });
});

describe("files copy time (F27)", () => {
  const copy = makeRow(makeRef("files", "/c/0"), { title: "a" }, { modifiedOrigin: "acquisition-copy" });
  const own = makeRow(makeRef("files", "/c/1"), { title: "b" }, { modifiedOrigin: "filesystem" });

  it("the header names copy times once some / all loaded rows are", () => {
    expect(copyTimeHeaderNote([copy, copy])).toBe("모두 사본 시각");
    expect(copyTimeHeaderNote([copy, own])).toBe("사본 시각 포함");
    expect(copyTimeHeaderNote([own])).toBeNull();
    expect(copyTimeHeaderNote([])).toBeNull();
  });

  it("a copy-time cell carries the word 사본 with its tooltip, not italics alone", () => {
    const { container } = render(<>{modifiedCell(copy, "2026-11-26 07:35:56 KST")}</>);
    const cell = container.querySelector("[data-testid=files-copy-time]") as HTMLElement;
    expect(cell.querySelector(".grid-copy-mark")?.textContent).toBe("사본");
    expect(cell.getAttribute("title")).toBe("취득 사본의 시각 — 원본 시각 아님");
    expect(cell.textContent).toContain("원본 시각 아님");
  });
});
