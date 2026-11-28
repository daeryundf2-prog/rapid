import { EmptyHintLink } from "./EmptyHintLink";
import { formatCount } from "./gridUtils";
import type { ColumnSpec } from "./types";

/** One column the grid hid because its loaded rows all read the same, or are all empty. */
export interface HiddenColumnNote {
  id: string;
  header: string;
  kind: "uniform" | "empty";
  /** The value every loaded row shows (uniform). */
  value?: string;
}

/** Longest shared value quoted in the note before it is cut ("…"; the button title has it all). */
const VALUE_MAX = 40;

/**
 * The quoted value, cut to VALUE_MAX characters (code points, never half an emoji). A path keeps
 * its end — the file name and the folders right above it — like the 경로 cell (F28, review P3-1).
 */
export function shortValue(value: string, columnId = ""): string {
  const chars = Array.from(value);
  if (chars.length <= VALUE_MAX) return value;
  return columnId === "path"
    ? `…${chars.slice(-(VALUE_MAX - 1)).join("")}`
    : `${chars.slice(0, VALUE_MAX - 1).join("")}…`;
}

/**
 * Basis of the decision: every row of a whole collection, or the rows loaded so far of a paged
 * one (a later page may differ, so the note says which).
 */
export function columnNoteScope(loaded: number, total: number | null): string {
  return total !== null && loaded < total
    ? `불러온 ${formatCount(loaded)}행 기준`
    : `${formatCount(loaded)}행 전체 기준`;
}

/**
 * The one line above the table that keeps what hidden uniform / empty columns said (X7: "모든 행
 * 같은 값: 일치 = invoice"). Each column is a button that shows it again (it then stays, like the
 * 열 menu's "— 표시"). `hint` = how empty columns get filled (files without an NTFS join: "NTFS
 * 메타 분석을 실행하면 채워집니다" + its run button), said once here instead of a link in every
 * NTFS header (F27).
 */
export function ColumnNote({
  notes,
  scope,
  hint,
  onShow,
}: {
  notes: readonly HiddenColumnNote[];
  scope: string;
  hint?: NonNullable<ColumnSpec["emptyHint"]>;
  onShow: (id: string) => void;
}) {
  const uniform = notes.filter((note) => note.kind === "uniform");
  const empty = notes.filter((note) => note.kind === "empty");
  if (!uniform.length && !empty.length && !hint) return null;
  const item = (note: HiddenColumnNote, label: string, title: string, aria: string) => (
    <button
      key={note.id}
      type="button"
      className="grid-colnote-item"
      data-col={note.id}
      title={title}
      aria-label={aria}
      onClick={() => onShow(note.id)}
    >
      {label}
    </button>
  );
  return (
    <div className="grid-colnote" role="note" data-testid="grid-column-note">
      {uniform.length ? (
        <p className="grid-colnote-part">
          <span className="grid-colnote-label">모든 행 같은 값</span>
          {uniform.map((note) =>
            item(
              note,
              `${note.header} = ${shortValue(note.value ?? "", note.id)}`,
              `${note.header} = ${note.value ?? ""} — 열 다시 표시`,
              `${note.header} 열 다시 표시 (모든 행 ${note.value ?? ""})`,
            ),
          )}
        </p>
      ) : null}
      {empty.length || hint ? (
        <p className="grid-colnote-part">
          {empty.length ? <span className="grid-colnote-label">값 없는 열</span> : null}
          {empty.map((note) =>
            item(note, note.header, `${note.header} — 열 다시 표시`, `${note.header} 열 다시 표시 (값 없음)`),
          )}
          {hint ? (
            <>
              <span id="grid-colnote-hint" className="grid-colnote-hint">
                {hint.text}
              </span>
              <EmptyHintLink hint={hint} hintId="grid-colnote-hint" />
            </>
          ) : null}
        </p>
      ) : null}
      {uniform.length || empty.length ? <span className="grid-colnote-scope">{scope}</span> : null}
    </div>
  );
}
