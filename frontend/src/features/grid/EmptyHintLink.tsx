import { DisabledReason } from "../../a11y/primitives";
import { useCommandState } from "../../commands/registry";
import type { ColumnSpec } from "./types";

/**
 * Run button for columns an analysis job fills ("NTFS 메타 분석을 실행하면 채워집니다" →
 * [NTFS 메타 분석 실행]): the command's own label, no arrow glyph.
 */
export function EmptyHintLink({
  hint,
  hintId,
}: {
  hint: NonNullable<ColumnSpec["emptyHint"]>;
  hintId: string;
}) {
  const { command, disabledReason, run } = useCommandState(hint.command);
  return (
    <DisabledReason reason={disabledReason}>
      <button
        type="button"
        className="grid-hint-link"
        aria-label={command?.label ?? hint.commandLabel}
        aria-describedby={hintId}
        title={disabledReason ? undefined : hint.text}
        data-command={hint.command}
        onClick={(event) => {
          event.stopPropagation();
          void run();
        }}
      >
        {hint.commandLabel}
      </button>
    </DisabledReason>
  );
}
