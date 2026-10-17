/**
 * Mount point of the review-tool dialogs (AXIOM E3) and their commands: rendered once by the
 * shell Layout. The commands (태그 관리, 메모·이력, 클래식 분할, 미디어 흐리게) register while it is
 * mounted; the dialogs open from uiStore.
 */

import { useEffect } from "react";
import { registerCommands } from "../../commands/registry";
import { reviewToolCommands } from "./commands";
import { NotePanel } from "./NotePanel";
import { TagManagerDialog } from "./TagManagerDialog";
import { useReviewToolsUi } from "./uiStore";

export function ReviewToolsHost() {
  const tagRunId = useReviewToolsUi((s) => s.tagManagerRunId);
  const noteTarget = useReviewToolsUi((s) => s.noteTarget);
  const closeTags = useReviewToolsUi((s) => s.closeTagManager);
  const closeNote = useReviewToolsUi((s) => s.closeNotePanel);
  useEffect(() => registerCommands(reviewToolCommands()), []);
  return (
    <>
      {tagRunId ? <TagManagerDialog runId={tagRunId} onClose={closeTags} /> : null}
      {noteTarget ? <NotePanel key={noteTarget.row.rowKey} target={noteTarget} onClose={closeNote} /> : null}
    </>
  );
}
