/**
 * 지금 어디·다음 키 (design-viewer-keys F15): one status-bar line with where the analyst is
 * (stage › collection), which rows a verdict key acts on right now (`reviewScope()`, the same
 * function the keys execute and announce with), and the keys usable at this moment — read from
 * the command registry (the source of the ? help overlay), so a key is listed only while its
 * command can run.
 */

import { useEffect, useState } from "react";
import { COLLECTION_NODES } from "../app/collections";
import { disabledReasonOf, getCommand, useCommandContext, useCommands } from "../commands/registry";
import { focusInViewer, reviewScope } from "../commands/verdict";
import type { CommandContext } from "../contracts/command";
import { STAGE_DEFS } from "../features/stages/stages";
import { stageOf } from "../router";
import { KEY_DESCRIPTIONS, keyLabel } from "../shortcuts";
import { useAppStore } from "../state/store";

/** One hint group: the commands whose keys show, and what they do (short). */
export interface HintGroup {
  ids: readonly string[];
  label: string;
  /** Only while focus is in / out of the viewer. */
  viewer?: boolean;
  /** The full sentence (tooltip), when the short label leaves out what matters. */
  title?: string;
}

export const HINT_GROUPS: readonly HintGroup[] = [
  { ids: ["navigate.row.next", "navigate.row.prev"], label: "이동" },
  {
    ids: ["review.mark.relevant", "review.mark.needs-review", "review.mark.excluded", "review.mark.bookmark"],
    label: "판정",
  },
  // Z: the actor of the undo write and the per-tab undo list are said in full (re-review P2).
  { ids: ["review.undo"], label: "되돌리기", title: `Z: ${KEY_DESCRIPTIONS.undoVerdict}` },
  { ids: ["viewer.open"], label: "뷰어", viewer: false },
  { ids: ["app.close"], label: "표로", viewer: true },
  { ids: ["app.help"], label: "모든 키" },
];

export interface HintKeys {
  label: string;
  keys: string[];
  title?: string;
}

/** The groups whose commands are registered and can run now, each with its keys. */
export function usableHints(ctx: CommandContext, inViewer: boolean): HintKeys[] {
  const out: HintKeys[] = [];
  for (const group of HINT_GROUPS) {
    if (group.viewer !== undefined && group.viewer !== inViewer) continue;
    const keys = group.ids
      .map((id) => getCommand(id))
      .filter((command) => command?.shortcut && !disabledReasonOf(command, ctx))
      .map((command) => command?.shortcut as string);
    if (keys.length) out.push({ label: group.label, keys, ...(group.title ? { title: group.title } : {}) });
  }
  return out;
}

/** "탐색 › 타임라인" (the review collection reads 검토 보드, the stage's own word). */
export function whereText(collection: string | null): string {
  if (!collection) return "";
  const stage = STAGE_DEFS[stageOf({ collection: collection as never })];
  const node = COLLECTION_NODES.find((n) => n.id === collection);
  const name = collection === "review" ? "검토 보드" : (node?.label ?? collection);
  return stage.label === name ? name : `${stage.label} › ${name}`;
}

/** Focus inside the viewer, kept current (the hint lists Esc there, Enter elsewhere). */
function useFocusInViewer(): boolean {
  const [inViewer, setInViewer] = useState(focusInViewer);
  useEffect(() => {
    const update = () => setInViewer(focusInViewer());
    document.addEventListener("focusin", update);
    document.addEventListener("focusout", update);
    return () => {
      document.removeEventListener("focusin", update);
      document.removeEventListener("focusout", update);
    };
  }, []);
  return inViewer;
}

export function ContextHint() {
  const ctx = useCommandContext();
  useCommands(); // re-render when commands (un)register
  // The scope reads the viewer row; subscribe so its label follows the row and its verdict.
  useAppStore((s) => s.viewerRow);
  const inViewer = useFocusInViewer();
  if (!ctx.runId) return null;
  const where = whereText(ctx.collection);
  const scope = reviewScope(ctx);
  const hints = usableHints(ctx, inViewer);
  return (
    <div className="status-hint" data-testid="status-hint">
      {where ? <span className="status-hint-where">{where}</span> : null}
      {scope.kind !== "none" ? (
        <span className="status-hint-scope" data-testid="status-hint-scope" data-scope={scope.kind}>
          판정 대상 <strong>{scope.label}</strong>
        </span>
      ) : null}
      {hints.length ? (
        <span className="status-hint-keys">
          {hints.map((hint) => (
            <span key={hint.label} className="status-hint-key" title={hint.title}>
              {hint.keys.map((key) => (
                <kbd key={key}>{keyLabel(key)}</kbd>
              ))}
              <span>{hint.label}</span>
            </span>
          ))}
        </span>
      ) : null}
    </div>
  );
}
