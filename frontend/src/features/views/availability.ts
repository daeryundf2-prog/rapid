/**
 * Explorer view availability (S9, plan X6/X12). Pure: which of the four views
 * a collection node can show, and the Korean reason when it cannot. The
 * ViewSwitch renders unavailable views disabled WITH that reason, and an
 * unavailable `view=` in the URL falls back to the column view.
 */

import type { CollectionId } from "../../contracts/collection";
import { KEY_MAP } from "../../contracts/command";
import type { ExplorerView } from "../../router";

export interface ViewDef {
  id: ExplorerView;
  label: string;
  commandId: string;
  shortcut: string;
}

export const VIEW_DEFS: readonly ViewDef[] = [
  { id: "columns", label: "열 보기", commandId: "view.columns", shortcut: KEY_MAP.viewColumns },
  { id: "thumbnails", label: "썸네일 보기", commandId: "view.thumbnails", shortcut: KEY_MAP.viewThumbnails },
  { id: "chat", label: "대화 보기", commandId: "view.chat", shortcut: KEY_MAP.viewChat },
  { id: "histogram", label: "히스토그램 보기", commandId: "view.histogram", shortcut: KEY_MAP.viewHistogram },
];

/** Artifact kinds whose rows point at image files. */
export const THUMBNAIL_KINDS: readonly string[] = ["media-image", "synthetic-media"];
/** Artifact kinds that carry messenger message rows. */
export const CHAT_KINDS: readonly string[] = [
  "kakaotalk-windows",
  "kakaotalk-macos",
  "mobile-export",
  // r2 M1: Teams·Slack·Discord·… desktop apps (`chat-message` rows; chat.ts reads them).
  "windows-messenger",
];
export const HISTOGRAM_COLLECTIONS: readonly CollectionId[] = [
  "timeline",
  "artifacts",
  "files",
  "docs",
  "search",
];

export interface ViewScope {
  id: CollectionId | null;
  kind?: string;
}

export const NO_NODE_REASON = "케이스의 컬렉션 노드를 먼저 여세요";
export const THUMBNAIL_REASON =
  "썸네일 보기는 파일 노드와 미디어 이미지 아티팩트 노드에서 사용할 수 있습니다";
export const CHAT_REASON =
  "대화 보기는 카카오톡·데스크톱 메신저·모바일 내보내기 아티팩트 노드에서 사용할 수 있습니다";
export const HISTOGRAM_REASON =
  "히스토그램 보기는 타임라인·아티팩트·파일·문서·검색 노드에서 사용할 수 있습니다";

/** Korean reason the view cannot show this node; undefined = available. */
export function viewDisabledReason(view: ExplorerView, scope: ViewScope): string | undefined {
  const { id, kind } = scope;
  if (!id || id === "intake") return view === "columns" ? undefined : NO_NODE_REASON;
  switch (view) {
    case "columns":
      return undefined;
    case "thumbnails":
      if (id === "files") return undefined;
      return id === "artifacts" && kind && THUMBNAIL_KINDS.includes(kind) ? undefined : THUMBNAIL_REASON;
    case "chat":
      return id === "artifacts" && kind && CHAT_KINDS.includes(kind) ? undefined : CHAT_REASON;
    case "histogram":
      return HISTOGRAM_COLLECTIONS.includes(id) ? undefined : HISTOGRAM_REASON;
    default:
      return NO_NODE_REASON;
  }
}

export function viewAvailability(scope: ViewScope): Record<ExplorerView, string | undefined> {
  return {
    columns: viewDisabledReason("columns", scope),
    thumbnails: viewDisabledReason("thumbnails", scope),
    chat: viewDisabledReason("chat", scope),
    histogram: viewDisabledReason("histogram", scope),
  };
}

/** The view actually shown: the requested one when the node supports it, else the column view. */
export function effectiveView(requested: ExplorerView | undefined, scope: ViewScope): ExplorerView {
  const view = requested ?? "columns";
  return viewDisabledReason(view, scope) ? "columns" : view;
}

export function viewLabel(view: ExplorerView): string {
  return VIEW_DEFS.find((def) => def.id === view)?.label ?? "열 보기";
}
