/**
 * View preferences of the review tools (AXIOM E3), kept across reloads in localStorage
 * (readStored/writeStored never throw: private mode or blocked storage just means the
 * preference does not persist):
 *  - classic split: grid above, details (viewer) below — key `;
 *  - media blur: gallery thumbnails and the viewer's image blurred until hovered/focused — Shift+B.
 */

import { create } from "zustand";
import { readStored, writeStored } from "../../state/storage";

export const CLASSIC_SPLIT_KEY = "rapidtriage.classicSplit";
export const MEDIA_BLUR_KEY = "rapidtriage.mediaBlur";
/** Classic split: the dragged grid/viewer heights (percentages), like the wide layout's widths. */
export const CLASSIC_LAYOUT_KEY = "rapidtriage.classicSplitLayout";

/** The saved classic split layout ({panel id: percentage}), or null when none / unreadable. */
export function readClassicLayout(): Record<string, number> | null {
  const raw = readStored(CLASSIC_LAYOUT_KEY);
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    const entries = Object.entries(parsed as Record<string, unknown>).filter(
      (entry): entry is [string, number] =>
        typeof entry[1] === "number" && Number.isFinite(entry[1]) && entry[1] > 0,
    );
    return entries.length >= 2 ? Object.fromEntries(entries) : null;
  } catch {
    return null;
  }
}

export function writeClassicLayout(layout: Record<string, number>): void {
  writeStored(CLASSIC_LAYOUT_KEY, JSON.stringify(layout));
}

const readFlag = (key: string) => readStored(key) === "1";

interface ViewPrefs {
  classicSplit: boolean;
  mediaBlur: boolean;
  setClassicSplit: (on: boolean) => void;
  setMediaBlur: (on: boolean) => void;
}

export const useViewPrefs = create<ViewPrefs>((set) => ({
  classicSplit: readFlag(CLASSIC_SPLIT_KEY),
  mediaBlur: readFlag(MEDIA_BLUR_KEY),
  setClassicSplit: (on) => {
    writeStored(CLASSIC_SPLIT_KEY, on ? "1" : null);
    set({ classicSplit: on });
  },
  setMediaBlur: (on) => {
    writeStored(MEDIA_BLUR_KEY, on ? "1" : null);
    set({ mediaBlur: on });
  },
}));

/** Tests / a storage change from another tab: re-read both flags. */
export function reloadViewPrefs(): void {
  useViewPrefs.setState({ classicSplit: readFlag(CLASSIC_SPLIT_KEY), mediaBlur: readFlag(MEDIA_BLUR_KEY) });
}
