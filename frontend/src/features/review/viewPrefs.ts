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
