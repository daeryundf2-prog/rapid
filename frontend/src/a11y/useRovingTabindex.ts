import { type KeyboardEvent, type RefObject, useCallback, useRef, useState } from "react";
import { isTextEntry } from "./focusable";

export type RovingOrientation = "vertical" | "horizontal" | "both";

export interface RovingOptions {
  orientation: RovingOrientation;
  /** CSS selector matching the focusable items inside the container (DOM order = index order). */
  itemSelector: string;
  /** Wrap from last to first and vice versa (default false; grids use false, tab lists true). */
  loop?: boolean;
  /** Printable-key search over item textContent (default false). */
  typeAhead?: boolean;
  /** Items moved by PageUp/PageDown (default 10). */
  pageSize?: number;
  initialIndex?: number;
  /** Called whenever the active index changes through keyboard or focus. */
  onActiveChange?: (index: number, element: HTMLElement | undefined) => void;
}

export interface RovingItemProps {
  tabIndex: 0 | -1;
  "data-roving-index": number;
  onFocus: () => void;
}

export interface RovingResult {
  activeIndex: number;
  setActiveIndex: (index: number) => void;
  /** Move roving focus and DOM focus to `index` (clamped). */
  focusIndex: (index: number) => void;
  containerProps: { onKeyDown: (event: KeyboardEvent<HTMLElement>) => void };
  getItemProps: (index: number) => RovingItemProps;
}

const TYPE_AHEAD_RESET_MS = 600;

export function useRovingTabindex(
  containerRef: RefObject<HTMLElement | null>,
  options: RovingOptions,
): RovingResult {
  const { orientation, itemSelector, loop = false, typeAhead = false, pageSize = 10 } = options;
  const [activeIndex, setActive] = useState(options.initialIndex ?? 0);
  const onChangeRef = useRef(options.onActiveChange);
  onChangeRef.current = options.onActiveChange;
  const bufferRef = useRef({ text: "", at: 0 });

  const items = useCallback(
    () => Array.from(containerRef.current?.querySelectorAll<HTMLElement>(itemSelector) ?? []),
    [containerRef, itemSelector],
  );

  const setActiveIndex = useCallback((index: number) => {
    setActive(index);
  }, []);

  const focusIndex = useCallback(
    (index: number) => {
      const list = items();
      if (list.length === 0) return;
      const next = Math.min(Math.max(index, 0), list.length - 1);
      setActive(next);
      list[next]?.focus();
      onChangeRef.current?.(next, list[next]);
    },
    [items],
  );

  const onKeyDown = useCallback(
    (event: KeyboardEvent<HTMLElement>) => {
      if (event.defaultPrevented) return;
      const list = items();
      if (list.length === 0) return;
      const target = event.target as HTMLElement;
      const owner = target.closest<HTMLElement>(itemSelector);
      // Keys typed inside an input/textarea nested in an item belong to that input.
      if (!owner || (owner !== target && isTextEntry(target))) return;
      const current = list.indexOf(owner);
      if (current < 0) return;
      const last = list.length - 1;
      const vertical = orientation !== "horizontal";
      const horizontal = orientation !== "vertical";
      const step = (delta: number) => {
        const raw = current + delta;
        if (loop) return (raw + list.length) % list.length;
        return Math.min(Math.max(raw, 0), last);
      };
      let next: number | null = null;
      switch (event.key) {
        case "ArrowDown":
          if (vertical) next = step(1);
          break;
        case "ArrowUp":
          if (vertical) next = step(-1);
          break;
        case "ArrowRight":
          if (horizontal) next = step(1);
          break;
        case "ArrowLeft":
          if (horizontal) next = step(-1);
          break;
        case "Home":
          next = 0;
          break;
        case "End":
          next = last;
          break;
        case "PageDown":
          if (vertical) next = Math.min(current + pageSize, last);
          break;
        case "PageUp":
          if (vertical) next = Math.max(current - pageSize, 0);
          break;
        default:
          if (typeAhead && event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
            if (event.key === " " && bufferRef.current.text === "") return; // Space is activation
            const now = event.timeStamp || Date.now();
            const buf = bufferRef.current;
            buf.text = now - buf.at > TYPE_AHEAD_RESET_MS ? event.key : buf.text + event.key;
            buf.at = now;
            const needle = buf.text.toLowerCase();
            const single = needle.split("").every((c) => c === needle[0]);
            const search = single ? (needle[0] ?? "") : needle;
            const startAt = single ? current + 1 : current;
            for (let n = 0; n < list.length; n++) {
              const i = (startAt + n) % list.length;
              if ((list[i]?.textContent ?? "").trim().toLowerCase().startsWith(search)) {
                next = i;
                break;
              }
            }
            if (next === null) return;
          }
      }
      if (next === null) return;
      event.preventDefault();
      focusIndex(next);
    },
    [items, itemSelector, orientation, loop, typeAhead, pageSize, focusIndex],
  );

  const getItemProps = useCallback(
    (index: number): RovingItemProps => ({
      tabIndex: index === activeIndex ? 0 : -1,
      "data-roving-index": index,
      onFocus: () => {
        if (index !== activeIndex) {
          setActive(index);
          onChangeRef.current?.(index, items()[index]);
        }
      },
    }),
    [activeIndex, items],
  );

  return { activeIndex, setActiveIndex, focusIndex, containerProps: { onKeyDown }, getItemProps };
}
