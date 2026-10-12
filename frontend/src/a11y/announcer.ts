export type Politeness = "polite" | "assertive";

export interface AnnounceOptions {
  politeness?: Politeness;
  /**
   * Polite only: the sentence must be heard before anything else (stage switches). Later polite
   * sentences neither replace it nor are spoken until it has had ANNOUNCE_HOLD_MS.
   */
  hold?: boolean;
}

/** Live regions announce short sentences only; longer text is truncated. */
export const MAX_ANNOUNCE_LENGTH = 200;
export const ANNOUNCE_DEBOUNCE_MS: Record<Politeness, number> = { polite: 150, assertive: 50 };

/** How long a `hold` sentence keeps later polite sentences waiting once it is spoken. */
export const ANNOUNCE_HOLD_MS = 800;

type Snapshot = { polite: string; assertive: string };

let snapshot: Snapshot = { polite: "", assertive: "" };
const listeners = new Set<() => void>();
const timers: Partial<Record<Politeness, ReturnType<typeof setTimeout>>> = {};
let heldTimer: ReturnType<typeof setTimeout> | undefined;
let holdUntil = 0;
const toggles: Record<Politeness, boolean> = { polite: false, assertive: false };

function emit() {
  for (const l of listeners) l();
}

export function subscribeAnnouncer(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function getAnnouncerSnapshot(): Snapshot {
  return snapshot;
}

/**
 * Queue a short sentence for screen readers. Calls within the debounce window
 * collapse to the last one. Never pass large content; this is not a DOM mirror.
 */
export function announce(text: string, options: AnnounceOptions = {}): void {
  const politeness = options.politeness ?? "polite";
  const clean = text.replace(/\s+/g, " ").trim().slice(0, MAX_ANNOUNCE_LENGTH);
  const now = Date.now();
  const flush = () => {
    // Repeating the same sentence must still be re-announced: alternate a trailing NBSP.
    toggles[politeness] = !toggles[politeness];
    const value = clean === "" ? "" : toggles[politeness] ? clean : `${clean} `;
    snapshot = { ...snapshot, [politeness]: value };
    emit();
  };
  if (options.hold && politeness === "polite") {
    if (heldTimer) clearTimeout(heldTimer);
    const delay = ANNOUNCE_DEBOUNCE_MS.polite;
    holdUntil = now + delay + ANNOUNCE_HOLD_MS;
    heldTimer = setTimeout(() => {
      heldTimer = undefined;
      flush();
    }, delay);
    return;
  }
  const pending = timers[politeness];
  if (pending) clearTimeout(pending);
  // A fresh stage sentence is not overwritten: later polite text waits until it has been heard.
  const wait = politeness === "polite" ? Math.max(0, holdUntil - now) : 0;
  timers[politeness] = setTimeout(
    () => {
      delete timers[politeness];
      flush();
    },
    Math.max(ANNOUNCE_DEBOUNCE_MS[politeness], wait),
  );
}

export function resetAnnouncer(): void {
  for (const key of ["polite", "assertive"] as const) {
    const t = timers[key];
    if (t) clearTimeout(t);
    delete timers[key];
  }
  if (heldTimer) clearTimeout(heldTimer);
  heldTimer = undefined;
  holdUntil = 0;
  snapshot = { polite: "", assertive: "" };
  emit();
}
