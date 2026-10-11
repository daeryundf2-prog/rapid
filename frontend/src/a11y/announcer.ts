export type Politeness = "polite" | "assertive";

export interface AnnounceOptions {
  politeness?: Politeness;
}

/** Live regions announce short sentences only; longer text is truncated. */
export const MAX_ANNOUNCE_LENGTH = 200;
export const ANNOUNCE_DEBOUNCE_MS: Record<Politeness, number> = { polite: 150, assertive: 50 };

type Snapshot = { polite: string; assertive: string };

let snapshot: Snapshot = { polite: "", assertive: "" };
const listeners = new Set<() => void>();
const timers: Partial<Record<Politeness, ReturnType<typeof setTimeout>>> = {};
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
  const pending = timers[politeness];
  if (pending) clearTimeout(pending);
  timers[politeness] = setTimeout(() => {
    delete timers[politeness];
    // Repeating the same sentence must still be re-announced: alternate a trailing NBSP.
    toggles[politeness] = !toggles[politeness];
    const value = clean === "" ? "" : toggles[politeness] ? clean : `${clean} `;
    snapshot = { ...snapshot, [politeness]: value };
    emit();
  }, ANNOUNCE_DEBOUNCE_MS[politeness]);
}

export function resetAnnouncer(): void {
  for (const key of ["polite", "assertive"] as const) {
    const t = timers[key];
    if (t) clearTimeout(t);
    delete timers[key];
  }
  snapshot = { polite: "", assertive: "" };
  emit();
}
