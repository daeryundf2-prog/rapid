import { useSyncExternalStore } from "react";

/** Notes saved in this session (the grid row snapshot does not refetch), keyed run|collection|kind|locator. */
const notes = new Map<string, string>();
const listeners = new Set<() => void>();
let version = 0;

export function noteKey(runId: string, ref: { collection: string; kind?: string; locator: string }): string {
  return `${runId}|${ref.collection}|${ref.kind ?? ""}|${ref.locator}`;
}

export function setSessionNote(key: string, note: string): void {
  notes.set(key, note);
  version++;
  for (const listener of listeners) listener();
}

export function getSessionNote(key: string): string | undefined {
  return notes.get(key);
}

export function clearSessionNotes(): void {
  notes.clear();
  version++;
  for (const listener of listeners) listener();
}

export function useSessionNote(key: string): string | undefined {
  useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => version,
    () => version,
  );
  return notes.get(key);
}
