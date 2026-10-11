/** localStorage access that never throws (private mode / disabled storage). */

export function readStored(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function writeStored(key: string, value: string | null): void {
  try {
    if (value === null) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, value);
  } catch {
    // Storage may be disabled; the preference simply won't persist.
  }
}

export function readStoredJson<T>(key: string, guard: (value: unknown) => value is T): T | null {
  const raw = readStored(key);
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    return guard(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
