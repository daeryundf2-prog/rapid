/**
 * Flat text of a decoded record value (artifact `details` field): scalars as-is,
 * scalar arrays as a comma list, anything else as JSON. Never clipped — callers
 * that display it clip with `clipValue` and keep the full text for search/copy.
 */
export function flatValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value) && value.every((item) => item === null || typeof item !== "object")) {
    return value.map((item) => String(item)).join(", ");
  }
  try {
    return JSON.stringify(value) ?? "";
  } catch {
    return "";
  }
}

/** Display clip for long record values (meta tab, grid cells). */
export const MAX_VALUE_CHARS = 600;

export function clipValue(text: string, max = MAX_VALUE_CHARS): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/** Scalar or array of scalars (the values a column can show and the server can sort). */
export function isScalarish(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value !== "object") return true;
  return Array.isArray(value) && value.every((item) => item === null || typeof item !== "object");
}
