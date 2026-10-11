import { Fragment, type ReactNode } from "react";

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Case-insensitive keyword regex, or null when there is nothing to highlight. */
export function keywordPattern(terms: string[]): RegExp | null {
  const cleaned = terms.map((term) => term.trim()).filter((term) => term.length > 0);
  if (!cleaned.length) return null;
  return new RegExp(`(${cleaned.map(escapeRegExp).join("|")})`, "gi");
}

/** Render `text` with `<mark>` around keyword hits (React escapes the text). */
export function highlight(text: string, pattern: RegExp | null): ReactNode {
  if (!pattern || !text) return text;
  const parts = text.split(pattern);
  if (parts.length === 1) return text;
  return parts.map((part, index) =>
    index % 2 === 1 ? (
      // biome-ignore lint/suspicious/noArrayIndexKey: split segments have no identity
      <mark key={index} className="viewer-hit">
        {part}
      </mark>
    ) : (
      // biome-ignore lint/suspicious/noArrayIndexKey: split segments have no identity
      <Fragment key={index}>{part}</Fragment>
    ),
  );
}

export function countHits(text: string, pattern: RegExp | null): number {
  if (!pattern || !text) return 0;
  return (text.match(pattern) || []).length;
}
