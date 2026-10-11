/**
 * Small fuzzy matcher for the command palette: the query's characters must
 * appear in order (spaces ignored, case-insensitive). Higher score = better:
 * contiguous runs, matches at word starts and a plain substring hit win.
 * Works for Hangul syllables as well as Latin text.
 */
export function fuzzyScore(query: string, text: string): number | null {
  const q = query.toLowerCase().replace(/\s+/g, "");
  if (!q) return 0;
  const t = text.toLowerCase();
  const substring = t.indexOf(q);
  if (substring >= 0) return 1000 - substring - (t.length - q.length) * 0.01;

  let score = 0;
  let ti = 0;
  let previous = -2;
  for (const ch of q) {
    const found = t.indexOf(ch, ti);
    if (found < 0) return null;
    score += 10;
    if (found === previous + 1) score += 15;
    if (found === 0 || /[\s:·/_.-]/.test(t[found - 1] ?? "")) score += 8;
    score -= Math.min(found - ti, 10);
    previous = found;
    ti = found + 1;
  }
  return score;
}
