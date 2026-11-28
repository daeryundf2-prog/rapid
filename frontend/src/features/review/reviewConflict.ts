/**
 * A review write the server refused (409 `review-conflict`, design review F14): another examiner
 * changed the mark after this console read it, and nothing was written. The prompt says who
 * changed it, when and to what, and lets the examiner overwrite it with their own decision or
 * leave it. One prompt at a time (ReviewToolsHost renders it).
 */

import { create } from "zustand";
import type { ConflictMark, ReviewConflict } from "../../api/caseDb";
import { formatMinute, type TimezoneChoice } from "../../utils/time";
import { reviewerLabel } from "./author";

/** Hangul syllable with a final consonant (받침); `rieul`: that consonant is ㄹ. */
function finalConsonant(word: string): { has: boolean; rieul: boolean } {
  const code = word.trim().charCodeAt(word.trim().length - 1) - 0xac00;
  if (Number.isNaN(code) || code < 0 || code > 11171) return { has: false, rieul: false };
  const jong = code % 28;
  return { has: jong !== 0, rieul: jong === 8 };
}

/** "김철수가" / "이름 없음이": the subject particle that fits the word's last syllable. */
export function withSubject(word: string): string {
  return `${word}${finalConsonant(word).has ? "이" : "가"}`;
}

/** "‘재검토’로" / "‘관련 있음’으로": the direction particle after a quoted word (ㄹ takes 로). */
export function quotedTo(word: string): string {
  const end = finalConsonant(word);
  return `‘${word}’${end.has && !end.rieul ? "으로" : "로"}`;
}

/** The stored decision as a word: 관련 있음 · 재검토 · 제외 · 보고서 포함 · 판정 없음. */
export function conflictStatusLabel(
  mark: Pick<ConflictMark, "exists" | "status" | "include_in_report">,
): string {
  if (mark.status === "relevant") return "관련 있음";
  if (mark.status === "needs-review") return "재검토";
  if (mark.status === "excluded" || mark.status === "not-relevant") return "제외";
  if (mark.include_in_report) return "보고서 포함";
  return mark.exists ? "판정 없음(태그·메모만)" : "판정 없음";
}

/** "14:05 KST" today in the display zone, "2026-11-27 14:05 KST" another day; "" when unknown. */
export function conflictTime(value: string, tz: TimezoneChoice, now: Date = new Date()): string {
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return "";
  const text = formatMinute(ms, tz);
  const today = formatMinute(now.getTime(), tz).slice(0, 10);
  return text.startsWith(today) ? text.slice(11) : text;
}

/** "김철수가 14:05 KST에 ‘재검토’로 바꿈" — who changed the mark, when, and to what. */
export function conflictSentence(conflict: ReviewConflict, tz: TimezoneChoice, now?: Date): string {
  const who = withSubject(reviewerLabel(conflict.current.reviewer));
  const when = conflictTime(conflict.current.updated_at, tz, now);
  return `${who} ${when ? `${when}에 ` : ""}${quotedTo(conflictStatusLabel(conflict.current))} 바꿈`;
}

export type ConflictChoice = "mine" | "keep";

export interface ConflictPrompt {
  runId: string;
  conflicts: ReviewConflict[];
  /** Row titles of the conflicting targets, in `conflicts` order ("" when unknown). */
  titles: string[];
  /** Targets in the refused write that did not conflict (applied by "그대로 두기"). */
  others: number;
  /** What the examiner tried to set ("관련 있음", "메모" …). */
  action: string;
  resolve: (choice: ConflictChoice) => Promise<void>;
}

interface ConflictState {
  prompt: ConflictPrompt | null;
  /** Bumped per prompt: a new conflict remounts the dialog (focus, busy state). */
  seq: number;
  open: (prompt: ConflictPrompt) => void;
  close: () => void;
}

export const useReviewConflict = create<ConflictState>((set) => ({
  prompt: null,
  seq: 0,
  open: (prompt) => set((state) => ({ prompt, seq: state.seq + 1 })),
  close: () => set({ prompt: null }),
}));
