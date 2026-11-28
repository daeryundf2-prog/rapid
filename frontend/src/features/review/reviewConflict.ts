/**
 * A review write the server refused (409 `review-conflict`, design review F14): another examiner
 * changed the mark after this console read it, and nothing was written. The prompt says who
 * changed what and when (the verdict by its own setter, P2-1; a note or tags by their writer,
 * P3-4), shows the current mark, and lets the examiner overwrite it with their own decision or
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

/** "메모를" / "보고서 포함을": the object particle that fits the word's last syllable. */
export function withObject(word: string): string {
  return `${word}${finalConsonant(word).has ? "을" : "를"}`;
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

/** Korean words of the mark fields a conflict reports, in the order the prompt names them. */
const FIELD_WORDS: ReadonlyArray<readonly [string, string]> = [
  ["status", "판정"],
  ["note", "메모"],
  ["tags", "태그"],
  ["include_in_report", "보고서 포함"],
  ["verification_status", "검증"],
  ["assignee", "담당자"],
  ["priority", "우선순위"],
  ["due_at", "기한"],
  ["source_citation_package", "인용 패키지"],
];

/** The fields changed since the version the console sent (every reported write), as words. */
export function changedFields(conflict: ReviewConflict): string[] {
  const changed = new Set(conflict.current.changes.flatMap((change) => change.fields));
  return FIELD_WORDS.filter(([field]) => changed.has(field)).map(([, word]) => word);
}

/**
 * "김철수가 14:05 KST에 ‘재검토’로 바꿈" when the verdict moved (its setter and time, not whoever
 * wrote last; P2-1), "이영희가 14:05 KST에 메모를 바꿈" when only other fields did (P3-4).
 */
export function conflictSentence(conflict: ReviewConflict, tz: TimezoneChoice, now?: Date): string {
  const { current } = conflict;
  const latest = current.changes[0];
  const at = (value: string) => {
    const when = conflictTime(value, tz, now);
    return when ? `${when}에 ` : "";
  };
  const words = changedFields(conflict);
  if (!current.exists) {
    const who = withSubject(reviewerLabel(latest?.actor ?? current.reviewer));
    return `${who} ${at(latest?.changed_at ?? current.updated_at)}표시를 지움`;
  }
  if (words.length === 0 || words[0] === "판정") {
    const who = withSubject(reviewerLabel(current.status_by || current.reviewer));
    const sentence = `${who} ${at(current.status_at || current.updated_at)}${quotedTo(conflictStatusLabel(current))} 바꿈`;
    const others = words.slice(1);
    return others.length ? `${sentence} (${others.join("·")}도 바뀜)` : sentence;
  }
  const actors = [...new Set(current.changes.map((change) => reviewerLabel(change.actor)))];
  const who = withSubject(actors.length > 1 ? `${actors[0]} 외 ${actors.length - 1}명` : (actors[0] ?? ""));
  return `${who} ${at(latest?.changed_at ?? current.updated_at)}${withObject(words.join("·"))} 바꿈`;
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
  /** The examiner's own unsaved input, shown beside the current one (a note write). */
  mine?: { note?: string };
  resolve: (choice: ConflictChoice) => Promise<void>;
  /** Another conflict replaced this prompt before the examiner chose: nothing was changed. */
  abandon?: () => void;
}

interface ConflictState {
  prompt: ConflictPrompt | null;
  /** Bumped per prompt: a new conflict remounts the dialog (focus, busy state). */
  seq: number;
  open: (prompt: ConflictPrompt) => void;
  close: () => void;
}

export const useReviewConflict = create<ConflictState>((set, get) => ({
  prompt: null,
  seq: 0,
  open: (prompt) => {
    get().prompt?.abandon?.();
    set((state) => ({ prompt, seq: state.seq + 1 }));
  },
  close: () => set({ prompt: null }),
}));
