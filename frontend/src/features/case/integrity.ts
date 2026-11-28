/**
 * Evidence integrity seal (design overhaul F8): the run's evidence hash states folded into one
 * state, decided here and nowhere else — the top-bar seal, the dashboard's 먼저 할 일 line and the
 * evidence table all read `sealState` / `itemSeal`, so they can never disagree.
 *
 * "계산만 됨" (computed: hashed, no expected value to compare with) is kept apart from "대조 일치"
 * (matched against the expected value): a reader must never take a bare digest for a verified one.
 * Evidence that is never hashed (a folder) is in scope too and keeps the seal at "미검증": a run over
 * a folder never claims a match. A match is a past result shown with its time.
 */

import { useQuery } from "@tanstack/react-query";
import { type CaseEvidence, getCase, koCompare } from "../../api/cases";

export type SealKind = "broken" | "unverified" | "hashing" | "computed" | "matched" | "na";

/** The one react-query key of `GET /api/cases/{id}` (dashboard, seal and case dialogs share it). */
export const caseQueryKey = (caseId: string) => ["case", caseId] as const;

const ITEM_KIND: Readonly<Record<string, Exclude<SealKind, "na">>> = {
  mismatched: "broken",
  failed: "broken",
  "not-requested": "unverified",
  interrupted: "unverified",
  hashing: "hashing",
  computed: "computed",
  matched: "matched",
};

/** Short word of one evidence item's hash state (the server label stays the tooltip). */
const ITEM_WORD: Readonly<Record<string, string>> = {
  mismatched: "불일치",
  failed: "계산 실패",
  "not-requested": "검증 안 함",
  interrupted: "계산 중단됨",
  hashing: "검증 중",
  computed: "계산만 됨",
  matched: "대조 일치",
};

/** Folder evidence (no size) and `not-applicable` rows are never hashed. */
export function isHashable(item: CaseEvidence): boolean {
  return item.size_bytes !== null && item.hash_status !== "not-applicable";
}

/** One item's seal state; an unknown server status counts as unverified (never as verified). */
export function itemSeal(item: CaseEvidence): SealKind {
  if (!isHashable(item)) return "na";
  return ITEM_KIND[item.hash_status] ?? "unverified";
}

export function itemSealWord(item: CaseEvidence): string {
  if (!isHashable(item)) return item.size_bytes === null ? "해당 없음 (폴더)" : "해당 없음";
  return ITEM_WORD[item.hash_status] ?? item.hash_status_label ?? item.hash_status;
}

/**
 * Any file evidence can be hashed again unless a hash is running: a stored match or mismatch is
 * the result of its time, and the server re-hashes from every other state.
 */
export function canRehash(item: CaseEvidence): boolean {
  return isHashable(item) && item.hash_status !== "hashing";
}

/** First 8 hex characters of the item's SHA-256 (the expected value when only that is known). */
export function sealStamp(item: CaseEvidence): string {
  return (item.hashes.sha256 || item.hash_expected || "").slice(0, 8).toLowerCase();
}

/**
 * The evidence a run's seal speaks for: the run's own evidence item when the snapshot names it,
 * else (an older snapshot without the citation) every evidence item of the case.
 */
export function runEvidence(
  evidence: readonly CaseEvidence[],
  citationId: string | null | undefined,
): CaseEvidence[] {
  const own = citationId ? evidence.filter((item) => item.citation_id === citationId) : [];
  return own.length ? own : [...evidence];
}

export interface Seal {
  kind: SealKind;
  /** Hashable evidence, by evidence number. */
  items: CaseEvidence[];
  /** Evidence in scope that is never hashed (folders): keeps the seal at unverified. */
  unhashable: CaseEvidence[];
  /** Hashable items that need an examiner: broken or unverified. */
  pending: CaseEvidence[];
  /** Hashable items a hash can start for now (everything but a running hash). */
  rehashable: CaseEvidence[];
  /** Matched only: SHA-256 prefix of the first item. */
  stamp?: string;
  /**
   * Oldest finished hash check among the items (ISO), when every item has one: the seal's result
   * is only as recent as its oldest check.
   */
  checkedAt?: string;
  /** `unverified` counts the folders too. */
  counts: Record<Exclude<SealKind, "na">, number>;
}

/** Weakest state wins: one broken item breaks the seal, one computed item keeps it from "matched". */
const PRECEDENCE: ReadonlyArray<Exclude<SealKind, "na">> = [
  "broken",
  "unverified",
  "hashing",
  "computed",
  "matched",
];

export function sealState(evidence: readonly CaseEvidence[]): Seal {
  const byNumber = (a: CaseEvidence, b: CaseEvidence) => koCompare(a.evidence_number, b.evidence_number);
  const items = evidence.filter(isHashable).sort(byNumber);
  const unhashable = evidence.filter((item) => !isHashable(item)).sort(byNumber);
  const counts = { broken: 0, unverified: unhashable.length, hashing: 0, computed: 0, matched: 0 };
  for (const item of items) counts[itemSeal(item) as keyof typeof counts] += 1;
  const kind: SealKind = PRECEDENCE.find((k) => counts[k] > 0) ?? "na";
  const pending = items.filter((item) => {
    const k = itemSeal(item);
    return k === "broken" || k === "unverified";
  });
  const first = items[0];
  const checks = items.map((item) => item.hash_checked_at ?? "");
  const checkedAt = items.length && checks.every(Boolean) ? checks.sort()[0] : undefined;
  return {
    kind,
    items,
    unhashable,
    pending,
    rehashable: items.filter(canRehash),
    ...(kind === "matched" && first ? { stamp: sealStamp(first) } : {}),
    ...(checkedAt ? { checkedAt } : {}),
    counts,
  };
}

export interface SealMeta {
  /** Full word (top bar ≥ 600px, dashboard). */
  label: string;
  /** Compact word (phones). */
  short: string;
  /** What the state means, for the details popover. */
  description: string;
}

export const SEAL_META: Readonly<Record<Exclude<SealKind, "na">, SealMeta>> = {
  broken: {
    label: "무결성 깨짐",
    short: "깨짐",
    description:
      "기대 해시와 계산값이 다르거나 해시 계산에 실패한 증거가 있습니다. 보고 전에 원본을 다시 확인하세요.",
  },
  unverified: {
    label: "해시 미검증",
    short: "미검증",
    description:
      "해시를 계산하지 않은 증거가 있습니다. 검증 실행으로 계산합니다 (기대값이 없으면 계산만 됩니다).",
  },
  hashing: {
    label: "해시 검증 중",
    short: "검증 중",
    description: "해시를 계산하는 중입니다. 끝나면 이 표시가 바뀝니다.",
  },
  computed: {
    label: "계산만 됨 (대조 없음)",
    short: "계산만",
    description:
      "해시를 계산했지만 비교할 기대값이 없습니다. 원본과 같다는 대조 증명이 아니라 계산했을 때의 값입니다.",
  },
  matched: {
    label: "대조 일치",
    short: "일치",
    description:
      "마지막 검증 때 증거의 해시가 등록한 기대값과 일치했습니다. 그 뒤에 바뀐 것은 다시 검증해야 드러납니다.",
  },
};

/** Why folder evidence keeps the seal at 미검증 ("" when there is none). */
export function unhashableSentence(seal: Seal): string {
  const count = seal.unhashable.length;
  if (!count) return "";
  return `폴더 증거 ${count.toLocaleString("ko-KR")}건은 해시가 없습니다 (폴더는 해시를 계산하지 않음). 대조로 검증된 증거가 아닙니다.`;
}

/** Accessible one-line reading of the seal ("증거 무결성: 대조 일치, SHA-256 a1b2c3d4"). */
export function sealSentence(seal: Seal): string {
  if (seal.kind === "na") return "증거 무결성: 증거 없음";
  const meta = SEAL_META[seal.kind];
  const parts = [`증거 무결성: ${meta.label}`];
  if (seal.stamp) parts.push(`SHA-256 ${seal.stamp}`);
  if (seal.unhashable.length) parts.push(`폴더 증거 ${seal.unhashable.length}건 해시 없음`);
  if (seal.items.length > 1) parts.push(`증거 ${seal.items.length}건`);
  return parts.join(", ");
}

/** `GET /api/cases/{id}`, re-read every 3 s while a hash or a sibling run is in flight. */
export function useCaseDetail(caseId: string | null | undefined) {
  return useQuery({
    queryKey: caseQueryKey(caseId ?? ""),
    queryFn: () => getCase(caseId as string),
    enabled: Boolean(caseId),
    retry: false,
    refetchInterval: (q) =>
      q.state.data?.evidence.some(
        (e) =>
          e.hash_status === "hashing" || e.runs.some((r) => r.status === "queued" || r.status === "running"),
      )
        ? 3000
        : false,
  });
}
