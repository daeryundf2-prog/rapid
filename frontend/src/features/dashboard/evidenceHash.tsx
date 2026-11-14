/**
 * Evidence hash state and values on the 접수 증거 card (R8 T-129, honest labels only). The server
 * says which bytes were hashed (`hash_scope`): for E01/Ex01 (`ewf-container-segment-bytes`) the
 * values are the container (segment file) bytes, never the acquisition media hash, so the labels
 * say "컨테이너". A legacy container-vs-input mismatch is amber; an input that differs from the
 * acquisition hash recorded in the image (same algorithm, decided by the server:
 * `hash_recorded_compare`) is red (WB-9 P1-5). A segment set known to be incomplete is amber and
 * never reads as "no recorded hash" (WB-9 P1-3). Per-segment values are shown first; the
 * acquisition hash recorded in the image (T-181, never recomputed) is the third line when present.
 * Status strings, digests and the verdict itself are the server's and unchanged.
 */

import type { CaseEvidence } from "../../api/cases";
import { type ChipTone, ToneChip } from "../../components/ToneChip";

export const EWF_HASH_SCOPE = "ewf-container-segment-bytes";
/** More segments than this fold into a disclosure. */
const SEGMENT_PREVIEW = 3;

/** File evidence (dd, raw, exports …): the pre-T-129 wording. */
const FILE_HASH: Record<string, [string, ChipTone]> = {
  "not-requested": ["해시 미검증", ""],
  hashing: ["해시 계산 중", "info"],
  matched: ["해시 일치", "ok"],
  computed: ["해시 계산됨", "ok"],
  mismatched: ["해시 불일치", "danger"],
  failed: ["해시 계산 실패", "danger"],
  interrupted: ["해시 계산 중단", "warn"],
};

/** E01 / Ex01 evidence: values are container bytes; the media (disk) is never re-hashed. */
const EWF_HASH: Record<string, [string, ChipTone]> = {
  ...FILE_HASH,
  matched: ["컨테이너 해시 일치", "ok"],
  computed: ["컨테이너 해시 계산됨", "ok"],
  mismatched: ["컨테이너 해시가 입력값과 다름 — 매체 해시 미대조", "warn"],
};

export const INCOMPLETE_SET_LABEL = "세그먼트 집합 불완전 — 컨테이너 해시는 있는 세그먼트만";
export const RECORDED_DIFFERS_LABEL =
  "입력값이 이미지에 기록된 취득 해시와 다름 — 취득 기록·이미지 확인 필요";

const ALGORITHM_BY_LENGTH: Record<number, "md5" | "sha1"> = { 32: "md5", 40: "sha1" };

/** E01/Ex01 by the server's hash scope; before a hash finished, by the evidence type. */
export function isEwfEvidence(item: CaseEvidence): boolean {
  return item.hash_scope ? item.hash_scope === EWF_HASH_SCOPE : item.source_type === "e01";
}

/** The recorded acquisition hash of the input's algorithm ("" when none was recorded). */
function recordedForInput(item: CaseEvidence): string {
  const expected = (item.hash_expected || "").trim().toLowerCase();
  const algorithm = ALGORITHM_BY_LENGTH[expected.length];
  return algorithm && item.hash_recorded ? item.hash_recorded[algorithm] || "" : "";
}

/** `[label, tone]` of an evidence item's hash state (the server's label is the fallback). */
export function evidenceHashLabel(item: CaseEvidence): [string, ChipTone] {
  if (!isEwfEvidence(item)) return FILE_HASH[item.hash_status] ?? [item.hash_status_label, ""];
  // The server's comparison first (audit record, independent of the display sidecar); the sidecar's
  // recorded value only for an older server that sends no `hash_recorded_compare`.
  const recorded = recordedForInput(item);
  const expected = (item.hash_expected || "").trim().toLowerCase();
  const compare =
    item.hash_recorded_compare ||
    (expected && recorded ? (recorded === expected ? "equals" : "differs") : "");
  if (item.hash_status === "mismatched" && compare === "differs") {
    return [RECORDED_DIFFERS_LABEL, "danger"];
  }
  const finished = item.hash_status === "computed" || item.hash_status === "matched";
  if (finished && (item.hash_set_incomplete || item.hash_recorded?.incomplete)) {
    return [INCOMPLETE_SET_LABEL, "warn"];
  }
  if (item.hash_status === "computed" && compare === "equals") {
    return ["입력값 = 기록된 취득 해시 — 매체 재계산 안 함", "info"];
  }
  // Nothing to compare the input with (E01 records no SHA-256, no hash section, read error): the
  // server stores `computed` (WB-8 P1-1); say so instead of "계산됨".
  if (item.hash_status === "computed" && expected) {
    return ["입력값 대조 불가 — 이미지에 같은 종류의 기록된 취득 해시 없음", "info"];
  }
  return EWF_HASH[item.hash_status] ?? [item.hash_status_label, ""];
}

export function EvidenceHashChip({ item }: { item: CaseEvidence }) {
  const [label, tone] = evidenceHashLabel(item);
  return (
    <ToneChip tone={tone} title={item.hash_message || undefined}>
      {label}
    </ToneChip>
  );
}

function RecordedLine({ item }: { item: CaseEvidence }) {
  const recorded = item.hash_recorded;
  if (!recorded) return null;
  const parts = [
    recorded.md5 ? `MD5 ${recorded.md5}` : "",
    recorded.sha1 ? `SHA-1 ${recorded.sha1}` : "",
  ].filter(Boolean);
  const reason = recorded.reason ? ` (${recorded.reason})` : "";
  let text = `이미지에 기록된 취득 해시 없음${reason}`;
  if (parts.length) text = `이미지에 기록된 취득 해시 ${parts.join(" · ")} (다시 계산하지 않음)`;
  else if (recorded.incomplete || item.hash_set_incomplete)
    text = `기록된 취득 해시를 읽지 못함 — 세그먼트 집합 불완전${reason}`;
  return (
    <p className="dash-note mono dash-wrap" data-testid="evidence-recorded-hash">
      {text}
    </p>
  );
}

/** Hash values under an evidence item: segment SHA-256 first, the recorded acquisition hash third. */
export function EvidenceHashValues({ item }: { item: CaseEvidence }) {
  const segments = item.hash_segments ?? [];
  const sha256 = item.hashes?.sha256;
  if (!isEwfEvidence(item)) {
    return sha256 ? <p className="dash-note mono dash-wrap">SHA-256 {sha256}</p> : null;
  }
  const rows = segments.map((segment, index) => (
    <li key={`${segment.segment_number ?? index}:${segment.name}`}>
      세그먼트 {segment.segment_number ?? index + 1} {segment.name} · SHA-256 {segment.sha256 || "없음"}
    </li>
  ));
  let values = null;
  if (rows.length > SEGMENT_PREVIEW) {
    values = (
      <details className="dash-details">
        <summary>세그먼트 {rows.length}개 컨테이너 SHA-256</summary>
        <ul className="dash-note mono dash-wrap" aria-label={`증거 ${item.evidence_number} 세그먼트 해시`}>
          {rows}
        </ul>
      </details>
    );
  } else if (rows.length) {
    values = (
      <ul className="dash-note mono dash-wrap" aria-label={`증거 ${item.evidence_number} 세그먼트 해시`}>
        {rows}
      </ul>
    );
  } else if (sha256) {
    values = <p className="dash-note mono dash-wrap">컨테이너 SHA-256 {sha256}</p>;
  }
  if (!values && !item.hash_recorded) return null;
  const gaps = item.hash_segment_gaps ?? [];
  return (
    <div data-testid="evidence-hash-values">
      {values}
      {gaps.length ? (
        <p className="dash-note" data-testid="evidence-segment-gaps">
          빠진 세그먼트 번호 {gaps.join(", ")} — 컨테이너 해시는 있는 세그먼트{" "}
          {item.hash_segment_count ?? rows.length}개만
        </p>
      ) : null}
      <RecordedLine item={item} />
      {values ? (
        <p className="dash-note">
          E01 파일 자체(컨테이너)의 해시입니다. 취득 로그의 매체(디스크) 해시와는 값이 다른 것이 정상입니다.
        </p>
      ) : null}
    </div>
  );
}
