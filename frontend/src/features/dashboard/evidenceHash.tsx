/**
 * Evidence hash state and values on the 접수 증거 card (R8 T-129, honest labels only). The server
 * says which bytes were hashed (`hash_scope`): for E01/Ex01 (`ewf-container-segment-bytes`) the
 * values are the container (segment file) bytes, never the acquisition media hash, so the labels
 * say "컨테이너" and a mismatch is amber, not red. Per-segment values are shown first; the
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
  const recorded = recordedForInput(item);
  const expected = (item.hash_expected || "").trim().toLowerCase();
  if (item.hash_status === "computed" && recorded && recorded === expected) {
    return ["입력값 = 기록된 취득 해시 — 매체 재계산 안 함", "info"];
  }
  // Nothing to compare the input with (E01 records no SHA-256, no hash section, read error): the
  // server stores `computed` (WB-8 P1-1); say so instead of "계산됨".
  if (item.hash_status === "computed" && expected && !recorded) {
    return ["입력값 대조 불가 — 이미지에 같은 종류의 기록된 취득 해시 없음", "info"];
  }
  if (item.hash_status === "mismatched" && recorded) {
    return ["입력값이 기록된 취득 해시와 다름 — 매체 해시 미대조", "warn"];
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
  return (
    <p className="dash-note mono dash-wrap" data-testid="evidence-recorded-hash">
      {parts.length
        ? `이미지에 기록된 취득 해시 ${parts.join(" · ")} (다시 계산하지 않음)`
        : `이미지에 기록된 취득 해시 없음${recorded.reason ? ` (${recorded.reason})` : ""}`}
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
  return (
    <div data-testid="evidence-hash-values">
      {values}
      <RecordedLine item={item} />
      {values ? (
        <p className="dash-note">
          E01 파일 자체(컨테이너)의 해시입니다. 취득 로그의 매체(디스크) 해시와는 값이 다른 것이 정상입니다.
        </p>
      ) : null}
    </div>
  );
}
