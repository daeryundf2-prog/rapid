/**
 * Processing-scope band (R8 T-024, IS-004; temporary until the briefing v0): the four axes of
 * `/dashboard` `scope` (T-023) on one line in the case dashboard head block.
 */

import type { RunScope } from "../../api/dashboard";

/** Count in 만/억 units, floored ("430,052" → "43만"): a compact figure never reads larger than it is. */
export function koCount(value: number): string {
  if (value >= 100_000_000) return `${Math.floor(value / 100_000_000).toLocaleString("ko-KR")}억`;
  if (value >= 10_000) return `${Math.floor(value / 10_000).toLocaleString("ko-KR")}만`;
  return value.toLocaleString("ko-KR");
}

export interface ScopeAxis {
  axis: "partitions" | "allocated" | "deleted" | "unallocated";
  /** Raw figure behind the text (QA reads it; `data-count`). */
  count: string;
  text: string;
}

/**
 * The four axes of the processing-scope band (T-024, IS-004): never one "n% of the volume"
 * figure. Server percentages are already floored and are shown as-is.
 */
export function scopeAxes(scope: RunScope): ScopeAxis[] {
  const { partitions, allocated, deleted, unallocated } = scope;
  const denominator = partitions.supported ?? partitions.total;
  const inferred = (allocated.basis ?? scope.basis) === "inferred";
  const notAttempted = deleted.not_attempted ?? null;
  let deletedText = "삭제 레코드 확인 못 함";
  if (notAttempted && notAttempted > 0) {
    deletedText = `삭제 레코드 ${koCount(notAttempted)} 건 내용 미시도`;
    if (deleted.attempted_pct !== null) deletedText += `(시도 ${deleted.attempted_pct}%)`;
  } else if (deleted.attempted_pct !== null) {
    deletedText = `삭제 레코드 시도 ${deleted.attempted_pct}%`;
  }
  return [
    {
      axis: "partitions",
      count: `${partitions.processed ?? ""}/${denominator ?? ""}`,
      text:
        partitions.processed !== null && denominator !== null
          ? `파티션 ${partitions.processed}/${denominator}`
          : "파티션 확인 못 함",
    },
    {
      axis: "allocated",
      count: allocated.listed_pct === null ? "" : String(allocated.listed_pct),
      text:
        allocated.listed_pct === null
          ? "할당 파일 목록화 확인 못 함"
          : `할당 파일 목록화 ${allocated.listed_pct}%${inferred ? "(추정)" : ""}`,
    },
    {
      axis: "deleted",
      count: String(notAttempted ?? deleted.attempted_pct ?? ""),
      text: deletedText,
    },
    {
      axis: "unallocated",
      count: unallocated.scanned_pct === null ? "" : String(unallocated.scanned_pct),
      text:
        unallocated.measured && unallocated.scanned_pct !== null
          ? `비할당 ${unallocated.scanned_pct}%`
          : "비할당 측정하지 않음",
    },
  ];
}

/**
 * Processing-scope band at the top of the case screen (T-024; temporary until the briefing v0).
 * Amber one line of four axes when the run is partial; nothing when every axis is complete or the
 * server sent no scope; a neutral note when the result has no extraction stats.
 */
export function ScopeBand({ scope }: { scope: RunScope | null | undefined }) {
  if (!scope) return null;
  if (scope.basis === "unavailable") {
    return (
      <p className="dash-scope-note" data-testid="dash-scope-note">
        처리 범위: {scope.notes[0] ?? "추출 통계가 없어 계산하지 않았습니다."}
      </p>
    );
  }
  if (scope.partial === false) return null;
  const cap = scope.caps.find((item) => item.reached);
  return (
    <section className="dash-scope" aria-label="처리 범위" data-testid="dash-scope">
      <p className="dash-scope-line">
        {scopeAxes(scope).map((item, index) => (
          <span key={item.axis} className="dash-scope-axis" data-axis={item.axis} data-count={item.count}>
            {index ? " · " : ""}
            {item.text}
          </span>
        ))}
        {cap ? (
          <span className="dash-scope-extra">
            추출 상한{typeof cap.limit === "number" ? ` ${cap.limit.toLocaleString("ko-KR")}개` : ""} 도달
          </span>
        ) : null}
        {scope.basis === "inferred" ? (
          <span className="dash-scope-extra" title="추출 통계에서 추론(basis: inferred)">
            Sleuth Kit 대조 전 추정
          </span>
        ) : null}
      </p>
      {scope.notes.length ? (
        <details className="dash-scope-details">
          <summary>자세히</summary>
          <ul>
            {scope.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </details>
      ) : null}
    </section>
  );
}
