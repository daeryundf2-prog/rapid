/**
 * 복구 범위: every limit that truncated parsing in a run (`coverage` of the run summary,
 * rapidtriage/core/coverage.py), one plain Korean sentence per entry.
 */

import type { CoverageEntry } from "../../api/runs";
import { formatBytes } from "../grid/columns/common";
import { formatCount } from "../grid/gridUtils";

const AREA_LABEL: Record<string, string> = {
  carving: "카빙",
  carve: "카빙",
  "carving.unallocated": "미할당 영역 카빙",
  eventlog: "이벤트 로그",
  registry: "레지스트리",
  "registry-hive-strings": "레지스트리 하이브 문자열",
  partition: "파티션",
  "e01_native.partition": "파티션",
  "e01_native.filesystem": "파일시스템",
  "e01_native.files": "파일 추출",
  "e01_native.deleted_mft": "삭제 항목 (NTFS)",
  "e01_native.deleted_tsk": "삭제 항목",
  deleted: "삭제 항목",
  docs: "문서",
  files: "파일",
  timeline: "타임라인",
};

/** Complete predicates: a skip is not "partly processed", so each reason carries its own ending. */
const REASON_LABEL: Record<string, string> = {
  scan_bytes_cap: "스캔 용량 상한에 걸려 일부만 처리됨",
  candidate_cap: "후보 수 상한에 걸려 일부만 처리됨",
  unallocated_run_cap: "미할당 구간 수 상한에 걸려 일부만 처리됨",
  "string-count-cap": "문자열 수 상한에 걸려 일부만 처리됨",
  "file-count-cap": "파일 수 상한에 걸려 일부만 추출됨",
  "unsupported-filesystem": "지원하지 않는 파일시스템이라 처리하지 않음",
  "partition-not-supported": "지원하지 않는 파티션이라 처리하지 않음",
  "deleted-sweep-cap": "삭제 항목 탐색 상한에 걸려 일부만 처리됨",
  "mft-local-copy-failed": "MFT 사본을 만들지 못해 느린 경로로 처리함",
  "evtx-string-cap": "레코드당 문자열 상한에 걸려 일부만 처리됨",
  "evtx-binxml-token-cap": "레코드당 BinXML 토큰 상한에 걸려 일부만 처리됨",
  "evtx-nested-binxml-size-cap": "중첩 BinXML 크기 상한에 걸려 일부만 처리됨",
  "evtx-record-size-cap": "레코드 크기 상한에 걸려 일부만 처리됨",
  "etl-scan-prefix-cap": "앞부분 스캔 상한에 걸려 일부만 처리됨",
};

const UNIT_LABEL: Record<string, string> = {
  candidates: "후보",
  records: "레코드",
  mft_records: "MFT 레코드",
  strings: "문자열",
  start_sector: "섹터",
  partition: "파티션",
  filesystem: "파일시스템",
  runs: "구간",
  files: "파일",
  entries: "항목",
  items: "항목",
  tokens: "토큰",
};

const normalize = (code: string) => code.trim().toLowerCase().replaceAll("_", "-");

const AREAS = new Map(Object.entries(AREA_LABEL));
const REASONS = new Map(Object.entries(REASON_LABEL).map(([code, label]) => [normalize(code), label]));

/** "12 MB" for bytes, "4,770 후보" for counts; "" when there is no number. */
export function formatCoverageValue(value: number | null | undefined, unit: string): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "";
  if (unit === "bytes") return formatBytes(value);
  const noun = UNIT_LABEL[unit] ?? "항목";
  return noun ? `${formatCount(value)} ${noun}` : formatCount(value);
}

/** The measured part of the sentence, or "" when neither number is known. */
function measureText(entry: CoverageEntry): string {
  // A partition skip reports where it started, not a count; a limit of 0 is not a cap.
  const start = entry.detail?.start_sector;
  if (typeof start === "number") return `시작 섹터 ${formatCount(start)}`;
  const observed = formatCoverageValue(entry.observed, entry.unit);
  const limit = entry.limit ? formatCoverageValue(entry.limit, entry.unit) : "";
  if (observed && limit) return `확인 ${observed} / 상한 ${limit}`;
  if (observed) return `확인 ${observed}`;
  if (limit) return `상한 ${limit}`;
  return "";
}

function CoverageItem({ entry }: { entry: CoverageEntry }) {
  const area = AREAS.get(entry.area);
  const reason = REASONS.get(normalize(entry.reason_code));
  const measure = measureText(entry);
  return (
    <li className="coverage-item" data-testid="coverage-item">
      <span title={area ? undefined : entry.area}>{area ?? "기타 영역"}</span>
      {": "}
      <span title={reason ? undefined : entry.reason_code}>{reason ?? "기타 제한이 적용됨"}</span>
      {measure ? ` — ${measure}` : ""}
    </li>
  );
}

export function CoveragePanel({ coverage }: { coverage: CoverageEntry[] | null | undefined }) {
  return (
    <section
      className="stage-section process-coverage"
      aria-labelledby="process-coverage-title"
      data-testid="process-coverage"
    >
      <h3 id="process-coverage-title">복구 범위</h3>
      {coverage == null ? (
        <p className="analysis-desc">이 런은 복구 범위 기록 이전에 만들어졌습니다</p>
      ) : coverage.length === 0 ? (
        <p className="analysis-desc">제한 없이 처리됨</p>
      ) : (
        <ul className="coverage-list">
          {coverage.map((entry, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: entries have no id; order is stable
            <CoverageItem key={index} entry={entry} />
          ))}
        </ul>
      )}
    </section>
  );
}
