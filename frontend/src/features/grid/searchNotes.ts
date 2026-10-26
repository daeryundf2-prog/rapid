/**
 * Footer note of a v2 console search (R7 S2 #3): the server's query warnings — rows whose body
 * the index cut at its cap (so their tail was not searched) and keywords too short for the index —
 * as ONE Korean line, with the per-source counts and the server sentences in its tooltip.
 */

import type { SearchWarning } from "../../api/search";
import { formatCount } from "./gridUtils";

/** Korean names of index domains (search_index engine `DOMAINS`) and collections / v1 sources. */
export const SEARCH_DOMAIN_LABELS: Readonly<Record<string, string>> = {
  os: "운영 체제",
  execution: "실행",
  filesystem: "파일 시스템",
  registry: "레지스트리",
  eventlog: "이벤트 로그",
  web: "웹·브라우저",
  messaging: "메신저",
  cloud: "클라우드",
  media: "문서·미디어",
  mobile: "모바일",
  devices: "장치",
  "anti-forensics": "안티포렌식",
  incident: "침해 대응",
  memory: "메모리",
  location: "위치",
  other: "기타",
  files: "파일",
  docs: "문서",
  documents: "문서 본문",
  artifacts: "아티팩트",
  indicators: "지표(IOC)",
  analysis: "분석 결과",
  timeline: "타임라인",
};

export function searchDomainLabel(name: string): string {
  return SEARCH_DOMAIN_LABELS[name] ?? name;
}

export const SEARCH_SHORT_KEYWORD_NOTE =
  "1자·영문 2자 검색어는 색인 없이 전체 본문을 훑었습니다(느릴 수 있음)";

function isWarning(value: unknown): value is SearchWarning {
  return (
    !!value &&
    typeof value === "object" &&
    typeof (value as SearchWarning).text === "string" &&
    typeof (value as SearchWarning).kind === "string"
  );
}

/**
 * One footer line + tooltip for the page's v2 warnings (`meta.searchWarnings`) and the top bar's
 * keyword-cap note (R7 S2 #4); undefined when there is neither.
 */
export function searchWarningNote(
  value: unknown,
  keywordNote?: string,
): { text: string; title: string } | undefined {
  const warnings = Array.isArray(value) ? value.filter(isWarning) : [];
  if (!warnings.length && !keywordNote) return undefined;
  const parts: string[] = keywordNote ? [keywordNote] : [];
  const tooltip: string[] = [];
  const truncated = warnings.filter((w) => w.kind === "truncated-rows");
  if (truncated.length) {
    const counts = new Map<string, number>();
    for (const warning of truncated)
      for (const [name, rows] of Object.entries(warning.counts ?? {}))
        counts.set(name, Math.max(counts.get(name) ?? 0, rows));
    const total = [...counts.values()].reduce((sum, rows) => sum + rows, 0);
    parts.push(
      total > 0
        ? `본문이 색인 상한에서 잘린 행 ${formatCount(total)}건은 뒷부분이 검색되지 않았습니다`
        : "본문이 색인 상한에서 잘린 행이 있어 그 뒷부분은 검색되지 않았습니다",
    );
    if (counts.size) {
      tooltip.push("출처별 잘린 행:");
      for (const [name, rows] of [...counts].sort((a, b) => b[1] - a[1]))
        tooltip.push(`· ${searchDomainLabel(name)} ${formatCount(rows)}건`);
    }
  }
  if (warnings.some((w) => w.kind === "short-keyword")) parts.push(SEARCH_SHORT_KEYWORD_NOTE);
  const other = warnings.filter((w) => w.kind === "other" && w.text);
  if (other[0]) parts.push(other.length > 1 ? `${other[0].text} 외 ${other.length - 1}건` : other[0].text);
  for (const warning of warnings) if (warning.text) tooltip.push(warning.text);
  return { text: `검색 참고: ${parts.join(" · ")}`, title: tooltip.join("\n") };
}
