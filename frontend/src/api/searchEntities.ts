import { api } from "./client";

/**
 * Entity search of the run's v2 index (R7 lane B): entity kinds / masked values / languages
 * (`POST /search/entities`), advanced queries (`POST /search/query` with `q`), the audited reveal of
 * one personal value of one row (`POST /search/entities/reveal`) and search lists (`list:<id>`).
 * The server never answers a personal number except through the reveal.
 */

const enc = encodeURIComponent;

export type EntityKind =
  | "rrn"
  | "corpno"
  | "card"
  | "bizno"
  | "phone"
  | "account"
  | "passport"
  | "email"
  | "ip"
  | "host";

/** Korean names of the entity kinds (patterns.py KIND_LABELS); never show the raw id. */
export const ENTITY_KIND_LABELS: Readonly<Record<EntityKind, string>> = {
  rrn: "주민등록번호",
  corpno: "법인등록번호",
  card: "카드번호",
  bizno: "사업자등록번호",
  phone: "전화번호",
  account: "계좌번호",
  passport: "여권번호",
  email: "이메일",
  ip: "IP 주소",
  host: "호스트",
};

/** Korean names of the language hints (doc_text.language_hint). */
export const LANGUAGE_LABELS: Readonly<Record<string, string>> = {
  ko: "한국어",
  ja: "일본어",
  zh: "중국어",
  en: "영어",
  ru: "러시아어",
  mixed: "혼합",
};

/** Korean names of the hash-set categories (hashsets.py CATEGORY_LABELS). */
export const HASHSET_CATEGORY_LABELS: Readonly<Record<string, string>> = {
  "known-good": "알려진 정상",
  "known-bad": "알려진 악성",
  custom: "사용자 지정",
};

export function entityKindLabel(kind: string): string {
  return (ENTITY_KIND_LABELS as Record<string, string>)[kind] ?? "기타 개체";
}

export function languageLabel(code: string): string {
  return LANGUAGE_LABELS[code] ?? "기타 언어";
}

export interface EntityKindCount {
  kind: string;
  label?: string;
  rows: number;
  values: number;
  verified_values: number;
  sensitive: boolean;
}

export interface EntityValue {
  kind: string;
  label?: string;
  masked: string;
  value_sha256: string;
  verified: boolean;
  rows?: number;
  source?: string;
}

export interface SearchRow {
  doc_id: number;
  group_id: number;
  collection: string;
  kind: string;
  locator: string;
  domain: string;
  artifact_type: string;
  title: string;
  path: string;
  record_ts?: string | null;
  ts?: string | null;
  snippet?: { text?: string; marks?: number[][] } | null;
  pii?: Record<string, number> | null;
  masked_preview?: string[];
  entities?: EntityValue[] | null;
}

export interface FacetItem {
  key: string;
  label?: string;
  count: number;
}

export interface EntitySummary {
  kinds: EntityKindCount[];
  values: EntityValue[];
  languages: FacetItem[];
  rows: SearchRow[] | null;
  rows_total: number | null;
  postings: number;
  query?: { raw?: string; warnings?: string[] };
}

export interface ListItemCount {
  item: string;
  type: string;
  count: number | null;
}

export interface AdvancedQueryResult {
  rows: SearchRow[];
  page: { total: number | null; total_exact: boolean; next_cursor: string | null; returned: number };
  facets: { entities?: FacetItem[]; lang?: FacetItem[] } | null;
  lists: { id: string; name: string; items: ListItemCount[]; omitted: number }[] | null;
  query: { raw: string; parsed: { warnings: string[] } };
  elapsed_ms: number;
  truncated: boolean;
  truncated_reason: string | null;
}

export interface RevealResult {
  value: string;
  masked: string;
  label: string;
  entity_kind: string;
  audit_id: string;
}

export function fetchEntitySummary(
  runId: string,
  body: { q?: string; kind?: EntityKind; value_sha256?: string; limit?: number },
  signal?: AbortSignal,
): Promise<EntitySummary> {
  return api<EntitySummary>(`/api/runs/${enc(runId)}/search/entities`, {
    method: "POST",
    signal,
    body: JSON.stringify(body),
  });
}

/** One page of an advanced query (`q` grammar) with facets and per-item list counts. */
export function runAdvancedQuery(
  runId: string,
  q: string,
  options: { cursor?: string | null; limit?: number } = {},
  signal?: AbortSignal,
): Promise<AdvancedQueryResult> {
  return api<AdvancedQueryResult>(`/api/runs/${enc(runId)}/search/query`, {
    method: "POST",
    signal,
    body: JSON.stringify({
      q,
      page: { limit: options.limit ?? 50, ...(options.cursor ? { cursor: options.cursor } : {}) },
      aggregates: true,
      facets: true,
      highlight: true,
    }),
  });
}

/** Reveal one personal value of one row (1 audit event server-side; the value is answered once). */
export function revealEntity(
  runId: string,
  row: Pick<SearchRow, "collection" | "kind" | "locator">,
  valueSha256: string,
  reason: string,
): Promise<RevealResult> {
  return api<RevealResult>(`/api/runs/${enc(runId)}/search/entities/reveal`, {
    method: "POST",
    body: JSON.stringify({
      collection: row.collection,
      kind: row.kind,
      locator: row.locator,
      value_sha256: valueSha256,
      reason,
    }),
  });
}

export interface SearchListSummary {
  id: string;
  name: string;
  kind: string;
  item_count: number;
  builtin?: boolean;
}

export function listSearchLists(runId: string): Promise<{ lists: SearchListSummary[] }> {
  return api<{ lists: SearchListSummary[] }>(`/api/runs/${enc(runId)}/search/lists`);
}

/** Syntax help of the advanced query (Korean descriptions; examples are typed as is). */
export const QUERY_SYNTAX_HELP: ReadonlyArray<{ example: string; text: string }> = [
  { example: "rrn:*", text: "주민등록번호가 있는 행(값은 가려서 보여 줍니다)" },
  { example: "rrn:verified", text: "검증 자리까지 맞는 주민등록번호만(후보: rrn:candidate)" },
  { example: "rrn:900101*", text: "마스크 앞자리(생년월일)로 찾기" },
  { example: "card:verified", text: "Luhn·발급사 번호까지 맞는 카드번호" },
  { example: "phone:010-1234-5678", text: "전화번호 정확히(+82 형식도 같은 번호)" },
  { example: "email:@naver.com", text: "이메일 도메인으로 찾기" },
  { example: "account:*", text: "계좌번호 후보(은행별 자릿수, 신뢰도 낮음)" },
  { example: "bizno:*", text: "사업자등록번호(corpno: 법인등록번호, passport: 여권번호)" },
  { example: "ip:10.0.0.0/8", text: "IP 주소·CIDR 범위" },
  { example: "host:example.com", text: "호스트(하위 도메인 포함)" },
  { example: "lang:ko -lang:ja", text: "문서·메일 언어(ko·ja·zh·en·ru·mixed)" },
  { example: "list:execution", text: "키워드 팩·IOC 목록의 항목 중 하나(항목별 건수 표시)" },
  { example: "pre:(계약 해지)/3", text: "순서대로, 앞 단어 뒤 3단어 안에" },
  { example: "-hashset:known-good", text: "알려진 정상 해시 집합에 든 파일 숨기기" },
];
