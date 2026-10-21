/**
 * Family catalogue (viewer-families plan §3.1/§3.2): `GET /api/meta/families` → per family the
 * core / auxiliary grid columns and the triage rules (특이사항 지표). The console starts with the
 * bundled fallback (families.fallback.json, generated from scripts/families-mock.mjs) and swaps in
 * the server's catalogue once it loads; an older server without the endpoint keeps the fallback.
 *
 * Contract (D1):
 *   { version, families: [{ id, label, types, kinds?, prefixes?, core_columns, aux_columns, rules }],
 *     rules: [{ id, family, grade, label_ko, rationale_ko, false_positive_ko, sources, version,
 *               status, params, validation? }] }
 *   validation (R6 S4): { synthetic, real: [{ source, hits?, false_positives?, checked_at?, note_ko? }],
 *               public: [...], notes_ko }
 *   column: { key, label, format?, ts_kind?, width?, aliases?, semantic?, semantic_when?, derive? }
 */

import { useQuery } from "@tanstack/react-query";
import { useEffect, useSyncExternalStore } from "react";
import { api } from "../../api/client";
import fallbackJson from "./families.fallback.json";

export type Grade = "A" | "B" | "C";
export const GRADES: readonly Grade[] = ["A", "B", "C"];

export interface CatalogColumn {
  key: string;
  label: string;
  format?: string;
  ts_kind?: string;
  width?: number;
  /** Other keys of the same fact, tried in order ("event_data.X" reads EVTX EventData). */
  aliases?: string[];
  /**
   * Meaning tag (axiom-adoption §3.2: person, account, device, path, url, hash, credential …): the
   * server's 통합 보기 tables gather every column with one.
   */
  semantic?: string;
  /** Display-only column computed from the row's own fields (`derivedFields.ts` DERIVERS id). */
  derive?: string;
  /**
   * Korean readings of raw values (`{outgoing: "발신", …}`, r2 console fix M7): the grid cell,
   * viewer and citation show the reading, the raw value stays in the tooltip, and a column filter
   * on the reading matches every raw spelling mapped to it (client-side column filters match the
   * shown text). Values not in the map are shown as written.
   */
  value_labels?: Record<string, string>;
}

export interface CatalogFamily {
  id: string;
  label: string;
  types: string[];
  kinds?: string[];
  prefixes?: string[];
  /** Type suffixes ("-string-candidate", "-summary"): checked before exact types and prefixes. */
  suffixes?: string[];
  core_columns: CatalogColumn[];
  aux_columns: CatalogColumn[];
  rules: string[];
}

/**
 * What one real-data / public-dataset check proves (UX-round review): `positive` = a confirmed true
 * positive was flagged; `negative` = the rule ran over real input with no confirmed true positive;
 * `not_applicable` = no input rows; `unevaluated` = the rule could not run. Only positive/negative count.
 */
export type RuleValidationResult = "positive" | "negative" | "not_applicable" | "unevaluated";

const VALIDATION_RESULTS: readonly RuleValidationResult[] = [
  "positive",
  "negative",
  "not_applicable",
  "unevaluated",
];

/** One real-data / public-dataset check of a rule (catalogue `validation.real` / `.public`). */
export interface RuleValidationEntry {
  source: string;
  /** Missing in an older payload: read as `unevaluated` (never counted). */
  result: RuleValidationResult;
  hits?: number;
  /** False positives in the reviewed sample (`sample_size` rows when given), not over every hit. */
  false_positives?: number;
  sample_size?: number;
  checked_at?: string;
  note_ko?: string;
}

/** What a rule was checked against beyond its code (R6 S4; metadata only, never a verdict). */
export interface RuleValidation {
  synthetic: boolean;
  real: RuleValidationEntry[];
  public: RuleValidationEntry[];
  notes_ko: string;
}

export interface CatalogRule {
  id: string;
  family: string;
  grade: Grade;
  label_ko: string;
  rationale_ko: string;
  false_positive_ko: string;
  sources: string[];
  version: string | number;
  status: "verified" | "provisional";
  params: Record<string, unknown>;
  validation?: RuleValidation;
}

export interface FamilyCatalog {
  version: string;
  families: CatalogFamily[];
  rules: CatalogRule[];
}

/**
 * Korean names for catalogue labels that arrive as a bare English token (older or partly
 * translated YAML): every label the console shows is Korean. A label that already contains Hangul
 * is kept as written; an unknown English one is shown as-is (the report lists them for the YAML).
 */
export const LABEL_KO: Readonly<Record<string, string>> = {
  SRUM: "시스템 자원 사용(SRUM)",
  "MFT/USN": "MFT/USN 메타데이터",
  "Zone.Identifier": "다운로드 출처 표식(Zone.Identifier)",
  Defender: "Defender 백신 로그",
  AppID: "앱 ID",
  ControlSet: "컨트롤 세트",
  "Secure/HttpOnly/SameSite": "쿠키 보안 속성(Secure/HttpOnly/SameSite)",
  "Takeout GPS ≠ EXIF GPS": "Takeout 위치 ≠ EXIF 위치",
  SID: "보안 식별자(SID)",
  URL: "URL 주소",
  PID: "프로세스 ID",
  GUID: "GUID 식별자",
};

const HANGUL = /[가-힣]/;

export function koreanLabel(label: string): string {
  if (HANGUL.test(label)) return label;
  return LABEL_KO[label.trim()] ?? label;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string" && v !== "") : [];
}

export function isGrade(value: unknown): value is Grade {
  return value === "A" || value === "B" || value === "C";
}

function column(raw: unknown): CatalogColumn | null {
  if (!isRecord(raw) || typeof raw.key !== "string" || !raw.key) return null;
  return {
    key: raw.key,
    label: koreanLabel(typeof raw.label === "string" && raw.label ? raw.label : raw.key),
    ...(typeof raw.format === "string" ? { format: raw.format } : {}),
    ...(typeof raw.ts_kind === "string" && raw.ts_kind ? { ts_kind: raw.ts_kind } : {}),
    ...(typeof raw.width === "number" && raw.width > 0 ? { width: raw.width } : {}),
    ...(strings(raw.aliases).length ? { aliases: strings(raw.aliases) } : {}),
    ...(typeof raw.semantic === "string" && raw.semantic ? { semantic: raw.semantic } : {}),
    ...(typeof raw.derive === "string" && raw.derive ? { derive: raw.derive } : {}),
    ...(valueLabels(raw.value_labels) ? { value_labels: valueLabels(raw.value_labels) } : {}),
  };
}

function valueLabels(raw: unknown): Record<string, string> | undefined {
  if (!isRecord(raw)) return undefined;
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (key && typeof value === "string" && value.trim()) out[key] = value;
  }
  return Object.keys(out).length ? out : undefined;
}

/** Korean reading of a raw scalar by a column's `value_labels` (undefined = none). */
export function columnValueLabel(def: Pick<CatalogColumn, "value_labels">, raw: unknown): string | undefined {
  if (!def.value_labels || (typeof raw !== "string" && typeof raw !== "number" && typeof raw !== "boolean"))
    return undefined;
  return def.value_labels[String(raw)];
}

/** The catalogue column of `family` reading record key `key` (its key or an alias). */
function familyColumnFor(family: CatalogFamily | undefined, key: string): CatalogColumn | undefined {
  if (!family) return undefined;
  return [...family.core_columns, ...family.aux_columns].find(
    (def) => def.key === key || (def.aliases ?? []).includes(key),
  );
}

/** Korean reading of `raw` in record key `key` of a row of `artifactType` (viewer meta). */
export function typeValueLabel(
  artifactType: string | null | undefined,
  key: string,
  raw: unknown,
): string | undefined {
  const def = familyColumnFor(familyForType(artifactType), key);
  return def ? columnValueLabel(def, raw) : undefined;
}

/** Korean reading of `raw` in record key `key` of family `familyId` (flag evidence in citations). */
export function familyValueLabel(
  familyId: string | undefined,
  key: string,
  raw: unknown,
): string | undefined {
  const family = familyId ? active.families.find((entry) => entry.id === familyId) : undefined;
  const def = familyColumnFor(family, key);
  return def ? columnValueLabel(def, raw) : undefined;
}

function validationEntries(raw: unknown): RuleValidationEntry[] {
  if (!Array.isArray(raw)) return [];
  const out: RuleValidationEntry[] = [];
  for (const entry of raw) {
    if (!isRecord(entry) || typeof entry.source !== "string" || !entry.source.trim()) continue;
    const result = VALIDATION_RESULTS.find((item) => item === entry.result) ?? "unevaluated";
    out.push({
      source: entry.source,
      result,
      ...(typeof entry.hits === "number" ? { hits: entry.hits } : {}),
      ...(typeof entry.false_positives === "number" ? { false_positives: entry.false_positives } : {}),
      ...(typeof entry.sample_size === "number" ? { sample_size: entry.sample_size } : {}),
      ...(typeof entry.checked_at === "string" && entry.checked_at ? { checked_at: entry.checked_at } : {}),
      ...(typeof entry.note_ko === "string" && entry.note_ko ? { note_ko: entry.note_ko } : {}),
    });
  }
  return out;
}

/** A rule's `validation` block; undefined when absent or malformed. */
function ruleValidation(raw: unknown): RuleValidation | undefined {
  if (!isRecord(raw) || typeof raw.synthetic !== "boolean") return undefined;
  return {
    synthetic: raw.synthetic,
    real: validationEntries(raw.real),
    public: validationEntries(raw.public),
    notes_ko: typeof raw.notes_ko === "string" ? raw.notes_ko : "",
  };
}

/** Validate a catalogue payload; malformed entries are dropped, a payload without families is null. */
export function normalizeCatalog(raw: unknown): FamilyCatalog | null {
  if (!isRecord(raw) || !Array.isArray(raw.families)) return null;
  const families: CatalogFamily[] = [];
  for (const entry of raw.families) {
    if (!isRecord(entry) || typeof entry.id !== "string" || !entry.id) continue;
    families.push({
      id: entry.id,
      label: koreanLabel(typeof entry.label === "string" && entry.label ? entry.label : entry.id),
      types: strings(entry.types),
      ...(strings(entry.kinds).length ? { kinds: strings(entry.kinds) } : {}),
      ...(strings(entry.prefixes).length ? { prefixes: strings(entry.prefixes) } : {}),
      ...(strings(entry.suffixes).length ? { suffixes: strings(entry.suffixes) } : {}),
      core_columns: (Array.isArray(entry.core_columns) ? entry.core_columns : [])
        .map(column)
        .filter((c): c is CatalogColumn => c !== null),
      aux_columns: (Array.isArray(entry.aux_columns) ? entry.aux_columns : [])
        .map(column)
        .filter((c): c is CatalogColumn => c !== null),
      rules: strings(entry.rules),
    });
  }
  if (!families.length) return null;
  const rules: CatalogRule[] = [];
  for (const entry of Array.isArray(raw.rules) ? raw.rules : []) {
    if (!isRecord(entry) || typeof entry.id !== "string" || !isGrade(entry.grade)) continue;
    const validation = ruleValidation(entry.validation);
    rules.push({
      id: entry.id,
      family: typeof entry.family === "string" ? entry.family : "",
      grade: entry.grade,
      label_ko: koreanLabel(typeof entry.label_ko === "string" && entry.label_ko ? entry.label_ko : entry.id),
      rationale_ko: typeof entry.rationale_ko === "string" ? entry.rationale_ko : "",
      false_positive_ko: typeof entry.false_positive_ko === "string" ? entry.false_positive_ko : "",
      sources: strings(entry.sources),
      version: typeof entry.version === "number" || typeof entry.version === "string" ? entry.version : "",
      status: entry.status === "provisional" ? "provisional" : "verified",
      params: isRecord(entry.params) ? entry.params : {},
      ...(validation ? { validation } : {}),
    });
  }
  return {
    version: typeof raw.version === "string" ? raw.version : String(raw.version ?? ""),
    families,
    rules,
  };
}

export const FALLBACK_CATALOG: FamilyCatalog = normalizeCatalog(fallbackJson) as FamilyCatalog;

export type CatalogSource = "fallback" | "server";

/** A catalogue that claims no family (tests of the KIND_COLUMNS fallback). */
export const EMPTY_CATALOG_FOR_TESTS: FamilyCatalog = Object.freeze({
  version: "empty",
  families: [],
  rules: [],
});

/** The catalogue `setCatalog(null)` returns to (tests pin it to the stable mock fixture). */
let fallback: FamilyCatalog = FALLBACK_CATALOG;
let active: FamilyCatalog = fallback;
let source: CatalogSource = "fallback";
const listeners = new Set<() => void>();
let ruleIndex = new Map<string, CatalogRule>();
let typeIndex = new Map<string, CatalogFamily>();

function reindex(): void {
  ruleIndex = new Map(active.rules.map((rule) => [rule.id, rule]));
  typeIndex = new Map();
  for (const family of active.families) for (const type of family.types) typeIndex.set(type, family);
}
reindex();

/** The catalogue in effect (server once loaded, else the bundled fallback). */
export function getCatalog(): FamilyCatalog {
  return active;
}

export function getCatalogSource(): CatalogSource {
  return source;
}

/** Install a catalogue (null = back to the bundled fallback). */
export function setCatalog(next: FamilyCatalog | null, from: CatalogSource = "server"): void {
  active = next ?? fallback;
  source = next ? from : "fallback";
  reindex();
  for (const listener of listeners) listener();
}

/**
 * Tests only (vitest setup): make `setCatalog(null)` return to a fixed catalogue (the families
 * mock) so unit tests do not drift with the backend YAML.
 */
export function pinFallbackCatalogForTests(next: FamilyCatalog): void {
  fallback = next;
  setCatalog(null);
}

export function subscribeCatalog(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useCatalog(): FamilyCatalog {
  return useSyncExternalStore(subscribeCatalog, getCatalog, getCatalog);
}

export function ruleById(id: string): CatalogRule | undefined {
  return ruleIndex.get(id);
}

/**
 * Family of one artifact type, in the backend's order (`Catalog.family_for`): a suffix
 * ("-string-candidate", "-summary"), the exact type, then the longest matching prefix.
 */
export function familyForType(type: string | null | undefined): CatalogFamily | undefined {
  if (!type) return undefined;
  for (const family of active.families) {
    if (family.suffixes?.some((suffix) => type.endsWith(suffix))) return family;
  }
  const exact = typeIndex.get(type);
  if (exact) return exact;
  let best: { family: CatalogFamily; length: number } | undefined;
  for (const family of active.families) {
    for (const prefix of family.prefixes ?? []) {
      if (type.startsWith(prefix) && (!best || prefix.length > best.length))
        best = { family, length: prefix.length };
    }
  }
  return best?.family;
}

/** The one family every type belongs to; undefined when they span families or one is unknown. */
export function familyForTypes(types: readonly string[] | undefined): CatalogFamily | undefined {
  if (!types?.length) return undefined;
  const first = familyForType(types[0]);
  if (!first) return undefined;
  return types.every((type) => familyForType(type)?.id === first.id) ? first : undefined;
}

/** Rows per artifact type of each kind (`/tree` artifact_type_counts), for the majority rule. */
const kindTypeCounts = new Map<string, Record<string, number>>();

/**
 * Record a kind's rows per artifact type (the grid does this from `/tree`). Returns true when the
 * counts changed (the column layout then rebuilds).
 */
export function noteKindTypeCounts(kind: string, counts: Record<string, number> | undefined): boolean {
  if (!counts) return false;
  const before = kindTypeCounts.get(kind);
  if (before && JSON.stringify(before) === JSON.stringify(counts)) return false;
  kindTypeCounts.set(kind, { ...counts });
  return true;
}

/** Share of a kind's rows the majority family must hold to give the kind its layout. */
export const MAJORITY_SHARE = 0.5;

/**
 * Family of a whole artifact kind: the single family listing the kind; else (a kind the
 * catalogue reaches only through its types, or a mixed kind) the family holding more than half of
 * the kind's rows by artifact type — rows of other families still show their 유형 chip. A kind
 * claimed by several families, or without a majority, has none (KIND_COLUMNS fallback).
 */
export function familyForKind(kind: string | undefined): CatalogFamily | undefined {
  if (!kind) return undefined;
  const claimed = active.families.filter((family) => family.kinds?.includes(kind));
  if (claimed.length === 1) return claimed[0];
  if (claimed.length > 1) return undefined;
  const counts = kindTypeCounts.get(kind);
  if (!counts) return undefined;
  const perFamily = new Map<CatalogFamily, number>();
  let total = 0;
  for (const [type, count] of Object.entries(counts)) {
    if (typeof count !== "number" || count <= 0) continue;
    total += count;
    const family = familyForType(type);
    if (family) perFamily.set(family, (perFamily.get(family) ?? 0) + count);
  }
  let best: [CatalogFamily, number] | undefined;
  for (const entry of perFamily) if (!best || entry[1] > best[1]) best = entry;
  return best && total > 0 && best[1] / total > MAJORITY_SHARE ? best[0] : undefined;
}

/**
 * Primary family of a node / filter listing several types of one kind (timeline/grid readability
 * C6): the family holding more than half of those types' rows (`/tree` counts) — rows of the
 * other types keep their 유형 chip. Undefined without counts or a majority (mixed layout).
 */
export function majorityFamilyForTypes(
  kind: string | undefined,
  types: readonly string[] | undefined,
): CatalogFamily | undefined {
  const counts = kind ? kindTypeCounts.get(kind) : undefined;
  if (!counts || !types?.length) return undefined;
  const perFamily = new Map<CatalogFamily, number>();
  let total = 0;
  for (const type of types) {
    const count = counts[type];
    if (typeof count !== "number" || count <= 0) continue;
    total += count;
    const family = familyForType(type);
    if (family) perFamily.set(family, (perFamily.get(family) ?? 0) + count);
  }
  let best: [CatalogFamily, number] | undefined;
  for (const entry of perFamily) if (!best || entry[1] > best[1]) best = entry;
  return best && total > 0 && best[1] / total > MAJORITY_SHARE ? best[0] : undefined;
}

/** Tests only. */
export function resetKindTypeCounts(): void {
  kindTypeCounts.clear();
}

export function familyById(id: string): CatalogFamily | undefined {
  return active.families.find((family) => family.id === id);
}

export const FAMILIES_QUERY_KEY = ["meta-families"] as const;

export function fetchFamilyCatalog(signal?: AbortSignal): Promise<unknown> {
  return api<unknown>("/api/meta/families", { signal });
}

/**
 * Mounted once by the app: loads the server catalogue (a 404 from an older server keeps the
 * bundled fallback, never an error state on screen).
 */
export function useFamilyCatalogLoader(enabled = true): void {
  const query = useQuery({
    queryKey: FAMILIES_QUERY_KEY,
    queryFn: ({ signal }) => fetchFamilyCatalog(signal),
    enabled,
    retry: false,
    staleTime: Number.POSITIVE_INFINITY,
  });
  useEffect(() => {
    if (!query.data) return;
    const next = normalizeCatalog(query.data);
    if (next) setCatalog(next, "server");
  }, [query.data]);
}
