import type { RunCreateBody } from "../../api/runs";

export interface RunForm {
  root: string;
  mode: string;
  inputKind: string;
  outputDir: string;
  collectProfile: string;
  maxExtractMb: string;
  maxFileCount: string;
  partitionSector: string;
  knownGoodFeeds: string;
  hideKnownGood: boolean;
  readOnly: boolean;
  dryRun: boolean;
  overwrite: boolean;
  extract: boolean;
  /** Skippable processing groups the examiner unchecked (R4 V1 "처리 그룹"; sent as `skip_groups`). */
  skipGroups: string[];
  /** R7 AI 사용 기록 (kind `ai-agent`): message bodies (masked) collected — default on. */
  aiBodies: boolean;
  /** AI 사용 기록: organisation e-mail domain (`org_email_domain`; the server validates it). */
  aiOrgDomain: string;
  /** AI 사용 기록: case evidence folders, one per line (`evidence_roots`). */
  aiEvidenceRoots: string;
  /** AI 사용 기록: per-tool read budget in MiB (`ai_read_mb`); empty = server default. */
  aiReadMb: string;
}

/** Upper bound of `ai_read_mb` (MAX_AI_READ_MB, artifacts/ai_agents/run_indirect.py). */
export const MAX_AI_READ_MB = 1024 * 1024;

export const DEFAULT_RUN_FORM: RunForm = {
  root: "",
  mode: "fraud",
  inputKind: "",
  outputDir: "",
  collectProfile: "",
  maxExtractMb: "0",
  maxFileCount: "0",
  partitionSector: "",
  knownGoodFeeds: "",
  hideKnownGood: false,
  readOnly: true,
  dryRun: false,
  overwrite: false,
  extract: false,
  skipGroups: [],
  aiBodies: true,
  aiOrgDomain: "",
  aiEvidenceRoots: "",
  aiReadMb: "",
};

/**
 * How the 출력 폴더 field reads (E01 QA D4). A forensic run never writes next to an evidence file
 * or inside an evidence folder by default: with a case folder the default is a run folder under
 * it; without one the field is required (shown outside 고급 옵션).
 */
export interface OutputFieldSpec {
  label: string;
  hint: string;
  required: boolean;
  /** Why the run cannot start while a required folder is empty (default: the case-folder text). */
  requiredReason?: string;
}

/** 출력 폴더 of a case run (런 추가): the case folder's run subfolder, else an explicit choice. */
export function caseRunOutputSpec(caseRoot: string | null | undefined): OutputFieldSpec {
  const root = (caseRoot ?? "").trim();
  if (root) {
    return {
      label: "출력 폴더 (비우면 케이스 폴더 아래)",
      hint: `비우면 케이스 폴더(${root}) 아래에 증거별 런 폴더를 만듭니다.`,
      required: false,
    };
  }
  return {
    label: "출력 폴더",
    hint: "케이스 폴더가 없어 런 출력 위치를 직접 지정해야 합니다. 원본 증거 옆이나 증거 폴더 안에는 쓰지 않습니다.",
    required: true,
  };
}

/**
 * 출력 폴더 of the quick run (no case): always required (R7). There is no automatic folder: the old
 * default for a folder evidence was inside the evidence, and evidence never receives a write.
 */
export const QUICK_RUN_OUTPUT_SPEC: OutputFieldSpec = {
  label: "출력 폴더",
  hint: "증거 밖의 출력 폴더를 반드시 지정하세요. 증거 폴더 안·증거와 같은 경로·증거를 담은 폴더에는 쓰지 않습니다.",
  required: true,
  requiredReason: "출력 폴더를 지정하세요 (증거 밖의 폴더)",
};

/** The required-output reason of a form (undefined when the folder is given or optional). */
export function outputRequiredReason(spec: OutputFieldSpec, outputDir: string): string | undefined {
  if (!spec.required || outputDir.trim()) return undefined;
  return spec.requiredReason ?? "출력 폴더를 지정하세요 (케이스 폴더가 없습니다)";
}

/** Same message as the server's ``OUTPUT_INSIDE_EVIDENCE`` (core/output_guard.py). */
export const OUTPUT_INSIDE_EVIDENCE_REASON =
  "출력 위치가 증거 경로 안(또는 증거와 같은 경로)입니다. 증거에는 아무것도 쓰지 않습니다. 증거 밖의 출력 폴더를 지정하세요";
/** Same message as the server's ``EVIDENCE_INSIDE_OUTPUT``. */
export const EVIDENCE_INSIDE_OUTPUT_REASON =
  "증거가 출력 폴더 안에 있습니다. 출력 폴더는 덮어쓰기·정리 대상이라 증거를 담을 수 없습니다. 증거 밖의 다른 출력 폴더를 지정하세요";

/** Lexical path form for the overlap check: separators unified, case folded, no trailing separator. */
function overlapKey(path: string): string {
  const text = path.trim().replace(/\//g, "\\").toLowerCase();
  return /^[a-z]:\\$/.test(text) ? text : text.replace(/\\+$/, "");
}

function within(child: string, parent: string): boolean {
  if (child === parent) return true;
  return child.startsWith(parent.endsWith("\\") ? parent : `${parent}\\`);
}

/**
 * Inline (pre-server) reason an output folder overlaps an evidence path (R7). The server check
 * (real paths, junctions, case) stays authoritative; this only catches what the text shows.
 * `allowEvidenceInside` = a case folder, which may hold evidence but never sit inside one.
 */
export function outputOverlapReason(
  outputDir: string,
  evidencePaths: readonly string[],
  { allowEvidenceInside = false }: { allowEvidenceInside?: boolean } = {},
): string | undefined {
  const output = overlapKey(outputDir);
  if (!output) return undefined;
  for (const raw of evidencePaths) {
    const evidence = overlapKey(raw);
    if (!evidence) continue;
    if (within(output, evidence)) return OUTPUT_INSIDE_EVIDENCE_REASON;
    if (!allowEvidenceInside && within(evidence, output)) return EVIDENCE_INSIDE_OUTPUT_REASON;
  }
  return undefined;
}

export const RUN_MODES: Array<{ id: string; label: string }> = [
  { id: "fraud", label: "문서·부정 조사" },
  { id: "seizure", label: "전수 수집" },
  { id: "hacking", label: "침해사고" },
  { id: "recovery", label: "복구" },
];

/** Values of `SUPPORTED_INPUT_ROOT_KINDS` (core/input_root.py); empty = auto-detect. */
export const INPUT_KINDS: Array<{ id: string; label: string }> = [
  { id: "", label: "자동 감지" },
  { id: "folder", label: "폴더" },
  { id: "mounted-image", label: "마운트된 이미지" },
  { id: "e01-derived", label: "E01에서 추출" },
  { id: "disk-image-derived", label: "디스크 이미지에서 추출" },
  { id: "archive-image-derived", label: "압축 이미지에서 추출" },
  { id: "live", label: "라이브" },
];

export type RunFormErrors = Partial<Record<keyof RunForm, string>>;

const NON_NEGATIVE_INT = /^\d+$/;

export function validateRunForm(form: RunForm): RunFormErrors {
  const errors: RunFormErrors = {};
  if (!form.root.trim()) errors.root = "증거 경로를 입력하세요.";
  if (!NON_NEGATIVE_INT.test(form.maxExtractMb.trim())) {
    errors.maxExtractMb = "최대 추출 크기는 0 이상의 정수(MB)여야 합니다.";
  }
  if (!NON_NEGATIVE_INT.test(form.maxFileCount.trim())) {
    errors.maxFileCount = "최대 파일 수는 0 이상의 정수여야 합니다.";
  }
  if (form.partitionSector.trim() && !NON_NEGATIVE_INT.test(form.partitionSector.trim())) {
    errors.partitionSector = "파티션 시작 섹터는 0 이상의 정수여야 합니다.";
  }
  if (form.hideKnownGood && !form.knownGoodFeeds.trim()) {
    errors.hideKnownGood = "known-good 해시 목록을 지정해야 숨길 수 있습니다.";
  }
  if (form.dryRun && form.extract) {
    errors.extract = "모의 실행에서는 추출할 수 없습니다.";
  }
  const readMb = aiReadMbError(form.aiReadMb);
  if (readMb) errors.aiReadMb = readMb;
  return errors;
}

/** Why an AI 읽기 예산 entry cannot be sent (empty = server default), else undefined. */
export function aiReadMbError(value: string): string | undefined {
  const text = value.trim();
  if (!text) return undefined;
  if (NON_NEGATIVE_INT.test(text) && Number(text) >= 1 && Number(text) <= MAX_AI_READ_MB) return undefined;
  return `AI 읽기 예산은 1~${MAX_AI_READ_MB.toLocaleString("ko-KR")} 사이의 정수(MiB)여야 합니다.`;
}

export function firstRunFormError(errors: RunFormErrors): string | undefined {
  return Object.values(errors).find(Boolean);
}

/**
 * Exact body for `POST /api/runs` (RunCreateRequest). `skip_groups` rides only when a group is
 * unchecked, so a run with the mode defaults sends the same body as before R4.
 */
export function buildRunBody(form: RunForm): RunCreateBody {
  const skipGroups = [...new Set(form.skipGroups)];
  const ai = aiCollectorOptions(form, skipGroups);
  return {
    ...buildBaseRunBody(form),
    ...(skipGroups.length ? { skip_groups: skipGroups } : {}),
    ...(ai ? { collector_options: { "ai-agent": ai } } : {}),
  };
}

/** `collector_options["ai-agent"]` keys the run dialog sends (run_indirect.AI_RUN_OPTION_KEYS). */
export type AiCollectorOptions = {
  ai_bodies?: false;
  org_email_domain?: string;
  evidence_roots?: string[];
  ai_read_mb?: number;
};

export type AiOptionFields = "aiBodies" | "aiOrgDomain" | "aiEvidenceRoots" | "aiReadMb";

/**
 * `collector_options["ai-agent"]` of the AI 사용 기록 options: only the keys that differ from the
 * defaults (본문 포함 · 도메인/증거 폴더 없음 · 서버 기본 예산), and only while the `ai` group
 * runs — a default run sends the same body. The domain goes as typed: the server says what is wrong.
 */
export function aiCollectorOptions(
  form: Partial<Pick<RunForm, AiOptionFields>>,
  skipGroups: readonly string[] = [],
): AiCollectorOptions | null {
  if (skipGroups.includes("ai")) return null;
  const out: AiCollectorOptions = {};
  if (form.aiBodies === false) out.ai_bodies = false;
  const domain = (form.aiOrgDomain ?? "").trim();
  if (domain) out.org_email_domain = domain;
  const roots = (form.aiEvidenceRoots ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  if (roots.length) out.evidence_roots = roots;
  const readMb = (form.aiReadMb ?? "").trim();
  if (/^\d+$/.test(readMb) && Number(readMb) >= 1) out.ai_read_mb = Number(readMb);
  return Object.keys(out).length ? out : null;
}

function buildBaseRunBody(form: RunForm): RunCreateBody {
  return {
    root: form.root.trim(),
    mode: form.mode,
    input_kind: form.inputKind || null,
    output_dir: form.outputDir.trim() || null,
    dry_run: form.dryRun,
    read_only: form.readOnly,
    overwrite: form.overwrite,
    extract: form.extract,
    max_extract_size_bytes: Number(form.maxExtractMb.trim()) * 1024 * 1024,
    max_file_count: Number(form.maxFileCount.trim()),
    e01_partition_start_sector: form.partitionSector.trim() ? Number(form.partitionSector.trim()) : null,
    known_good_hash_feeds: form.knownGoodFeeds
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean),
    hide_known_good: form.hideKnownGood,
    wait: false,
  };
}
