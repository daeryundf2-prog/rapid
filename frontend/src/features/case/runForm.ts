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
  /** R7 AI 사용 기록: hash the large AI databases (never copied) — default off. */
  aiHashDbs: boolean;
}

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
  aiHashDbs: false,
};

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
  return errors;
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

/**
 * `collector_options["ai-agent"]` of the AI 사용 기록 options: only when they differ from the
 * defaults (본문 포함 · 해시 안 함) and the `ai` group runs — a default run sends the same body.
 */
export function aiCollectorOptions(
  form: Pick<RunForm, "aiBodies" | "aiHashDbs">,
  skipGroups: readonly string[] = [],
): { ai_bodies: boolean; ai_hash_dbs: boolean } | null {
  if (skipGroups.includes("ai")) return null;
  if (form.aiBodies !== false && form.aiHashDbs !== true) return null;
  return { ai_bodies: form.aiBodies !== false, ai_hash_dbs: form.aiHashDbs === true };
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
