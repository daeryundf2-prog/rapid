/**
 * Analysis dialog forms (plan analysis-workbench-p1 §3.2 options, §4 AnalysisDialog): field
 * specs per API kind, validation (Korean messages) and the exact `options` body. Pure — the
 * dialog renders these specs; tests drive them directly.
 */

import type { AnalysisKind } from "../../api/analyses";

const MB = 1024 * 1024;

export interface Choice {
  id: string;
  label: string;
}

interface BaseField {
  key: string;
  label: string;
  /** Help line under the field (aria-describedby). */
  help: string;
}

export type FieldSpec =
  | (BaseField & { type: "int"; min: number; max?: number; optional?: boolean; unit?: "MB" })
  | (BaseField & { type: "bool" })
  | (BaseField & { type: "text"; optional?: boolean; placeholder?: string })
  /**
   * `pick`: what the server browser may select ("directory" by default; "file" = a file).
   * `roots`: which allowed roots the picker lists ("input" by default; "output" = extraction).
   */
  | (BaseField & {
      type: "path";
      optional?: boolean;
      pick?: "directory" | "file";
      roots?: "input" | "output";
    })
  /** One of `choices`; "" (the first, "자동") sends nothing so the server decides. */
  | (BaseField & { type: "choice"; choices: Choice[]; autoLabel: string })
  | (BaseField & { type: "multi"; choices: Choice[]; minCount?: number })
  | (BaseField & { type: "snapshot" })
  | (BaseField & { type: "cases"; minCount: number; maxCount: number });

/** Form context: the current run (cross-case always adds it server-side). */
export interface AnalysisFormContext {
  runId?: string | null;
}

/** Backend `OcrTarget.locators` max_length / `OcrBatchOptions.max_items` le (analysis_kinds.py). */
export const OCR_MAX_ITEMS = 1000;

export type FormValue = string | boolean | string[];
export type AnalysisFormState = Record<string, FormValue>;
export type AnalysisFormErrors = Record<string, string>;

export const CARVE_KINDS: Choice[] = [
  { id: "jpeg", label: "JPEG" },
  { id: "png", label: "PNG" },
  { id: "gif", label: "GIF" },
  { id: "pdf", label: "PDF" },
  { id: "zip", label: "ZIP" },
  { id: "7z", label: "7z" },
  { id: "rar", label: "RAR" },
  { id: "sqlite", label: "SQLite" },
  // R3 §3.3 (core/carving.py SIGNATURE_KINDS).
  { id: "wav", label: "WAV 오디오" },
  { id: "mp3", label: "MP3 오디오" },
  { id: "m4a", label: "M4A 오디오" },
  { id: "mp4", label: "MP4 동영상" },
  { id: "docx", label: "Word(DOCX)" },
  { id: "xlsx", label: "Excel(XLSX)" },
  { id: "pptx", label: "PowerPoint(PPTX)" },
  { id: "hwp", label: "한글(HWP)" },
  { id: "hwpx", label: "한글(HWPX)" },
  { id: "eml", label: "이메일(EML)" },
  { id: "pe", label: "실행 파일(PE)" },
  { id: "evtx", label: "이벤트 로그(EVTX)" },
];

export const VSC_STATUSES: Choice[] = [
  { id: "deleted", label: "삭제됨" },
  { id: "modified", label: "수정됨" },
  { id: "added", label: "추가됨" },
];

export const OCR_LANGUAGES: Choice[] = [
  { id: "kor", label: "한국어" },
  { id: "eng", label: "영어" },
  { id: "jpn", label: "일본어" },
  { id: "chi_sim", label: "중국어(간체)" },
];

export const ANALYSIS_FIELDS: Record<AnalysisKind, FieldSpec[]> = {
  // Full build only (incremental updates run by themselves after each analysis).
  "search-index": [],
  carve: [
    {
      key: "ext",
      type: "text",
      label: "소스 확장자",
      help: "쉼표로 구분합니다(예: .bin, .dat). 비우면 모든 파일을 훑습니다.",
      optional: true,
      placeholder: ".bin, .dat",
    },
    {
      key: "kinds",
      type: "multi",
      label: "찾을 서명",
      help: "선택하지 않으면 모든 서명을 찾습니다.",
      choices: CARVE_KINDS,
    },
    {
      key: "max_scan_bytes",
      type: "int",
      unit: "MB",
      min: 1,
      max: 16384,
      label: "파일당 최대 스캔 크기 (MB)",
      help: "소스 파일 하나에서 읽는 최대 크기입니다.",
    },
    {
      key: "max_carve_bytes",
      type: "int",
      unit: "MB",
      min: 1,
      max: 1024,
      label: "후보당 최대 크기 (MB)",
      help: "잘라 낸 후보 하나의 최대 크기입니다.",
    },
    {
      key: "max_candidates",
      type: "int",
      min: 1,
      max: 100_000,
      label: "최대 후보 수",
      help: "이 수에 이르면 멈춥니다.",
    },
    {
      key: "extract",
      type: "bool",
      label: "후보 파일 추출",
      help: "켜면 잘라 낸 바이트를 런 출력 폴더 analyses/ 아래에 씁니다.",
    },
    {
      key: "include_rejected",
      type: "bool",
      label: "검증에 실패한 후보도 행으로 남기기",
      help: "끄면 서명 뒤 구조 검증에 실패한 후보는 개수(요약의 거부 건수)만 기록하고 결과 행에서 뺍니다.",
    },
  ],
  "vsc-discover": [
    {
      key: "max_depth",
      type: "int",
      min: 0,
      max: 1,
      label: "최대 깊이",
      help: "스캔 루트의 상위 폴더에서 몇 단계 아래까지 살펴볼지 정합니다(0~1, 서버는 한 단계까지만 탐색합니다).",
    },
  ],
  "vsc-compare": [
    {
      key: "snapshot_root",
      type: "snapshot",
      label: "스냅샷",
      help: "볼륨 섀도우 탐색 결과에서 비교할 스냅샷을 고릅니다.",
    },
    {
      key: "hash",
      type: "bool",
      label: "해시로 수정 여부 판단",
      help: "공통 파일의 내용을 해시합니다. 오래 걸립니다.",
    },
    { key: "case_sensitive", type: "bool", label: "경로 대소문자 구분", help: "윈도 증거는 보통 끕니다." },
    {
      key: "max_records",
      type: "int",
      min: 1,
      max: 1_000_000,
      label: "최대 변경 기록 수",
      help: "보고할 변경 기록의 상한입니다(1~1,000,000).",
    },
  ],
  "vsc-extract": [
    {
      key: "snapshot_root",
      type: "snapshot",
      label: "스냅샷",
      help: "볼륨 섀도우 탐색 결과에서 파일을 꺼낼 스냅샷을 고릅니다.",
    },
    {
      key: "status",
      type: "multi",
      label: "꺼낼 변경 상태",
      help: "하나 이상 고르세요.",
      choices: VSC_STATUSES,
      minCount: 1,
    },
    {
      key: "max_file_count",
      type: "int",
      min: 1,
      max: 100_000,
      label: "최대 파일 수",
      help: "복사할 파일 수의 상한입니다(1~100,000).",
    },
    {
      key: "max_total_bytes",
      type: "int",
      unit: "MB",
      min: 1,
      max: 262_144,
      label: "최대 총 크기 (MB)",
      help: "복사할 원본 크기의 상한입니다(1~262,144 MB).",
    },
    {
      key: "output_dir",
      type: "path",
      roots: "output",
      optional: true,
      label: "추출 폴더",
      help: "비우면 런 출력 폴더의 analyses/ 아래에 씁니다. 런 출력 폴더나 서버 출력 허용 루트(RAPIDTRIAGE_ANALYSIS_OUTPUT_ROOTS) 밖이면 거부됩니다(403). 입력 허용 루트(RAPIDTRIAGE_ANALYSIS_ROOTS)·증거 경로에는 쓸 수 없습니다.",
    },
    {
      key: "overwrite",
      type: "bool",
      label: "기존 파일 덮어쓰기",
      help: "같은 이름의 추출 파일이 있으면 덮어씁니다.",
    },
  ],
  "ntfs-meta": [
    {
      key: "image_path",
      type: "path",
      pick: "file",
      optional: true,
      label: "증거 이미지 또는 $MFT 파일",
      help: "E01/raw 디스크 이미지나 이미 추출한 $MFT 파일을 고릅니다. 폴더로 실행한 런은 지정해야 하고, 비우면 런의 소스 이미지를 씁니다(입력 허용 루트 아래).",
    },
    {
      key: "source",
      type: "choice",
      label: "입력 종류",
      autoLabel: "자동 감지",
      choices: [
        { id: "image", label: "디스크 이미지(Sleuth Kit으로 추출)" },
        { id: "mft", label: "추출한 $MFT 파일(바로 파싱)" },
      ],
      help: "자동 감지는 파일 첫 레코드가 FILE 서명이면 $MFT로 읽습니다. $MFT 파일에는 USN 저널이 없어 MFT 행만 나옵니다.",
    },
    {
      key: "partition_start_sector",
      type: "int",
      min: 0,
      optional: true,
      label: "파티션 시작 섹터",
      help: "비우면 런이 쓴 파티션을 자동으로 고릅니다.",
    },
    {
      key: "full_journal",
      type: "bool",
      label: "USN 저널 전체",
      help: "희소 구간까지 포함한 $J 전체를 씁니다. 크기가 매우 클 수 있습니다.",
    },
  ],
  "ocr-batch": [
    {
      key: "max_items",
      type: "int",
      min: 1,
      max: OCR_MAX_ITEMS,
      label: "최대 이미지 수",
      help: "대상 이미지 중 이 수만큼 처리합니다(1~1,000).",
    },
    {
      key: "languages",
      type: "multi",
      label: "언어",
      help: "하나 이상 고르세요.",
      choices: OCR_LANGUAGES,
      minCount: 1,
    },
    {
      key: "retry_failures",
      type: "bool",
      label: "실패한 이미지 다시 시도",
      help: "지난 OCR에서 실패한 이미지만 다시 읽습니다.",
    },
  ],
  "memory-import": [
    {
      key: "volatility_output_dir",
      type: "path",
      label: "Volatility 출력 폴더",
      help: "서버 설정의 허용 루트 아래 폴더여야 합니다.",
    },
  ],
  "cross-case": [
    {
      key: "case_ids",
      type: "cases",
      minCount: 1,
      maxCount: 20,
      label: "비교할 케이스",
      help: "현재 케이스와 비교할 다른 케이스를 1~20개 고르세요. 현재 케이스는 항상 포함됩니다(런 ID로 보냅니다).",
    },
    {
      key: "max_shared",
      type: "int",
      min: 1,
      max: 5000,
      label: "최대 공유 지표 수",
      help: "구역마다 보고할 공유 지표의 상한입니다.",
    },
  ],
  "url-carve": [
    {
      key: "sources",
      type: "multi",
      label: "소스 종류",
      help: "pagefile.sys·swapfile.sys, 이름에 unalloc/blkls가 든 미할당 덤프, .dmp/.mem 메모리 덤프, 디스크 이미지(E01/raw) NTFS 볼륨의 미할당 클러스터 중 고르세요.",
      choices: [
        { id: "pagefile", label: "페이지 파일" },
        { id: "unallocated", label: "미할당 영역 덤프" },
        { id: "memory-dump", label: "메모리 덤프" },
        { id: "image-unallocated", label: "이미지 미할당 영역" },
      ],
      minCount: 1,
    },
    {
      key: "image_path",
      type: "path",
      pick: "file",
      optional: true,
      label: "디스크 이미지",
      help: "'이미지 미할당 영역'을 고를 때만 씁니다. E01/raw 이미지를 고르고, 비우면 런의 소스 이미지를 씁니다($Bitmap 기준 미할당 클러스터만 읽음).",
    },
    {
      key: "partition_start_sector",
      type: "int",
      min: 0,
      optional: true,
      label: "파티션 시작 섹터",
      help: "'이미지 미할당 영역'을 고를 때만 씁니다. 비우면 NTFS 파티션을 자동으로 찾습니다.",
    },
    {
      key: "max_scan_bytes",
      type: "int",
      min: 1,
      max: 65536,
      unit: "MB",
      label: "파일당 최대 스캔(MB)",
      help: "파일마다 앞에서부터 이 크기까지 읽습니다. '이미지 미할당 영역'은 이 값이 미할당 클러스터 전체에서 읽는 총량입니다(넘으면 일부만 스캔).",
    },
    {
      key: "max_candidates",
      type: "int",
      min: 1,
      max: 500000,
      label: "최대 URL 후보 수",
      help: "중복을 뺀 URL 수의 상한입니다.",
    },
    {
      key: "ascii_urls",
      type: "bool",
      label: "ASCII URL",
      help: "ASCII·UTF-8 바이트로 쓰인 URL을 찾습니다.",
    },
    {
      key: "utf16_urls",
      type: "bool",
      label: "UTF-16LE URL",
      help: "Windows 메모리에 흔한 UTF-16LE URL을 찾습니다.",
    },
  ],
};

/** Selected OCR targets of a form (grid "선택 행 OCR 실행" preset), blanks dropped. */
export function formLocators(form: Partial<AnalysisFormState>): string[] {
  return Array.isArray(form.locators) ? form.locators.filter(Boolean) : [];
}

/**
 * Defaults mirror the backend pydantic defaults (analysis_kinds.py). With selected OCR rows
 * (`ctx.locators`) the image limit defaults to the selection size so the server's
 * `locators[:max_items]` never silently drops part of the selection.
 */
export function defaultForm(
  kind: AnalysisKind,
  ctx: AnalysisFormContext & { locators?: FormValue } = {},
): AnalysisFormState {
  switch (kind) {
    case "carve":
      return {
        ext: "",
        kinds: [],
        max_scan_bytes: "256",
        max_carve_bytes: "50",
        max_candidates: "250",
        extract: false,
        include_rejected: false,
      };
    case "vsc-discover":
      return { max_depth: "1" };
    case "vsc-compare":
      return { snapshot_root: "", hash: false, case_sensitive: false, max_records: "10000" };
    case "vsc-extract":
      return {
        snapshot_root: "",
        status: ["deleted", "modified"],
        max_file_count: "1000",
        max_total_bytes: "2048",
        output_dir: "",
        overwrite: false,
      };
    case "ntfs-meta":
      return { image_path: "", source: "", partition_start_sector: "", full_journal: false };
    case "ocr-batch": {
      const count = formLocators({ locators: ctx.locators ?? [] }).length;
      const maxItems = count ? Math.min(count, OCR_MAX_ITEMS) : 50;
      return { max_items: String(maxItems), languages: ["kor", "eng"], retry_failures: false };
    }
    case "memory-import":
      return { volatility_output_dir: "" };
    case "cross-case":
      return { case_ids: [], max_shared: "500" };
    case "search-index":
      return {};
    case "url-carve":
      return {
        sources: ["pagefile", "unallocated"],
        image_path: "",
        partition_start_sector: "",
        max_scan_bytes: "4096",
        max_candidates: "50000",
        ascii_urls: true,
        utf16_urls: true,
      };
  }
}

const INT = /^\d+$/;

/** Cross-case ids actually sent: the current run is dropped (the server always adds it), de-duplicated. */
export function otherCaseIds(value: FormValue | undefined, ctx: AnalysisFormContext = {}): string[] {
  const list = Array.isArray(value) ? value : [];
  const out: string[] = [];
  for (const raw of list) {
    const id = raw.trim();
    if (id && id !== ctx.runId && !out.includes(id)) out.push(id);
  }
  return out;
}

export function validateAnalysisForm(
  kind: AnalysisKind,
  form: AnalysisFormState,
  ctx: AnalysisFormContext = {},
): AnalysisFormErrors {
  const errors: AnalysisFormErrors = {};
  if (kind === "ocr-batch") {
    const count = formLocators(form).length;
    if (count > OCR_MAX_ITEMS) {
      errors.locators = `대상: 한 번에 ${OCR_MAX_ITEMS.toLocaleString("ko-KR")}장까지 OCR할 수 있습니다(선택 ${count.toLocaleString("ko-KR")}장).`;
    }
  }
  if (kind === "url-carve") {
    // R6 S2: the image options only apply to the image-unallocated source (the server says 422 otherwise).
    const sources = Array.isArray(form.sources) ? form.sources : [];
    // The message goes on the field that holds the value (aria-invalid / describedby there).
    if (!sources.includes("image-unallocated")) {
      const filled = (key: string) => typeof form[key] === "string" && (form[key] as string).trim() !== "";
      if (filled("image_path")) {
        errors.image_path = "디스크 이미지: 소스 종류에서 '이미지 미할당 영역'을 고를 때만 씁니다.";
      }
      if (filled("partition_start_sector")) {
        errors.partition_start_sector =
          "파티션 시작 섹터: 소스 종류에서 '이미지 미할당 영역'을 고를 때만 씁니다.";
      }
    }
  }
  for (const field of ANALYSIS_FIELDS[kind]) {
    const value = form[field.key];
    switch (field.type) {
      case "int": {
        const text = typeof value === "string" ? value.trim() : "";
        if (!text) {
          if (!field.optional) errors[field.key] = `${field.label}: 값을 입력하세요.`;
          break;
        }
        if (!INT.test(text)) {
          errors[field.key] = `${field.label}: 0 이상의 정수를 입력하세요.`;
          break;
        }
        const n = Number(text);
        if (n < field.min || (field.max !== undefined && n > field.max)) {
          errors[field.key] =
            field.max !== undefined
              ? `${field.label}: ${field.min}~${field.max} 사이로 입력하세요.`
              : `${field.label}: ${field.min} 이상으로 입력하세요.`;
        }
        break;
      }
      case "text": {
        const text = typeof value === "string" ? value.trim() : "";
        if (!text && !field.optional) errors[field.key] = `${field.label}: 값을 입력하세요.`;
        if (field.key === "ext" && text && !parseExtensions(text).length) {
          errors[field.key] = `${field.label}: 확장자를 쉼표로 구분해 입력하세요.`;
        }
        break;
      }
      case "path": {
        const text = typeof value === "string" ? value.trim() : "";
        if (!text && !field.optional)
          errors[field.key] = `${field.label}: ${field.pick === "file" ? "파일을" : "폴더를"} 고르세요.`;
        break;
      }
      case "choice": {
        const text = typeof value === "string" ? value : "";
        if (text && !field.choices.some((c) => c.id === text))
          errors[field.key] = `${field.label}: 목록에서 고르세요.`;
        break;
      }
      case "multi": {
        const list = Array.isArray(value) ? value : [];
        if (field.minCount && list.length < field.minCount) {
          errors[field.key] = `${field.label}: ${field.minCount}개 이상 고르세요.`;
        }
        break;
      }
      case "snapshot": {
        if (typeof value !== "string" || !value.trim())
          errors[field.key] = `${field.label}: 스냅샷을 고르세요.`;
        break;
      }
      case "cases": {
        const count = otherCaseIds(value, ctx).length;
        if (count < field.minCount)
          errors[field.key] = `${field.label}: 현재 케이스 외에 ${field.minCount}개 이상 고르세요.`;
        else if (count > field.maxCount)
          errors[field.key] = `${field.label}: 현재 케이스 외에 ${field.maxCount}개까지 고를 수 있습니다.`;
        break;
      }
      default:
    }
  }
  return errors;
}

export function firstAnalysisError(errors: AnalysisFormErrors): string | undefined {
  return Object.values(errors).find(Boolean);
}

/** ".bin, dat" → [".bin", ".dat"] (lower-case, leading dot, de-duplicated). */
export function parseExtensions(text: string): string[] {
  const out: string[] = [];
  for (const part of text.split(/[\s,;]+/)) {
    const clean = part
      .trim()
      .replace(/^\*?\.*/, "")
      .toLowerCase();
    if (clean && /^[a-z0-9_-]{1,16}$/.test(clean) && !out.includes(`.${clean}`)) out.push(`.${clean}`);
  }
  return out;
}

/** Exact `options` object for `POST /analyses` (§3.2). */
export function buildAnalysisOptions(
  kind: AnalysisKind,
  form: AnalysisFormState,
  ctx: AnalysisFormContext = {},
): Record<string, unknown> {
  const options: Record<string, unknown> = {};
  for (const field of ANALYSIS_FIELDS[kind]) {
    const value = form[field.key];
    switch (field.type) {
      case "int": {
        const text = typeof value === "string" ? value.trim() : "";
        if (!text) break;
        const n = Number(text);
        options[field.key] = field.unit === "MB" ? n * MB : n;
        break;
      }
      case "bool":
        options[field.key] = value === true;
        break;
      case "text": {
        const text = typeof value === "string" ? value.trim() : "";
        if (field.key === "ext") {
          const list = parseExtensions(text);
          if (list.length) options.ext = list;
        } else if (text) options[field.key] = text;
        break;
      }
      case "path":
      case "choice":
      case "snapshot": {
        const text = typeof value === "string" ? value.trim() : "";
        if (text) options[field.key] = text;
        break;
      }
      case "multi": {
        const list = Array.isArray(value) ? value : [];
        if (list.length || field.minCount) options[field.key] = [...list];
        break;
      }
      case "cases":
        // `CrossCaseOptions.case_ids` (1~20): other runs only — the server prepends the current run.
        options[field.key] = otherCaseIds(value, ctx);
        break;
      default:
    }
  }
  if (kind === "ntfs-meta") options.parse = true;
  if (kind === "ocr-batch") {
    // Selected image rows (grid "선택 행 OCR 실행") → locators; otherwise every media image.
    const locators = formLocators(form);
    options.target = locators.length ? { locators } : { kind: "media-image" };
    // A limit above the selection size means nothing; send the selection size instead.
    if (locators.length && typeof options.max_items === "number" && options.max_items > locators.length)
      options.max_items = Math.min(locators.length, OCR_MAX_ITEMS);
  }
  return options;
}
