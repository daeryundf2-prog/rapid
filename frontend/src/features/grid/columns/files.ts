import { fetchFilesPage } from "../../../api/collections";
import { formatGridTime } from "../../../utils/time";
import { parseFlags } from "../../flags/flags";
import type { CollectionDef, ColumnSpec } from "../types";
import {
  baseName,
  col,
  currentTimezone,
  fieldStr,
  formatBytes,
  isRecord,
  joinList,
  makeRef,
  makeRow,
  recoveryFields,
  sha256Of,
  str,
  strOrNull,
} from "./common";
import {
  COPY_TIME_TITLE,
  DELETION_UNKNOWN_TITLE,
  deletionCell,
  modifiedCell,
  signatureCell,
} from "./FileCells";
import { flagsColumn } from "./families";

/** Shown on the NTFS columns while no NTFS-meta analysis has been joined (plan U-P1-3). */
export const NTFS_EMPTY_HINT = "NTFS 메타 분석을 실행하면 채워집니다";
export const NTFS_RUN_COMMAND = "analysis.run.ntfs-meta";

const ntfsHint = { text: NTFS_EMPTY_HINT, command: NTFS_RUN_COMMAND, commandLabel: "실행" };

/** Fallback when a not-joined `ntfs_join` carries no `reason` (backend files_ntfs.py statuses). */
const NTFS_STATUS_REASON: Record<string, string> = {
  too_large: "NTFS 조인 색인이 한도를 넘어 조인하지 않았습니다",
  no_volume_prefix: "파일 경로에서 NTFS 볼륨 루트를 찾지 못해 조인하지 않았습니다",
  skipped: "NTFS 조인을 건너뛰었습니다",
};

/**
 * `ntfs_join` of a files page (backend files_ntfs.py): `{analysis_id, status, matched, total,
 * reason?}`. `status` is "joined" only when rows were looked up; "too_large" /
 * "no_volume_prefix" / "skipped" keep the `analysis_id` but join nothing (`reason` says why).
 * null = no NTFS-meta analysis (status "no_analysis") / old server.
 */
export interface NtfsJoin {
  analysis_id: string | null;
  /** Server status; null on servers that predate it (then a set analysis_id means joined). */
  status: string | null;
  joined: boolean;
  /** Korean reason when not joined. */
  reason: string | null;
  matched: number;
  total: number;
}

export function ntfsJoinOf(meta: Record<string, unknown> | undefined): NtfsJoin | null {
  const raw = meta?.ntfs_join;
  if (!isRecord(raw)) return null;
  const id = typeof raw.analysis_id === "string" && raw.analysis_id ? raw.analysis_id : null;
  if (!id) return null;
  const status = typeof raw.status === "string" && raw.status ? raw.status : null;
  const joined = status === null || status === "joined";
  const reason = joined
    ? null
    : (typeof raw.reason === "string" && raw.reason) ||
      NTFS_STATUS_REASON[status ?? ""] ||
      `NTFS 조인을 하지 않았습니다(${status})`;
  return {
    analysis_id: id,
    status,
    joined,
    reason,
    matched: typeof raw.matched === "number" ? raw.matched : 0,
    total: typeof raw.total === "number" ? raw.total : 0,
  };
}

function ntfsOf(row: { fields: Record<string, unknown> }): Record<string, unknown> {
  return isRecord(row.fields.ntfs) ? row.fields.ntfs : {};
}

function ntfsTime(id: string, header: string, key: string): ColumnSpec {
  return col.field(id, header, 170, ["source"], (r) => strOrNull(ntfsOf(r)[key]), {
    format: (r) => {
      const value = ntfsOf(r)[key];
      return typeof value === "string" || typeof value === "number"
        ? formatGridTime(value, currentTimezone())
        : "";
    },
    filterKind: "time",
    emptyHint: ntfsHint,
  });
}

/** A row that names a directory: an explicit flag/kind from the server, or a trailing separator. */
export function isDirectoryRaw(raw: Record<string, unknown>, path: string | null): boolean {
  if (raw.is_directory === true || raw.is_dir === true || raw.directory === true) return true;
  if (raw.kind === "directory" || raw.entry_type === "directory" || raw.type === "directory") return true;
  const ntfs = isRecord(raw.ntfs) ? raw.ntfs : null;
  if (ntfs?.directory === true) return true;
  return path !== null && /[\\/]$/.test(path);
}

/** Korean names of the files output categories (core/files.py DEFAULT_FILE_CATEGORIES). */
export const FILE_CATEGORY_LABELS: Readonly<Record<string, string>> = {
  documents: "문서",
  images: "이미지",
  archives: "압축",
  databases: "데이터베이스",
  emails: "이메일",
  "mobile-images": "모바일 이미지",
  executables: "실행 파일",
  "memory-dumps": "메모리 덤프",
  "disk-images": "디스크 이미지",
  "vehicle-images": "차량 이미지",
  other: "기타",
};

export function fileCategoryLabel(category: string): string {
  return FILE_CATEGORY_LABELS[category] ?? category;
}

/** Where the 수정 time of a files row comes from (`modified_at_origin`, core/files.py). */
export const MODIFIED_ORIGIN_LABELS: Readonly<Record<string, string>> = {
  filesystem: "파일시스템 시각",
  listing: "이미지 목록(fls/MFT) 시각",
  "acquisition-copy": "취득 사본 시각",
  "ntfs-si": "NTFS $SI 수정 시각(조인)",
};

export interface ModifiedTime {
  value: string | null;
  /** `filesystem` | `listing` | `acquisition-copy` | `ntfs-si` | null (old outputs: unknown). */
  origin: string | null;
}

/**
 * The 수정 time of a files row: `fs_modified_at` (the evidence filesystem's own time) when
 * present; for an acquisition copy the NTFS join's `$SI` modified time when joined, else the
 * copy's host mtime flagged `acquisition-copy`; otherwise `modified_at`.
 */
export function modifiedTimeOf(raw: Record<string, unknown>): ModifiedTime {
  const origin = strOrNull(raw.modified_at_origin);
  const fs = strOrNull(raw.fs_modified_at);
  if (fs) return { value: fs, origin: origin && origin !== "acquisition-copy" ? origin : "filesystem" };
  const ntfs = isRecord(raw.ntfs) ? raw.ntfs : {};
  const si = strOrNull(ntfs.si_modified_at);
  if (origin === "acquisition-copy") {
    if (si) return { value: si, origin: "ntfs-si" };
    return { value: strOrNull(raw.modified_at), origin };
  }
  return { value: strOrNull(raw.modified_at), origin };
}

/** 수정 / 시각 출처 tooltip: the time plus where it comes from. */
export function modifiedTooltip(row: { fields: Record<string, unknown> }): string {
  const value = strOrNull(row.fields.modifiedAt);
  const origin = strOrNull(row.fields.modifiedOrigin);
  if (origin === "acquisition-copy") return COPY_TIME_TITLE;
  const text = value ? formatGridTime(value, currentTimezone()) : "";
  const hint = origin ? (MODIFIED_ORIGIN_LABELS[origin] ?? origin) : "";
  return [text, hint].filter(Boolean).join(" · ");
}

/** `deletion_state` of a files / inventory row (core/files.py deletion_state_for). */
export type DeletionState = "deleted" | "allocated" | "unknown";

export const DELETION_STATE_LABELS: Readonly<Record<DeletionState, string>> = {
  deleted: "삭제됨",
  allocated: "할당",
  unknown: "알 수 없음",
};

/**
 * Deletion state of a row: `deletion_state` (inventory rows) / `recovery.deletion_state`
 * (parser-quality r2: unknown | allocated | deleted, agreeing with `is_deleted`), else the
 * `is_deleted` flag of the row or its NTFS join. null = the server says nothing.
 */
export function deletionStateOf(raw: Record<string, unknown>): DeletionState | null {
  const recovery = isRecord(raw.recovery) ? raw.recovery : {};
  const state = str(raw.deletion_state ?? recovery.deletion_state);
  if (state === "deleted" || state === "allocated" || state === "unknown") return state;
  const ntfs = isRecord(raw.ntfs) ? raw.ntfs : null;
  const flag =
    typeof raw.is_deleted === "boolean"
      ? raw.is_deleted
      : typeof ntfs?.is_deleted === "boolean"
        ? ntfs.is_deleted
        : null;
  return flag === null ? null : flag ? "deleted" : "allocated";
}

/** How a row was matched to its NTFS / inventory record (`match_method`) → Korean. */
export const MATCH_METHOD_LABELS: Readonly<Record<string, string>> = {
  "relative-path": "상대 경로",
  path: "경로",
  "full-path": "전체 경로",
  "mft-ref": "MFT 참조",
  mft_ref: "MFT 참조",
  "entry-number": "MFT 엔트리 번호",
  "name-size": "이름·크기",
  "path-fold": "경로 일치(대소문자 무시)",
  none: "일치 없음",
};

/** `match_method` of a row, or of its NTFS join. */
export function matchMethodOf(raw: Record<string, unknown>): string | null {
  const ntfs = isRecord(raw.ntfs) ? raw.ntfs : {};
  return strOrNull(raw.match_method) ?? strOrNull(ntfs.match_method);
}

/** Direction of a signature mismatch (`mismatch_direction`, shared with `file-signature-mismatch`). */
export const MISMATCH_DIRECTION_LABELS: Readonly<Record<string, string>> = {
  "magic-not-expected-for-extension": "확장자와 다른 헤더 서명",
  "extension-expected-signature-missing": "확장자에 맞는 서명 없음",
};

export function mismatchDirectionLabel(direction: string): string {
  return MISMATCH_DIRECTION_LABELS[direction] ?? direction;
}

export interface FileSignature {
  /** "mismatch" | "match" | "read-error" | null (not checked / not applicable). */
  state: "mismatch" | "match" | "read-error" | null;
  direction: string | null;
  detected: string | null;
  expected: string;
}

/**
 * `file_signature` of a files row (core/files.py apply_file_signature_profile, aligned with the
 * `file-signature-mismatch` artifact): `mismatch` + `mismatch_direction` decide the state.
 */
export function fileSignatureOf(raw: Record<string, unknown>): FileSignature {
  const sig = isRecord(raw.file_signature) ? raw.file_signature : {};
  const status = str(sig.status);
  const direction = strOrNull(sig.mismatch_direction);
  const mismatch = sig.mismatch === true || Boolean(direction) || status === "extension-signature-mismatch";
  const state = mismatch
    ? "mismatch"
    : status === "signature-matches-extension"
      ? "match"
      : status === "read-error"
        ? "read-error"
        : null;
  return { state, direction, detected: strOrNull(sig.detected), expected: joinList(sig.expected) };
}

export function signatureTooltip(sig: FileSignature): string {
  if (!sig.state) return "";
  return [
    sig.direction ? mismatchDirectionLabel(sig.direction) : "",
    sig.detected ? `감지 ${sig.detected}` : "",
    sig.expected ? `기대 ${sig.expected}` : "",
  ]
    .filter(Boolean)
    .join(" · ");
}

export const SIGNATURE_STATE_LABELS: Readonly<Record<string, string>> = {
  mismatch: "불일치",
  match: "일치",
  "read-error": "읽기 오류",
};

/** Files default layout, highest priority first: 이름 > 수정 > 크기 > 선별 > 경로 > NTFS 생성. */
export const FILES_PRIORITY = [
  "title",
  "flags",
  "timestamp",
  "size",
  "review",
  "path",
  "ntfsCreated",
] as const;

export const filesCollection: CollectionDef = {
  id: "files",
  label: "파일",
  source: "paged",
  fetch: (runId, query, signal) =>
    fetchFilesPage(runId, query.offset, query.limit, signal, query.ref.category || undefined, {
      ids: query.flags,
      grade: query.flagGrade,
      conditions: query.rowConditions,
    }),
  widthPriority: () => FILES_PRIORITY,
  mapRow: (raw, position, ctx) => {
    // A category-filtered page is not candidate-ordered: keep the candidate's own index.
    const own = typeof raw.candidate_index === "number" ? raw.candidate_index : raw.record_index;
    const index = typeof own === "number" && Number.isInteger(own) && own >= 0 ? own : position;
    const path = strOrNull(raw.path);
    // Inventory rows (files outside the selected categories, `scope=inventory`) live in `inventory`.
    const inventoryOnly = raw.inventory_only === true;
    const recovery = isRecord(raw.recovery) ? raw.recovery : {};
    const hashes = isRecord(raw.hashes) ? raw.hashes : {};
    const join = ntfsJoinOf(ctx?.page?.meta);
    const modified = modifiedTimeOf(raw);
    const ntfs = isRecord(raw.ntfs) ? raw.ntfs : null;
    const deletion = deletionStateOf(raw);
    const deleted = deletion === "deleted" ? true : deletion === "allocated" ? false : null;
    const signature = fileSignatureOf(raw);
    const categories = Array.isArray(raw.categories) ? raw.categories.map(str).filter(Boolean) : [];
    return makeRow(
      makeRef("files", `/${inventoryOnly ? "inventory" : "candidates"}/${index}`),
      {
        title: strOrNull(raw.name) ?? (baseName(path) || `파일 ${index + 1}`),
        sourcePath: path,
        // A copy's host mtime is not an evidence time: it never feeds time filters / views.
        timestamp: modified.origin === "acquisition-copy" ? null : modified.value,
        artifactType: strOrNull(raw.extension),
        sha256: sha256Of(raw.sha256, hashes.sha256),
      },
      {
        extension: str(raw.extension),
        size: typeof raw.size === "number" ? raw.size : null,
        categories: Array.isArray(raw.categories)
          ? // An inventory row without a selected category is "other" (core/files.py OTHER_CATEGORY).
            (categories.length || !inventoryOnly ? categories : ["other"]).map(fileCategoryLabel).join(", ")
          : joinList(raw.categories) || (inventoryOnly ? fileCategoryLabel("other") : ""),
        modifiedAt: modified.value,
        modifiedOrigin: modified.origin,
        isDeleted: deleted,
        deletion,
        inventoryOnly,
        inventoryReason: strOrNull(raw.inventory_reason),
        matchMethod: matchMethodOf(raw),
        signature,
        siModified: strOrNull(ntfs?.si_modified_at),
        attributes: Array.isArray(ntfs?.attributes) ? joinList(ntfs?.attributes) : str(ntfs?.attributes),
        recovery: str(recovery.candidate_kind),
        knownGood: str(raw.known_good_status),
        // NTFS provenance (plan analysis-workbench-p1 §3.3): null until an NTFS-meta analysis is joined.
        ntfs: isRecord(raw.ntfs) ? raw.ntfs : null,
        filesystem: strOrNull(raw.filesystem),
        sourceImage: strOrNull(raw.source_image),
        // Set only when the page was actually joined; otherwise the reason the join was not made.
        ntfsJoinId: join?.joined ? join.analysis_id : null,
        ntfsJoinReason: join && !join.joined ? join.reason : null,
        // Directory candidates: the viewer shows a directory state instead of requesting a preview.
        isDirectory: isDirectoryRaw(raw, path),
        ...recoveryFields(raw.recovery),
        ...(Array.isArray(raw.flags) ? { flags: raw.flags, flagList: parseFlags(raw.flags) } : {}),
      },
    );
  },
  // Default layout (visual-polish S4): 이름 · 경로 · 크기 · 수정 · NTFS 생성 · 선별. Default width =
  // minimum width; 이름 takes the slack and a narrow grid hides columns by FILES_PRIORITY.
  columns: [
    { ...col.title("이름", 220), minWidth: 220 },
    // 특이사항 (U-F4): hidden while no loaded row carries a flag (FILES_PRIORITY empty-column rule).
    flagsColumn(["analysis", "compact"]),
    col.path(200, ["analysis", "source"]),
    col.field("size", "크기", 80, ["analysis", "compact"], (r) => (r.fields.size as number | null) ?? null, {
      align: "right",
      minWidth: 80,
      format: (r) => formatBytes(r.fields.size),
    }),
    {
      id: "timestamp",
      header: "수정",
      width: 150,
      minWidth: 150,
      presets: ["analysis", "compact"],
      filterKind: "time",
      value: (r) => strOrNull(r.fields.modifiedAt),
      format: (r) => {
        const value = strOrNull(r.fields.modifiedAt);
        return value ? formatGridTime(value, currentTimezone()) : "";
      },
      tooltip: (r) => modifiedTooltip(r),
      render: (r) => {
        const value = strOrNull(r.fields.modifiedAt);
        return modifiedCell(r, value ? formatGridTime(value, currentTimezone()) : "");
      },
    },
    {
      ...ntfsTime("ntfsCreated", "NTFS 생성", "created_at"),
      width: 150,
      minWidth: 150,
      presets: ["analysis", "source"],
    },
    { ...col.review(), width: 88, minWidth: 88 },
    col.field("extension", "확장자", 80, ["compact"], (r) => fieldStr(r, "extension")),
    col.field("categories", "분류", 160, ["compact"], (r) => fieldStr(r, "categories")),
    col.field("recovery", "복구 유형", 100, ["source"], (r) => fieldStr(r, "recovery")),
    col.field("modifiedOrigin", "시각 출처", 130, ["source"], (r) => strOrNull(r.fields.modifiedOrigin), {
      format: (r) => {
        const origin = strOrNull(r.fields.modifiedOrigin);
        return origin ? (MODIFIED_ORIGIN_LABELS[origin] ?? origin) : "";
      },
      tooltip: (r) => modifiedTooltip(r),
    }),
    ntfsTime("ntfsSiModified", "NTFS $SI 수정", "si_modified_at"),
    col.field("deleted", "삭제", 96, ["source"], (r) => strOrNull(r.fields.deletion), {
      format: (r) => {
        const state = r.fields.deletion as DeletionState | null | undefined;
        return state ? DELETION_STATE_LABELS[state] : "";
      },
      tooltip: (r) => (r.fields.deletion === "unknown" ? DELETION_UNKNOWN_TITLE : ""),
      render: deletionCell,
    }),
    col.field("matchMethod", "일치 방식", 110, ["source"], (r) => strOrNull(r.fields.matchMethod), {
      format: (r) => {
        const method = strOrNull(r.fields.matchMethod);
        return method ? (MATCH_METHOD_LABELS[method] ?? method) : "—";
      },
      tooltip: (r) => str(r.fields.matchMethod),
    }),
    col.field(
      "signature",
      "시그니처",
      110,
      ["source"],
      (r) => (r.fields.signature as FileSignature | undefined)?.state ?? null,
      {
        format: (r) =>
          SIGNATURE_STATE_LABELS[(r.fields.signature as FileSignature | undefined)?.state ?? ""] ?? "",
        tooltip: (r) => {
          const sig = r.fields.signature as FileSignature | undefined;
          return sig ? signatureTooltip(sig) : "";
        },
        render: signatureCell,
      },
    ),
    col.field("attributes", "파일 속성", 160, ["source"], (r) => strOrNull(r.fields.attributes), {
      emptyHint: ntfsHint,
    }),
    ntfsTime("ntfsAccessed", "NTFS 접근", "accessed_at"),
    col.field(
      "ntfsEntry",
      "MFT 엔트리",
      100,
      ["source"],
      (r) => {
        const value = ntfsOf(r).entry_number;
        return typeof value === "number" ? value : strOrNull(value);
      },
      { mono: true, align: "right", filterKind: "number", emptyHint: ntfsHint },
    ),
    col.field("filesystem", "파일 시스템", 100, ["source"], (r) => strOrNull(r.fields.filesystem), {
      emptyHint: ntfsHint,
    }),
    col.field("sourceImage", "소스 이미지 경로", 280, ["source"], (r) => strOrNull(r.fields.sourceImage), {
      emptyHint: ntfsHint,
    }),
    col.sha256(),
  ],
};
