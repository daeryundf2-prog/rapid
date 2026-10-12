import { fetchFilesPage } from "../../../api/collections";
import { formatTimestamp } from "../../../utils/time";
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
        ? formatTimestamp(value, currentTimezone())
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

/** Files default layout, highest priority first: 이름 > 수정 > 크기 > 선별 > 경로 > NTFS 생성. */
export const FILES_PRIORITY = ["title", "timestamp", "size", "review", "path", "ntfsCreated"] as const;

export const filesCollection: CollectionDef = {
  id: "files",
  label: "파일",
  source: "paged",
  fetch: (runId, query, signal) =>
    fetchFilesPage(runId, query.offset, query.limit, signal, query.ref.category || undefined),
  widthPriority: () => FILES_PRIORITY,
  mapRow: (raw, position, ctx) => {
    // A category-filtered page is not candidate-ordered: keep the candidate's own index.
    const own = typeof raw.candidate_index === "number" ? raw.candidate_index : raw.record_index;
    const index = typeof own === "number" && Number.isInteger(own) && own >= 0 ? own : position;
    const path = strOrNull(raw.path);
    const recovery = isRecord(raw.recovery) ? raw.recovery : {};
    const hashes = isRecord(raw.hashes) ? raw.hashes : {};
    const join = ntfsJoinOf(ctx?.page?.meta);
    return makeRow(
      makeRef("files", `/candidates/${index}`),
      {
        title: strOrNull(raw.name) ?? (baseName(path) || `파일 ${index + 1}`),
        sourcePath: path,
        timestamp: strOrNull(raw.modified_at),
        artifactType: strOrNull(raw.extension),
        sha256: sha256Of(raw.sha256, hashes.sha256),
      },
      {
        extension: str(raw.extension),
        size: typeof raw.size === "number" ? raw.size : null,
        categories: joinList(raw.categories),
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
      },
    );
  },
  // Default layout (visual-polish S4): 이름 · 경로 · 크기 · 수정 · NTFS 생성 · 선별. Default width =
  // minimum width; 이름 takes the slack and a narrow grid hides columns by FILES_PRIORITY.
  columns: [
    { ...col.title("이름", 220), minWidth: 220 },
    col.path(200, ["analysis", "source"]),
    col.field("size", "크기", 80, ["analysis", "compact"], (r) => (r.fields.size as number | null) ?? null, {
      align: "right",
      minWidth: 80,
      format: (r) => formatBytes(r.fields.size),
    }),
    { ...col.timestamp(150), header: "수정", minWidth: 150 },
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
