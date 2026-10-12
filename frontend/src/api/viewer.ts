// Viewer API calls (stream S2). Every shape below is read from the FastAPI
// route builders in rapidtriage/api/app (routes_media.py + runops.py, hex.py,
// sqlite.py, image.py, email.py, media.py, previews.py, core/sqlite_wal.py),
// and the review routes (routes_case_db.py `CaseDbReviewRequest`,
// routes_reports.py `BookmarkCreateRequest`). Only fields the viewer reads are
// typed; the payloads carry many more profile fields.

import { api, apiResponse } from "./client";

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

export type PreviewType =
  | "text"
  | "json"
  | "xml"
  | "image"
  | "sqlite"
  | "email"
  | "media"
  | "hex"
  | "binary"
  /** A directory (runops.build_directory_preview): no content preview. */
  | "directory";

export interface HexRow {
  offset: number;
  offset_hex: string;
  hex: string;
  ascii: string;
}

export interface SqliteColumnDetail {
  name?: string;
  type?: string;
  notnull?: boolean | number;
  pk?: boolean | number;
}

export interface SqlitePreviewTable {
  name: string;
  row_count?: number | null;
  column_count?: number;
  columns?: string[];
  column_details?: SqliteColumnDetail[];
  primary_key_columns?: string[];
}

export interface SqliteSidecarInfo {
  exists?: boolean;
  size_bytes?: number;
  header?: {
    status?: string;
    magic_hex?: string;
    page_size?: number | string;
    estimated_frame_count?: number;
  };
}

export interface SqliteSidecarStateProfile {
  requires_wal_review?: boolean;
  source_viewer_warning?: string;
  detected_sidecars?: string[];
  source_path?: string;
  sidecars?: { wal?: SqliteSidecarInfo; shm?: SqliteSidecarInfo; rollback_journal?: SqliteSidecarInfo };
}

export interface SqlitePreviewPayload {
  table_count?: number;
  tables?: SqlitePreviewTable[];
  sidecar_state_profile?: SqliteSidecarStateProfile;
  database_metadata?: { page_size?: number | string; sidecar_state_profile?: SqliteSidecarStateProfile };
  truncated?: boolean;
  error?: string;
}

export interface ImageSidecar {
  text?: string;
  source_path?: string;
  /** "analysis" = stored by a 처리-stage OCR 일괄 job (reused, never re-run here). */
  source?: string;
  analysis_id?: string;
}

export interface ImagePreviewPayload {
  decoded?: boolean;
  width?: number | null;
  height?: number | null;
  hashes?: Record<string, string>;
  perceptual_hash?: string;
  similarity_bucket?: string;
  ocr_sidecar?: ImageSidecar;
  translation_sidecar?: ImageSidecar;
  korean_ocr_translation_profile?: { has_ocr_sidecar?: boolean; has_translation_sidecar?: boolean };
  gallery_review?: { tag_suggestions?: string[] };
  error?: string;
}

export interface EmailAttachment {
  index: number;
  filename?: string;
  content_type?: string;
  size?: number;
  sha256?: string;
  exportable?: boolean;
}

export interface EmailMessage {
  index: number;
  subject?: string;
  from?: string;
  to?: string;
  cc?: string;
  date?: string;
  message_id?: string;
  attachments?: EmailAttachment[];
  attachment_count?: number;
  body_preview?: string;
  body_truncated?: boolean;
}

export interface EmailPreviewPayload {
  message_count?: number;
  messages?: EmailMessage[];
  parse_diagnostics?: {
    source_truncated?: boolean;
    message_limit_reached?: boolean;
    message_size_truncated_count?: number;
  };
  error?: string;
}

export interface MediaCue {
  start?: string;
  end?: string;
  text?: string;
}

export interface MediaSidecar {
  name?: string;
  path?: string;
  preview?: string;
  cues?: MediaCue[];
}

export interface MediaPreviewPayload {
  mime_type?: string;
  metadata?: {
    duration_seconds?: number | null;
    audio_channels?: number | null;
    sample_rate?: number | null;
    frame_count?: number | null;
  };
  source_hashes?: Record<string, string>;
  transcript_sidecars?: MediaSidecar[];
}

export interface JsonPreviewPayload {
  summary?: unknown;
  item_count?: number;
  item_limit?: number;
  truncated?: boolean;
}

export interface XmlNode {
  path?: string;
  tag?: string;
  text?: string;
  attributes?: Record<string, string>;
}

export interface XmlPreviewPayload {
  root_tag?: string;
  nodes?: XmlNode[];
  truncated?: boolean;
}

/** `GET /api/runs/{run}/source-preview?path=` (runops.build_source_preview). */
export interface SourcePreview {
  path: string;
  name: string;
  extension: string;
  size: number;
  /** epoch seconds (plain file) or ISO string (zip entry). */
  modified_at?: number | string;
  mime_type: string;
  download_url?: string;
  preview_type: PreviewType;
  /** Directory targets (`preview_type: "directory"`, size null). */
  is_directory?: boolean;
  text?: string;
  truncated?: boolean;
  message?: string;
  /** Present only for `archive.zip::entry` previews. */
  container_path?: string;
  viewer_limitations?: string[];
  viewer_metadata?: { source_format?: string; strategy?: string; preview_status?: string; parser?: string };
  hex?: { rows?: HexRow[]; bytes_read?: number; truncated?: boolean };
  image_url?: string;
  image?: ImagePreviewPayload;
  sqlite?: SqlitePreviewPayload;
  email?: EmailPreviewPayload;
  media?: MediaPreviewPayload;
  json?: JsonPreviewPayload;
  xml?: XmlPreviewPayload;
}

/** `GET /api/runs/{run}/source-metadata?path=&hash=` (runops.build_source_metadata). */
export interface SourceMetadata {
  path: string;
  name: string;
  extension: string;
  size: number;
  modified_at: string;
  created_at: string;
  mime_type: string;
  hashes: { md5?: string; sha1?: string; sha256?: string };
  hash_status: "not-requested" | "computed" | string;
  /** Directory targets (runops.build_directory_metadata): size null, no hashes. */
  is_directory?: boolean;
}

/** `GET /api/runs/{run}/source-hex-range` (hex.build_hex_range_citation_package). */
export interface HexRange {
  offset: number;
  offset_hex: string;
  end_offset_exclusive: number;
  length_returned: number;
  size: number;
  rows: HexRow[];
  range_hashes?: { sha256?: string };
  citation?: string;
}

/** `GET /api/runs/{run}/source-sqlite-table` (sqlite.build_sqlite_table_page). */
export interface SqliteTablePage {
  table: string;
  columns: string[];
  column_count: number;
  primary_key_columns?: string[];
  rows: Array<{ row_number: number; rowid: number | string; values: Record<string, unknown> }>;
  pagination: {
    offset: number;
    limit: number;
    returned: number;
    total: number | null;
    has_next: boolean;
    next_offset: number | null;
    max_page_rows: number;
  };
}

/** `GET /api/runs/{run}/source-sqlite-wal-preview` (core/sqlite_wal.build_sqlite_wal_preview). */
export interface SqliteWalPreview {
  wal: {
    exists?: boolean;
    status?: string;
    header?: { page_size?: number; checkpoint_sequence?: number };
    estimated_frame_count?: number;
    preview_frame_count?: number;
    frames?: Array<{
      frame_index: number;
      page_number: number;
      is_commit_frame?: boolean;
      salt_matches_header?: boolean;
    }>;
  };
  recovery_scope?: { deleted_record_candidate_count?: number; schema_mapped_record_count?: number };
}

/** `GET /api/runs/{run}/source-image-gallery` (image.build_image_gallery_page). */
export interface ImageGalleryPage {
  offset: number;
  limit: number;
  returned: number;
  total: number;
  has_next: boolean;
  next_offset: number | null;
  items: Array<{
    path: string;
    name: string;
    is_anchor?: boolean;
    size?: number;
    similarity_bucket?: string;
  }>;
}

/** `GET /api/runs/{run}/source-ocr-queue` (image.build_source_ocr_queue → core/ocr_queue). */
export interface OcrQueue {
  summary?: {
    candidate_count?: number;
    status_counts?: Record<string, number>;
    sidecar_imported_count?: number;
  };
  items?: Array<{ source_name?: string; source_path?: string; status?: string; language_hint?: string }>;
}

/** `GET /api/runs/{run}/source-ocr-translation` (image.build_source_ocr_translation_package). */
export interface OcrTranslation {
  summary?: {
    ocr_sidecar_present?: boolean;
    translation_sidecar_present?: boolean;
    translation_required?: boolean;
  };
  side_by_side_review?: Array<{
    role: string;
    label: string;
    language_hint?: string;
    sidecar_name?: string;
    text?: string;
    truncated?: boolean;
    character_count?: number;
  }>;
}

/** `GET /api/runs/{run}/source-email-attachment` (email.build_email_attachment_package). */
export interface EmailAttachmentPackage {
  filename?: string;
  content_type?: string;
  size?: number;
  hashes?: { sha256?: string; md5?: string; sha1?: string };
  copy_safe_citation?: { text?: string };
}

/** `GET /api/runs/{run}/source-media-cue` (media.build_media_cue_package). */
export interface MediaCuePackage {
  start?: string;
  end?: string;
  text?: string;
  copy_safe_citation?: { text?: string };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ARCHIVE_SEPARATOR = "::";

/** `archive.zip::entry/x.json` → file APIs (metadata, hash, download, hex range) act on the container. */
export function fileApiPath(path: string): string {
  const index = path.indexOf(ARCHIVE_SEPARATOR);
  return index > 0 ? path.slice(0, index) : path;
}

export function isArchiveEntryPath(path: string): boolean {
  return path.indexOf(ARCHIVE_SEPARATOR) > 0;
}

function runBase(runId: string): string {
  return `/api/runs/${encodeURIComponent(runId)}`;
}

function query(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined) continue;
    search.set(key, String(value));
  }
  return search.toString();
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

export function fetchSourcePreview(
  runId: string,
  path: string,
  signal?: AbortSignal,
): Promise<SourcePreview> {
  return api<SourcePreview>(`${runBase(runId)}/source-preview?${query({ path })}`, { signal });
}

export function fetchSourceMetadata(
  runId: string,
  path: string,
  options: { hash?: boolean; signal?: AbortSignal } = {},
): Promise<SourceMetadata> {
  const params = query({ path: fileApiPath(path), hash: options.hash ? true : undefined });
  return api<SourceMetadata>(`${runBase(runId)}/source-metadata?${params}`, { signal: options.signal });
}

/** Server caps `length` at 64 KiB (HEX_RANGE_EXPORT_MAX_BYTES); 416 when offset ≥ size. */
export function fetchHexRange(
  runId: string,
  path: string,
  offset: number,
  length: number,
  signal?: AbortSignal,
): Promise<HexRange> {
  return api<HexRange>(`${runBase(runId)}/source-hex-range?${query({ path, offset, length })}`, { signal });
}

/** Server caps `limit` at 500 (SQLITE_TABLE_PAGE_MAX_ROWS). */
export function fetchSqliteTable(
  runId: string,
  path: string,
  table: string,
  offset: number,
  limit: number,
  signal?: AbortSignal,
): Promise<SqliteTablePage> {
  return api<SqliteTablePage>(
    `${runBase(runId)}/source-sqlite-table?${query({ path, table, offset, limit })}`,
    {
      signal,
    },
  );
}

export function fetchSqliteWalPreview(
  runId: string,
  path: string,
  maxFrames = 20,
): Promise<SqliteWalPreview> {
  return api<SqliteWalPreview>(
    `${runBase(runId)}/source-sqlite-wal-preview?${query({ path, max_frames: maxFrames })}`,
  );
}

export function fetchImageGallery(
  runId: string,
  path: string,
  offset: number,
  limit: number,
  signal?: AbortSignal,
): Promise<ImageGalleryPage> {
  return api<ImageGalleryPage>(`${runBase(runId)}/source-image-gallery?${query({ path, offset, limit })}`, {
    signal,
  });
}

export function fetchOcrQueue(runId: string, path: string, maxItems = 50): Promise<OcrQueue> {
  return api<OcrQueue>(`${runBase(runId)}/source-ocr-queue?${query({ path, max_items: maxItems })}`);
}

export function fetchOcrTranslation(
  runId: string,
  path: string,
  signal?: AbortSignal,
): Promise<OcrTranslation> {
  return api<OcrTranslation>(`${runBase(runId)}/source-ocr-translation?${query({ path })}`, { signal });
}

export function fetchEmailAttachment(
  runId: string,
  path: string,
  messageIndex: number,
  attachmentIndex: number,
): Promise<EmailAttachmentPackage> {
  return api<EmailAttachmentPackage>(
    `${runBase(runId)}/source-email-attachment?${query({
      path,
      message_index: messageIndex,
      attachment_index: attachmentIndex,
    })}`,
  );
}

export function fetchMediaCue(
  runId: string,
  path: string,
  sidecarIndex: number,
  cueIndex: number,
): Promise<MediaCuePackage> {
  return api<MediaCuePackage>(
    `${runBase(runId)}/source-media-cue?${query({ path, sidecar_index: sidecarIndex, cue_index: cueIndex })}`,
  );
}

export function sourceFileUrl(runId: string, path: string): string {
  return `${runBase(runId)}/source-file?${query({ path: fileApiPath(path) })}`;
}

/**
 * The auth token travels only in a header (query tokens are rejected), so a
 * plain `<a href>`/`<img src>` cannot load the original. Fetch it as a blob.
 */
export async function fetchSourceBlob(runId: string, path: string, signal?: AbortSignal): Promise<Blob> {
  const response = await apiResponse(sourceFileUrl(runId, path), { signal });
  return response.blob();
}

/** Server-side cached JPEG thumbnail (≤ 512 px; GET /source-thumbnail). */
export const THUMBNAIL_DEFAULT_SIZE = 160;

export function sourceThumbnailUrl(runId: string, path: string, size = THUMBNAIL_DEFAULT_SIZE): string {
  return `${runBase(runId)}/source-thumbnail?${query({ path: fileApiPath(path), size })}`;
}

export async function fetchSourceThumbnailBlob(
  runId: string,
  path: string,
  size = THUMBNAIL_DEFAULT_SIZE,
  signal?: AbortSignal,
): Promise<Blob> {
  const response = await apiResponse(sourceThumbnailUrl(runId, path, size), { signal });
  return response.blob();
}

/** Read at most `maxBytes` of the original as UTF-8 (stream is cancelled after the cap). */
export async function fetchSourceTextPrefix(
  runId: string,
  path: string,
  maxBytes: number,
  signal?: AbortSignal,
): Promise<{ text: string; bytesRead: number; complete: boolean }> {
  const response = await apiResponse(sourceFileUrl(runId, path), { signal });
  const body = response.body;
  if (!body) {
    const buffer = new Uint8Array(await response.arrayBuffer());
    const slice = buffer.slice(0, maxBytes);
    return {
      text: new TextDecoder("utf-8").decode(slice),
      bytesRead: slice.length,
      complete: buffer.length <= maxBytes,
    };
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let complete = true;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const room = maxBytes - total;
    if (value.length > room) {
      chunks.push(value.slice(0, room));
      total += room;
      complete = false;
      await reader.cancel().catch(() => undefined);
      break;
    }
    chunks.push(value);
    total += value.length;
  }
  const merged = new Uint8Array(total);
  let cursor = 0;
  for (const chunk of chunks) {
    merged.set(chunk, cursor);
    cursor += chunk.length;
  }
  return { text: new TextDecoder("utf-8").decode(merged), bytesRead: total, complete };
}

// ---------------------------------------------------------------------------
// Review marks
// ---------------------------------------------------------------------------

/** Canonical case-db ensure lives in api/caseDb.ts (S4); kept under the viewer's name. */
export { ensureCaseDb as ensureRunCaseDb } from "./caseDb";

/** Canonical bookmark API lives in api/collections.ts (shared with the grid's review actions). */
export { type BookmarkBody, postBookmark } from "./collections";
