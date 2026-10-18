/**
 * 콘텐츠 유형 (r4 §2.3, AXIOM content type): one global chip set for files and artifacts.
 * Keep aligned with `rapidtriage/api/app/row_conditions.py` CONTENT_TYPES — the server filters
 * `/artifacts`, `/files` and `/timeline` (`content=`); this copy classifies loaded rows of the
 * other listings (문서·검색…) and the explorer views.
 *
 *  - files rows: the scan category (문서 documents · 이미지 images · 압축 archives · 실행
 *    executables · DB databases · 메일 emails); 영상/음성 have no category and go by extension;
 *  - artifact / timeline rows: the artifact type (media-image → 이미지 …) or the extension of the
 *    file the row points at (`target_path`, `local_path`, …; never `source_path`, the container the
 *    parser read). Only artifact types whose own path IS the content (media-*, document-*, file,
 *    email-attachment …: PATH_IS_CONTENT_*) fall back to the row's path — a History database or
 *    an .evtx is not the row's content.
 */

import type { GridRow } from "../../contracts/collection";

export type ContentTypeId =
  | "document"
  | "image"
  | "video"
  | "audio"
  | "archive"
  | "executable"
  | "database"
  | "mail";

interface ContentTypeDef {
  label: string;
  categories: readonly string[];
  extensions: ReadonlySet<string>;
  types: readonly string[];
}

const words = (text: string): ReadonlySet<string> => new Set(text.split(/\s+/).filter(Boolean));

export const CONTENT_TYPES: Readonly<Record<ContentTypeId, ContentTypeDef>> = {
  document: {
    label: "문서",
    categories: ["documents"],
    extensions: words(
      "txt pdf doc dot docx docm dotx rtf odt ods odp xls xlt xlsx xlsm xlsb ppt pps pptx pptm ppsx hwp hwpx hwt cell show nxl csv tsv md",
    ),
    types: ["document-"],
  },
  image: {
    label: "이미지",
    categories: ["images"],
    extensions: words("jpg jpeg jfif jpe png gif bmp dib tif tiff heic heif avif webp ico dng cr2 nef arw"),
    types: ["media-image", "synthetic-media-image", "thumbnail-cache-media", "icon-cache-media"],
  },
  video: {
    label: "영상",
    categories: [],
    extensions: words("mp4 m4v mov avi mkv wmv flv webm 3gp 3g2 mpg mpeg ts mts m2ts vob asf"),
    types: ["media-video"],
  },
  audio: {
    label: "음성",
    categories: [],
    extensions: words("mp3 wav m4a aac flac ogg oga opus wma amr aiff aif mid midi"),
    types: ["media-audio"],
  },
  archive: {
    label: "압축",
    categories: ["archives"],
    extensions: words(
      "zip 7z rar tar gz gzip tgz bz2 tbz2 xz txz zst lz lzma cpio cab alz egg z00 z01 zipx wim swm",
    ),
    types: ["archive-"],
  },
  executable: {
    label: "실행",
    categories: ["executables"],
    extensions: words(
      "exe dll sys msi msp bat cmd ps1 psm1 sh com scr cpl ocx jar apk appimage vbs vbe js jse wsf hta elf so dylib msix appx",
    ),
    types: ["prefetch-file"],
  },
  database: {
    label: "DB",
    categories: ["databases"],
    extensions: words("db db3 sqlite sqlite3 sqlitedb mdb accdb edb sdf wal sqlite-wal db-wal"),
    types: ["sqlite-"],
  },
  mail: {
    label: "메일",
    categories: ["emails"],
    extensions: words("eml msg pst ost mbox emlx"),
    types: ["email"],
  },
};

export const CONTENT_TYPE_IDS = Object.keys(CONTENT_TYPES) as ContentTypeId[];

export function isContentTypeId(value: unknown): value is ContentTypeId {
  return typeof value === "string" && value in CONTENT_TYPES;
}

export function contentTypeLabel(id: string): string {
  return isContentTypeId(id) ? CONTENT_TYPES[id].label : id;
}

const TARGET_PATH_KEYS = [
  "target_path",
  "local_path",
  "target_file",
  "file_path",
  "executable_path",
  "referenced_path",
  "file_name",
  "filename",
  "attachment_name",
];
const PATH_IS_CONTENT_PREFIXES = ["media-", "document-", "synthetic-media-"];
const PATH_IS_CONTENT_TYPES: ReadonlySet<string> = new Set([
  "file",
  "file-signature-mismatch",
  "ios-backup-file",
  "cloud-sync-file",
  "kakaotalk-shared-picture",
  "email-attachment",
  "android-apk",
]);

/** The artifact type's own path is the content file (server `row_conditions.path_is_content`). */
export function pathIsContent(type: string): boolean {
  return (
    PATH_IS_CONTENT_TYPES.has(type) || PATH_IS_CONTENT_PREFIXES.some((prefix) => type.startsWith(prefix))
  );
}

/** Lower-case extension of a path's last component (no dot), "" when none. */
export function pathExtension(value: unknown): string {
  if (typeof value !== "string" || !value) return "";
  const name = value.trim().split(/[\\/]/).pop() ?? "";
  const dot = name.lastIndexOf(".");
  if (dot <= 0 || dot === name.length - 1) return "";
  const ext = name.slice(dot + 1);
  return ext.length <= 12 && /^[A-Za-z0-9-]+$/.test(ext) ? ext.toLowerCase() : "";
}

function detailsOf(row: GridRow): Record<string, unknown> {
  const details = row.fields.details;
  return details && typeof details === "object" && !Array.isArray(details)
    ? (details as Record<string, unknown>)
    : {};
}

/** 콘텐츠 유형 ids of a loaded row (module doc). */
export function rowContentTypes(row: GridRow): Set<ContentTypeId> {
  const found = new Set<ContentTypeId>();
  if (row.ref.collection === "files") {
    const categories = Array.isArray(row.fields.categories) ? row.fields.categories.map(String) : [];
    const ext = pathExtension(row.sourcePath ?? row.title);
    for (const id of CONTENT_TYPE_IDS) {
      const def = CONTENT_TYPES[id];
      const hit = def.categories.length
        ? def.categories.some((category) => categories.includes(category))
        : def.extensions.has(ext);
      if (hit) found.add(id);
    }
    return found;
  }
  const details = detailsOf(row);
  const type = String(details.artifact_type ?? row.artifactType ?? "").toLowerCase();
  let target = "";
  for (const key of TARGET_PATH_KEYS) {
    target = pathExtension(details[key]);
    if (target) break;
  }
  if (!target && row.ref.collection === "artifacts" && pathIsContent(type))
    target = pathExtension(row.sourcePath);
  for (const id of CONTENT_TYPE_IDS) {
    const def = CONTENT_TYPES[id];
    const byType = type !== "" && def.types.some((prefix) => type === prefix || type.startsWith(prefix));
    if (byType || (target !== "" && def.extensions.has(target))) found.add(id);
  }
  return found;
}
