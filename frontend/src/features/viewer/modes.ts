/**
 * Mode resolution: which viewer modes a target supports, why the others are
 * disabled (Korean reason → tab tooltip), and which one to auto-select.
 * Pure functions so the matrix is unit-testable without rendering.
 */

import type { SourcePreview } from "../../api/viewer";
import type { ViewerMode, ViewerModeState, ViewerTarget } from "../../contracts/viewer";

export const MODE_ORDER: ViewerMode[] = [
  "source",
  "hex",
  "sqlite",
  "image",
  "document",
  "email",
  "media",
  "meta",
];

export const MODE_LABELS: Record<ViewerMode, string> = {
  source: "원본",
  hex: "헥스",
  sqlite: "SQLite",
  image: "이미지",
  document: "문서",
  email: "이메일",
  media: "미디어",
  meta: "메타",
};

/**
 * Extensions whose `text` preview is an extraction result (core/docs
 * SUPPORTED_DOC_EXTS minus the plain-text ones) — shown in the document tab.
 */
export const DOCUMENT_EXTENSIONS = new Set([
  ".pdf",
  ".docx",
  ".doc",
  ".odt",
  ".ods",
  ".odp",
  ".pptx",
  ".xlsx",
  ".rtf",
  ".msg",
  ".pst",
  ".ost",
  ".htm",
  ".html",
  ".hwp",
  ".hwpx",
]);

export const REASONS = {
  noPath: "원본 파일 경로가 없는 행입니다(파생 항목).",
  loading: "원본 정보를 불러오는 중입니다.",
  emptyFile: "빈 파일(0바이트)입니다.",
  notText: "텍스트로 읽을 수 없는 파일입니다. 헥스 탭에서 바이트를 확인하세요.",
  documentHere: "추출 텍스트는 문서 탭에서 봅니다.",
  emailHere: "메일 헤더·본문은 이메일 탭에서 봅니다.",
  notSqlite: "SQLite 데이터베이스가 아닙니다.",
  notImage: "이미지 파일이 아닙니다.",
  notDocument: "PDF·DOCX 등 문서 텍스트 추출 대상이 아닙니다.",
  notEmail: "EML/MBOX 메일 파일이 아닙니다.",
  notMedia: "오디오·비디오 파일이 아닙니다.",
  archiveHex: "ZIP 내부 항목은 헥스 미리보기를 제공하지 않습니다.",
  directory: "디렉터리는 미리보기가 없습니다. 디렉터리 안의 파일을 선택하세요.",
} as const;

/** A directory target: flagged by its row, or answered as one by the preview API. */
export function isDirectoryTarget(target: ViewerTarget | null, preview: SourcePreview | null): boolean {
  return (
    target?.isDirectory === true || preview?.is_directory === true || preview?.preview_type === "directory"
  );
}

export interface ResolveInput {
  target: ViewerTarget | null;
  preview: SourcePreview | null;
  /** Preview request failed (message shown as the reason). */
  previewError?: string | null;
  loading?: boolean;
}

export interface ResolvedModes {
  modes: ViewerModeState[];
  best: ViewerMode | null;
}

function state(mode: ViewerMode, reason?: string): ViewerModeState {
  return reason ? { mode, available: false, reason } : { mode, available: true };
}

export function isDocumentPreview(preview: SourcePreview): boolean {
  return DOCUMENT_EXTENSIONS.has((preview.extension || "").toLowerCase());
}

/** Mode the payload naturally belongs to (before availability checks). */
export function naturalMode(preview: SourcePreview): ViewerMode {
  switch (preview.preview_type) {
    case "image":
      return "image";
    case "sqlite":
      return "sqlite";
    case "email":
      return "email";
    case "media":
      return "media";
    case "json":
    case "xml":
      return "source";
    case "text":
      return isDocumentPreview(preview) ? "document" : "source";
    default:
      return "hex";
  }
}

function hexState(preview: SourcePreview | null, target: ViewerTarget): ViewerModeState {
  if (!target.sourcePath) return state("hex", REASONS.noPath);
  if (preview && preview.size === 0) return state("hex", REASONS.emptyFile);
  const archive = Boolean(preview?.container_path);
  if (archive && !preview?.hex?.rows?.length) return state("hex", REASONS.archiveHex);
  return state("hex");
}

export function resolveModes(input: ResolveInput): ResolvedModes {
  const { target, preview, previewError, loading } = input;
  if (!target) {
    return { modes: MODE_ORDER.map((mode) => state(mode, "선택된 행이 없습니다.")), best: null };
  }
  // Decoded artifact rows (F2): the record itself (메타 → 레코드) is what the analyst wants first.
  const recordFirst = target.ref.collection === "artifacts";
  if (!target.sourcePath) {
    return {
      modes: MODE_ORDER.map((mode) => (mode === "meta" ? state("meta") : state(mode, REASONS.noPath))),
      best: "meta",
    };
  }
  if (isDirectoryTarget(target, preview)) {
    return {
      modes: MODE_ORDER.map((mode) => (mode === "meta" ? state("meta") : state(mode, REASONS.directory))),
      best: "meta",
    };
  }
  if (!preview) {
    const reason = previewError ? `미리보기를 불러오지 못했습니다: ${previewError}` : REASONS.loading;
    const modes = MODE_ORDER.map((mode) => {
      if (mode === "meta") return state("meta");
      if (mode === "hex" && (previewError || !loading)) return hexState(null, target);
      return state(mode, reason);
    });
    const best = recordFirst
      ? "meta"
      : previewError
        ? modes.find((m) => m.mode === "hex")?.available
          ? "hex"
          : "meta"
        : null;
    return { modes, best };
  }

  const natural = naturalMode(preview);
  const type = preview.preview_type;
  const textual = type === "text" || type === "json" || type === "xml";
  const modes: ViewerModeState[] = MODE_ORDER.map((mode) => {
    switch (mode) {
      case "source":
        if (textual && natural !== "document") return state("source");
        if (natural === "document") return state("source", REASONS.documentHere);
        if (type === "email") return state("source", REASONS.emailHere);
        return state("source", REASONS.notText);
      case "hex":
        return hexState(preview, target);
      case "sqlite":
        return type === "sqlite" ? state("sqlite") : state("sqlite", REASONS.notSqlite);
      case "image":
        return type === "image" ? state("image") : state("image", REASONS.notImage);
      case "document":
        if (natural === "document") return state("document");
        if (DOCUMENT_EXTENSIONS.has((preview.extension || "").toLowerCase())) {
          // Extraction failed (preview_type stays "binary"); surface the API message.
          return state("document", preview.message || REASONS.notDocument);
        }
        return state("document", REASONS.notDocument);
      case "email":
        return type === "email" ? state("email") : state("email", REASONS.notEmail);
      case "media":
        return type === "media" ? state("media") : state("media", REASONS.notMedia);
      default:
        return state("meta");
    }
  });
  const available = (mode: ViewerMode) => modes.find((m) => m.mode === mode)?.available === true;
  let best: ViewerMode = recordFirst
    ? "meta"
    : available(natural)
      ? natural
      : available("hex")
        ? "hex"
        : "meta";
  if (target.preferredMode && available(target.preferredMode)) best = target.preferredMode;
  return { modes, best };
}
