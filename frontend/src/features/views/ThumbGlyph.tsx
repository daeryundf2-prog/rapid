/**
 * No-preview tile of the 썸네일 보기 (r8 T-017): a format glyph (image / video / document) +
 * "미리보기 없음" instead of a blank square, plus the withheld reason for a credential file
 * (server: 403 CREDENTIAL_FILE_WITHHELD). The server contract (T-018): an image-typed file that does
 * not decode answers HTTP 204 with `X-RapidTriage-Thumbnail: unavailable`.
 */

import { ApiError } from "../../api/client";
import { Icon, type IconName } from "../../icons";
import { IMAGE_EXTENSIONS } from "./thumbnails";

/** Tile text when there is no picture to show (r8 T-017). */
export const THUMB_NO_PREVIEW_TEXT = "미리보기 없음";
/** Why a credential / secret file has no picture (server: 403 CREDENTIAL_FILE_WITHHELD). */
export const THUMB_WITHHELD_TEXT = "자격 증명 파일 — 본문 미수집";
const CREDENTIAL_FILE_WITHHELD = "CREDENTIAL_FILE_WITHHELD";

/** The tile draws the type glyph: no fallback, no retry. `message` is the Korean tile reason. */
export class ThumbUnavailableError extends Error {
  readonly withheld: boolean;
  constructor(withheld: boolean) {
    super(withheld ? THUMB_WITHHELD_TEXT : THUMB_NO_PREVIEW_TEXT);
    this.name = "ThumbUnavailableError";
    this.withheld = withheld;
  }
}

/**
 * The no-preview error for a failed thumbnail call, or `null` when the original may still render:
 * 415 (a type the server does not decode), 5xx and network failures. A credential file's 403 is
 * "withheld"; every other 4xx is plain "no preview".
 */
export function noPreviewFor(error: unknown): ThumbUnavailableError | null {
  if (!(error instanceof ApiError)) return null;
  if (error.code === CREDENTIAL_FILE_WITHHELD) return new ThumbUnavailableError(true);
  if (error.status === 415 || error.status === 0 || error.status >= 500) return null;
  return new ThumbUnavailableError(false);
}

const VIDEO_EXTENSIONS: ReadonlySet<string> = new Set([
  "mp4",
  "m4v",
  "mov",
  "avi",
  "mkv",
  "webm",
  "wmv",
  "3gp",
  "mpg",
  "mpeg",
]);

/** Format glyph of a tile without a picture: image, video or document. */
export function thumbGlyph(path: string): IconName {
  const name = path.split(/[\\/]/).pop() ?? "";
  const dot = name.lastIndexOf(".");
  const extension = dot > 0 ? name.slice(dot + 1).toLowerCase() : "";
  if (IMAGE_EXTENSIONS.has(extension)) return "image";
  if (VIDEO_EXTENSIONS.has(extension)) return "film";
  return "file-text";
}

export function ThumbGlyph({ path, withheld }: { path: string; withheld: boolean }) {
  return (
    <span className="thumb-glyph" data-testid="thumb-glyph" data-withheld={withheld || undefined}>
      <Icon name={withheld ? "key" : thumbGlyph(path)} size={36} />
      <span className="thumb-glyph-text">{THUMB_NO_PREVIEW_TEXT}</span>
      {withheld ? <span className="thumb-glyph-reason">{THUMB_WITHHELD_TEXT}</span> : null}
    </span>
  );
}
