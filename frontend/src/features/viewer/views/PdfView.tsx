import { fetchSourceBlob, fetchSourcePrefix, type SourcePreview } from "../../../api/viewer";
import { bytesLabel } from "../fieldFormat";
import { type BlobUrlState, useBlobUrl } from "../useAsync";
import { Unavailable } from "./Unavailable";

/** The PDF is loaded whole as a blob (auth header) for the browser's own viewer; larger files open externally. */
export const PDF_INLINE_MAX_BYTES = 256 * 1024 * 1024;
/** PDF readers accept the header anywhere in the first 1024 bytes. */
const PDF_HEADER_WINDOW = 1024;
const PDF_HEADER = "%PDF-";

export class PdfSignatureError extends Error {
  constructor() {
    super("PDF 서명(%PDF-)이 없는 파일입니다. 확장자만 .pdf일 수 있으니 헥스 탭에서 실제 형식을 확인하세요.");
    this.name = "PdfSignatureError";
  }
}

function hasPdfHeader(head: Uint8Array): boolean {
  return new TextDecoder("latin1").decode(head.subarray(0, PDF_HEADER_WINDOW)).includes(PDF_HEADER);
}

/**
 * The original as an `application/pdf` blob, only when its bytes carry the PDF header. The header
 * is read first from the start of the stream, so a large file that is not a PDF is never fetched whole.
 */
async function fetchPdfBlob(runId: string, path: string, signal: AbortSignal): Promise<Blob> {
  const head = await fetchSourcePrefix(runId, path, PDF_HEADER_WINDOW, signal);
  if (!hasPdfHeader(head.bytes)) throw new PdfSignatureError();
  const blob = head.complete ? new Blob([head.bytes]) : await fetchSourceBlob(runId, path, signal);
  // The bytes framed are the ones checked, even if the file changed between the two reads.
  if (!head.complete && !hasPdfHeader(new Uint8Array(await blob.slice(0, PDF_HEADER_WINDOW).arrayBuffer()))) {
    throw new PdfSignatureError();
  }
  // The blob's type alone decides how the frame treats the bytes: always PDF, never the server's
  // guess from the file name. This is the only guard between evidence and the console's origin
  // (a blob: document shares it), so it must stay: the frame cannot be sandboxed, because Chrome
  // refuses to run its PDF viewer in any sandboxed frame, whatever the allow-* tokens.
  return blob.slice(0, blob.size, "application/pdf");
}

export interface PdfDocument {
  /** At most PDF_INLINE_MAX_BYTES: fetched and shown here. */
  inline: boolean;
  /** False where PDFs download instead of rendering in the page (phones, a switched-off viewer). */
  embeddable: boolean;
  pdf: BlobUrlState;
}

/**
 * The PDF's bytes as a blob URL, loaded once `wanted` and kept (not refetched) while the caller
 * stays mounted; the URL is revoked when it unmounts or the file changes.
 */
export function usePdfDocument(runId: string, preview: SourcePreview, wanted: boolean): PdfDocument {
  const inline = preview.size <= PDF_INLINE_MAX_BYTES;
  const embeddable = navigator.pdfViewerEnabled !== false;
  const pdf = useBlobUrl(wanted && inline && embeddable ? `${runId}|${preview.path}` : null, (signal) =>
    fetchPdfBlob(runId, preview.path, signal),
  );
  return { inline, embeddable, pdf };
}

interface PdfViewProps {
  preview: SourcePreview;
  document: PdfDocument;
  onOpenOriginal: () => void;
}

/** The PDF's pages in the browser's own PDF viewer, fed the original's bytes. */
export function PdfView({ preview, document: { inline, embeddable, pdf }, onOpenOriginal }: PdfViewProps) {
  if (!inline) {
    return (
      <Unavailable onOpenOriginal={onOpenOriginal}>
        {bytesLabel(preview.size)} PDF는 뷰어 안에 표시하지 않습니다. 한도는 256 MB입니다. 원본 열기로
        내려받아 확인하세요.
      </Unavailable>
    );
  }
  if (!embeddable) {
    return (
      <Unavailable onOpenOriginal={onOpenOriginal}>
        이 브라우저는 내장 PDF 보기가 꺼져 있어 PDF를 화면 안에 표시하지 않습니다. 원본 열기로 내려받아
        확인하세요.
      </Unavailable>
    );
  }
  if (pdf.status === "error") {
    return (
      <Unavailable tone="error" onOpenOriginal={onOpenOriginal}>
        PDF를 표시하지 못했습니다: {pdf.error}
      </Unavailable>
    );
  }
  if (!pdf.url) return <p className="viewer-note">PDF 불러오는 중…</p>;
  return <iframe className="pdf-frame" src={pdf.url} title={`${preview.name} PDF 보기`} />;
}
