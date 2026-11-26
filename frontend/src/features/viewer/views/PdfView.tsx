import { fetchSourceBlob, type SourcePreview } from "../../../api/viewer";
import { bytesLabel } from "../fieldFormat";
import { useBlobUrl } from "../useAsync";
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

/** The original as an `application/pdf` blob, only when its bytes carry the PDF header. */
async function fetchPdfBlob(runId: string, path: string, signal: AbortSignal): Promise<Blob> {
  const blob = await fetchSourceBlob(runId, path, signal);
  const head = new TextDecoder("latin1").decode(await blob.slice(0, PDF_HEADER_WINDOW).arrayBuffer());
  if (!head.includes(PDF_HEADER)) throw new PdfSignatureError();
  // The blob's type decides how the frame treats the bytes: always PDF, never the server's guess
  // from the file name (evidence named .pdf must not run as a page in the console's origin).
  return blob.slice(0, blob.size, "application/pdf");
}

interface PdfViewProps {
  runId: string;
  preview: SourcePreview;
  onOpenOriginal: () => void;
}

/** The PDF's pages in the browser's own PDF viewer, fed the original's bytes. */
export function PdfView({ runId, preview, onOpenOriginal }: PdfViewProps) {
  const inline = preview.size <= PDF_INLINE_MAX_BYTES;
  // False where PDFs download instead of rendering in the page (phones, a switched-off viewer).
  const embeddable = navigator.pdfViewerEnabled !== false;
  const pdf = useBlobUrl(inline && embeddable ? `${runId}|${preview.path}` : null, (signal) =>
    fetchPdfBlob(runId, preview.path, signal),
  );
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
