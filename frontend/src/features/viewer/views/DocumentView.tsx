import { useMemo, useState } from "react";
import type { SourcePreview } from "../../../api/viewer";
import { isRenderablePdf } from "../modes";
import { countHits, keywordPattern } from "./Highlight";
import { PdfView, usePdfDocument } from "./PdfView";
import { RedactionNote } from "./RedactionNote";
import { TextLines } from "./SourceView";

type Presentation = "pdf" | "text";

interface DocumentViewProps {
  runId: string;
  preview: SourcePreview;
  terms: string[];
  onOpenOriginal: () => void;
}

/**
 * A document: the PDF itself, rendered from its bytes, and the text source-preview extracted from
 * it (PDF/DOCX/…). A PDF opens on its pages, unless the route's keywords hit the extracted text:
 * then the highlighted text comes first. The toggle switches either way for this file. The PDF's
 * bytes are fetched the first time its pages show and kept until the file changes or the viewer
 * closes, so toggling back does not fetch them again.
 */
export function DocumentView({ runId, preview, terms, onOpenOriginal }: DocumentViewProps) {
  const text = preview.text ?? "";
  const pdf = isRenderablePdf(preview);
  const hits = useMemo(() => countHits(text, keywordPattern(terms)), [text, terms]);
  const [chosen, setChosen] = useState<Presentation | null>(null);
  const presentation: Presentation = pdf ? (chosen ?? (hits > 0 ? "text" : "pdf")) : "text";
  const [pagesShown, setPagesShown] = useState(false);
  if (presentation === "pdf" && !pagesShown) setPagesShown(true);
  const pdfDocument = usePdfDocument(runId, preview, pdf && (pagesShown || presentation === "pdf"));
  return (
    <div className="viewer-document" data-presentation={presentation}>
      {pdf ? (
        <fieldset className="segmented" aria-label="문서 표시 방식">
          <button type="button" aria-pressed={presentation === "pdf"} onClick={() => setChosen("pdf")}>
            PDF
          </button>
          <button type="button" aria-pressed={presentation === "text"} onClick={() => setChosen("text")}>
            추출 텍스트
          </button>
        </fieldset>
      ) : null}
      {presentation === "pdf" ? (
        <PdfView preview={preview} document={pdfDocument} onOpenOriginal={onOpenOriginal} />
      ) : (
        <ExtractedText preview={preview} terms={terms} />
      )}
    </div>
  );
}

/** Text extracted from PDF/DOCX/etc. (source-preview runs the docs extractor). */
function ExtractedText({ preview, terms }: { preview: SourcePreview; terms: string[] }) {
  const text = preview.text ?? "";
  // "binary": the extractor failed and the API message says why. "hex": it ran and found no text.
  const failure = preview.preview_type === "binary" ? preview.message : "";
  if (!text) {
    return (
      <p className="viewer-empty">
        {failure ? `텍스트를 추출하지 못했습니다: ${failure}` : "추출된 텍스트가 없습니다."}
      </p>
    );
  }
  return (
    <>
      <p className="viewer-note">
        {(preview.extension || "").replace(".", "").toUpperCase()} 문서에서 추출한 텍스트입니다. 서식·이미지는
        포함되지 않으며, 인용 전에 원본을 확인하세요.
      </p>
      {preview.redacted ? <RedactionNote /> : null}
      <TextLines text={text} terms={terms} label={`${preview.name} 추출 텍스트`} />
      {preview.truncated ? (
        <p className="viewer-note">
          추출 텍스트는 처음 {text.length.toLocaleString("ko-KR")}자만 표시합니다. 전체 문서는 원본 열기로
          확인하세요.
        </p>
      ) : null}
    </>
  );
}
