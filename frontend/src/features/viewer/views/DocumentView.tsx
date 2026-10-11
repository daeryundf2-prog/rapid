import type { SourcePreview } from "../../../api/viewer";
import { TextLines } from "./SourceView";

interface DocumentViewProps {
  preview: SourcePreview;
  terms: string[];
}

/** Text extracted from PDF/DOCX/etc. (source-preview runs the docs extractor). */
export function DocumentView({ preview, terms }: DocumentViewProps) {
  const text = preview.text ?? "";
  return (
    <div className="viewer-document">
      <p className="viewer-note">
        {(preview.extension || "").replace(".", "").toUpperCase()} 문서에서 추출한 텍스트입니다. 서식·이미지는
        포함되지 않으며, 인용 전에 원본을 확인하세요.
      </p>
      {text ? (
        <TextLines text={text} terms={terms} label={`${preview.name} 추출 텍스트`} />
      ) : (
        <p className="viewer-empty">추출된 텍스트가 없습니다.</p>
      )}
      {preview.truncated ? (
        <p className="viewer-note">
          추출 텍스트는 처음 {text.length.toLocaleString("ko-KR")}자만 표시합니다. 전체 문서는 원본 열기로
          확인하세요.
        </p>
      ) : null}
    </div>
  );
}
