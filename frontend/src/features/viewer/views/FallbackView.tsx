import type { ReactNode } from "react";
import type { SourcePreview } from "../../../api/viewer";
import { bytesLabel } from "../fieldFormat";
import { Unavailable } from "./Unavailable";

interface FallbackViewProps {
  preview: SourcePreview;
  onOpenOriginal: () => void;
  /** The hex grid, shown under the notice. */
  children: ReactNode;
}

/** A file type with no viewer of its own: why it is shown as bytes, what it is, then the hex grid. */
export function FallbackView({ preview, onOpenOriginal, children }: FallbackViewProps) {
  // "binary": the server's own preview failed (text extraction, hex read) and its message says why.
  const failure = preview.preview_type === "binary" ? preview.message : "";
  return (
    <div className="viewer-fallback">
      <Unavailable onOpenOriginal={onOpenOriginal}>
        이 형식은 전용 뷰어가 없어 바이트(헥스)로 표시합니다. 내용은 원본 열기로 내려받아 해당 프로그램에서
        확인하세요.
      </Unavailable>
      <dl className="viewer-dl">
        <dt>형식</dt>
        <dd>{(preview.extension || "").replace(".", "").toUpperCase() || "확장자 없음"}</dd>
        <dt>MIME</dt>
        <dd className="viewer-break">{preview.mime_type}</dd>
        <dt>크기</dt>
        <dd>{bytesLabel(preview.size)}</dd>
        {failure ? (
          <>
            <dt>서버 응답</dt>
            <dd className="viewer-break">{failure}</dd>
          </>
        ) : null}
      </dl>
      {children}
    </div>
  );
}
