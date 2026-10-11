import { useMemo, useState } from "react";
import { fetchSourceTextPrefix, isArchiveEntryPath, type SourcePreview } from "../../../api/viewer";
import { errorText } from "../useAsync";
import { countHits, highlight, keywordPattern } from "./Highlight";

export const FULL_TEXT_MAX_BYTES = 2 * 1024 * 1024;
export const LINE_WINDOW = 2000;

interface TextLinesProps {
  text: string;
  terms: string[];
  label: string;
}

/** Line-numbered text with windowed rendering ("더 보기" adds LINE_WINDOW lines). */
export function TextLines({ text, terms, label }: TextLinesProps) {
  const lines = useMemo(() => text.split(/\r?\n/), [text]);
  const pattern = useMemo(() => keywordPattern(terms), [terms]);
  const [shown, setShown] = useState(LINE_WINDOW);
  const visible = lines.slice(0, shown);
  const digits = String(lines.length).length;
  const hits = useMemo(() => countHits(text, pattern), [text, pattern]);
  return (
    <div className="viewer-text">
      {pattern ? (
        <p className="viewer-note">
          검색어 강조 {hits.toLocaleString("ko-KR")}건 ({terms.join(", ")})
        </p>
      ) : null}
      <pre className="viewer-lines" title={label}>
        {visible.map((line, index) => (
          // biome-ignore lint/suspicious/noArrayIndexKey: line number is the identity
          <span className="viewer-line" key={index}>
            <span className="viewer-ln" aria-hidden="true">
              {String(index + 1).padStart(digits, " ")}
            </span>
            <span className="viewer-lt">{highlight(line, pattern)}</span>
            {"\n"}
          </span>
        ))}
      </pre>
      {lines.length > shown ? (
        <button
          type="button"
          className="viewer-button"
          onClick={() => setShown((value) => value + LINE_WINDOW)}
        >
          더 보기 ({Math.min(LINE_WINDOW, lines.length - shown).toLocaleString("ko-KR")}줄 더 · 전체{" "}
          {lines.length.toLocaleString("ko-KR")}줄)
        </button>
      ) : null}
    </div>
  );
}

interface SourceViewProps {
  runId: string;
  preview: SourcePreview;
  terms: string[];
}

export function SourceView({ runId, preview, terms }: SourceViewProps) {
  const [full, setFull] = useState<{ text: string; complete: boolean; bytes: number } | null>(null);
  const [loadState, setLoadState] = useState<{ busy: boolean; error: string | null }>({
    busy: false,
    error: null,
  });
  const archive = isArchiveEntryPath(preview.path) || Boolean(preview.container_path);
  const text = full?.text ?? preview.text ?? "";

  const loadMore = async () => {
    setLoadState({ busy: true, error: null });
    try {
      const result = await fetchSourceTextPrefix(runId, preview.path, FULL_TEXT_MAX_BYTES);
      setFull({ text: result.text, complete: result.complete, bytes: result.bytesRead });
      setLoadState({ busy: false, error: null });
    } catch (error) {
      setLoadState({ busy: false, error: errorText(error) });
    }
  };

  return (
    <div className="viewer-source">
      {preview.preview_type === "json" && preview.json ? (
        <p className="viewer-note">
          JSON 항목 {preview.json.item_count ?? 0}개
          {preview.json.truncated ? " · 구조 요약이 제한되었습니다" : ""}
        </p>
      ) : null}
      {preview.preview_type === "xml" && preview.xml ? (
        <details className="viewer-details">
          <summary>
            XML 구조 · 루트 {preview.xml.root_tag || "알 수 없음"} · 노드 {preview.xml.nodes?.length ?? 0}개
          </summary>
          <ul className="viewer-outline">
            {(preview.xml.nodes || []).map((node, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: outline order is the identity
              <li key={index}>
                <code>{node.path || node.tag}</code> {node.text}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
      {text ? (
        <TextLines text={text} terms={terms} label={`${preview.name} 원본 텍스트`} />
      ) : (
        <p className="viewer-empty">표시할 텍스트가 없습니다.</p>
      )}
      {preview.truncated && !full ? (
        <div className="viewer-more">
          <p className="viewer-note">
            미리보기는 처음 {(preview.text ?? "").length.toLocaleString("ko-KR")}자만 표시합니다.
          </p>
          {archive ? (
            <p className="viewer-note">
              ZIP 내부 항목은 전체 텍스트를 불러올 수 없습니다. 원본 열기로 확인하세요.
            </p>
          ) : (
            <button type="button" className="viewer-button" onClick={loadMore} disabled={loadState.busy}>
              {loadState.busy ? "불러오는 중…" : "더 보기 (최대 2 MB)"}
            </button>
          )}
        </div>
      ) : null}
      {full && !full.complete ? (
        <p className="viewer-note">처음 2 MB만 표시합니다. 전체 내용은 원본 열기로 확인하세요.</p>
      ) : null}
      {loadState.error ? (
        <p className="viewer-error">전체 텍스트를 불러오지 못했습니다: {loadState.error}</p>
      ) : null}
    </div>
  );
}
