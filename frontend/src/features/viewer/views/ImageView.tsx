import { useState } from "react";
import {
  fetchImageGallery,
  fetchOcrQueue,
  fetchOcrTranslation,
  fetchSourceBlob,
  type OcrQueue,
  type SourcePreview,
} from "../../../api/viewer";
import "../../review/review.css";
import { useViewPrefs } from "../../review/viewPrefs";
import { errorText, useAsync, useBlobUrl } from "../useAsync";
import { latestOcrFailure } from "./ocrFailure";

export const GALLERY_PAGE = 12;

function AuthImage({
  runId,
  path,
  alt,
  className,
}: {
  runId: string;
  path: string;
  alt: string;
  className?: string;
}) {
  const image = useBlobUrl(`${runId}|${path}`, (signal) => fetchSourceBlob(runId, path, signal));
  if (image.status === "error")
    return <span className="viewer-error">이미지를 불러오지 못했습니다: {image.error}</span>;
  if (!image.url) return <span className="viewer-note">이미지 불러오는 중…</span>;
  return <img src={image.url} alt={alt} className={className} />;
}

interface ImageViewProps {
  runId: string;
  preview: SourcePreview;
  onOpenPath: (path: string) => void;
}

export function ImageView({ runId, preview, onOpenPath }: ImageViewProps) {
  const image = preview.image || {};
  const [galleryOffset, setGalleryOffset] = useState(0);
  const gallery = useAsync(`${preview.path}|${galleryOffset}`, (signal) =>
    fetchImageGallery(runId, preview.path, galleryOffset, GALLERY_PAGE, signal),
  );
  const profile = image.korean_ocr_translation_profile || {};
  const wantsTranslation = Boolean(profile.has_translation_sidecar || profile.has_ocr_sidecar);
  const translation = useAsync(wantsTranslation ? preview.path : null, (signal) =>
    fetchOcrTranslation(runId, preview.path, signal),
  );
  const [queue, setQueue] = useState<{ busy: boolean; data: OcrQueue | null; error: string | null }>({
    busy: false,
    data: null,
    error: null,
  });
  const loadQueue = async () => {
    setQueue({ busy: true, data: null, error: null });
    try {
      setQueue({ busy: false, data: await fetchOcrQueue(runId, preview.path), error: null });
    } catch (error) {
      setQueue({ busy: false, data: null, error: errorText(error) });
    }
  };
  const ocrText = image.ocr_sidecar?.text || "";
  const translationText = image.translation_sidecar?.text || "";
  const sides = translation.status === "ok" ? translation.data.side_by_side_review || [] : [];
  // No text to show: ask whether the newest OCR batch over this image failed (and why).
  const noText = !ocrText && !translationText && sides.length === 0;
  const failure = useAsync(noText ? `${runId}|${preview.path}|ocr-failure` : null, (signal) =>
    latestOcrFailure(runId, preview.path, signal).catch(() => null),
  );
  const ocrFailure = failure.status === "ok" ? failure.data : null;
  // Examiner protection (AXIOM E3): the same 미디어 흐리게 preference as the gallery (Shift+B).
  const blur = useViewPrefs((s) => s.mediaBlur);

  return (
    <div className="image-view" data-media-blur={blur ? "on" : undefined}>
      <div className="image-main">
        <figure className="image-figure">
          <AuthImage
            runId={runId}
            path={preview.path}
            alt={preview.name}
            className="image-original viewer-media-blurrable"
          />
          <figcaption className="viewer-note">
            {image.width && image.height ? `${image.width}×${image.height}` : "크기 알 수 없음"}
            {image.decoded === false ? " · 디코딩 실패(메타데이터만)" : ""}
            {image.similarity_bucket ? ` · 유사 버킷 ${image.similarity_bucket}` : ""}
            {image.perceptual_hash ? ` · 지각 해시 ${image.perceptual_hash}` : ""}
          </figcaption>
        </figure>
        <aside className="image-ocr" aria-label="OCR 텍스트">
          <h3 className="viewer-subtitle">OCR 텍스트</h3>
          {sides.length ? (
            sides.map((side) => (
              <section key={side.role} className="image-ocr-side">
                <h4>
                  {side.role === "ocr-source" ? "OCR 원문" : "번역"} ({side.language_hint || "언어 미상"})
                </h4>
                {side.text ? (
                  <pre className="viewer-pre">{side.text}</pre>
                ) : (
                  <p className="viewer-note">사이드카 없음</p>
                )}
                {side.truncated ? <p className="viewer-note">일부만 표시했습니다.</p> : null}
              </section>
            ))
          ) : ocrText || translationText ? (
            <>
              {ocrText ? <pre className="viewer-pre">{ocrText}</pre> : null}
              {ocrText && image.ocr_sidecar?.source === "analysis" ? (
                <p className="viewer-note" data-testid="ocr-from-analysis">
                  처리 단계 OCR 일괄 결과를 그대로 보여 줍니다(다시 OCR하지 않음).
                </p>
              ) : null}
              {translationText ? (
                <>
                  <h4>번역</h4>
                  <pre className="viewer-pre">{translationText}</pre>
                </>
              ) : null}
            </>
          ) : ocrFailure ? (
            <p className="viewer-error" data-testid="ocr-failed">
              {ocrFailure.batch
                ? "최근 OCR 일괄 작업이 실패했습니다"
                : "최근 OCR 일괄에서 이 이미지를 읽지 못했습니다"}
              {` (분석 ${ocrFailure.analysisId.slice(0, 8)}): ${ocrFailure.reason}`}
            </p>
          ) : (
            <p className="viewer-note">이 이미지 옆에 OCR 사이드카가 없습니다.</p>
          )}
          {translation.status === "error" ? (
            <p className="viewer-error">번역 검토를 불러오지 못했습니다: {translation.error}</p>
          ) : null}
          {sides.length ? (
            <p className="viewer-note">OCR·번역은 원본 이미지와 대조한 뒤 인용하세요(검수 서명 필요).</p>
          ) : null}
          <button type="button" className="viewer-button" onClick={loadQueue} disabled={queue.busy}>
            {queue.busy ? "대기열 확인 중…" : "폴더 OCR 대기열 확인"}
          </button>
          {queue.error ? <p className="viewer-error">OCR 대기열 실패: {queue.error}</p> : null}
          {queue.data ? (
            <p className="viewer-note">
              후보 {queue.data.summary?.candidate_count ?? queue.data.items?.length ?? 0}개 · 사이드카 반영{" "}
              {queue.data.summary?.sidecar_imported_count ?? 0}개 · 상태{" "}
              {Object.entries(queue.data.summary?.status_counts || {})
                .map(([key, value]) => `${key} ${value}`)
                .join(", ") || "없음"}
            </p>
          ) : null}
        </aside>
      </div>
      <section className="image-gallery" aria-label="같은 폴더의 이미지">
        {gallery.status === "loading" ? <p className="viewer-note">갤러리 불러오는 중…</p> : null}
        {gallery.status === "error" ? (
          <p className="viewer-error">갤러리를 불러오지 못했습니다: {gallery.error}</p>
        ) : null}
        {gallery.status === "ok" ? (
          <>
            <p className="viewer-note">
              같은 폴더 이미지 {galleryOffset + 1}–{galleryOffset + gallery.data.items.length} /{" "}
              {gallery.data.total.toLocaleString("ko-KR")}
            </p>
            <ul className="image-strip">
              {gallery.data.items.map((item) => (
                <li key={item.path}>
                  <button
                    type="button"
                    className={`image-thumb${item.is_anchor ? " is-current" : ""}`}
                    aria-current={item.is_anchor ? "true" : undefined}
                    aria-disabled={item.is_anchor ? "true" : undefined}
                    title={item.is_anchor ? "현재 보고 있는 이미지입니다." : item.path}
                    onClick={() => {
                      if (!item.is_anchor) onOpenPath(item.path);
                    }}
                  >
                    <AuthImage
                      runId={runId}
                      path={item.path}
                      alt=""
                      className="image-thumb-img viewer-media-blurrable"
                    />
                    <span>{item.name}</span>
                  </button>
                </li>
              ))}
            </ul>
            <div className="viewer-row">
              <button
                type="button"
                className="viewer-button"
                disabled={galleryOffset === 0}
                onClick={() => setGalleryOffset(Math.max(0, galleryOffset - GALLERY_PAGE))}
              >
                이전 이미지
              </button>
              <button
                type="button"
                className="viewer-button"
                disabled={!gallery.data.has_next}
                onClick={() => setGalleryOffset(gallery.data.next_offset ?? galleryOffset + GALLERY_PAGE)}
              >
                다음 이미지
              </button>
            </div>
          </>
        ) : null}
      </section>
    </div>
  );
}
