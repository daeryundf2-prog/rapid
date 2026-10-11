import { useRef, useState } from "react";
import { fetchMediaCue, fetchSourceBlob, type SourcePreview } from "../../../api/viewer";
import { errorText, useBlobUrl } from "../useAsync";

/** Media is loaded as a blob (auth header); larger files are opened externally. */
export const MEDIA_INLINE_MAX_BYTES = 512 * 1024 * 1024;

/** "00:01:02.500" / "01:02,5" / "62.5" → seconds. */
export function parseCueTime(value: string | undefined): number | null {
  if (!value) return null;
  const parts = value.trim().replace(",", ".").split(":");
  let seconds = 0;
  for (const part of parts) {
    const number = Number(part);
    if (!Number.isFinite(number)) return null;
    seconds = seconds * 60 + number;
  }
  return seconds;
}

interface MediaViewProps {
  runId: string;
  preview: SourcePreview;
  onCopy: (text: string, sentence: string) => void;
}

export function MediaView({ runId, preview, onCopy }: MediaViewProps) {
  const media = preview.media || {};
  const mime = media.mime_type || preview.mime_type || "";
  const isVideo = mime.startsWith("video/");
  const inline = preview.size <= MEDIA_INLINE_MAX_BYTES;
  const blob = useBlobUrl(inline ? `${runId}|${preview.path}` : null, (signal) =>
    fetchSourceBlob(runId, preview.path, signal),
  );
  const playerRef = useRef<HTMLMediaElement | null>(null);
  const [cueError, setCueError] = useState<string | null>(null);
  const sidecars = media.transcript_sidecars || [];
  const metadata = media.metadata || {};

  const seek = (start: string | undefined) => {
    const seconds = parseCueTime(start);
    if (seconds === null || !playerRef.current) return;
    playerRef.current.currentTime = seconds;
    void playerRef.current.play?.()?.catch?.(() => undefined);
  };

  const copyCue = async (sidecarIndex: number, cueIndex: number) => {
    setCueError(null);
    try {
      const pkg = await fetchMediaCue(runId, preview.path, sidecarIndex, cueIndex);
      onCopy(
        pkg.copy_safe_citation?.text || `${preview.name} ${pkg.start}-${pkg.end} ${pkg.text ?? ""}`,
        "자막 구간 인용을 복사했습니다.",
      );
    } catch (error) {
      setCueError(errorText(error));
    }
  };

  return (
    <div className="media-view">
      {!inline ? (
        <p className="viewer-note">
          {(preview.size / 1024 / 1024).toFixed(0)} MB 파일은 뷰어에서 재생하지 않습니다. 원본 열기로
          확인하세요.
        </p>
      ) : blob.status === "error" ? (
        <p className="viewer-error">미디어를 불러오지 못했습니다: {blob.error}</p>
      ) : !blob.url ? (
        <p className="viewer-note">미디어 불러오는 중…</p>
      ) : isVideo ? (
        // biome-ignore lint/a11y/useMediaCaption: evidence media has no caption track; transcript cues are listed below
        <video
          ref={(element) => {
            playerRef.current = element;
          }}
          className="media-player"
          src={blob.url}
          controls
          preload="metadata"
          aria-label={`${preview.name} 재생`}
        />
      ) : (
        // biome-ignore lint/a11y/useMediaCaption: evidence media has no caption track; transcript cues are listed below
        <audio
          ref={(element) => {
            playerRef.current = element;
          }}
          className="media-player"
          src={blob.url}
          controls
          preload="metadata"
          aria-label={`${preview.name} 재생`}
        />
      )}
      <p className="viewer-note">
        {mime || "미디어"} · 길이 {metadata.duration_seconds ?? "알 수 없음"}초
        {metadata.sample_rate ? ` · 샘플레이트 ${metadata.sample_rate}` : ""}
        {metadata.audio_channels ? ` · 채널 ${metadata.audio_channels}` : ""}
      </p>
      <section aria-label="자막·전사 구간">
        <h3 className="viewer-subtitle">전사 구간</h3>
        {cueError ? <p className="viewer-error">구간 인용 실패: {cueError}</p> : null}
        {sidecars.length === 0 ? (
          <p className="viewer-note">이 미디어 옆에 전사(자막) 사이드카가 없습니다.</p>
        ) : null}
        {sidecars.map((sidecar, sidecarIndex) => (
          <div key={sidecar.path || sidecarIndex} className="media-sidecar">
            <p className="viewer-note">{sidecar.name || "전사"}</p>
            {(sidecar.cues || []).length ? (
              <ol className="media-cues">
                {(sidecar.cues || []).map((cue, cueIndex) => (
                  // biome-ignore lint/suspicious/noArrayIndexKey: cue order is the identity (API index)
                  <li key={cueIndex}>
                    <button
                      type="button"
                      className="media-cue"
                      onClick={() => seek(cue.start)}
                      disabled={!blob.url}
                      title={blob.url ? `${cue.start}로 이동` : "미디어를 재생할 수 없어 이동할 수 없습니다."}
                    >
                      <span className="mono">
                        {cue.start}–{cue.end}
                      </span>{" "}
                      {cue.text}
                    </button>
                    <button
                      type="button"
                      className="viewer-button"
                      onClick={() => copyCue(sidecarIndex + 1, cueIndex + 1)}
                      aria-label={`${cue.start} 구간 인용 복사`}
                    >
                      인용
                    </button>
                  </li>
                ))}
              </ol>
            ) : (
              <pre className="viewer-pre">{sidecar.preview}</pre>
            )}
          </div>
        ))}
      </section>
    </div>
  );
}
