import { type ReactNode, useState } from "react";
import { fetchSourceImage, fetchSourceThumbnailBlob } from "../../../api/viewer";
import { useBlobUrl } from "../useAsync";

interface EvidenceImageProps {
  runId: string;
  path: string;
  alt: string;
  className?: string;
  /** Edge (px) of the server's JPEG shown when the browser cannot decode the original (at most 512). */
  renditionSize: number;
  /** Shown under the server's JPEG: it is a preview, not the original's pixels. */
  renditionNote?: ReactNode;
  /** Shown when neither the browser nor the server can decode the image. */
  children?: ReactNode;
}

/**
 * An evidence image loaded through the auth header. A format the browser cannot decode (TIFF, …)
 * is replaced by the server's JPEG of it, and by `children` when the server cannot decode it either.
 */
export function EvidenceImage(props: EvidenceImageProps) {
  const { runId, path, alt, className } = props;
  const [decodable, setDecodable] = useState(true);
  const original = useBlobUrl(decodable ? `${runId}|${path}` : null, (signal) =>
    fetchSourceImage(runId, path, signal),
  );
  if (!decodable) return <ServerRendition {...props} />;
  if (original.status === "error")
    return <span className="viewer-error">이미지를 불러오지 못했습니다: {original.error}</span>;
  if (!original.url) return <span className="viewer-note">이미지 불러오는 중…</span>;
  return <img src={original.url} alt={alt} className={className} onError={() => setDecodable(false)} />;
}

function ServerRendition(props: EvidenceImageProps) {
  const { runId, path, alt, className, renditionSize, renditionNote, children } = props;
  const [decodable, setDecodable] = useState(true);
  const rendition = useBlobUrl(`${runId}|${path}|${renditionSize}`, (signal) =>
    fetchSourceThumbnailBlob(runId, path, renditionSize, signal),
  );
  if (rendition.status === "error" || !decodable) return children;
  if (!rendition.url) return <span className="viewer-note">이미지 불러오는 중…</span>;
  return (
    <>
      <img src={rendition.url} alt={alt} className={className} onError={() => setDecodable(false)} />
      {renditionNote}
    </>
  );
}
