import type { SourceMetadata, SourcePreview } from "../../api/viewer";
import type { ViewerMode, ViewerTarget } from "../../contracts/viewer";
import type { useViewerRowContext } from "./adapter";
import { naturalMode } from "./modes";
import type { AsyncState } from "./useAsync";
import { ArchiveView } from "./views/ArchiveView";
import { DocumentView } from "./views/DocumentView";
import { EmailView } from "./views/EmailView";
import { FallbackView } from "./views/FallbackView";
import { HexView } from "./views/HexView";
import { ImageView } from "./views/ImageView";
import { MediaView } from "./views/MediaView";
import { MetaView } from "./views/MetaView";
import { SourceView } from "./views/SourceView";
import { SqliteView } from "./views/SqliteView";

export interface ViewerBodyProps {
  target: ViewerTarget;
  mode: ViewerMode;
  /** Preview still loading and no mode chosen yet (artifact rows resolve to 메타 immediately). */
  resolving: boolean;
  highlight: ViewerTarget["highlight"];
  previewState: AsyncState<SourcePreview>;
  metadata: SourceMetadata | null;
  metadataError: string | null;
  hashBusy: boolean;
  row: ReturnType<typeof useViewerRowContext>;
  sessionMarks: string[];
  terms: string[];
  onComputeHash: () => void;
  onOpenPath: (path: string) => void;
  onCopy: (text: string, sentence: string) => void;
  /** Download the original (the viewer's 원본 열기 command): the way out of a view that cannot show the file. */
  onOpenOriginal: () => void;
}

/** The active mode's view of the target: loading and error states first, then one view per mode. */
export function ViewerBody(props: ViewerBodyProps) {
  const { target, mode, previewState, metadata, highlight } = props;
  const hexKey = `${target.sourcePath}|${highlight?.offset ?? ""}`;
  const preview = previewState.status === "ok" ? previewState.data : null;
  if (
    props.resolving ||
    (mode !== "meta" &&
      target.sourcePath &&
      (previewState.status === "loading" || previewState.status === "idle"))
  ) {
    return <p className="viewer-note">원본을 불러오는 중…</p>;
  }
  if (mode === "meta" || !target.sourcePath) {
    return (
      <MetaView
        target={target}
        preview={preview}
        metadata={metadata}
        metadataError={props.metadataError}
        hashBusy={props.hashBusy}
        row={props.row}
        sessionMarks={props.sessionMarks}
        onComputeHash={props.onComputeHash}
      />
    );
  }
  if (mode === "hex" && !preview && previewState.status === "error") {
    if (!metadata) {
      // The size comes from source-metadata: when that failed too (a 404 for a deleted
      // snapshot file), say so — never an endless "확인하는 중".
      if (props.metadataError) {
        return (
          <p className="viewer-error" data-testid="viewer-hex-error">
            원본을 불러오지 못했습니다: {previewState.error} · 파일 정보: {props.metadataError}
          </p>
        );
      }
      return <p className="viewer-note">파일 크기를 확인하는 중…</p>;
    }
    return (
      <HexView
        key={hexKey}
        runId={target.runId}
        path={target.sourcePath}
        size={metadata.size}
        highlight={highlight}
      />
    );
  }
  if (previewState.status === "error" || !preview) {
    return <p className="viewer-error">원본을 불러오지 못했습니다: {previewState.error}</p>;
  }
  switch (mode) {
    case "source":
      return <SourceView key={preview.path} runId={target.runId} preview={preview} terms={props.terms} />;
    case "document":
      return (
        <DocumentView
          key={preview.path}
          runId={target.runId}
          preview={preview}
          terms={props.terms}
          onOpenOriginal={props.onOpenOriginal}
        />
      );
    case "hex": {
      const hex = (
        <HexView
          key={hexKey}
          runId={target.runId}
          path={target.sourcePath}
          size={preview.size}
          highlight={highlight}
        />
      );
      // Hex as the last resort (no viewer for this type, and no record range to look at): say so.
      return naturalMode(preview) === "hex" && !highlight ? (
        <FallbackView preview={preview} onOpenOriginal={props.onOpenOriginal}>
          {hex}
        </FallbackView>
      ) : (
        hex
      );
    }
    case "sqlite":
      return <SqliteView key={preview.path} runId={target.runId} preview={preview} highlight={highlight} />;
    case "image":
      return (
        <ImageView
          key={preview.path}
          runId={target.runId}
          preview={preview}
          onOpenPath={props.onOpenPath}
          onOpenOriginal={props.onOpenOriginal}
        />
      );
    case "email":
      return <EmailView runId={target.runId} preview={preview} terms={props.terms} onCopy={props.onCopy} />;
    case "media":
      return (
        <MediaView
          key={preview.path}
          runId={target.runId}
          preview={preview}
          onCopy={props.onCopy}
          onOpenOriginal={props.onOpenOriginal}
        />
      );
    case "archive":
      return (
        <ArchiveView
          key={preview.path}
          runId={target.runId}
          preview={preview}
          onOpenPath={props.onOpenPath}
        />
      );
    default:
      return null;
  }
}
