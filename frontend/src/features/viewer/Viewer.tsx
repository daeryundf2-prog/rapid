import { type KeyboardEvent, useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { announce, DisabledReason } from "../../a11y";
import {
  fetchSourceBlob,
  fetchSourceMetadata,
  fetchSourcePreview,
  type SourceMetadata,
  type SourcePreview,
} from "../../api/viewer";
import { collapseViewerPane } from "../../commands/builtin";
import { MiddlePath } from "../../components/MiddlePath";
import type { Command } from "../../contracts/command";
import type { MarkAction, ViewerMode, ViewerTarget } from "../../contracts/viewer";
import { Icon } from "../../icons";
import { currentTimezone } from "../grid/columns/common";
import { storeNotice } from "../grid/reviewActions";
import {
  dispatchCommand,
  getCommand,
  registerCommand,
  setViewerTarget,
  useCommandContext,
  useCommandsVersion,
  useHighlightTerms,
  useRouteFilterKey,
  useViewerFocusRequest,
  useViewerRouteMode,
  useViewerRowContext,
  useViewerTarget,
} from "./adapter";
import { applyMark, buildCitation, MARK_LABELS } from "./citation";
import {
  buildViewerCommands,
  NO_TARGET_REASON,
  ROWS_FOR_SOURCE_COMMAND,
  VIEWER_COMMAND_IDS,
  type ViewerController,
  writeClipboard,
} from "./commands";
import { targetKey } from "./history";
import { ModeTabs, panelId, tabId, VIEWER_PANEL_ID } from "./ModeTabs";
import { resolveModes } from "./modes";
import { recordByteRange } from "./record";
import { viewerSession } from "./session";
import { type AsyncState, errorText, useAsync } from "./useAsync";
import { ViewerToolbar } from "./ViewerToolbar";
import { DocumentView } from "./views/DocumentView";
import { EmailView } from "./views/EmailView";
import { HexView } from "./views/HexView";
import { ImageView } from "./views/ImageView";
import { MediaView } from "./views/MediaView";
import { MetaView } from "./views/MetaView";
import { SourceView } from "./views/SourceView";
import { SqliteView } from "./views/SqliteView";
import "./viewer.css";

/** Files up to this size get their SHA-256 computed automatically after load. */
export const AUTO_HASH_MAX_BYTES = 32 * 1024 * 1024;

function baseName(path: string): string {
  const parts = path.split(/[\\/]|::/);
  return parts[parts.length - 1] || path;
}

/**
 * Viewer heading: the file name, else the row's own title (a cross-case indicator, an NTFS
 * record) — a bare locator ("/rows/0") only when the row has no title at all.
 */
export function targetTitle(
  target: ViewerTarget,
  preview: SourcePreview | null,
  row?: { title?: string; ref?: { locator: string } } | null,
): string {
  if (preview?.name) return preview.name;
  if (target.sourcePath) return baseName(target.sourcePath);
  const rowTitle = row && row.ref?.locator === target.ref.locator ? row.title?.trim() : "";
  return rowTitle || target.ref.locator;
}

export function Viewer({ drawer = false }: { drawer?: boolean } = {}) {
  const target = useViewerTarget();
  const row = useViewerRowContext();
  const focusSeq = useViewerFocusRequest();
  const ctx = useCommandContext();
  const terms = useHighlightTerms();
  useCommandsVersion();

  const runId = target?.runId ?? "";
  const path = target?.sourcePath ?? null;
  // Directory rows have no content to preview: request nothing (older servers 404 on them).
  const fileKey = target && path && !target.isDirectory ? `${runId}|${path}` : null;
  const key = target ? targetKey(target) : null;

  const previewState = useAsync<SourcePreview>(fileKey, (signal) =>
    fetchSourcePreview(runId, path as string, signal),
  );
  const metaState = useAsync<SourceMetadata>(fileKey, (signal) =>
    fetchSourceMetadata(runId, path as string, { signal }),
  );
  const preview = previewState.status === "ok" ? previewState.data : null;

  // ---- hashes (on demand; automatic for small files) ----------------------
  const [hashed, setHashed] = useState<{
    key: string;
    data: SourceMetadata | null;
    busy: boolean;
    error?: string;
  }>({ key: "", data: null, busy: false });
  const hashedForFile = hashed.key === fileKey ? hashed : null;
  const metadata = hashedForFile?.data ?? (metaState.status === "ok" ? metaState.data : null);
  const freeSha =
    preview?.image?.hashes?.sha256 ||
    preview?.media?.source_hashes?.sha256 ||
    metadata?.hashes?.sha256 ||
    null;
  const hashPromise = useRef<{ key: string; promise: Promise<string | null> } | null>(null);

  const ensureSha256 = useCallback(async (): Promise<string | null> => {
    if (!fileKey || !path) return null;
    if (freeSha && !preview?.container_path) return freeSha;
    if (hashedForFile?.data?.hashes?.sha256) return hashedForFile.data.hashes.sha256;
    if (hashPromise.current?.key === fileKey) return hashPromise.current.promise;
    setHashed({ key: fileKey, data: null, busy: true });
    const promise = fetchSourceMetadata(runId, path, { hash: true }).then(
      (data) => {
        setHashed({ key: fileKey, data, busy: false });
        return data.hashes?.sha256 ?? null;
      },
      (error: unknown) => {
        setHashed({ key: fileKey, data: null, busy: false, error: errorText(error) });
        hashPromise.current = null;
        throw error;
      },
    );
    hashPromise.current = { key: fileKey, promise };
    return promise;
  }, [fileKey, path, runId, freeSha, preview?.container_path, hashedForFile]);

  const metaSize = metaState.status === "ok" ? metaState.data.size : null;
  // biome-ignore lint/correctness/useExhaustiveDependencies: auto-hash once per file when metadata arrives
  useEffect(() => {
    if (metaSize !== null && metaSize <= AUTO_HASH_MAX_BYTES) ensureSha256().catch(() => undefined);
  }, [fileKey, metaSize]);

  // Decoded artifact rows carry the record's byte range (F2): hex opens there.
  const highlight = useMemo(
    () => target?.highlight ?? recordByteRange(row) ?? undefined,
    [target?.highlight, row],
  );

  // ---- announcements (S5 singleton live region) ---------------------------
  useEffect(() => {
    if (!target) return;
    if (!path) {
      announce(`원본 파일이 없는 행입니다: ${target.ref.locator}`);
    } else if (target.isDirectory) {
      announce(`디렉터리입니다: ${path}`);
    } else if (previewState.status === "ok") {
      announce(`원본 로드됨: ${previewState.data.name}`);
    } else if (previewState.status === "error") {
      announce(`원본을 불러오지 못했습니다: ${previewState.error}`);
    }
  }, [target, path, previewState]);

  // ---- modes --------------------------------------------------------------
  const { modes, best } = useMemo(
    () =>
      resolveModes({
        target,
        preview,
        previewError: previewState.status === "error" ? previewState.error : null,
        loading: previewState.status === "loading",
      }),
    [target, preview, previewState],
  );
  const { mode: routeMode, setMode: setRouteMode } = useViewerRouteMode();
  // The chosen tab lives in the viewer session so a remount (stage switch) keeps it.
  const [userMode, setUserModeState] = useState(() => viewerSession().userMode);
  const setUserMode = useCallback((value: { key: string; mode: ViewerMode } | null) => {
    viewerSession().userMode = value;
    setUserModeState(value);
  }, []);
  // URL `mode=` restores the tab for the first target; later rows auto-select again.
  // biome-ignore lint/correctness/useExhaustiveDependencies: runs once per target key
  useEffect(() => {
    if (!key) return;
    if (!viewerSession().restoredMode) {
      viewerSession().restoredMode = true;
      if (routeMode) setUserMode({ key, mode: routeMode });
      return;
    }
    if (routeMode !== undefined && userMode?.key !== key) setRouteMode(undefined);
  }, [key]);
  const userChoice =
    userMode && userMode.key === key && modes.find((m) => m.mode === userMode.mode)?.available
      ? userMode.mode
      : null;
  const activeMode: ViewerMode = userChoice ?? best ?? target?.preferredMode ?? "meta";
  const hasActiveTab = modes.some((m) => m.mode === activeMode);
  const selectMode = useCallback(
    (mode: ViewerMode) => {
      if (key) setUserMode({ key, mode });
      setRouteMode(mode);
    },
    [key, setRouteMode, setUserMode],
  );

  // ---- history ------------------------------------------------------------
  // Alt+←/→ history survives a remount of the viewer (review B2-3): it lives in the session.
  const history = useRef(viewerSession().history);
  const historyRows = useRef(viewerSession().rows);
  const [, bumpHistory] = useReducer((value: number) => value + 1, 0);
  useEffect(() => {
    if (!target) return;
    history.current.visit(target);
    historyRows.current.set(targetKey(target), row);
    bumpHistory();
  }, [target, row]);
  const goHistory = useCallback((direction: "back" | "forward") => {
    const next = direction === "back" ? history.current.back() : history.current.forward();
    if (next) setViewerTarget(next, historyRows.current.get(targetKey(next)) ?? null);
    bumpHistory();
  }, []);

  // ---- session marks ------------------------------------------------------
  const [marks, setMarks] = useState<Record<string, string[]>>({});

  // ---- controller + commands ----------------------------------------------
  const controller = useRef<ViewerController | null>(null);
  controller.current = {
    getTarget: () => target,
    openOriginal: async () => {
      if (!target?.sourcePath) return;
      try {
        const blob = await fetchSourceBlob(target.runId, target.sourcePath);
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = baseName(
          preview?.container_path ?? target.sourcePath.split("::")[0] ?? target.sourcePath,
        );
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        setTimeout(() => URL.revokeObjectURL(url), 60_000);
        announce(`원본을 내려받았습니다: ${anchor.download}`);
      } catch (error) {
        announce(`원본 열기 실패: ${errorText(error)}`);
      }
    },
    copyHash: async () => {
      try {
        const sha = await ensureSha256();
        if (!sha) throw new Error("SHA-256을 계산하지 못했습니다.");
        await writeClipboard(sha);
        announce(`SHA-256을 복사했습니다: ${sha.slice(0, 12)}…`);
      } catch (error) {
        announce(`해시 복사 실패: ${errorText(error)}`);
      }
    },
    copyPath: async () => {
      if (!target?.sourcePath) return;
      try {
        await writeClipboard(target.sourcePath);
        announce("경로를 복사했습니다.");
      } catch (error) {
        announce(`경로 복사 실패: ${errorText(error)}`);
      }
    },
    copyCitation: async () => {
      if (!target) return;
      try {
        const sha = target.sourcePath ? await ensureSha256().catch(() => null) : null;
        await writeClipboard(buildCitation({ ...target, highlight }, sha, row, currentTimezone()));
        announce("인용을 복사했습니다.");
      } catch (error) {
        announce(`인용 복사 실패: ${errorText(error)}`);
      }
    },
    mark: async (action: MarkAction) => {
      if (!target) return;
      try {
        const result = await applyMark(target, action);
        const markKey = targetKey(target);
        setMarks((current) => ({
          ...current,
          [markKey]: [
            ...(current[markKey] || []).filter((m) => m !== MARK_LABELS[action]),
            MARK_LABELS[action],
          ],
        }));
        announce(`표시됨: ${MARK_LABELS[action]}${storeNotice(result)}`);
      } catch (error) {
        announce(`표시 실패: ${errorText(error)}`);
      }
    },
    back: () => goHistory("back"),
    forward: () => goHistory("forward"),
    canBack: () => history.current.canBack(),
    canForward: () => history.current.canForward(),
  };

  const commands = useMemo(
    () =>
      buildViewerCommands({
        getTarget: () => controller.current?.getTarget() ?? null,
        openOriginal: () => controller.current?.openOriginal() ?? Promise.resolve(),
        copyHash: () => controller.current?.copyHash() ?? Promise.resolve(),
        copyPath: () => controller.current?.copyPath() ?? Promise.resolve(),
        copyCitation: () => controller.current?.copyCitation() ?? Promise.resolve(),
        mark: (action) => controller.current?.mark(action) ?? Promise.resolve(),
        back: () => controller.current?.back(),
        forward: () => controller.current?.forward(),
        canBack: () => controller.current?.canBack() ?? false,
        canForward: () => controller.current?.canForward() ?? false,
      }),
    [],
  );
  useEffect(() => {
    const unregister = commands.map((command) => registerCommand(command));
    return () => {
      for (const off of unregister) off();
    };
  }, [commands]);

  const byId = (id: string) => commands.find((command) => command.id === id) as Command;
  const sourceCommands = [
    byId(VIEWER_COMMAND_IDS.openOriginal),
    byId(VIEWER_COMMAND_IDS.hash),
    byId(VIEWER_COMMAND_IDS.copyPath),
    byId(VIEWER_COMMAND_IDS.cite),
  ];
  const markCommands = commands.filter((command) => command.id.startsWith("viewer.mark."));
  const runCommand = useCallback(
    (command: Command) => {
      const reason = command.disabledReason?.(ctx);
      if (reason) {
        announce(reason);
        return;
      }
      void command.run(ctx);
    },
    [ctx],
  );

  useRouteFilterKey(); // the reason below reads the route (intake, active source filter)
  const rowsForSource = getCommand(ROWS_FOR_SOURCE_COMMAND);
  const rowsForSourceReason = !target
    ? NO_TARGET_REASON
    : !path
      ? "원본 파일 경로가 없는 행입니다."
      : !rowsForSource
        ? "같은 출처 행 목록을 처리할 화면이 연결되지 않았습니다."
        : rowsForSource.disabledReason?.(ctx);

  // ---- focus on Enter-open ------------------------------------------------
  const regionRef = useRef<HTMLElement>(null);
  const initialFocusSeq = useRef(focusSeq);
  const [pendingFocus, setPendingFocus] = useState(false);
  useEffect(() => {
    if (focusSeq !== initialFocusSeq.current) setPendingFocus(true);
  }, [focusSeq]);
  useEffect(() => {
    if (!pendingFocus || previewState.status === "loading") return;
    const tab = regionRef.current?.querySelector<HTMLElement>(`#${tabId(activeMode)}`);
    if (target && tab) tab.focus();
    else regionRef.current?.focus();
    setPendingFocus(false);
  }, [pendingFocus, previewState.status, activeMode, target]);

  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if (!event.altKey || (event.key !== "ArrowLeft" && event.key !== "ArrowRight")) return;
    event.preventDefault();
    event.stopPropagation();
    runCommand(byId(event.key === "ArrowLeft" ? VIEWER_COMMAND_IDS.back : VIEWER_COMMAND_IDS.forward));
  };

  const openGalleryPath = (nextPath: string) => {
    if (!target) return;
    setViewerTarget(
      {
        runId: target.runId,
        ref: { collection: target.ref.collection, kind: target.ref.kind, locator: `source:${nextPath}` },
        sourcePath: nextPath,
        preferredMode: "image",
      },
      null,
    );
  };

  const copyAndAnnounce = (text: string, sentence: string) => {
    writeClipboard(text).then(
      () => announce(sentence),
      (error: unknown) => announce(`복사 실패: ${errorText(error)}`),
    );
  };

  const busy = previewState.status === "loading";
  const title = target ? targetTitle(target, preview, row) : "원본 뷰어";

  return (
    <section
      ref={regionRef}
      className="viewer"
      aria-label="원본 뷰어"
      aria-busy={busy}
      tabIndex={-1}
      onKeyDown={onKeyDown}
    >
      {/* One header line (visual-polish S5): history · title · review + action menus; then one tab row. */}
      <div className="viewer-header">
        <div className="viewer-nav">
          <DisabledReason reason={history.current.canBack() ? undefined : "이전에 본 대상이 없습니다."}>
            <button
              type="button"
              className="viewer-icon-button"
              aria-label="이전 대상 (Alt+←)"
              title={history.current.canBack() ? "이전 대상 (Alt+←)" : undefined}
              onClick={() => runCommand(byId(VIEWER_COMMAND_IDS.back))}
            >
              <Icon name="arrow-left" />
            </button>
          </DisabledReason>
          <DisabledReason reason={history.current.canForward() ? undefined : "다음 대상이 없습니다."}>
            <button
              type="button"
              className="viewer-icon-button"
              aria-label="다음 대상 (Alt+→)"
              title={history.current.canForward() ? "다음 대상 (Alt+→)" : undefined}
              onClick={() => runCommand(byId(VIEWER_COMMAND_IDS.forward))}
            >
              <Icon name="arrow-right" />
            </button>
          </DisabledReason>
        </div>
        <div className="viewer-heading">
          <h2 className="viewer-title" title={target?.sourcePath ?? undefined}>
            {title}
          </h2>
          {/* Parent folder, middle-ellipsized (review #6); the full path is the tooltip. */}
          {target?.sourcePath ? (
            <p className="viewer-path">
              <MiddlePath path={target.sourcePath} />
            </p>
          ) : null}
        </div>
        <ViewerToolbar
          sourceCommands={sourceCommands}
          markCommands={markCommands}
          ctx={ctx}
          onRun={runCommand}
          rowsForSource={{
            reason: rowsForSourceReason,
            run: () => void dispatchCommand(ROWS_FOR_SOURCE_COMMAND, ctx),
          }}
        />
        {/* Wide layout only: the drawer has its own close button (Esc). */}
        {drawer ? null : (
          <button
            type="button"
            className="viewer-icon-button"
            aria-label="뷰어 접기"
            title="뷰어 접기"
            data-testid="viewer-collapse"
            onClick={collapseViewerPane}
          >
            <Icon name="chevron-right" />
          </button>
        )}
      </div>
      <ModeTabs modes={modes} active={activeMode} onSelect={selectMode} />
      {/* Inactive modes get an empty, hidden panel so every tab's aria-controls resolves to a
          tabpanel labelled by that tab; only the active mode renders content. */}
      {modes
        .filter((m) => m.mode !== activeMode)
        .map((m) => (
          <div
            key={m.mode}
            className="viewer-panel"
            role="tabpanel"
            id={panelId(m.mode)}
            aria-labelledby={tabId(m.mode)}
            hidden
          />
        ))}
      <div
        className="viewer-panel"
        role="tabpanel"
        id={hasActiveTab ? panelId(activeMode) : VIEWER_PANEL_ID}
        // Name the panel by its tab; with no tabs (empty viewer) give it a name of its own.
        aria-labelledby={hasActiveTab ? tabId(activeMode) : undefined}
        aria-label={hasActiveTab ? undefined : "원본 내용"}
        // biome-ignore lint/a11y/noNoninteractiveTabindex: WAI-ARIA tabpanel is focusable so scrolled content without controls is reachable
        tabIndex={0}
      >
        {!target ? (
          <div className="viewer-empty">
            <span className="viewer-empty-icon" aria-hidden="true">
              <Icon name="eye" />
            </span>
            <p>
              그리드에서 행을 선택하면 원본이 여기에 표시됩니다 — <kbd>Enter</kbd> 키로 뷰어로 이동하세요.
            </p>
          </div>
        ) : (
          <ViewerBody
            target={target}
            mode={activeMode}
            resolving={previewState.status === "loading" && best === null && userChoice === null}
            highlight={highlight}
            previewState={previewState}
            metadata={metadata}
            metadataError={metaState.status === "error" ? metaState.error : (hashedForFile?.error ?? null)}
            hashBusy={Boolean(hashedForFile?.busy)}
            row={row}
            sessionMarks={key ? marks[key] || [] : []}
            terms={terms}
            onComputeHash={() => {
              ensureSha256().catch((error: unknown) => announce(`해시 계산 실패: ${errorText(error)}`));
            }}
            onOpenPath={openGalleryPath}
            onCopy={copyAndAnnounce}
          />
        )}
      </div>
    </section>
  );
}

interface ViewerBodyProps {
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
}

function ViewerBody(props: ViewerBodyProps) {
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
      return <DocumentView preview={preview} terms={props.terms} />;
    case "hex":
      return (
        <HexView
          key={hexKey}
          runId={target.runId}
          path={target.sourcePath}
          size={preview.size}
          highlight={highlight}
          staticRows={preview.container_path ? preview.hex?.rows : undefined}
        />
      );
    case "sqlite":
      return <SqliteView key={preview.path} runId={target.runId} preview={preview} highlight={highlight} />;
    case "image":
      return (
        <ImageView key={preview.path} runId={target.runId} preview={preview} onOpenPath={props.onOpenPath} />
      );
    case "email":
      return <EmailView runId={target.runId} preview={preview} terms={props.terms} onCopy={props.onCopy} />;
    case "media":
      return <MediaView key={preview.path} runId={target.runId} preview={preview} onCopy={props.onCopy} />;
    default:
      return null;
  }
}
