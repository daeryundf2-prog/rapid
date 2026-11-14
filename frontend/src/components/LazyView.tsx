/**
 * Lazy-loaded screens (T-116): a screen behind `lazyView` is its own JS chunk, fetched the first
 * time it renders. While the chunk loads the slot shows "… 불러오는 중" (role=status, polite);
 * a chunk that fails to load (network drop, or a server update renamed the hashed chunk) shows a
 * Korean message with 다시 시도 (a fresh import, not React's cached rejection) and 새로 고침 —
 * never a blank pane. Errors thrown while *rendering* the loaded screen are not load failures:
 * they go on to the region's RegionBoundary unchanged.
 *
 * A dialog (R8 WB-12 review P2-13) passes `Frame` (its modal) and `closeOf`: the loading status and
 * the failure message then render inside that frame, which has 닫기 (and Esc), never inline where the
 * dialog host sits. A failed chunk is imported again on the next mount (P2-15), not replayed.
 */

import {
  Component,
  type ComponentType,
  type ErrorInfo,
  lazy,
  type ReactNode,
  Suspense,
  useState,
} from "react";

/** A chunk (dynamic import) that did not load; the only error `LoadBoundary` handles itself. */
export class ChunkLoadError extends Error {
  constructor(
    readonly label: string,
    cause: unknown,
  ) {
    super(`${label} 화면 파일을 불러오지 못했습니다.`, { cause });
    this.name = "ChunkLoadError";
  }
}

/**
 * The Suspense fallback of every lazy screen. Not a live region: the app mounts exactly one polite
 * region (`LiveRegion`), and a second `role=status` while a chunk loads broke that rule (a11y
 * rule 9 — e2e review-tools Q-X10 / a11y saw "live-polite 2" whenever the viewer's 이미지 chunk
 * was still loading). The visible text says what is loading; `aria-busy` marks the pane.
 */
export function LazyFallback({ label }: { label: string }) {
  return (
    <div className="pane-empty lazy-view-loading" aria-busy="true" data-testid="lazy-view-loading">
      {label} 불러오는 중…
    </div>
  );
}

/** What wraps the loading status and the failure message of a framed lazy component (a dialog). */
export interface LazyFrameProps {
  label: string;
  onClose?: () => void;
  children: ReactNode;
}

interface LoadBoundaryProps {
  label: string;
  onRetry: () => void;
  Frame?: ComponentType<LazyFrameProps>;
  onClose?: () => void;
  children: ReactNode;
}

class LoadBoundary extends Component<LoadBoundaryProps, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: unknown): { error: Error } {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    if (error instanceof ChunkLoadError)
      console.error(`[${this.props.label}] 화면 파일 오류`, error.cause, info.componentStack);
  }

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    // A render error of the loaded screen belongs to the region boundary above.
    if (!(error instanceof ChunkLoadError)) throw error;
    const { Frame, onClose, label } = this.props;
    const message = (
      <div className="pane-empty pane-empty-block region-error" role="alert" data-testid="lazy-view-error">
        <p>
          <strong>{this.props.label} 화면을 불러오지 못했습니다.</strong>
        </p>
        <p className="region-error-detail">
          네트워크 연결을 확인한 뒤 다시 시도하세요. 서버가 새 버전으로 바뀌었다면 새로 고침하세요.
        </p>
        <div className="region-error-actions">
          <button type="button" className="button" onClick={this.props.onRetry}>
            다시 시도
          </button>
          <button type="button" className="button ghost" onClick={() => window.location.reload()}>
            새로 고침
          </button>
          {onClose && !Frame ? (
            <button type="button" className="button ghost" onClick={onClose}>
              닫기
            </button>
          ) : null}
        </div>
      </div>
    );
    return Frame ? (
      <Frame label={label} onClose={onClose}>
        {message}
      </Frame>
    ) : (
      message
    );
  }
}

export interface LazyViewOptions<P> {
  /** Wraps the loading status and the failure message (a dialog's modal frame). */
  Frame?: ComponentType<LazyFrameProps>;
  /** The component's own close action, offered by the frame / failure message (닫기). */
  closeOf?: (props: P) => (() => void) | undefined;
}

export type LazyViewComponent<P extends object> = ((props: P) => ReactNode) & {
  /** Start fetching the chunk ahead of the first render (e.g. on hover); errors are ignored. */
  preload: () => void;
};

/**
 * Wrap a dynamic import as a screen component. `label` names the screen in Korean (shown in the
 * loading and failure messages); `load` resolves to the component, e.g.
 * `() => import("../features/views/MapView").then((m) => m.MapView)`.
 */
export function lazyView<P extends object>(
  label: string,
  load: () => Promise<ComponentType<P>>,
  options: LazyViewOptions<P> = {},
): LazyViewComponent<P> {
  const { Frame, closeOf } = options;
  let pending: Promise<{ default: ComponentType<P> }> | null = null;
  let failed = false;
  const fetchChunk = () => {
    pending ??= load().then(
      (component) => ({ default: component }),
      (error: unknown) => {
        pending = null; // the next attempt imports again
        failed = true;
        throw new ChunkLoadError(label, error);
      },
    );
    return pending;
  };
  const make = () => lazy(fetchChunk);
  let Lazy = make();

  function LazyView(props: P) {
    // A remount after a failed load imports again instead of replaying React's cached rejection.
    const [attempt, setAttempt] = useState(() => {
      if (failed) {
        failed = false;
        Lazy = make();
      }
      return 0;
    });
    const retry = () => {
      failed = false;
      Lazy = make();
      setAttempt((n) => n + 1);
    };
    const Loaded = Lazy as unknown as ComponentType<P>;
    const onClose = closeOf?.(props);
    const fallback = Frame ? (
      <Frame label={label} onClose={onClose}>
        <LazyFallback label={label} />
      </Frame>
    ) : (
      <LazyFallback label={label} />
    );
    return (
      <LoadBoundary key={attempt} label={label} onRetry={retry} Frame={Frame} onClose={onClose}>
        <Suspense fallback={fallback}>
          <Loaded {...props} />
        </Suspense>
      </LoadBoundary>
    );
  }
  LazyView.displayName = `LazyView(${label})`;
  LazyView.preload = () => {
    fetchChunk().catch(() => undefined);
  };
  return LazyView;
}
