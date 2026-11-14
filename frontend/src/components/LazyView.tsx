/**
 * Lazy-loaded screens (T-116): a screen behind `lazyView` is its own JS chunk, fetched the first
 * time it renders. While the chunk loads the slot shows "… 불러오는 중" (role=status, polite);
 * a chunk that fails to load (network drop, or a server update renamed the hashed chunk) shows a
 * Korean message with 다시 시도 (a fresh import, not React's cached rejection) and 새로 고침 —
 * never a blank pane. Errors thrown while *rendering* the loaded screen are not load failures:
 * they go on to the region's RegionBoundary unchanged.
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

/** The Suspense fallback of every lazy screen. */
export function LazyFallback({ label }: { label: string }) {
  return (
    <div
      className="pane-empty lazy-view-loading"
      role="status"
      aria-live="polite"
      data-testid="lazy-view-loading"
    >
      {label} 불러오는 중…
    </div>
  );
}

interface LoadBoundaryProps {
  label: string;
  onRetry: () => void;
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
    return (
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
        </div>
      </div>
    );
  }
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
): LazyViewComponent<P> {
  let pending: Promise<{ default: ComponentType<P> }> | null = null;
  const fetchChunk = () => {
    pending ??= load().then(
      (component) => ({ default: component }),
      (error: unknown) => {
        pending = null; // the next attempt imports again
        throw new ChunkLoadError(label, error);
      },
    );
    return pending;
  };
  const make = () => lazy(fetchChunk);
  let Lazy = make();

  function LazyView(props: P) {
    const [attempt, setAttempt] = useState(0);
    const retry = () => {
      Lazy = make();
      setAttempt((n) => n + 1);
    };
    const Loaded = Lazy as unknown as ComponentType<P>;
    return (
      <LoadBoundary key={attempt} label={label} onRetry={retry}>
        <Suspense fallback={<LazyFallback label={label} />}>
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
