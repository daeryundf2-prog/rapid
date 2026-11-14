/**
 * Per-region error boundary (R7 S1): one component that throws while rendering (or in an
 * effect) must not blank the whole console. Each main region — shell, tree, grid, viewer —
 * renders behind one; a failure shows a Korean message with 다시 시도 / 다른 화면으로 /
 * 새로 고침 and leaves every other region working. Moving to another place (route change)
 * clears the error automatically.
 */

import { Component, type ErrorInfo, type ReactNode } from "react";
import { useAppStore } from "../state/store";

export interface RegionBoundaryProps {
  /** Region name in Korean, e.g. "탐색 트리" / "목록" / "뷰어" / "콘솔". */
  region: string;
  /** Regions without a pane of their own (case-level features) show the message as a floating card. */
  floating?: boolean;
  children: ReactNode;
}

interface InnerProps extends RegionBoundaryProps {
  resetKey: string;
  onLeave: () => void;
}

interface InnerState {
  error: Error | null;
  resetKey: string;
}

class Boundary extends Component<InnerProps, InnerState> {
  state: InnerState = { error: null, resetKey: this.props.resetKey };

  static getDerivedStateFromError(error: unknown): Partial<InnerState> {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  static getDerivedStateFromProps(props: InnerProps, state: InnerState): Partial<InnerState> | null {
    // Navigating elsewhere gives the region a fresh try.
    if (props.resetKey !== state.resetKey) return { error: null, resetKey: props.resetKey };
    return null;
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error(`[${this.props.region}] 화면 오류`, error, info.componentStack);
  }

  private retry = () => this.setState({ error: null });

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    const { region, onLeave, floating } = this.props;
    return (
      <div
        className={`pane-empty pane-empty-block region-error${floating ? " region-error-floating" : ""}`}
        role="alert"
        data-testid="region-error"
      >
        <p>
          <strong>{region}을(를) 표시하지 못했습니다.</strong>
        </p>
        <p className="region-error-detail">{error.message || "알 수 없는 오류"}</p>
        <div className="region-error-actions">
          <button type="button" className="button" onClick={this.retry}>
            다시 시도
          </button>
          <button
            type="button"
            className="button"
            onClick={() => {
              this.retry();
              onLeave();
            }}
          >
            다른 화면으로
          </button>
          <button type="button" className="button ghost" onClick={() => window.location.reload()}>
            새로 고침
          </button>
        </div>
      </div>
    );
  }
}

/** "다른 화면으로": the case's 접수 page, or the case list when already there / no case. */
function leave(): void {
  const { route, navigate } = useAppStore.getState();
  if (route.runId && route.collection !== "intake") navigate({ runId: route.runId, collection: "intake" });
  else navigate({ runId: null, collection: null });
}

export function RegionBoundary({ region, floating, children }: RegionBoundaryProps) {
  // Another case / list / kind / row is "somewhere else": the region gets a fresh try.
  const resetKey = useAppStore(
    (s) =>
      `${s.route.runId ?? ""}|${s.route.collection ?? ""}|${s.route.kind ?? ""}|${s.route.status ?? ""}|${
        s.route.row ? JSON.stringify(s.route.row) : ""
      }`,
  );
  return (
    <Boundary region={region} floating={floating} resetKey={resetKey} onLeave={leave}>
      {children}
    </Boundary>
  );
}
