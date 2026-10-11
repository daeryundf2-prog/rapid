import { type FormEvent, useEffect, useId, useRef, useState } from "react";
import { announce, useEscape, useFocusTrap } from "../a11y";
import { COLLECTION_LABEL, RUN_MODE_LABEL, runDisplayName } from "../app/collections";
import { focusGridWhenReady, GLOBAL_SEARCH_ID, NO_RUN_REASON } from "../commands/builtin";
import { CommandButton } from "../commands/CommandButton";
import { SearchOptionsButton } from "../features/case/SearchOptionsPopover";
import { useSearchState } from "../features/case/searchState";
import { useRoute, useRuns } from "../state/hooks";
import { useAppStore } from "../state/store";
import { Slot } from "./slots";

/** Default case picker (S4 may register a richer "case-picker" slot). */
export function CasePickerFallback() {
  const { runs } = useRuns();
  const { route, navigate } = useRoute();
  const id = useId();
  return (
    <div className="case-picker">
      <label htmlFor={id} className="visually-hidden">
        케이스
      </label>
      <select
        id={id}
        value={route.runId ?? ""}
        data-testid="case-picker"
        onChange={(event) => {
          const runId = event.target.value;
          navigate(runId ? { runId, collection: "intake" } : { runId: null, collection: null });
        }}
      >
        <option value="">{runs.length ? "케이스 선택…" : "케이스 없음"}</option>
        {runs.map((run) => (
          <option key={run.run_id} value={run.run_id}>
            {runDisplayName(run)} · {RUN_MODE_LABEL[run.request?.mode ?? ""] ?? run.request?.mode ?? "케이스"}
          </option>
        ))}
      </select>
    </div>
  );
}

function GlobalSearch() {
  const { route, openCollection } = useRoute();
  const showNotice = useAppStore((s) => s.showNotice);
  const routedQuery = route.collection === "search" ? (route.q ?? "") : "";
  const [value, setValue] = useState(routedQuery);
  const hintId = useId();

  useEffect(() => setValue(routedQuery), [routedQuery]);

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    const q = value.trim();
    if (!route.runId) {
      showNotice(`전체 검색: ${NO_RUN_REASON}`);
      announce(`전체 검색: ${NO_RUN_REASON}`);
      return;
    }
    if (!q) {
      announce("검색어를 입력하세요");
      return;
    }
    // S4's search options read the keywords; the grid builds the FTS request (searchPath()).
    useSearchState.getState().setKeywords(q.split(/[\s,]+/).filter(Boolean));
    openCollection("search", { q });
    // The analyst's next key is J: hand focus to the results grid once it renders.
    focusGridWhenReady();
  };

  return (
    <search className="global-search" aria-label="전체 검색">
      <form onSubmit={onSubmit}>
        <input
          id={GLOBAL_SEARCH_ID}
          type="search"
          value={value}
          aria-label="전체 검색어"
          aria-describedby={hintId}
          aria-disabled={route.runId ? undefined : true}
          placeholder={route.runId ? "전체 검색 (Enter)" : NO_RUN_REASON}
          onChange={(event) => setValue(event.target.value)}
        />
        <span id={hintId} className="visually-hidden">
          {route.runId ? `${COLLECTION_LABEL.search}로 이동합니다` : NO_RUN_REASON}
        </span>
      </form>
    </search>
  );
}

/** Shown only until S4 registers the "run-dialog" slot. */
function RunDialogPlaceholder({ onClose }: { onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useFocusTrap(ref, { active: true });
  useEscape(onClose);
  return (
    <div className="overlay-scrim">
      <div ref={ref} className="help-dialog" role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <div className="dialog-head">
          <h2 id={titleId}>실행/불러오기</h2>
        </div>
        <p>실행 다이얼로그를 불러오지 못했습니다. 새로고침 후 다시 시도하세요.</p>
        <button type="button" className="button" onClick={onClose}>
          닫기
        </button>
      </div>
    </div>
  );
}

/**
 * The search-options dropdown (S4) is transient: it closes when the route
 * changes and on a pointer press outside it, so it never lingers over the panes.
 */
function useSearchOptionsDismissal(): void {
  const open = useSearchState((s) => s.popoverOpen);
  const routeKey = useAppStore((s) => `${s.route.runId}|${s.route.collection}|${s.route.kind ?? ""}`);
  // biome-ignore lint/correctness/useExhaustiveDependencies: close on every route change
  useEffect(() => {
    useSearchState.getState().setPopoverOpen(false);
  }, [routeKey]);
  useEffect(() => {
    if (!open) return;
    const onDown = (event: PointerEvent) => {
      if (event.target instanceof Element && event.target.closest(".search-options-anchor")) return;
      useSearchState.getState().setPopoverOpen(false);
    };
    document.addEventListener("pointerdown", onDown, true);
    return () => document.removeEventListener("pointerdown", onDown, true);
  }, [open]);
}

/** Top bar (plan §4.1 / §4.3): case · run/import · global search · review board · report · theme · help. */
export function TopBar() {
  const runDialogOpen = useAppStore((s) => s.runDialogOpen);
  const runId = useAppStore((s) => s.route.runId);
  useSearchOptionsDismissal();
  const setOverlay = useAppStore((s) => s.setOverlay);
  return (
    <header className="topbar" data-testid="topbar">
      <span className="brand">RapidForensic</span>
      <Slot name="case-picker" fallback={<CasePickerFallback />} />
      <CommandButton command="case.run-dialog" testId="run-dialog-button" />
      <div className="topbar-search">
        <GlobalSearch />
        <SearchOptionsButton runId={runId} />
        <CommandButton command="app.palette" label="명령 팔레트" testId="palette-button" />
      </div>
      <div className="topbar-actions">
        <CommandButton command="navigate.review" label="리뷰보드" testId="review-board-button" />
        <CommandButton command="export.report" label="보고서" testId="report-button" />
        <CommandButton command="app.theme.toggle" iconOnly variant="ghost" testId="theme-toggle" />
        <CommandButton command="app.density.cycle" iconOnly variant="ghost" testId="density-toggle" />
        <CommandButton command="app.help" iconOnly variant="ghost" testId="help-button" />
      </div>
      <Slot
        name="run-dialog"
        open={runDialogOpen}
        onClose={() => setOverlay("runDialog", false)}
        fallback={
          runDialogOpen ? <RunDialogPlaceholder onClose={() => setOverlay("runDialog", false)} /> : null
        }
      />
    </header>
  );
}
