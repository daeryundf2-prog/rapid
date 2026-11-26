/**
 * 탐색 › 검색 결과: every search of the run stays as a chip with its count. A chip shows its search
 * alone; "함께 보기" shows several at once (rows of any of them, or only rows all of them match),
 * and the compare table sets them side by side. The routed `q` is the selection (queryModel), so
 * the address bar, Back and the top-bar box always agree with the chips; the grid below shows it.
 */

import { type ReactNode, useEffect, useId, useMemo, useState } from "react";
import { DisabledReason } from "../../a11y";
import { Icon } from "../../icons";
import { useRoute } from "../../state/hooks";
import { useSearchState } from "../case/searchState";
import { registerCommand } from "../grid/adapter";
import { formatCount } from "../grid/gridUtils";
import { type SearchCountState, useSearchCounts } from "./counts";
import { homeListCommand } from "./homeList";
import {
  combineSearches,
  parseSearchInput,
  type SearchCombine,
  searchPlan,
  searchSpecOf,
} from "./queryModel";
import { COMPARE_MAX, SearchCompare } from "./SearchCompare";
import { SearchStatus } from "./SearchStatus";
import "./search.css";

const NO_SEARCHES: readonly string[] = [];
const NO_INDEX_COUNTS = "색인 검색에서만 건수를 세고 비교할 수 있습니다";

function ChipCount({ state }: { state: SearchCountState | undefined }) {
  const result = state?.result;
  if (!result) return state?.counting ? <Icon name="spinner" size={12} label="세는 중" /> : null;
  if (result.error) return <Icon name="alert" size={12} label={result.error} />;
  if (result.count === null) return <span title="시간 안에 세지 못했습니다">-</span>;
  return (
    <span className="search-chip-count num">
      {formatCount(result.count)}
      {result.exact ? "" : "+"}
      <span className="visually-hidden">건</span>
    </span>
  );
}

export function SearchWorkspace({ runId, children }: { runId: string; children: ReactNode }) {
  const { route, patchRoute } = useRoute();
  const selection = useMemo(() => parseSearchInput(route.q ?? ""), [route.q]);
  const stored = useSearchState((s) => s.recent[runId] ?? NO_SEARCHES);
  const options = useSearchState((s) => s.options);
  const [togetherChosen, setTogetherChosen] = useState(false);
  const [combineChosen, setCombineChosen] = useState<SearchCombine>("any");
  const [compareOpen, setCompareOpen] = useState(false);
  const compareId = useId();

  useEffect(() => {
    useSearchState.getState().rememberSearches(runId, selection.searches);
  }, [runId, selection]);
  // Row menu and palette: "원본 목록에서 보기" for the focused hit.
  useEffect(() => registerCommand(homeListCommand()), []);

  // The chips of this render: the kept ones plus a search the effect above has not kept yet.
  const chips = useMemo(
    () => [...stored, ...selection.searches.filter((search) => !stored.includes(search))],
    [stored, selection],
  );
  const shown = selection.searches;
  const together = shown.length > 1 || togetherChosen;
  const combine = shown.length > 1 ? selection.combine : combineChosen;

  /** Index query of a selection under the search options; null when the options need the scan. */
  const indexQuery = (searches: readonly string[], mode: SearchCombine): string | null => {
    const plan = searchPlan(searchSpecOf({ searches, combine: mode }, options));
    return plan.kind === "index" ? plan.q : null;
  };
  // The shown searches are counted first, so their chips never wait behind a broad older search.
  const countOrder = [
    ...chips.filter((chip) => shown.includes(chip)),
    ...chips.filter((chip) => !shown.includes(chip)),
  ];
  const counted = useSearchCounts(
    runId,
    countOrder.flatMap((chip) => indexQuery([chip], "any") ?? []),
  );
  const countOf = (chip: string) => counted[countOrder.indexOf(chip)];

  const show = (searches: readonly string[], mode: SearchCombine) => {
    // Chip order, so the same selection always writes the same query text.
    const ordered = [
      ...chips.filter((chip) => searches.includes(chip)),
      ...searches.filter((search) => !chips.includes(search)),
    ];
    patchRoute({ q: combineSearches(ordered, mode) || undefined });
  };
  const onChip = (chip: string) => {
    const isShown = shown.includes(chip);
    if (!together) {
      if (!isShown) show([chip], "any");
      return;
    }
    const next = isShown ? shown.filter((search) => search !== chip) : [...shown, chip];
    // The last shown search stays: an empty selection would be an empty page.
    if (next.length > 0) show(next, combine);
  };
  const onRemove = (chip: string) => {
    useSearchState.getState().forgetSearch(runId, chip);
    if (!shown.includes(chip)) return;
    const rest = shown.filter((search) => search !== chip);
    const neighbour = chips.filter((other) => other !== chip).at(-1);
    show(rest.length ? rest : neighbour ? [neighbour] : [], combine);
  };
  const onTogether = () => {
    setTogetherChosen(!together);
    const [first] = shown;
    if (together && shown.length > 1 && first !== undefined) show([first], "any");
  };
  const onCombine = (mode: SearchCombine) => {
    setCombineChosen(mode);
    if (shown.length > 1) show(shown, mode);
  };

  const compared = chips.slice(-COMPARE_MAX);
  const compareReason =
    chips.length < 2
      ? "검색이 두 개 이상 있어야 비교할 수 있습니다"
      : indexQuery(chips, "any") === null
        ? NO_INDEX_COUNTS
        : undefined;

  return (
    <div className="search-pane">
      {chips.length ? (
        <div className="search-bar" data-testid="search-bar">
          <ul className="search-chips" aria-label="이 케이스에서 한 검색">
            {chips.map((chip) => (
              <li key={chip} className="search-chip chip" data-shown={shown.includes(chip) ? "" : undefined}>
                <button
                  type="button"
                  className="chip-open"
                  aria-pressed={shown.includes(chip)}
                  title={chip}
                  onClick={() => onChip(chip)}
                >
                  <Icon name="check" size={12} className="search-chip-check" />
                  <span className="search-chip-text">{chip}</span> <ChipCount state={countOf(chip)} />
                </button>
                <button
                  type="button"
                  className="chip-remove"
                  aria-label={`${chip} 검색 닫기`}
                  title="검색 닫기"
                  onClick={() => onRemove(chip)}
                >
                  <Icon name="close" size={12} />
                </button>
              </li>
            ))}
          </ul>
          <div className="search-bar-controls">
            <button type="button" className="button ghost" aria-pressed={together} onClick={onTogether}>
              함께 보기
            </button>
            {together ? (
              // biome-ignore lint/a11y/useSemanticElements: a two-button toggle group, like the view switch
              <div className="segmented" role="group" aria-label="함께 보는 방식">
                <button type="button" aria-pressed={combine === "any"} onClick={() => onCombine("any")}>
                  하나라도 일치
                </button>
                <button type="button" aria-pressed={combine === "all"} onClick={() => onCombine("all")}>
                  모두 일치
                </button>
              </div>
            ) : null}
            <DisabledReason reason={compareReason}>
              <button
                type="button"
                className="button ghost"
                aria-expanded={compareOpen && !compareReason}
                aria-controls={compareOpen && !compareReason ? compareId : undefined}
                onClick={() => setCompareOpen((open) => !open)}
              >
                검색 비교
              </button>
            </DisabledReason>
          </div>
        </div>
      ) : null}
      <SearchStatus runId={runId} />
      {compareOpen && !compareReason ? (
        <>
          {chips.length > COMPARE_MAX ? (
            <p className="search-compare-note">
              검색이 {COMPARE_MAX}개를 넘어 최근 {COMPARE_MAX}개만 비교합니다.
            </p>
          ) : null}
          <SearchCompare
            id={compareId}
            runId={runId}
            searches={compared}
            totals={compared.map(countOf)}
            indexQuery={(searches, mode) => indexQuery(searches, mode) ?? ""}
            onShow={show}
          />
        </>
      ) : null}
      <div className="search-body">{children}</div>
    </div>
  );
}
