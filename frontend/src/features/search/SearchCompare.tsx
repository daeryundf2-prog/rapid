/**
 * Compare table of a run's searches: rows each search has, rows only it has, rows it shares with
 * every other search, and where its rows are (forensic domain). Every number opens those rows in
 * the grid below.
 */

import { Icon } from "../../icons";
import { formatCount } from "../grid/gridUtils";
import { type SearchCountState, useSearchCounts } from "./counts";
import { domainLabel } from "./domainLabel";
import { onlyQuery, type SearchCombine } from "./queryModel";

/** Searches compared at once: the pair counts grow with the square. */
export const COMPARE_MAX = 8;
/** Domain columns shown, largest first. */
const DOMAIN_COLUMNS = 6;

interface SearchCompareProps {
  id: string;
  runId: string;
  searches: readonly string[];
  /** Count of each search, in the same order (shared with the chips). */
  totals: readonly (SearchCountState | undefined)[];
  /** Index query of a selection under the current search options. */
  indexQuery: (searches: readonly string[], combine: SearchCombine) => string;
  /** Show a selection in the grid. */
  onShow: (searches: readonly string[], combine: SearchCombine) => void;
}

function CountCell({
  state,
  label,
  onOpen,
}: {
  state: SearchCountState | undefined;
  /** What the number counts ("급여대장 그리고 비자금"). */
  label: string;
  onOpen: () => void;
}) {
  const result = state?.result;
  if (!result) {
    return <td>{state?.counting ? <Icon name="spinner" size={12} label={`${label} 세는 중`} /> : "-"}</td>;
  }
  if (result.count === null) return <td title={result.error ?? "시간 안에 세지 못했습니다"}>-</td>;
  if (result.count === 0) return <td className="search-compare-zero">0</td>;
  return (
    <td>
      <button
        type="button"
        className="search-compare-open num"
        aria-label={`${label} ${formatCount(result.count)}건 보기`}
        onClick={onOpen}
      >
        {formatCount(result.count)}
        {result.exact ? "" : "+"}
      </button>
    </td>
  );
}

/** Domains the searches hit, largest total first. */
function topDomains(totals: readonly (SearchCountState | undefined)[]): string[] {
  const sums = new Map<string, number>();
  for (const total of totals) {
    for (const [domain, count] of total?.result?.byDomain ?? []) {
      sums.set(domain, (sums.get(domain) ?? 0) + count);
    }
  }
  return [...sums]
    .sort((a, b) => b[1] - a[1])
    .slice(0, DOMAIN_COLUMNS)
    .map(([domain]) => domain);
}

export function SearchCompare({ id, runId, searches, totals, indexQuery, onShow }: SearchCompareProps) {
  const pairs = searches.flatMap((a, i) => searches.slice(i + 1).map((b) => [a, b] as const));
  const onlyTexts = searches.map((search) =>
    onlyQuery(
      search,
      searches.filter((other) => other !== search),
    ),
  );
  const counted = useSearchCounts(runId, [
    ...onlyTexts.map((text) => indexQuery([text], "any")),
    ...pairs.map((pair) => indexQuery(pair, "all")),
  ]);
  const pairCount = (a: string, b: string) =>
    counted[searches.length + pairs.findIndex((pair) => pair.includes(a) && pair.includes(b))];
  const domains = topDomains(totals);
  return (
    <section id={id} className="search-compare" aria-label="검색 비교" data-testid="search-compare">
      <table>
        <caption className="visually-hidden">
          검색별 전체 건수, 그 검색에만 있는 건수, 다른 검색과 함께 일치하는 건수, 영역별 건수
        </caption>
        <thead>
          <tr>
            <th scope="col" rowSpan={2}>
              검색
            </th>
            <th scope="col" rowSpan={2}>
              전체
            </th>
            <th scope="col" rowSpan={2}>
              이 검색만
            </th>
            <th scope="colgroup" colSpan={searches.length}>
              함께 일치
            </th>
            {domains.length ? (
              <th scope="colgroup" colSpan={domains.length}>
                영역별
              </th>
            ) : null}
          </tr>
          <tr>
            {searches.map((search) => (
              <th key={search} scope="col" className="search-compare-name" title={search}>
                {search}
              </th>
            ))}
            {domains.map((domain) => (
              <th key={domain} scope="col">
                {domainLabel(domain)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {searches.map((search, row) => (
            <tr key={search}>
              <th scope="row" className="search-compare-name" title={search}>
                {search}
              </th>
              <CountCell state={totals[row]} label={search} onOpen={() => onShow([search], "any")} />
              <CountCell
                state={counted[row]}
                label={`${search}에만 있는 행`}
                onOpen={() => onShow([onlyTexts[row] ?? search], "any")}
              />
              {searches.map((other) =>
                other === search ? (
                  <td key={other} className="search-compare-zero" aria-hidden="true">
                    ·
                  </td>
                ) : (
                  <CountCell
                    key={other}
                    state={pairCount(search, other)}
                    label={`${search} 그리고 ${other}`}
                    onOpen={() => onShow([search, other], "all")}
                  />
                ),
              )}
              {domains.map((domain) => {
                const count = totals[row]?.result?.byDomain.find(([id]) => id === domain)?.[1] ?? 0;
                return count === 0 ? (
                  <td key={domain} className="search-compare-zero">
                    0
                  </td>
                ) : (
                  <td key={domain}>
                    <button
                      type="button"
                      className="search-compare-open num"
                      aria-label={`${search}, ${domainLabel(domain)} ${formatCount(count)}건 보기`}
                      onClick={() => onShow([`(${search}) AND in:${domain}`], "any")}
                    >
                      {formatCount(count)}
                    </button>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
