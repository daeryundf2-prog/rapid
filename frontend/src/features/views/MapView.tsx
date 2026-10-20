/**
 * 지도 대체 보기 (r4 §2.3; AXIOM 세계 지도 → 표 대체): rows that carry a latitude / longitude
 * (EXIF GPS of media rows, location rows) as
 *   1. 근접 묶음 — 0.01° grid cells (≈1.1 km) with row count and first / last time; choosing a
 *      cluster filters the grid to that cell (server `geo=` box) and switches to the column view;
 *   2. 좌표 표 — every located row (위도 · 경도 · 시각 · 경로); Enter / click opens the row.
 * The listing asks the server for located rows only (`geo=` world box), so a node with millions
 * of rows and a handful of GPS rows still lists just those.
 * r6 §3.3 갈래 C: the clusters come from the server's located-row index first (`GET /geo-clusters`,
 * every located row of the node, no rows downloaded); the table pages 500 rows at a time (one
 * page per "더 불러오기", no prefetch). While an older run's index is being built the view says so
 * (위치 색인 만드는 중) and asks again for up to 5 minutes; without server clusters (live run,
 * failed build, filters or a search text the server applies only in part) it clusters the loaded
 * rows itself, so the cluster counts always agree with the table.
 * Policy: no map tiles and no external map calls — the coordinates stay in this console.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { announce } from "../../a11y";
import type { GridRow } from "../../contracts/collection";
import { useTimezone } from "../../state/hooks";
import { formatGridTime } from "../../utils/time";
import { hasActiveFilters } from "../filters/filterModel";
import { useFilterStore } from "../filters/filterStore";
import { useRoute, useViewerTarget } from "../grid/adapter";
import { buildViewerTarget } from "../grid/gridCommands";
import { errorText } from "../viewer/useAsync";
import { switchView } from "./commands";
import { clusterRows, formatCoordinates, type GeoCluster, geoRows, serverClusters } from "./geo";
import { useAutoLoad, useGeoClusters, useViewRows } from "./useViewRows";
import { EmptyState, ErrorState, LoadingCard } from "./ViewState";
import "./cardMap.css";

/** Coordinate-table page: rows fetched per request (then "더 불러오기"). */
export const MAP_TABLE_PAGE = 500;
/** Rows paged automatically only while no located row has arrived yet (a scan window can be empty). */
export const MAP_EMPTY_SCAN_ROWS = 20_000;
/** Cluster buttons drawn at first and per "묶음 더 보기" (the server sends up to 10,000). */
export const MAP_CLUSTER_PAGE = 300;
export const MAP_POLICY_NOTE =
  "지도 타일과 외부 지도 서비스는 쓰지 않습니다(정책). 좌표는 이 콘솔 밖으로 나가지 않으며, 표와 근접 묶음(0.01° 격자, 약 1.1 km)으로 보여 줍니다.";

/** The server returns only located rows (`geo=` world box; `row_conditions.row_coordinates`). */
export const MAP_ROW_CONDITIONS: Readonly<Record<string, string>> = Object.freeze({ geo: "-90,-180,90,180" });

/** Why the coordinate table's `geo=` listing did not come from the located-row index (`cross_kind.geo_index`). */
const LISTING_GEO_NOTES: Readonly<Record<string, string>> = {
  building:
    "좌표 표: 위치 색인을 만드는 중이라 서버가 행을 직접 훑었습니다. 느리거나 일부만 보일 수 있습니다.",
  truncated:
    "좌표 표: 위치 색인이 상한에 닿아 서버가 행을 직접 훑었습니다. 느리거나 일부만 보일 수 있습니다.",
  unavailable:
    "좌표 표: 위치 색인을 쓸 수 없어 서버가 행을 직접 훑었습니다. 느리거나 일부만 보일 수 있습니다.",
};

const allRows = () => true;
const ko = (value: number) => value.toLocaleString("ko-KR");

export function MapView() {
  const { cq, rows, runId, q } = useViewRows({
    predicate: allRows,
    textFilter: true,
    rowConditions: MAP_ROW_CONDITIONS,
    pageSize: MAP_TABLE_PAGE,
    prefetchNext: false,
  });
  const route = useRoute();
  const server = useGeoClusters({ textFilter: true, rowConditions: MAP_ROW_CONDITIONS });
  const { timezone } = useTimezone();
  const { publishFocusedRow, requestFocus } = useViewerTarget();
  const patchFilters = useFilterStore((s) => s.patchFilters);
  const filtered = useFilterStore((s) => hasActiveFilters(s.filters)) || Boolean(q);
  const located = useMemo(() => geoRows(rows), [rows]);
  // Server clusters cover every located row of the node; the console clusters only its loaded rows.
  const serverReady = server.payload?.geo_index === "ready" && !server.clientFiltered ? server.payload : null;
  // The server found no located row while the listing shows some (an index older than the
  // rows): trust the rows and cluster them instead of saying the node has none.
  const ready = serverReady && !(serverReady.matched === 0 && located.length > 0) ? serverReady : null;
  const building = server.payload?.geo_index === "building" && !server.buildingTimedOut;
  const clustersLoading = server.isLoading && !server.clientFiltered;
  const clusters = useMemo(() => (ready ? serverClusters(ready) : clusterRows(located)), [ready, located]);
  // `picked` / the cluster limit belong to one run · node: another node starts afresh.
  const scope = `${runId ?? ""}|${JSON.stringify(route.collection)}`;
  const [pickedState, setPickedState] = useState<{ scope: string; id: string } | null>(null);
  const picked = pickedState?.scope === scope ? pickedState.id : null;
  const clusterScope = `${scope}|${ready ? "server" : "rows"}`;
  const [limitState, setLimitState] = useState<{ scope: string; limit: number } | null>(null);
  const clusterLimit = limitState?.scope === clusterScope ? limitState.limit : MAP_CLUSTER_PAGE;
  const shownClusters = clusters.length > clusterLimit ? clusters.slice(0, clusterLimit) : clusters;
  // Page on automatically only while nothing located has arrived (a scan window may be empty);
  // otherwise the table grows 500 rows per "더 불러오기".
  const capped = useAutoLoad(cq, located.length === 0, MAP_EMPTY_SCAN_ROWS);
  // A failed page stops the automatic paging (useAutoLoad): no endless "찾는 중".
  const scanning = !cq.error && (cq.isFetching || (located.length === 0 && cq.canLoadMore && !capped));
  const serverEmpty = ready !== null && ready.matched === 0;

  // "더 불러오기" stays rendered (aria-disabled + aria-busy) while its page loads so keyboard
  // focus stays on it; when the last page arrived and the button goes, focus moves to the table title.
  const showMore = Boolean(cq.error) || cq.canLoadMore || (cq.isFetching && cq.loadedCount > 0);
  const moreBusy = cq.isFetching && !cq.error;
  const moreRef = useRef<HTMLButtonElement | null>(null);
  const tableTitleRef = useRef<HTMLHeadingElement | null>(null);
  const moreHadFocus = useRef(false);
  useEffect(() => {
    if (showMore || !moreHadFocus.current) return;
    moreHadFocus.current = false;
    const active = document.activeElement;
    if (!active || active === document.body) tableTitleRef.current?.focus();
  }, [showMore]);
  // "묶음 더 보기" moves focus to the first newly drawn cluster.
  const clusterListRef = useRef<HTMLUListElement | null>(null);
  const focusCluster = useRef<number | null>(null);
  // biome-ignore lint/correctness/useExhaustiveDependencies: runs once the larger limit drew the new buttons
  useEffect(() => {
    const index = focusCluster.current;
    if (index === null) return;
    focusCluster.current = null;
    clusterListRef.current?.querySelectorAll<HTMLButtonElement>("button.map-cluster")[index]?.focus();
  }, [clusterLimit]);

  const time = (value: string | null) => (value ? formatGridTime(value, timezone) : "—");

  const openRow = (row: GridRow) => {
    if (!runId) return;
    publishFocusedRow(row, buildViewerTarget(runId, row));
    requestFocus();
  };

  const filterCluster = (cluster: GeoCluster) => {
    setPickedState({ scope, id: cluster.id });
    patchFilters({ geo: cluster.box });
    switchView("columns");
    announce(
      `위치 ${cluster.lat.toFixed(3)}, ${cluster.lon.toFixed(3)} 부근 ${ko(cluster.count)}건으로 거르고 열 보기로 전환했습니다`,
    );
  };

  const onMore = () => {
    if (cq.error) {
      cq.refetch();
      return;
    }
    if (moreBusy) return;
    moreHadFocus.current = document.activeElement === moreRef.current;
    cq.loadMore();
  };

  if (cq.error && cq.loadedCount === 0 && !ready) {
    return <ErrorState message={`행을 불러오지 못했습니다. ${errorText(cq.error)}`} onRetry={cq.refetch} />;
  }
  if (cq.isLoading && !ready) {
    return <LoadingCard label={building ? "위치 색인 만드는 중…" : "위치 행을 찾는 중…"} />;
  }
  if (serverEmpty || (located.length === 0 && !ready)) {
    if (!serverEmpty && scanning) {
      return <LoadingCard label={building ? "위치 색인 만드는 중…" : "위치 행을 찾는 중…"} />;
    }
    if (!serverEmpty && cq.error) {
      return (
        <ErrorState
          message={`위치 행을 더 불러오지 못했습니다. ${errorText(cq.error)}`}
          onRetry={cq.refetch}
        />
      );
    }
    return (
      <EmptyState
        title={
          filtered
            ? "현재 조건에 맞는 행 중 위도·경도가 있는 행이 없습니다."
            : "이 노드에는 위도·경도가 있는 행이 없습니다."
        }
        hint={
          filtered
            ? `필터·검색 조건을 줄이면 위치 행이 나타날 수 있습니다. ${MAP_POLICY_NOTE}`
            : `서버가 이 노드의 모든 행에서 좌표 열(EXIF GPS·위치)을 찾았지만 없었습니다. ${MAP_POLICY_NOTE}`
        }
      >
        {!serverEmpty && capped ? (
          <button type="button" className="view-link" onClick={() => cq.loadMore()}>
            더 불러오기
          </button>
        ) : null}
      </EmptyState>
    );
  }

  const total = ready?.matched ?? null;
  // `truncated`: the index stopped at its row cap or the filter read cap — the count is a floor.
  const atLeast = ready?.truncated === true;
  const clusterCount = ready ? ready.clusters_total : clusters.length;
  const listingGeo = cq.pageMeta?.geoIndex;
  const listingNote = typeof listingGeo === "string" ? LISTING_GEO_NOTES[listingGeo] : undefined;
  return (
    <div className="view-pane map-view">
      <div className="view-toolbar">
        <span className="view-count">
          {`위치 행 ${ko(total ?? located.length)}건${atLeast ? " 이상" : ""} · 묶음 ${ko(clusterCount)}개`}
          {total === null && cq.total !== null && cq.total > cq.loadedCount
            ? ` (전체 ${ko(cq.total)}건 중)`
            : ""}
          {cq.isFetching ? " · 불러오는 중…" : ""}
        </span>
        {showMore ? (
          <button
            ref={moreRef}
            type="button"
            className="view-link"
            aria-disabled={moreBusy || undefined}
            aria-busy={moreBusy || undefined}
            onClick={onMore}
          >
            {cq.error
              ? "좌표 표 다시 불러오기"
              : moreBusy
                ? "좌표 표 불러오는 중…"
                : `좌표 표 ${MAP_TABLE_PAGE}건 더 불러오기`}
          </button>
        ) : null}
      </div>
      <p className="map-policy" role="note">
        {MAP_POLICY_NOTE}
      </p>
      <div className="map-body">
        <section className="map-clusters" aria-labelledby="map-clusters-title">
          <h3 id="map-clusters-title" className="map-title">
            근접 묶음 (0.01° 격자)
          </h3>
          {clustersLoading ? (
            <p className="map-policy" role="status">
              묶음 불러오는 중…
            </p>
          ) : building ? (
            <p className="map-policy" role="status">
              위치 색인 만드는 중… 끝나면 이 노드의 모든 위치 행으로 묶음을 다시 그립니다. 지금은 불러온 행
              기준입니다.
            </p>
          ) : server.buildingTimedOut ? (
            <p className="map-policy" role="status">
              위치 색인이 5분 안에 끝나지 않아 불러온 행 기준으로 묶었습니다. 실행이 끝나거나 이 보기를 다시
              열면 서버 묶음을 다시 확인합니다.
            </p>
          ) : server.clientFiltered ? (
            <p className="map-policy">
              불러온 행 기준 묶음입니다. 검색어·필터 일부를 서버 묶음에 반영할 수 없어 표와 같은 행만
              묶었습니다.
            </p>
          ) : !ready ? (
            <p className="map-policy">불러온 행 기준 묶음입니다.</p>
          ) : null}
          {ready?.clusters_truncated ? (
            <p className="map-policy">
              {`묶음이 많아 처음 ${ko(ready.clusters.length)}개만 받았습니다(전체 ${ko(ready.clusters_total)}개).`}
            </p>
          ) : null}
          {ready?.truncated ? (
            <p className="map-policy">
              위치 행 색인 상한 또는 필터 읽기 상한에 닿아 일부 행만 묶었습니다. 실제 위치 행은 표시된 건수
              이상입니다.
            </p>
          ) : null}
          {clustersLoading ? null : (
            <ul
              ref={clusterListRef}
              className="map-cluster-list"
              aria-label="근접 묶음 — 선택하면 그 위치의 행만 열 보기로 거릅니다"
            >
              {shownClusters.map((cluster) => (
                <li key={cluster.id}>
                  <button
                    type="button"
                    className="map-cluster"
                    aria-pressed={picked === cluster.id}
                    aria-label={`${formatCoordinates(cluster.lat, cluster.lon)} 부근 ${ko(cluster.count)}건, 처음 ${time(cluster.first)}, 마지막 ${time(cluster.last)} — 이 위치로 거르기`}
                    onClick={() => filterCluster(cluster)}
                  >
                    <span className="map-cluster-coord mono">
                      {formatCoordinates(cluster.lat, cluster.lon)}
                    </span>
                    <span className="map-cluster-count">{ko(cluster.count)}건</span>
                    <span className="map-cluster-time">
                      {time(cluster.first)}
                      {cluster.last && cluster.last !== cluster.first ? ` ~ ${time(cluster.last)}` : ""}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {!clustersLoading && clusters.length > shownClusters.length ? (
            <button
              type="button"
              className="view-link"
              onClick={() => {
                focusCluster.current = shownClusters.length;
                setLimitState({ scope: clusterScope, limit: clusterLimit + MAP_CLUSTER_PAGE });
              }}
            >
              {`묶음 ${ko(Math.min(MAP_CLUSTER_PAGE, clusters.length - shownClusters.length))}개 더 보기 (${ko(shownClusters.length)} / ${ko(clusters.length)})`}
            </button>
          ) : null}
        </section>
        <section className="map-table-wrap" aria-labelledby="map-table-title">
          <h3 id="map-table-title" className="map-title" ref={tableTitleRef} tabIndex={-1}>
            {`좌표 표 (불러온 ${ko(located.length)}건)`}
          </h3>
          {cq.error ? (
            <div className="map-policy" role="alert">
              {`좌표 표를 ${cq.loadedCount > 0 ? "더 " : ""}불러오지 못했습니다. ${errorText(cq.error)} `}
              <button type="button" className="view-link" onClick={cq.refetch}>
                재시도
              </button>
            </div>
          ) : null}
          {listingNote ? (
            <p className="map-policy" role="note">
              {listingNote}
            </p>
          ) : null}
          <table className="map-table">
            <caption className="sr-only">
              위치가 있는 행: 위도, 경도, 시각, 경로. 행을 고르면 뷰어로 엽니다.
            </caption>
            <thead>
              <tr>
                <th scope="col">위도</th>
                <th scope="col">경도</th>
                <th scope="col" title="GPS 시각이 있으면 GPS 시각, 없으면 행의 시각">
                  시각(GPS 우선)
                </th>
                <th scope="col">경로</th>
                <th scope="col">
                  <span className="sr-only">열기</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {located.map((item) => (
                <tr key={item.row.rowKey}>
                  <td className="mono num">{item.lat.toFixed(6)}</td>
                  <td className="mono num">{item.lon.toFixed(6)}</td>
                  <td>{time(item.time)}</td>
                  <td className="mono map-path" title={item.row.sourcePath ?? item.row.title}>
                    {item.row.sourcePath ?? item.row.title}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="view-link"
                      aria-label={`${item.row.title} 원본 열기`}
                      onClick={() => openRow(item.row)}
                    >
                      열기
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </div>
  );
}
