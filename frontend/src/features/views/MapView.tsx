/**
 * 지도 대체 보기 (r4 §2.3; AXIOM 세계 지도 → 표 대체): rows that carry a latitude / longitude
 * (EXIF GPS of media rows, location rows) as
 *   1. 근접 묶음 — 0.01° grid cells (≈1.1 km) with row count and first / last time; choosing a
 *      cluster filters the grid to that cell (server `geo=` box) and switches to the column view;
 *   2. 좌표 표 — every located row (위도 · 경도 · 시각 · 경로); Enter / click opens the row.
 * The listing asks the server for located rows only (`geo=` world box), so a node with millions
 * of rows and a handful of GPS rows still lists just those.
 * r6 §3.3 갈래 C: the clusters come from the server's located-row index first (`GET /geo-clusters`,
 * every located row of the node, no rows downloaded); the table pages 500 rows at a time. While an
 * older run's index is being built the view says so (위치 색인 만드는 중) and asks again; without
 * server clusters (live run, failed build, filters only the console applies) it clusters the
 * loaded rows itself.
 * Policy: no map tiles and no external map calls — the coordinates stay in this console.
 */

import { useMemo, useState } from "react";
import { announce } from "../../a11y";
import type { GridRow } from "../../contracts/collection";
import { useTimezone } from "../../state/hooks";
import { formatGridTime } from "../../utils/time";
import { hasActiveFilters } from "../filters/filterModel";
import { useFilterStore } from "../filters/filterStore";
import { useViewerTarget } from "../grid/adapter";
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
export const MAP_POLICY_NOTE =
  "지도 타일과 외부 지도 서비스는 쓰지 않습니다(정책). 좌표는 이 콘솔 밖으로 나가지 않으며, 표와 근접 묶음(0.01° 격자, 약 1.1 km)으로 보여 줍니다.";

/** The server returns only located rows (`geo=` world box; `row_conditions.row_coordinates`). */
export const MAP_ROW_CONDITIONS: Readonly<Record<string, string>> = Object.freeze({ geo: "-90,-180,90,180" });

const allRows = () => true;

export function MapView() {
  const { cq, rows, runId, q } = useViewRows({
    predicate: allRows,
    textFilter: true,
    rowConditions: MAP_ROW_CONDITIONS,
    pageSize: MAP_TABLE_PAGE,
  });
  const server = useGeoClusters({ textFilter: true, rowConditions: MAP_ROW_CONDITIONS });
  const { timezone } = useTimezone();
  const { publishFocusedRow, requestFocus } = useViewerTarget();
  const patchFilters = useFilterStore((s) => s.patchFilters);
  const filtered = useFilterStore((s) => hasActiveFilters(s.filters)) || Boolean(q);
  const located = useMemo(() => geoRows(rows), [rows]);
  // Server clusters cover every located row of the node; the console clusters only its loaded rows.
  const ready = server.payload?.geo_index === "ready" && !server.clientFiltered ? server.payload : null;
  const building = server.payload?.geo_index === "building";
  const clusters = useMemo(() => (ready ? serverClusters(ready) : clusterRows(located)), [ready, located]);
  const [picked, setPicked] = useState<string | null>(null);
  // Page on automatically only while nothing located has arrived (a scan window may be empty);
  // otherwise the table grows 500 rows per "더 불러오기".
  const capped = useAutoLoad(cq, located.length === 0, MAP_EMPTY_SCAN_ROWS);
  // A failed page stops the automatic paging (useAutoLoad): no endless "찾는 중".
  const scanning = !cq.error && (cq.isFetching || (located.length === 0 && cq.canLoadMore && !capped));
  const serverEmpty = ready !== null && ready.matched === 0;

  const time = (value: string | null) => (value ? formatGridTime(value, timezone) : "—");

  const openRow = (row: GridRow) => {
    if (!runId) return;
    publishFocusedRow(row, buildViewerTarget(runId, row));
    requestFocus();
  };

  const filterCluster = (cluster: GeoCluster) => {
    setPicked(cluster.id);
    patchFilters({ geo: cluster.box });
    switchView("columns");
    announce(
      `위치 ${cluster.lat.toFixed(3)}, ${cluster.lon.toFixed(3)} 부근 ${cluster.count.toLocaleString("ko-KR")}건으로 거르고 열 보기로 전환했습니다`,
    );
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
  const clusterCount = ready ? ready.clusters_total : clusters.length;
  return (
    <div className="view-pane map-view">
      <div className="view-toolbar">
        <span className="view-count">
          {`위치 행 ${(total ?? located.length).toLocaleString("ko-KR")}건 · 묶음 ${clusterCount.toLocaleString("ko-KR")}개`}
          {total === null && cq.total !== null && cq.total > cq.loadedCount
            ? ` (전체 ${cq.total.toLocaleString("ko-KR")}건 중)`
            : ""}
          {cq.isFetching ? " · 불러오는 중…" : ""}
        </span>
        {cq.canLoadMore && !cq.isFetching ? (
          <button type="button" className="view-link" onClick={() => cq.loadMore()}>
            {`좌표 표 ${MAP_TABLE_PAGE}건 더 불러오기`}
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
          {building ? (
            <p className="map-policy" role="status">
              위치 색인 만드는 중… 끝나면 이 노드의 모든 위치 행으로 묶음을 다시 그립니다. 지금은 불러온 행
              기준입니다.
            </p>
          ) : !ready ? (
            <p className="map-policy">불러온 행 기준 묶음입니다.</p>
          ) : ready.clusters_truncated || ready.truncated ? (
            <p className="map-policy">
              {`묶음이 많아 처음 ${ready.clusters.length.toLocaleString("ko-KR")}개만 보입니다(위치 행 색인 상한).`}
            </p>
          ) : null}
          <ul
            className="map-cluster-list"
            aria-label="근접 묶음 — 선택하면 그 위치의 행만 열 보기로 거릅니다"
          >
            {clusters.map((cluster) => (
              <li key={cluster.id}>
                <button
                  type="button"
                  className="map-cluster"
                  aria-pressed={picked === cluster.id}
                  aria-label={`${formatCoordinates(cluster.lat, cluster.lon)} 부근 ${cluster.count}건, 처음 ${time(cluster.first)}, 마지막 ${time(cluster.last)} — 이 위치로 거르기`}
                  onClick={() => filterCluster(cluster)}
                >
                  <span className="map-cluster-coord mono">
                    {formatCoordinates(cluster.lat, cluster.lon)}
                  </span>
                  <span className="map-cluster-count">{cluster.count.toLocaleString("ko-KR")}건</span>
                  <span className="map-cluster-time">
                    {time(cluster.first)}
                    {cluster.last && cluster.last !== cluster.first ? ` ~ ${time(cluster.last)}` : ""}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
        <section className="map-table-wrap" aria-labelledby="map-table-title">
          <h3 id="map-table-title" className="map-title">
            {`좌표 표 (불러온 ${located.length.toLocaleString("ko-KR")}건)`}
          </h3>
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
