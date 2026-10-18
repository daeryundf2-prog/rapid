/**
 * 지도 대체 보기 (r4 §2.3; AXIOM 세계 지도 → 표 대체): rows that carry a latitude / longitude
 * (EXIF GPS of media rows, location rows) as
 *   1. 근접 묶음 — 0.01° grid cells (≈1.1 km) with row count and first / last time; choosing a
 *      cluster filters the grid to that cell (server `geo=` box) and switches to the column view;
 *   2. 좌표 표 — every located row (위도 · 경도 · 시각 · 경로); Enter / click opens the row.
 * The listing asks the server for located rows only (`geo=` world box), so a node with millions
 * of rows and a handful of GPS rows still lists just those.
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
import { clusterRows, formatCoordinates, type GeoCluster, geoRows } from "./geo";
import { useAutoLoad, useViewRows } from "./useViewRows";
import { EmptyState, ErrorState, LoadingCard } from "./ViewState";
import "./cardMap.css";

/** Rows scanned automatically for coordinates (then "더 불러오기"). */
export const MAP_AUTOLOAD_ROWS = 20_000;
/** Coordinate-table rows drawn at once (the clusters always cover every loaded row). */
export const MAP_TABLE_MAX = 500;
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
  });
  const { timezone } = useTimezone();
  const { publishFocusedRow, requestFocus } = useViewerTarget();
  const patchFilters = useFilterStore((s) => s.patchFilters);
  const filtered = useFilterStore((s) => hasActiveFilters(s.filters)) || Boolean(q);
  const located = useMemo(() => geoRows(rows), [rows]);
  const clusters = useMemo(() => clusterRows(located), [located]);
  const [picked, setPicked] = useState<string | null>(null);
  // Every loaded row is located (server filter); keep paging up to the cap.
  const capped = useAutoLoad(cq, true, MAP_AUTOLOAD_ROWS);
  // A failed page stops the automatic paging (useAutoLoad): no endless "찾는 중".
  const scanning = !cq.error && (cq.isFetching || (cq.canLoadMore && !capped));

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

  if (cq.error && cq.loadedCount === 0) {
    return <ErrorState message={`행을 불러오지 못했습니다. ${errorText(cq.error)}`} onRetry={cq.refetch} />;
  }
  if (cq.isLoading) return <LoadingCard label="위치 행을 찾는 중…" />;
  if (located.length === 0) {
    if (scanning) {
      return <LoadingCard label="위치 행을 찾는 중…" />;
    }
    if (cq.error) {
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
        {capped ? (
          <button type="button" className="view-link" onClick={() => cq.loadMore()}>
            더 불러오기
          </button>
        ) : null}
      </EmptyState>
    );
  }

  const shown = located.slice(0, MAP_TABLE_MAX);
  return (
    <div className="view-pane map-view">
      <div className="view-toolbar">
        <span className="view-count">
          {`위치 행 ${located.length.toLocaleString("ko-KR")}건 · 묶음 ${clusters.length.toLocaleString("ko-KR")}개`}
          {cq.total !== null && cq.total > cq.loadedCount
            ? ` (전체 ${cq.total.toLocaleString("ko-KR")}건 중)`
            : ""}
          {scanning ? " · 불러오는 중…" : ""}
        </span>
        {capped ? (
          <button type="button" className="view-link" onClick={() => cq.loadMore()}>
            더 불러오기
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
            좌표 표{located.length > MAP_TABLE_MAX ? ` (처음 ${MAP_TABLE_MAX}건)` : ""}
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
              {shown.map((item) => (
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
