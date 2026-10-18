/**
 * 미디어 탐색기 panel of the thumbnail view (plan r4 §2.2 V2).
 *
 * - 관련 미디어: the focused image's files with the same content hash (`GET /related-media`) and its
 *   pHash neighbours within distance 8 (`GET /media/similar?max_distance=8`), as two groups.
 * - 유사 사진 찾기: pHash neighbours of the focused image with a chosen distance (0–16).
 * - 그룹: EXIF camera or capture-day groups of the run's images (`GET /media/groups`).
 *
 * Every result set can narrow the thumbnail grid to its images ("격자에 이 묶음만") and select its
 * loaded tiles ("이 묶음 선택") so the selection bar tags them; blurred tiles stay blurred. A result
 * item focuses its tile when the grid has it loaded, else opens the image row of the media node.
 */

import { useQuery } from "@tanstack/react-query";
import { type ReactNode, useId, useState } from "react";
import { announce, DisabledReason } from "../../a11y";
import {
  fetchMediaGroups,
  fetchSimilarMedia,
  MAX_PHASH_DISTANCE,
  type MediaGroupBy,
  RELATED_PHASH_DISTANCE,
  type SimilarMediaItem,
} from "../../api/explorers";
import { getRelatedMedia } from "../../api/reviewTools";
import { errorText } from "../viewer/useAsync";
import "./explorers.css";

export type MediaPanelMode = "related" | "similar" | "groups";

export const MEDIA_PANEL_LABELS: Record<MediaPanelMode, string> = {
  related: "관련 미디어",
  similar: "유사 사진 찾기",
  groups: "카메라·촬영일 그룹",
};

export const NO_ACTIVE_IMAGE_REASON = "썸네일을 하나 고르면(포커스) 사용할 수 있습니다";

/** Path key shared by the panel and the grid filter (case-insensitive, `/` separators). */
export function mediaPathKey(path: string): string {
  return path.replace(/\\/g, "/").toLowerCase();
}

export interface MediaSet {
  label: string;
  paths: string[];
}

export interface MediaPanelProps {
  runId: string;
  mode: MediaPanelMode;
  /** Focused tile's source path and name (null when no tile). */
  activePath: string | null;
  activeName: string;
  /** Paths of the loaded tiles (lower-cased keys) — "n건 격자에 있음". */
  loadedKeys: ReadonlySet<string>;
  onNarrow: (set: MediaSet | null) => void;
  onSelect: (set: MediaSet) => void;
  /** Focus the tile of `path` (true) — false when it is not loaded. */
  onFocusPath: (path: string) => boolean;
  /** Open the media-image row (record_index) when its tile is not loaded. */
  onOpenRecord: (recordIndex: number, path: string) => void;
}

const n = (value: number) => value.toLocaleString("ko-KR");

function errorStatus(error: unknown): number | undefined {
  return typeof error === "object" && error && "status" in error
    ? Number((error as { status: unknown }).status)
    : undefined;
}

function SetActions({
  set,
  loadedKeys,
  onNarrow,
  onSelect,
}: {
  set: MediaSet;
  loadedKeys: ReadonlySet<string>;
  onNarrow: MediaPanelProps["onNarrow"];
  onSelect: MediaPanelProps["onSelect"];
}) {
  const loaded = set.paths.filter((path) => loadedKeys.has(mediaPathKey(path))).length;
  const reason = loaded === 0 ? "이 묶음의 이미지가 아직 격자에 불러와지지 않았습니다" : undefined;
  return (
    <span className="media-panel-row">
      <span className="explorer-muted">
        격자에 있음 {n(loaded)}/{n(set.paths.length)}
      </span>
      <button type="button" className="view-link" onClick={() => onNarrow(set)}>
        격자에 이 묶음만
      </button>
      <DisabledReason reason={reason}>
        <button type="button" className="view-link" onClick={() => onSelect(set)}>
          이 묶음 선택(태그용)
        </button>
      </DisabledReason>
    </span>
  );
}

function ItemList({
  items,
  label,
  onPick,
}: {
  items: Array<{ path: string; name: string; detail: string; recordIndex?: number }>;
  label: string;
  onPick: (item: { path: string; recordIndex?: number; name: string }) => void;
}) {
  if (!items.length) return null;
  return (
    <ul aria-label={label}>
      {items.map((item) => (
        <li key={item.path}>
          <button type="button" className="view-link" title={item.path} onClick={() => onPick(item)}>
            {item.name}
          </button>
          <span className="explorer-muted"> {item.detail}</span>
        </li>
      ))}
    </ul>
  );
}

/** Containing folder name of a path (one segment), so equal names in two folders stay apart. */
export function parentFolder(path: string): string {
  const parts = path.split(/[\\/]/).filter(Boolean);
  return parts.length > 1 ? (parts[parts.length - 2] ?? "") : "";
}

function similarDetail(item: SimilarMediaItem): string {
  const parts = [item.same_hash ? "같은 해시" : `pHash 거리 ${item.distance}`];
  const folder = parentFolder(item.path);
  if (folder) parts.push(`폴더 ${folder}`);
  if (item.camera) parts.push(item.camera);
  if (item.captured_at) parts.push(item.captured_at);
  return parts.join(" · ");
}

export function MediaExplorerPanel(props: MediaPanelProps) {
  const { runId, mode, activePath, activeName, loadedKeys, onNarrow, onSelect, onFocusPath, onOpenRecord } =
    props;
  const [distance, setDistance] = useState(RELATED_PHASH_DISTANCE);
  const [groupBy, setGroupBy] = useState<MediaGroupBy>("camera");
  const [groupKey, setGroupKey] = useState<string | null>(null);
  const headingId = useId();
  const wantedDistance = mode === "related" ? RELATED_PHASH_DISTANCE : distance;
  const similar = useQuery({
    queryKey: ["media-similar", runId, activePath, wantedDistance],
    queryFn: ({ signal }) =>
      fetchSimilarMedia(runId, activePath as string, { maxDistance: wantedDistance }, signal),
    enabled: Boolean(activePath) && mode !== "groups",
    staleTime: 60_000,
    retry: false,
  });
  const sameHash = useQuery({
    queryKey: ["related-media", runId, activePath],
    queryFn: ({ signal }) => getRelatedMedia(runId, activePath as string, signal),
    enabled: Boolean(activePath) && mode === "related",
    staleTime: 60_000,
    retry: false,
  });
  const groups = useQuery({
    queryKey: ["media-groups", runId, groupBy],
    queryFn: ({ signal }) => fetchMediaGroups(runId, groupBy, undefined, signal),
    enabled: mode === "groups",
    staleTime: 5 * 60_000,
    retry: false,
  });
  const members = useQuery({
    queryKey: ["media-groups", runId, groupBy, groupKey],
    queryFn: ({ signal }) => fetchMediaGroups(runId, groupBy, groupKey as string, signal),
    enabled: mode === "groups" && groupKey !== null,
    staleTime: 5 * 60_000,
    retry: false,
  });

  const pick = (item: { path: string; recordIndex?: number; name: string }) => {
    if (onFocusPath(item.path)) return;
    if (item.recordIndex !== undefined) {
      onOpenRecord(item.recordIndex, item.path);
      return;
    }
    announce(`${item.name}은(는) 지금 격자에 불러와지지 않았습니다`);
  };

  const similarError = (): ReactNode => {
    const status = errorStatus(similar.error);
    if (status === 404)
      return "이 이미지는 이미지 아티팩트(media-image) 목록에 없어 pHash로 비교할 수 없습니다.";
    if (status === 409) return "이 이미지에는 pHash(지각 해시)가 없어 유사 사진을 찾을 수 없습니다.";
    return `유사 사진을 찾지 못했습니다: ${errorText(similar.error)}`;
  };

  let body: ReactNode;
  if (mode === "groups") {
    const list = groups.data?.groups ?? [];
    const memberSet: MediaSet | null =
      members.data?.paths && groupKey !== null
        ? {
            label: `${groupBy === "camera" ? "카메라" : "촬영일"}: ${list.find((g) => g.key === groupKey)?.label ?? groupKey}`,
            paths: members.data.paths,
          }
        : null;
    body = (
      <>
        <div className="media-panel-row">
          <label className="explorer-field">
            묶는 기준
            <select
              value={groupBy}
              onChange={(event) => {
                setGroupBy(event.target.value as MediaGroupBy);
                setGroupKey(null);
              }}
            >
              <option value="camera">EXIF 카메라</option>
              <option value="date">촬영일</option>
            </select>
          </label>
          {groups.data ? <span className="explorer-muted">그룹 {n(list.length)}개</span> : null}
        </div>
        {groups.isLoading ? <p className="explorer-note">그룹을 불러오는 중…</p> : null}
        {groups.error ? (
          <p className="explorer-note is-error">그룹을 불러오지 못했습니다: {errorText(groups.error)}</p>
        ) : null}
        {list.length ? (
          <ul className="media-group-list" aria-label="그룹">
            {list.map((group) => (
              <li key={group.key || "(none)"}>
                <button
                  type="button"
                  className="view-link"
                  aria-pressed={groupKey === group.key}
                  onClick={() => {
                    setGroupKey(group.key);
                    announce(`${group.label} ${n(group.count)}건`);
                  }}
                >
                  {group.label} ({n(group.count)})
                </button>
              </li>
            ))}
          </ul>
        ) : groups.data ? (
          <p className="explorer-note">이미지 아티팩트가 없어 묶을 그룹이 없습니다.</p>
        ) : null}
        {members.error ? <p className="explorer-note is-error">{errorText(members.error)}</p> : null}
        {memberSet ? (
          <SetActions set={memberSet} loadedKeys={loadedKeys} onNarrow={onNarrow} onSelect={onSelect} />
        ) : null}
      </>
    );
  } else if (!activePath) {
    body = <p className="explorer-note">{NO_ACTIVE_IMAGE_REASON}.</p>;
  } else {
    const items = similar.data?.items ?? [];
    const near = mode === "related" ? items.filter((item) => !item.same_hash) : items;
    const nearSet: MediaSet = {
      label:
        mode === "related"
          ? `pHash 근접(≤ ${RELATED_PHASH_DISTANCE}): ${activeName}`
          : `유사 사진(≤ ${distance}): ${activeName}`,
      paths: [activePath, ...near.map((item) => item.path)],
    };
    const hashPaths = sameHash.data?.paths ?? [];
    const hashSet: MediaSet = { label: `같은 해시: ${activeName}`, paths: [activePath, ...hashPaths] };
    body = (
      <>
        {mode === "similar" ? (
          <div className="media-panel-row">
            <label className="explorer-field">
              최대 pHash 거리
              <select value={distance} onChange={(event) => setDistance(Number(event.target.value))}>
                {Array.from({ length: MAX_PHASH_DISTANCE + 1 }, (_, value) => value).map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            {similar.data ? (
              <span className="explorer-muted">
                {n(similar.data.counts.matched)}건 (pHash 있는 이미지 {n(similar.data.counts.with_phash)}개
                중)
              </span>
            ) : null}
          </div>
        ) : null}
        {mode === "related" ? (
          <section aria-label="같은 해시">
            <h4 className="media-panel-row">
              같은 해시 {sameHash.data ? n(sameHash.data.count) : "…"}
              {sameHash.data?.source === "case-db" ? (
                <span className="explorer-muted">(케이스 DB 해시)</span>
              ) : null}
            </h4>
            {sameHash.error ? <p className="explorer-note is-error">{errorText(sameHash.error)}</p> : null}
            <ItemList
              label="같은 해시 파일"
              items={hashPaths.map((path) => ({
                path,
                name: path.split(/[\\/]/).pop() || path,
                detail: parentFolder(path) ? `같은 해시 · 폴더 ${parentFolder(path)}` : "같은 해시",
              }))}
              onPick={pick}
            />
            {hashPaths.length ? (
              <SetActions set={hashSet} loadedKeys={loadedKeys} onNarrow={onNarrow} onSelect={onSelect} />
            ) : null}
          </section>
        ) : null}
        <section
          aria-label={mode === "related" ? `pHash 근접 거리 ${RELATED_PHASH_DISTANCE} 이하` : "유사 사진"}
        >
          {mode === "related" ? (
            <h4 className="media-panel-row">
              pHash 근접(≤ {RELATED_PHASH_DISTANCE}){" "}
              {similar.data ? n(near.length) : similar.error ? "—" : "…"}
            </h4>
          ) : null}
          {similar.isLoading ? <p className="explorer-note">pHash를 비교하는 중…</p> : null}
          {similar.error ? <p className="explorer-note">{similarError()}</p> : null}
          {similar.data && near.length === 0 ? (
            <p className="explorer-note">거리 {wantedDistance} 이내의 다른 이미지가 없습니다.</p>
          ) : null}
          <ItemList
            label={mode === "related" ? "pHash 근접 이미지" : "유사 사진"}
            items={near.map((item) => ({
              path: item.path,
              name: item.name,
              detail: similarDetail(item),
              recordIndex: item.record_index,
            }))}
            onPick={pick}
          />
          {near.length ? (
            <SetActions set={nearSet} loadedKeys={loadedKeys} onNarrow={onNarrow} onSelect={onSelect} />
          ) : null}
        </section>
      </>
    );
  }

  return (
    <section className="media-panel" aria-labelledby={headingId} data-testid="media-panel" data-mode={mode}>
      <h3 id={headingId}>
        {MEDIA_PANEL_LABELS[mode]}
        {mode !== "groups" && activePath ? ` — ${activeName}` : ""}
      </h3>
      {body}
    </section>
  );
}
