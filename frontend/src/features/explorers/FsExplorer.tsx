// biome-ignore-all lint/a11y/useSemanticElements: the sub-folder rows are an ARIA grid of CSS-grid rows (like DataGrid / DerivedPane), not a <table>
// biome-ignore-all lint/a11y/useFocusableInteractive: roving tabindex; only the focused folder row is focusable by design
/**
 * 파일 시스템 탐색기 (plan r4 §2.2 V2): folder tree beside the files grid.
 *
 * Opened by the route's `dir=` (files only; `dir=/` = volume root) or a special node
 * (`special=`). The left pane is a lazy folder tree over `GET /fs-tree` (volume root →
 * folders; 고아 파일·미할당 공간·슬랙 special nodes when the run has them, else listed as hidden
 * with the reason); Enter / click opens a folder and the grid lists it through
 * `GET /files?path_prefix=` (direct files, or the subtree with 하위 폴더 포함). The header shows
 * the breadcrumb and the folder's counts, which equal the grid total for the same list.
 */

import { useQuery } from "@tanstack/react-query";
import { type KeyboardEvent, type ReactNode, useCallback, useMemo, useRef, useState } from "react";
import { announce } from "../../a11y";
import { FILES_INVENTORY } from "../../api/collections";
import {
  type FsFolder,
  type FsScope,
  type FsSpecialNode,
  type FsTreePage,
  fetchFsTree,
} from "../../api/explorers";
import { focusGridWhenReady } from "../../commands/builtin";
import { Icon } from "../../icons";
import type { FsSpecial, Route } from "../../router";
import { useRoute } from "../../state/hooks";
import { formatBytes } from "../grid/columns/common";
import { errorText } from "../viewer/useAsync";
import { type ExplorerChildPage, ExplorerTree, type ExplorerTreeItem } from "./ExplorerTree";
import "./explorers.css";

export const FS_TREE_PAGE = 200;
const ROOT_ID = "dir:";
const SPECIAL_PREFIX = "special:";

/** The files list the grid shows for this route: candidates, or the inventory (`category=inventory…`). */
export function fsScopeOf(category: string | undefined): FsScope {
  return category === FILES_INVENTORY || category?.startsWith(`${FILES_INVENTORY}:`)
    ? "inventory"
    : "candidates";
}

/** True when the route opens the file system explorer (folder or special node). */
export function fsExplorerOpen(route: Pick<Route, "collection" | "dir" | "special">): boolean {
  return route.collection === "files" && (route.dir !== undefined || Boolean(route.special));
}

const n = (value: number) => value.toLocaleString("ko-KR");

export function folderItem(folder: FsFolder): ExplorerTreeItem {
  const size = formatBytes(folder.size);
  return {
    id: `dir:${folder.path}`,
    label: folder.name,
    badge: n(folder.file_count),
    description: `파일 ${n(folder.file_count)}개${size ? `, ${size}` : ""}, 하위 폴더 ${n(folder.folder_count)}개`,
    hasChildren: folder.has_children,
    icon: "folder",
    title: `${folder.path} — 파일 ${n(folder.file_count)}개(직속 ${n(folder.direct_file_count)}개)${size ? ` · ${size}` : ""}`,
  };
}

/** Ancestors of `dir` as tree ids (volume root first), the folder itself excluded. */
export function ancestorIds(dir: string): string[] {
  const parts = dir.split("/").filter(Boolean);
  const out = [ROOT_ID];
  for (let i = 1; i < parts.length; i += 1) out.push(`dir:${parts.slice(0, i).join("/")}`);
  return out;
}

function useFsLevel(runId: string | null, scope: FsScope, path: string | undefined) {
  return useQuery({
    queryKey: ["fs-tree", runId, scope, path ?? ""],
    queryFn: ({ signal }) => fetchFsTree(runId as string, { path, scope, limit: FS_TREE_PAGE }, signal),
    enabled: Boolean(runId) && path !== undefined,
    staleTime: 60_000,
    retry: false,
  });
}

function specialItem(node: FsSpecialNode): ExplorerTreeItem {
  const source =
    node.source === "files" ? "파일 목록" : node.source === "ntfs-meta" ? "NTFS 메타 분석" : "카빙 분석";
  return {
    id: `${SPECIAL_PREFIX}${node.id}`,
    label: node.label,
    badge: n(node.count),
    description: `${n(node.count)}건, 출처 ${source}`,
    hasChildren: false,
    icon: node.id === "orphan" ? "file" : "partition",
    title: node.note ?? `${node.label} — ${source} ${n(node.count)}건`,
  };
}

export function FsExplorerPane() {
  const { route, patchRoute, navigate } = useRoute();
  const runId = route.runId;
  const scope = fsScopeOf(route.category);
  const root = useFsLevel(runId, scope, "");
  const dir = route.dir;
  const specials = root.data?.special_nodes ?? [];

  const loadChildren = useCallback(
    async (id: string, after: string | null, signal: AbortSignal): Promise<ExplorerChildPage> => {
      const path = id.slice(ROOT_ID.length);
      const page = await fetchFsTree(runId as string, { path, scope, limit: FS_TREE_PAGE, after }, signal);
      return { items: page.children.map(folderItem), nextAfter: page.next_after, total: page.child_total };
    },
    [runId, scope],
  );

  const roots = useMemo<ExplorerTreeItem[]>(() => {
    const data = root.data;
    if (!data) return [];
    const size = formatBytes(data.node.size);
    return [
      {
        id: ROOT_ID,
        label: data.volume.label,
        badge: n(data.node.file_count),
        description: `파일 ${n(data.node.file_count)}개${size ? `, ${size}` : ""}`,
        hasChildren: data.node.has_children,
        icon: "hard-drive",
        title: data.volume.root ?? data.volume.label,
      },
      ...(data.special_nodes ?? []).map(specialItem),
    ];
  }, [root.data]);

  const selectedId = route.special
    ? `${SPECIAL_PREFIX}${route.special}`
    : dir !== undefined
      ? `dir:${dir}`
      : null;
  const expandIds = useMemo(() => (dir !== undefined ? ancestorIds(dir) : [ROOT_ID]), [dir]);

  const onOpen = (item: ExplorerTreeItem) => {
    if (!runId) return;
    if (item.id.startsWith(SPECIAL_PREFIX)) {
      const node = specials.find((entry) => `${SPECIAL_PREFIX}${entry.id}` === item.id);
      if (!node) return;
      if (node.analysis) {
        // 고아 파일 / 미할당 공간 from an analysis: its result rows (analysis node).
        navigate({
          runId,
          collection: "analysis",
          kind: node.analysis.kind,
          analysisId: node.analysis.analysis_id,
        });
      } else {
        // The list (candidates / inventory) that holds the node's rows: rows only the inventory
        // has would show an empty candidates list.
        const inInventory = (node.counts?.candidates ?? 0) === 0 && (node.counts?.inventory ?? 0) > 0;
        const inCandidates = (node.counts?.candidates ?? 0) > 0 && (node.counts?.inventory ?? 0) === 0;
        const category = inInventory ? FILES_INVENTORY : inCandidates ? undefined : route.category;
        patchRoute({
          dir: undefined,
          rec: undefined,
          special: node.id as FsSpecial,
          category,
          row: undefined,
          mode: undefined,
        });
        announce(`${node.label} ${n(node.count)}건을 목록에 표시합니다`);
      }
      focusGridWhenReady();
      return;
    }
    const path = item.id.slice(ROOT_ID.length);
    // A candidates category would make the grid total differ from the folder counts: the explorer
    // lists the whole list (candidates or the inventory) of the folder.
    const category = scope === "inventory" ? FILES_INVENTORY : undefined;
    patchRoute({ dir: path, special: undefined, category, row: undefined, mode: undefined });
    announce(`${item.label} 폴더를 엽니다`);
  };

  const hidden = root.data?.hidden_special_nodes ?? [];
  let body: ReactNode;
  if (root.isLoading) body = <p className="explorer-note">폴더 트리를 불러오는 중…</p>;
  else if (root.error) {
    body = (
      <p className="explorer-note is-error" role="alert">
        폴더 트리를 불러오지 못했습니다: {errorText(root.error)}
      </p>
    );
  } else if (root.data && root.data.node.file_count === 0) {
    // No folder to show, but the special nodes (고아 파일 · 미할당 공간 · NTFS 메타) still open.
    const specialRoots = roots.filter((item) => item.id.startsWith(SPECIAL_PREFIX));
    body = (
      <>
        <p className="explorer-note" data-testid="fs-explorer-empty">
          이 목록({scope === "inventory" ? "기타 파일" : "후보 파일"})에는 폴더에 놓을 파일이 없습니다.
        </p>
        {specialRoots.length ? (
          <ExplorerTree
            label="파일 시스템 특수 노드"
            roots={specialRoots}
            loadChildren={loadChildren}
            selectedId={selectedId}
            onOpen={onOpen}
            resetKey={`${runId}|${scope}`}
            testId="fs-explorer-tree"
          />
        ) : null}
      </>
    );
  } else {
    body = (
      <ExplorerTree
        label="파일 시스템 폴더 트리"
        roots={roots}
        loadChildren={loadChildren}
        selectedId={selectedId}
        onOpen={onOpen}
        expandIds={expandIds}
        resetKey={`${runId}|${scope}`}
        testId="fs-explorer-tree"
      />
    );
  }
  return (
    <section
      className="explorer-pane fs-explorer-pane"
      aria-label="파일 시스템 탐색기"
      data-testid="fs-explorer"
    >
      <div className="explorer-pane-head">
        <h2 className="explorer-title">
          <Icon name="hard-drive" /> 파일 시스템
        </h2>
        <label className="explorer-field">
          목록
          <select
            value={scope}
            onChange={(event) => {
              const next = event.target.value as FsScope;
              // The other list may not have this folder: start again at the volume root.
              patchRoute({
                category: next === "inventory" ? FILES_INVENTORY : undefined,
                dir: "",
                special: undefined,
                row: undefined,
                mode: undefined,
              });
              announce(
                next === "inventory" ? "기타 파일(인벤토리) 폴더를 봅니다" : "후보 파일 폴더를 봅니다",
              );
            }}
          >
            <option value="candidates">후보 파일</option>
            <option value="inventory">기타 파일(인벤토리)</option>
          </select>
        </label>
      </div>
      {body}
      {root.data?.index.outside_root ? (
        <p className="explorer-note" title={root.data.index.outside_root_reason}>
          증거 루트 밖·상대 경로 없음 {n(root.data.index.outside_root)}건은 폴더 트리에 넣지 않았습니다.
        </p>
      ) : null}
      {root.data?.index.truncated ? <p className="explorer-note">{root.data.index.reason}</p> : null}
      {hidden.length ? (
        <details className="explorer-hidden">
          <summary>숨긴 특수 노드 {hidden.length}개</summary>
          <ul>
            {hidden.map((node) => (
              <li key={node.id}>
                <strong>{node.label}</strong> — {node.reason}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </section>
  );
}

/** Breadcrumb + counts + 하위 폴더 포함 above the grid while the explorer is open. */
export function FsExplorerHeader() {
  const { route, patchRoute } = useRoute();
  const scope = fsScopeOf(route.category);
  const level = useFsLevel(route.runId, scope, route.dir);
  const root = useFsLevel(route.runId, scope, route.dir === undefined ? "" : undefined);
  const close = () => {
    patchRoute({ dir: undefined, rec: undefined, special: undefined });
    announce("파일 시스템 탐색기를 닫았습니다");
  };
  const closeButton = (
    <button type="button" className="view-link" onClick={close} data-testid="fs-explorer-close">
      탐색기 닫기
    </button>
  );
  if (route.special) {
    const node = root.data?.special_nodes?.find((entry) => entry.id === route.special);
    return (
      <div className="explorer-header" data-testid="fs-explorer-header">
        <p className="explorer-crumbs-text">
          특수 노드: <strong>{node?.label ?? route.special}</strong>
          {node ? ` · ${n(node.count)}건` : ""}
        </p>
        {closeButton}
      </div>
    );
  }
  const data: FsTreePage | undefined = level.data;
  const crumbs = data?.breadcrumb ?? [];
  const node = data?.node;
  return (
    <div className="explorer-header" data-testid="fs-explorer-header">
      <nav aria-label="폴더 경로" className="explorer-crumbs">
        <ol>
          <li>
            {crumbs.length ? (
              <button
                type="button"
                className="view-link"
                onClick={() => patchRoute({ dir: "", row: undefined, mode: undefined })}
              >
                {data?.volume.label ?? "볼륨"}
              </button>
            ) : (
              <span aria-current="page">{data?.volume.label ?? "볼륨"}</span>
            )}
          </li>
          {crumbs.map((crumb, index) => (
            <li key={crumb.path}>
              <span aria-hidden="true" className="explorer-crumb-sep">
                ›
              </span>
              {index === crumbs.length - 1 ? (
                <span aria-current="page">{crumb.name}</span>
              ) : (
                <button
                  type="button"
                  className="view-link"
                  onClick={() => patchRoute({ dir: crumb.path, row: undefined, mode: undefined })}
                >
                  {crumb.name}
                </button>
              )}
            </li>
          ))}
        </ol>
      </nav>
      {level.error ? (
        <span className="explorer-note is-error">{errorText(level.error)}</span>
      ) : node ? (
        <span className="explorer-counts" data-testid="fs-explorer-counts">
          직속 파일 {n(node.direct_file_count)}개 · 하위 포함 {n(node.file_count)}개 ·{" "}
          {formatBytes(node.size) || "0 B"}
        </span>
      ) : null}
      <label className="explorer-field">
        <input
          type="checkbox"
          checked={Boolean(route.rec)}
          onChange={(event) => {
            patchRoute({ rec: event.target.checked ? true : undefined, row: undefined, mode: undefined });
            announce(
              event.target.checked ? "하위 폴더의 파일까지 표시합니다" : "이 폴더의 직속 파일만 표시합니다",
            );
          }}
        />
        하위 폴더 포함
      </label>
      {route.category && scope === "candidates" ? (
        <span className="explorer-note" title="폴더 수치는 후보 파일 전체 기준입니다">
          범주 필터 적용 중 — 폴더 수치는 범주 전체 기준
        </span>
      ) : null}
      {closeButton}
    </div>
  );
}

/**
 * Sub-folders of the open folder in the centre (r7 L4, C-E1 — Explorer-like): the volume root and
 * `Users` hold folders, not files, so the files grid alone was empty there. One row per child
 * folder (icon · name · files · sub-folders · size, the `/fs-tree` counts); double-click or Enter
 * opens it, ↑/↓/Home/End move. The files of the folder stay in the grid below.
 */
export function FsFolderRows() {
  const { route, patchRoute } = useRoute();
  const scope = fsScopeOf(route.category);
  const level = useFsLevel(route.runId, scope, route.dir);
  const [focus, setFocus] = useState(0);
  const gridRef = useRef<HTMLDivElement>(null);
  const folders = level.data?.children ?? [];
  if (route.special || route.dir === undefined || !level.data || folders.length === 0) return null;
  const total = level.data.child_total ?? folders.length;
  const at = Math.min(focus, folders.length - 1);
  const enter = (folder: FsFolder) => {
    patchRoute({ dir: folder.path, row: undefined, mode: undefined });
    announce(`${folder.name} 폴더를 엽니다`);
  };
  const focusRow = (index: number) => {
    const next = Math.max(0, Math.min(folders.length - 1, index));
    setFocus(next);
    gridRef.current?.querySelector<HTMLElement>(`[data-folder-index="${next}"]`)?.focus();
  };
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>, index: number) => {
    const folder = folders[index];
    if (!folder) return;
    switch (event.key) {
      case "Enter":
        event.preventDefault();
        enter(folder);
        break;
      case "ArrowDown":
        event.preventDefault();
        focusRow(index + 1);
        break;
      case "ArrowUp":
        event.preventDefault();
        focusRow(index - 1);
        break;
      case "Home":
        event.preventDefault();
        focusRow(0);
        break;
      case "End":
        event.preventDefault();
        focusRow(folders.length - 1);
        break;
      default:
        break;
    }
  };
  return (
    <section className="fs-folder-rows" aria-label="하위 폴더" data-testid="fs-folder-rows">
      <div
        ref={gridRef}
        role="grid"
        aria-label={`하위 폴더 ${n(total)}개 — 두 번 클릭 또는 Enter로 열기`}
        aria-rowcount={total + 1}
        className="fs-folder-grid"
      >
        <div role="row" aria-rowindex={1} className="fs-folder-row fs-folder-head">
          <div role="columnheader">이름</div>
          <div role="columnheader">파일</div>
          <div role="columnheader">하위 폴더</div>
          <div role="columnheader">크기</div>
        </div>
        {folders.map((folder, index) => (
          <div
            key={folder.path}
            role="row"
            aria-rowindex={index + 2}
            tabIndex={index === at ? 0 : -1}
            aria-selected={index === at}
            className="fs-folder-row"
            data-folder-index={index}
            data-testid="fs-folder-row"
            title={`${folder.path} — 두 번 클릭하면 엽니다`}
            onFocus={() => setFocus(index)}
            onDoubleClick={() => enter(folder)}
            onKeyDown={(event) => onKeyDown(event, index)}
          >
            <div role="gridcell" className="fs-folder-name">
              <Icon name="folder" /> {folder.name}
            </div>
            <div role="gridcell" className="fs-folder-num">
              {n(folder.file_count)}
            </div>
            <div role="gridcell" className="fs-folder-num">
              {n(folder.folder_count)}
            </div>
            <div role="gridcell" className="fs-folder-num">
              {formatBytes(folder.size) || "0 B"}
            </div>
          </div>
        ))}
      </div>
      {total > folders.length ? (
        <p className="explorer-note">
          처음 {n(folders.length)}개 폴더만 표시합니다 (전체 {n(total)}개) — 나머지는 왼쪽 폴더 트리에서
          여세요.
        </p>
      ) : null}
    </section>
  );
}

/** Explorer layout of the files collection: folder tree | header + sub-folders + grid. */
export function FsExplorerLayout({ children }: { children: ReactNode }) {
  return (
    <div className="explorer-layout" data-testid="fs-explorer-layout">
      <FsExplorerPane />
      <div className="explorer-main">
        <FsExplorerHeader />
        <FsFolderRows />
        <div className="explorer-main-body">{children}</div>
      </div>
    </div>
  );
}
