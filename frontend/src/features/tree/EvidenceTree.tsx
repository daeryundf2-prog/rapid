import {
  defaultRangeExtractor,
  observeElementRect,
  type Range,
  useVirtualizer,
} from "@tanstack/react-virtual";
import { type KeyboardEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { announce } from "../../a11y";
import { focusGridWhenReady } from "../../commands/builtin";
import { Icon } from "../../icons";
import { useAppStore } from "../../state/store";
import { navigate } from "./adapter";
import { targetKey } from "./domains";
import { LiveRunBanner } from "./LiveRunBanner";
import { filterEmptyNodes, flagCountsText, flattenVisible, type TreeModelNode, UNKNOWN_COUNT } from "./model";
import { useTreePrefs } from "./treePrefs";
import { useTreeState } from "./useTreeModel";
import "../flags/flags.css";
import "./tree.css";

const DEFAULT_EXPANDED = ["evidence", "views", "search"];
const TYPE_AHEAD_RESET_MS = 600;
/** Row heights mirror tree.css: 28px items, 32px for level-1 section headers (24px + top gap). */
const ROW_HEIGHT = 28;
const SECTION_ROW_HEIGHT = 32;
const OVERSCAN = 12;
const INITIAL_RECT = { width: 300, height: 600 };

function treeItemLabel(node: TreeModelNode): string {
  const label = node.marker ? `${node.label} (${node.marker})` : node.label;
  const flags = node.flagCounts ? `, ${flagCountsText(node.flagCounts)}` : "";
  if (node.count === undefined) return `${label}${flags}`;
  if (node.count === UNKNOWN_COUNT) return `${label}, 건수 미상${flags}`;
  return typeof node.count === "number"
    ? `${label}, ${node.count.toLocaleString("ko-KR")}건${flags}`
    : `${label}, 진행 ${node.count}${flags}`;
}

/** Strongest grade with rows (the badge colour) and its count. */
function topFlag(counts: TreeModelNode["flagCounts"]): { grade: "A" | "B" | "C"; count: number } | null {
  for (const grade of ["A", "B", "C"] as const) {
    const count = counts?.[grade] ?? 0;
    if (count > 0) return { grade, count };
  }
  return null;
}

/** Ids of the node and its ancestors, or null when it is not in the tree. */
function pathTo(nodes: readonly TreeModelNode[], id: string, trail: string[] = []): string[] | null {
  for (const node of nodes) {
    if (node.id === id) return [...trail, node.id];
    const hit = node.children ? pathTo(node.children, id, [...trail, node.id]) : null;
    if (hit) return hit;
  }
  return null;
}

export function EvidenceTree({ runId }: { runId: string }) {
  const { model: fullModel, loading, treeSettled, liveTree } = useTreeState(runId);
  // U-F7: empty families are hidden unless "결과 없는 계열 표시" (T) is on; the T command needs a
  // mounted tree.
  const showEmpty = useTreePrefs((s) => s.showEmpty);
  const setShowEmpty = useTreePrefs((s) => s.setShowEmpty);
  useEffect(() => {
    useTreePrefs.setState((s) => ({ mounted: s.mounted + 1 }));
    return () => useTreePrefs.setState((s) => ({ mounted: Math.max(0, s.mounted - 1) }));
  }, []);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(DEFAULT_EXPANDED));
  const [focusedId, setFocusedId] = useState<string>("views");
  const [blockedReason, setBlockedReason] = useState("");
  const refs = useRef(new Map<string, HTMLLIElement>());
  const typeAhead = useRef({ buffer: "", timer: 0 });
  const scrollRef = useRef<HTMLDivElement>(null);
  // Id whose row was unmounted when focus moved to it; the row focuses itself once it mounts.
  const pendingFocus = useRef<string | null>(null);

  // Tree search (트리 검색): matches ALL nodes, collapsed domains included; the matches and their
  // ancestors are shown expanded. Type-ahead keeps working on the visible nodes.
  const [search, setSearch] = useState("");
  const needle = search.trim().toLocaleLowerCase("ko-KR");
  const searchView = useMemo(() => {
    if (!needle) return null;
    const keep = new Set<string>();
    const open = new Set<string>();
    const walk = (nodes: TreeModelNode[], ancestors: string[]): boolean => {
      let any = false;
      for (const node of nodes) {
        const self = node.label.toLocaleLowerCase("ko-KR").includes(needle);
        const below = node.children ? walk(node.children, [...ancestors, node.id]) : false;
        if (self || below) {
          keep.add(node.id);
          for (const id of ancestors) keep.add(id);
          if (below) open.add(node.id);
          any = true;
        }
      }
      return any;
    };
    walk(fullModel, []);
    return { keep, open };
  }, [fullModel, needle]);
  const routeKey = useAppStore((s) =>
    s.route.runId === runId && s.route.collection
      ? targetKey({ ...s.route, collection: s.route.collection })
      : "",
  );
  // One selected node: the first (DFS order) whose key is the route's — the 전체 보기 views come
  // before the domain nodes that repeat them (전체 파일, IOC). Hidden (empty) nodes count too: a
  // deep link to one reveals it.
  const selectedId = useMemo(() => {
    const visit = (nodes: TreeModelNode[]): string | null => {
      for (const node of nodes) {
        if (
          !node.noSelect &&
          !node.activate &&
          (node.selectKey ?? targetKey({ ...node.route })) === routeKey
        ) {
          return node.id;
        }
        const hit = node.children ? visit(node.children) : null;
        if (hit) return hit;
      }
      return null;
    };
    return routeKey ? visit(fullModel) : null;
  }, [fullModel, routeKey]);
  const reveal = useMemo(() => {
    const ids = new Set<string>(searchView?.keep ?? []);
    for (const id of selectedId ? (pathTo(fullModel, selectedId) ?? []) : []) ids.add(id);
    return ids;
  }, [fullModel, searchView, selectedId]);
  const emptyView = useMemo(
    () => filterEmptyNodes(fullModel, showEmpty, reveal),
    [fullModel, showEmpty, reveal],
  );
  const model = emptyView.nodes;
  const visible = useMemo(() => {
    if (!searchView) return flattenVisible(model, expanded);
    const shown = new Set([...expanded, ...searchView.open]);
    return flattenVisible(model, shown).filter((entry) => searchView.keep.has(entry.node.id));
  }, [model, expanded, searchView]);
  // The roving tab stop falls back to the first node when the focused one is not shown.
  const tabStopId = visible.some((entry) => entry.node.id === focusedId) ? focusedId : visible[0]?.node.id;

  const focusedIndex = visible.findIndex((entry) => entry.node.id === focusedId);
  const focusedIndexRef = useRef(focusedIndex);
  focusedIndexRef.current = focusedIndex;
  // The extractor identity changes with the focused row so it stays mounted (same as DataGrid).
  const rangeExtractor = useCallback(
    (range: Range) => {
      const base = defaultRangeExtractor(range);
      if (focusedIndex >= 0 && !base.includes(focusedIndex))
        return [...base, focusedIndex].sort((a, b) => a - b);
      return base;
    },
    [focusedIndex],
  );
  const virtualizer = useVirtualizer({
    count: visible.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: (i) => (visible[i]?.level === 1 ? SECTION_ROW_HEIGHT : ROW_HEIGHT),
    overscan: OVERSCAN,
    rangeExtractor,
    initialRect: INITIAL_RECT,
    // A zero-size viewport (hidden panel, no layout) keeps the initial window instead of rendering no rows.
    observeElementRect: (instance, cb) =>
      observeElementRect(instance, (rect) => cb(rect.height > 0 ? rect : INITIAL_RECT)),
    getItemKey: (i) => visible[i]?.node.id ?? i,
  });

  const focusNode = useCallback(
    (id: string) => {
      setFocusedId(id);
      const el = refs.current.get(id);
      if (el) {
        el.focus();
        pendingFocus.current = null;
        return;
      }
      pendingFocus.current = id;
      const idx = visible.findIndex((entry) => entry.node.id === id);
      if (idx >= 0) virtualizer.scrollToIndex(idx, { align: "auto" });
    },
    [visible, virtualizer],
  );

  const activate = useCallback(
    (node: TreeModelNode) => {
      if (node.disabledReason) {
        setBlockedReason(node.disabledReason);
        announce(node.disabledReason);
        return;
      }
      setBlockedReason("");
      if (node.toggleOnly) {
        // Domain / group headers only open or close; they never navigate to a child.
        setExpanded((prev) => {
          const next = new Set(prev);
          if (next.has(node.id)) next.delete(node.id);
          else next.add(node.id);
          return next;
        });
        return;
      }
      if (node.activate) node.activate();
      else if (node.target) {
        // Domain nodes carry their server filters (`types=` → artifact_type, `ext=`).
        useAppStore.getState().navigate({ runId, ...node.target });
        focusGridWhenReady();
      } else navigate({ runId, ...node.route });
    },
    [runId],
  );

  const toggle = useCallback((id: string, open: boolean) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (open) next.add(id);
      else next.delete(id);
      return next;
    });
  }, []);

  const onKeyDown = (event: KeyboardEvent<HTMLUListElement>) => {
    if (event.ctrlKey || event.metaKey || event.altKey) return;
    const targetId = (event.target as HTMLElement).closest<HTMLElement>("[role='treeitem']")?.dataset.nodeId;
    const index = visible.findIndex((entry) => entry.node.id === (targetId ?? focusedId));
    const current = visible[index];
    if (!current) return;
    const { node } = current;
    const hasChildren = Boolean(node.children?.length);
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault();
        if (visible[index + 1]) focusNode(visible[index + 1]?.node.id as string);
        return;
      case "ArrowUp":
        event.preventDefault();
        if (index > 0) focusNode(visible[index - 1]?.node.id as string);
        return;
      case "Home":
        event.preventDefault();
        focusNode(visible[0]?.node.id as string);
        return;
      case "End":
        event.preventDefault();
        focusNode(visible[visible.length - 1]?.node.id as string);
        return;
      case "ArrowRight":
        event.preventDefault();
        if (hasChildren && !expanded.has(node.id)) toggle(node.id, true);
        else if (hasChildren) focusNode(node.children?.[0]?.id as string);
        return;
      case "ArrowLeft":
        event.preventDefault();
        if (hasChildren && expanded.has(node.id)) toggle(node.id, false);
        else if (current.parentId) focusNode(current.parentId);
        return;
      case "Enter":
      case " ":
        event.preventDefault();
        activate(node);
        return;
      default:
    }
    if (event.key.length === 1 && /\S/.test(event.key)) {
      window.clearTimeout(typeAhead.current.timer);
      typeAhead.current.buffer += event.key.toLocaleLowerCase("ko-KR");
      typeAhead.current.timer = window.setTimeout(() => {
        typeAhead.current.buffer = "";
      }, TYPE_AHEAD_RESET_MS);
      const buffer = typeAhead.current.buffer;
      const ordered = [...visible.slice(index + 1), ...visible.slice(0, index + 1)];
      const hit = ordered.find((entry) => entry.node.label.toLocaleLowerCase("ko-KR").startsWith(buffer));
      if (hit) focusNode(hit.node.id);
    }
  };

  const selected = (node: TreeModelNode) => node.id === selectedId;

  // Open the domain (and group, e.g. 실행 흔적 › Amcache) that holds the selected node (deep links, 결과 보기 →).
  useEffect(() => {
    if (!selectedId) return;
    const ancestors = (nodes: TreeModelNode[], trail: string[]): string[] | null => {
      for (const node of nodes) {
        if (node.id === selectedId) return trail;
        const hit = node.children ? ancestors(node.children, [...trail, node.id]) : null;
        if (hit) return hit;
      }
      return null;
    };
    const open = ancestors(model, []) ?? [];
    if (!open.length) return;
    setExpanded((prev) => (open.every((id) => prev.has(id)) ? prev : new Set([...prev, ...open])));
  }, [model, selectedId]);

  return (
    <div className="case-tree evidence-tree" data-testid="evidence-tree">
      <LiveRunBanner live={liveTree} />
      <input
        type="search"
        className="case-tree-search"
        aria-label="트리 검색"
        placeholder="트리 검색"
        value={search}
        onChange={(event) => setSearch(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Escape" && search) {
            event.preventDefault();
            event.stopPropagation();
            setSearch("");
          } else if (event.key === "Enter" || event.key === "ArrowDown") {
            const first = visible.find((entry) =>
              entry.node.label.toLocaleLowerCase("ko-KR").includes(needle),
            );
            if (first) {
              event.preventDefault();
              focusNode(first.node.id);
            }
          }
        }}
      />
      {searchView && visible.length === 0 ? (
        <p className="case-tree-reason">일치하는 노드가 없습니다.</p>
      ) : null}
      <div className="evidence-tree-scroll" ref={scrollRef}>
        <ul
          // biome-ignore lint/a11y/noNoninteractiveElementToInteractiveRole: ul is the ARIA tree container
          role="tree"
          aria-label="케이스 탐색 트리"
          onKeyDown={onKeyDown}
          style={{ height: virtualizer.getTotalSize() }}
        >
          {virtualizer.getVirtualItems().map((item) => {
            const entry = visible[item.index];
            if (!entry) return null;
            const { node, level } = entry;
            const position = item.index;
            const hasChildren = Boolean(node.children?.length);
            const isOpen = expanded.has(node.id) || Boolean(searchView?.open.has(node.id));
            const isSelected = selected(node);
            const emptyReason = emptyView.hiddenIds.has(node.id) ? node.hiddenReason : undefined;
            return (
              // biome-ignore lint/a11y/useKeyWithClickEvents: keyboard handled by the tree root (arrows/Enter/Space)
              <li
                key={node.id}
                role="treeitem"
                data-node-id={node.id}
                ref={(el) => {
                  if (el) {
                    refs.current.set(node.id, el);
                    if (pendingFocus.current === node.id) {
                      pendingFocus.current = null;
                      el.focus();
                    }
                  } else refs.current.delete(node.id);
                }}
                tabIndex={tabStopId === node.id ? 0 : -1}
                aria-label={treeItemLabel(node)}
                aria-level={level}
                aria-posinset={position + 1}
                aria-setsize={visible.length}
                aria-expanded={hasChildren ? isOpen : undefined}
                aria-selected={isSelected}
                aria-current={isSelected ? "page" : undefined}
                aria-disabled={node.disabledReason ? true : undefined}
                // The 특이사항 section's note (partial coverage) is read, not only hovered.
                aria-description={
                  emptyReason ? `결과 없음: ${emptyReason}` : node.id === "flags" ? node.note : undefined
                }
                data-hidden-empty={emptyReason ? "" : undefined}
                title={node.disabledReason ?? (emptyReason ? `결과 없음: ${emptyReason}` : node.note)}
                className={`case-tree-item${isSelected ? " selected" : ""}${node.disabledReason ? " disabled" : ""}${node.count === 0 ? " is-empty" : ""}${node.dimmed || emptyReason ? " is-dimmed" : ""}`}
                style={{
                  paddingInlineStart: `calc(var(--space-2) + ${level - 1} * var(--space-4))`,
                  height: item.size,
                  transform: `translateY(${item.start}px)`,
                }}
                onFocus={() => setFocusedId(node.id)}
                onClick={(event) => {
                  event.stopPropagation();
                  activate(node);
                }}
              >
                {hasChildren ? (
                  <span
                    className="case-tree-twisty"
                    aria-hidden="true"
                    onClick={(event) => {
                      event.stopPropagation();
                      toggle(node.id, !isOpen);
                    }}
                  >
                    <Icon name={isOpen ? "chevron-down" : "chevron-right"} />
                  </span>
                ) : (
                  <span className="case-tree-twisty" aria-hidden="true" />
                )}
                {node.icon ? (
                  <Icon name={node.icon} className="case-tree-icon" />
                ) : (
                  <span className="case-tree-icon" aria-hidden="true" />
                )}
                <span className="case-tree-label">{node.label}</span>
                {node.marker ? (
                  <span className="case-tree-marker" aria-hidden="true">
                    {node.marker}
                  </span>
                ) : null}
                {(() => {
                  // 특이사항 badge (U-F4): strongest grade and its rows; the full split is in the name.
                  const top = topFlag(node.flagCounts);
                  return top && node.flagCounts ? (
                    <span
                      className="case-tree-flag flag-chip"
                      data-grade={top.grade}
                      title={flagCountsText(node.flagCounts)}
                      aria-hidden="true"
                    >
                      <span className="flag-chip-grade">{top.grade}</span>
                      {top.count.toLocaleString("ko-KR")}
                    </span>
                  ) : null;
                })()}
                {/* Counts stay hidden until the first load settles (review #11): no "—" flicker. */}
                {node.count !== undefined && !loading && (
                  <span
                    className={`badge muted${node.strongCount && node.count !== 0 ? " strong" : ""}`}
                    aria-hidden="true"
                  >
                    {typeof node.count === "number" ? node.count.toLocaleString("ko-KR") : node.count}
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      </div>
      {/* The foot stays pinned below the scrolling tree list (scroll review C1). */}
      <div className="evidence-tree-foot">
        {loading ? (
          // Not a live region: the shell's single polite region (announce()) carries status text,
          // and a second polite region while the tree loads broke the one-region rule.
          <p className="case-tree-loading">
            <Icon name="spinner" className="spin" />
            건수와 아티팩트 목록을 불러오는 중…
          </p>
        ) : null}
        <p className="case-tree-reason">{blockedReason}</p>
        {/* The count is final once `/tree` answered (before that, kinds look unknown, not empty). */}
        {treeSettled && emptyView.hiddenCount > 0 ? (
          <button
            type="button"
            className="case-tree-empty-toggle"
            aria-pressed={showEmpty}
            aria-keyshortcuts="T"
            data-testid="tree-empty-toggle"
            title={
              showEmpty
                ? "결과가 없거나 분석되지 않은 계열을 다시 숨깁니다 (T)"
                : "결과가 없거나 분석되지 않은 계열을 흐리게 사유와 함께 표시합니다 (T)"
            }
            onClick={() => {
              const next = !showEmpty;
              setShowEmpty(next);
              announce(
                next
                  ? `결과 없는 계열 ${emptyView.hiddenCount}개를 표시합니다.`
                  : `결과 없는 계열 ${emptyView.hiddenCount}개를 숨겼습니다.`,
              );
            }}
          >
            <Icon name={showEmpty ? "eye" : "list"} />
            <span>
              결과 없는 계열 {emptyView.hiddenCount.toLocaleString("ko-KR")}개 {showEmpty ? "숨김" : "표시"}
            </span>
          </button>
        ) : null}
      </div>
    </div>
  );
}
