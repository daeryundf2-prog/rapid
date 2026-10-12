import { type KeyboardEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { announce } from "../../a11y";
import { focusGridWhenReady } from "../../commands/builtin";
import { Icon } from "../../icons";
import { useAppStore } from "../../state/store";
import { navigate } from "./adapter";
import { targetKey } from "./domains";
import { flattenVisible, type TreeModelNode, UNKNOWN_COUNT } from "./model";
import { useTreeState } from "./useTreeModel";
import "./tree.css";

const DEFAULT_EXPANDED = ["evidence", "views", "search"];
const TYPE_AHEAD_RESET_MS = 600;

function treeItemLabel(node: TreeModelNode): string {
  const label = node.marker ? `${node.label} (${node.marker})` : node.label;
  if (node.count === undefined) return label;
  if (node.count === UNKNOWN_COUNT) return `${label}, 건수 미상`;
  return typeof node.count === "number"
    ? `${label}, ${node.count.toLocaleString("ko-KR")}건`
    : `${label}, 진행 ${node.count}`;
}

export function EvidenceTree({ runId }: { runId: string }) {
  const { model, loading } = useTreeState(runId);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(DEFAULT_EXPANDED));
  const [focusedId, setFocusedId] = useState<string>("views");
  const [blockedReason, setBlockedReason] = useState("");
  const refs = useRef(new Map<string, HTMLLIElement>());
  const typeAhead = useRef({ buffer: "", timer: 0 });

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
    walk(model, []);
    return { keep, open };
  }, [model, needle]);
  const visible = useMemo(() => {
    if (!searchView) return flattenVisible(model, expanded);
    const shown = new Set([...expanded, ...searchView.open]);
    return flattenVisible(model, shown).filter((entry) => searchView.keep.has(entry.node.id));
  }, [model, expanded, searchView]);
  // The roving tab stop falls back to the first node when the focused one is not shown.
  const tabStopId = visible.some((entry) => entry.node.id === focusedId) ? focusedId : visible[0]?.node.id;

  const focusNode = useCallback((id: string) => {
    setFocusedId(id);
    refs.current.get(id)?.focus();
  }, []);

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

  const routeKey = useAppStore((s) =>
    s.route.runId === runId && s.route.collection
      ? targetKey({ ...s.route, collection: s.route.collection })
      : "",
  );
  // One selected node: the first (DFS order) whose key is the route's — the 전체 보기 views come
  // before the domain nodes that repeat them (전체 파일, IOC).
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
    return routeKey ? visit(model) : null;
  }, [model, routeKey]);
  const selected = (node: TreeModelNode) => node.id === selectedId;

  // Open the domain that holds the selected node (deep links, 결과 보기 →).
  useEffect(() => {
    if (!selectedId) return;
    for (const parent of model) {
      if (parent.children?.some((child) => child.id === selectedId)) {
        setExpanded((prev) => (prev.has(parent.id) ? prev : new Set([...prev, parent.id])));
      }
    }
  }, [model, selectedId]);

  return (
    <div className="case-tree" data-testid="evidence-tree">
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
      {/* biome-ignore lint/a11y/noNoninteractiveElementToInteractiveRole: ul is the ARIA tree container */}
      <ul role="tree" aria-label="케이스 탐색 트리" onKeyDown={onKeyDown}>
        {visible.map(({ node, level }, position) => {
          const hasChildren = Boolean(node.children?.length);
          const isOpen = expanded.has(node.id) || Boolean(searchView?.open.has(node.id));
          const isSelected = selected(node);
          return (
            // biome-ignore lint/a11y/useKeyWithClickEvents: keyboard handled by the tree root (arrows/Enter/Space)
            <li
              key={node.id}
              role="treeitem"
              data-node-id={node.id}
              ref={(el) => {
                if (el) refs.current.set(node.id, el);
                else refs.current.delete(node.id);
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
              title={node.disabledReason}
              className={`case-tree-item${isSelected ? " selected" : ""}${node.disabledReason ? " disabled" : ""}${node.count === 0 ? " is-empty" : ""}`}
              style={{ paddingInlineStart: `calc(var(--space-2) + ${level - 1} * var(--space-4))` }}
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
              {node.icon ? <Icon name={node.icon} className="case-tree-icon" /> : null}
              <span className="case-tree-label">{node.label}</span>
              {node.marker ? (
                <span className="case-tree-marker" aria-hidden="true">
                  {node.marker}
                </span>
              ) : null}
              {node.count !== undefined && (
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
      {loading ? (
        <p className="case-tree-loading" role="status">
          <Icon name="spinner" className="spin" />
          건수와 아티팩트 목록을 불러오는 중…
        </p>
      ) : null}
      <p className="case-tree-reason">{blockedReason}</p>
    </div>
  );
}
