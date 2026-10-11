import { type KeyboardEvent, useCallback, useMemo, useRef, useState } from "react";
import { announce } from "../../a11y";
import { Icon } from "../../icons";
import { type CaseRoute, navigate, sameRoute, useRoute } from "./adapter";
import { flattenVisible, type TreeModelNode } from "./model";
import { useTreeState } from "./useTreeModel";
import "./tree.css";

const DEFAULT_EXPANDED = ["evidence", "search", "artifacts", "review"];
const TYPE_AHEAD_RESET_MS = 600;

function treeItemLabel(node: TreeModelNode): string {
  const label = node.marker ? `${node.label} (${node.marker})` : node.label;
  if (node.count === undefined) return label;
  return typeof node.count === "number"
    ? `${label}, ${node.count.toLocaleString("ko-KR")}건`
    : `${label}, 진행 ${node.count}`;
}

export function EvidenceTree({ runId }: { runId: string }) {
  const route = useRoute();
  const { model, loading } = useTreeState(runId);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(DEFAULT_EXPANDED));
  const [focusedId, setFocusedId] = useState<string>("intake");
  const [blockedReason, setBlockedReason] = useState("");
  const refs = useRef(new Map<string, HTMLLIElement>());
  const typeAhead = useRef({ buffer: "", timer: 0 });

  const visible = useMemo(() => flattenVisible(model, expanded), [model, expanded]);

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
      if (node.activate) node.activate();
      else navigate({ runId, ...node.route });
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

  const selected = (node: TreeModelNode) =>
    !node.noSelect && sameRoute(route, { runId, ...node.route } as CaseRoute);

  return (
    <div className="case-tree" data-testid="evidence-tree">
      {/* biome-ignore lint/a11y/noNoninteractiveElementToInteractiveRole: ul is the ARIA tree container */}
      <ul role="tree" aria-label="케이스 탐색 트리" onKeyDown={onKeyDown}>
        {visible.map(({ node, level }, position) => {
          const hasChildren = Boolean(node.children?.length);
          const isOpen = expanded.has(node.id);
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
              tabIndex={focusedId === node.id ? 0 : -1}
              aria-label={treeItemLabel(node)}
              aria-level={level}
              aria-posinset={position + 1}
              aria-setsize={visible.length}
              aria-expanded={hasChildren ? isOpen : undefined}
              aria-selected={isSelected}
              aria-current={isSelected ? "page" : undefined}
              aria-disabled={node.disabledReason ? true : undefined}
              title={node.disabledReason}
              className={`case-tree-item${isSelected ? " selected" : ""}${node.disabledReason ? " disabled" : ""}`}
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
                  {isOpen ? "▾" : "▸"}
                </span>
              ) : (
                <span className="case-tree-twisty" aria-hidden="true" />
              )}
              {node.icon ? <Icon name={node.icon} size={14} className="case-tree-icon" /> : null}
              <span className="case-tree-label">{node.label}</span>
              {node.marker ? (
                <span className="case-tree-marker" aria-hidden="true">
                  {node.marker}
                </span>
              ) : null}
              {node.count !== undefined && (
                <span className={`badge muted${node.strongCount ? " strong" : ""}`} aria-hidden="true">
                  {typeof node.count === "number" ? node.count.toLocaleString("ko-KR") : node.count}
                </span>
              )}
            </li>
          );
        })}
      </ul>
      {loading ? (
        <p className="case-tree-loading" role="status">
          <Icon name="spinner" size={14} className="spin" />
          건수와 아티팩트 목록을 불러오는 중…
        </p>
      ) : null}
      <p className="case-tree-reason">{blockedReason}</p>
    </div>
  );
}
