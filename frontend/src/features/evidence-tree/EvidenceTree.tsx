import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { getRunTree, type TreeNode } from "../../api/runs";
import { useUiStore } from "../../state/ui";

export function EvidenceTree() {
  const selectedRunId = useUiStore((s) => s.selectedRunId);
  const selectedNode = useUiStore((s) => s.selectedNode);
  const selectNode = useUiStore((s) => s.selectNode);
  const [hideEmpty, setHideEmpty] = useState(true);

  const treeQuery = useQuery({
    queryKey: ["run-tree", selectedRunId],
    queryFn: () => getRunTree(selectedRunId as string),
    enabled: Boolean(selectedRunId),
  });

  if (!selectedRunId) {
    return null;
  }
  if (treeQuery.isPending) {
    return <p className="pane-empty">트리를 불러오는 중…</p>;
  }
  if (treeQuery.isError) {
    return <p className="pane-empty">트리를 불러오지 못했습니다.</p>;
  }

  const nodes = treeQuery.data.nodes;
  return (
    <div className="evidence-tree" data-testid="evidence-tree">
      <div className="tree-toolbar">
        <label className="tree-toggle">
          <input type="checkbox" checked={hideEmpty} onChange={(e) => setHideEmpty(e.target.checked)} />
          0건 숨기기
        </label>
      </div>
      <ul className="tree-root" aria-label="증거 트리">
        {nodes.map((node) => (
          <TreeItem
            key={node.id}
            node={node}
            depth={0}
            hideEmpty={hideEmpty}
            selectedId={selectedNode?.id ?? null}
            onSelect={selectNode}
          />
        ))}
      </ul>
    </div>
  );
}

function TreeItem({
  node,
  depth,
  hideEmpty,
  selectedId,
  onSelect,
}: {
  node: TreeNode;
  depth: number;
  hideEmpty: boolean;
  selectedId: string | null;
  onSelect: (node: TreeNode) => void;
}) {
  const [expanded, setExpanded] = useState(depth === 0);
  const children = (node.children ?? []).filter((c) => !hideEmpty || c.count > 0 || hasItems(c));
  const selectable = Boolean(node.collection) || children.length === 0;

  return (
    <li>
      <div
        className={`tree-row${node.id === selectedId ? " selected" : ""}${node.count === 0 ? " empty" : ""}`}
        style={{ paddingLeft: `calc(var(--space-2) + ${depth} * var(--space-5))` }}
      >
        {children.length > 0 ? (
          <button
            type="button"
            className="tree-disclosure"
            aria-label={expanded ? "접기" : "펼치기"}
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? "▾" : "▸"}
          </button>
        ) : (
          <span className="tree-disclosure-spacer" />
        )}
        <button
          type="button"
          className="tree-label"
          disabled={!selectable}
          onClick={() => selectable && onSelect(node)}
        >
          {node.label}
        </button>
        <span className="badge muted">{node.count.toLocaleString("ko-KR")}</span>
      </div>
      {expanded && children.length > 0 && (
        <ul>
          {children.map((child) => (
            <TreeItem
              key={child.id}
              node={child}
              depth={depth + 1}
              hideEmpty={hideEmpty}
              selectedId={selectedId}
              onSelect={onSelect}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

function hasItems(node: TreeNode): boolean {
  if (node.count > 0) {
    return true;
  }
  return (node.children ?? []).some(hasItems);
}
