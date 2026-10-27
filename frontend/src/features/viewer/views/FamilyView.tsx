/**
 * 계열 tab (R7 갈래 A, Nuix family view): the row's parent chain, then the family tree — the
 * top-level item, its children and theirs — with the row marked. A row node opens that row
 * (its family listed in the grid, this tab kept); a ZIP entry opens its preview; other virtual
 * entries (archive members without a preview, embedded mail attachments) are shown only.
 */

import type { ReactNode } from "react";
import { type FamilyNode, type FamilyResponse, fetchFamily } from "../../../api/families";
import type { ViewerTarget } from "../../../contracts/viewer";
import { artifactTypeLabel } from "../../filters/typeLabels";
import { familyForType } from "../../flags/catalog";
import { setViewerTarget } from "../adapter";
import { familyRoute, openFamilyRoute } from "../familyNav";
import { familyRefOf } from "../modes";
import { useAsync } from "../useAsync";

/** Node types that are no artifact type of a parser (virtual entries, the files row of a source). */
const NODE_TYPE_LABELS: Readonly<Record<string, string>> = {
  "archive-entry": "압축 항목",
  "source-file": "원본 파일",
  file: "파일",
  "email-attachment": "메일 첨부",
  "email-message": "이메일",
  "carve-row": "카빙 결과",
};

/** Korean type name of a node (never the raw id: unknown types show no type). */
export function nodeTypeLabel(type: string): string {
  if (!type) return "";
  return NODE_TYPE_LABELS[type] ?? artifactTypeLabel(type) ?? familyForType(type)?.label ?? "";
}

function nodeTitle(node: FamilyNode): string {
  return node.title.trim() || nodeTypeLabel(node.artifact_type) || "(이름 없음)";
}

interface FamilyViewProps {
  target: ViewerTarget;
}

export function FamilyView({ target }: FamilyViewProps) {
  const ref = familyRefOf(target);
  // The archive row's own path lets its ZIP entries carry a preview path.
  const sourcePath = target.sourcePath && !target.sourcePath.includes("::") ? target.sourcePath : null;
  const key = ref ? `${target.runId}|${ref}|${sourcePath ?? ""}` : null;
  const state = useAsync<FamilyResponse>(key, (signal) =>
    fetchFamily(target.runId, ref as string, { direction: "family", sourcePath, signal }),
  );
  if (!ref) return <p className="viewer-note">계열은 파일·아티팩트·분석 결과 행에서 볼 수 있습니다.</p>;
  if (state.status === "loading" || state.status === "idle")
    return <p className="viewer-note">계열을 불러오는 중… (처음에는 런 전체를 한 번 훑습니다)</p>;
  if (state.status === "error")
    return (
      <p className="viewer-error" role="alert">
        계열을 불러오지 못했습니다: {state.error}
      </p>
    );
  const data = state.data;
  if (!data.has_family) {
    return (
      <div className="family-view" data-testid="family-view">
        <p className="viewer-note">
          이 항목에는 상위·하위 항목이 없습니다(메일 첨부·압축 항목·백업 항목·카빙 결과 관계가 없는 단독
          항목).
        </p>
      </div>
    );
  }
  const open = (node: FamilyNode) => openNode(target, data, node);
  const ancestors = [...(data.ancestors ?? [])].reverse();
  const counts = data.counts;
  return (
    <div className="family-view" data-testid="family-view">
      {counts ? (
        <p className="family-summary">
          {`계열 ${counts.members.toLocaleString("ko-KR")}개 항목 · 하위 ${counts.descendants.toLocaleString("ko-KR")}개`}
          {counts.members - counts.material > 0 ? ` · 비중요 ${counts.members - counts.material}개` : ""}
          {data.is_top ? " · 이 항목이 상위 항목" : ""}
        </p>
      ) : null}
      {ancestors.length ? (
        <nav className="family-ancestors" aria-label="상위 항목">
          <span className="family-label">상위 항목</span>
          <ol>
            {ancestors.map((node) => (
              <li key={node.ref}>
                <NodeButton node={node} current={false} onOpen={open} />
              </li>
            ))}
          </ol>
        </nav>
      ) : null}
      {data.tree ? (
        <section className="family-tree" aria-label="계열">
          <ul aria-label="계열 항목">
            <TreeNode node={data.tree} currentRef={data.ref} level={1} onOpen={open} />
          </ul>
          {data.tree_truncated ? <p className="viewer-note">항목이 많아 일부만 표시합니다.</p> : null}
        </section>
      ) : null}
    </div>
  );
}

function TreeNode({
  node,
  currentRef,
  level,
  onOpen,
}: {
  node: FamilyNode;
  currentRef: string;
  level: number;
  onOpen: (node: FamilyNode) => void;
}): ReactNode {
  const children = node.items ?? [];
  return (
    <li data-level={level}>
      <NodeButton node={node} current={node.ref === currentRef} onOpen={onOpen} />
      {children.length ? (
        <ul>
          {children.map((child) => (
            <TreeNode
              key={child.ref}
              node={child}
              currentRef={currentRef}
              level={level + 1}
              onOpen={onOpen}
            />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

function NodeButton({
  node,
  current,
  onOpen,
}: {
  node: FamilyNode;
  current: boolean;
  onOpen: (node: FamilyNode) => void;
}) {
  const type = nodeTypeLabel(node.artifact_type);
  const previewable = Boolean(node.source_path);
  const actionable = !current && (node.navigable || previewable);
  const hint = current
    ? "지금 보는 항목"
    : node.navigable
      ? "이 행으로 이동"
      : previewable
        ? "압축 항목 미리보기"
        : node.collection === "source"
          ? "행으로 기록되지 않은 원본 파일입니다"
          : "행이 아닌 하위 항목입니다(미리보기 없음)";
  return (
    <button
      type="button"
      className={`family-node${current ? " is-current" : ""}${node.material ? "" : " is-immaterial"}`}
      aria-current={current ? "true" : undefined}
      aria-disabled={actionable ? undefined : true}
      title={hint}
      data-family-ref={node.ref}
      onClick={() => {
        if (actionable) onOpen(node);
      }}
    >
      <span className="family-node-title">{nodeTitle(node)}</span>
      {type ? <span className="family-node-type">{type}</span> : null}
      {node.relation_label ? <span className="family-node-relation">{node.relation_label}</span> : null}
      {node.material ? null : <span className="family-node-badge">비중요</span>}
      {node.virtual && node.collection !== "source" ? (
        <span className="family-node-badge">행 아님</span>
      ) : null}
      {node.children ? <span className="family-node-count">{`하위 ${node.children}`}</span> : null}
    </button>
  );
}

/** Open a node: a row → its family listed with that row in this tab; a ZIP entry → its preview. */
export function openNode(target: ViewerTarget, data: FamilyResponse, node: FamilyNode): void {
  if (node.navigable) {
    const route = familyRoute(target.runId, node.ref, data.top.ref);
    if (route) openFamilyRoute(route);
    return;
  }
  if (node.source_path) {
    setViewerTarget(
      {
        runId: target.runId,
        ref: { collection: "artifacts", kind: node.kind, locator: node.locator },
        sourcePath: node.source_path,
        preferredMode: "source",
      },
      null,
    );
  }
}
