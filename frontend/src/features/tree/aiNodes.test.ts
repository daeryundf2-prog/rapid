/**
 * R7 AI 사용 (plan docs/plans/r7-ai-usage-2026-10-27.md §3.5 / Q-AI10, 갈래 D): the "AI 사용" domain —
 * one primary node per AI row type, the browser AI visits moved in (cross-listed under 웹·브라우저),
 * counts from `/tree` per-type counts, 도구·설치 views counted from the presence facets, and a run
 * without AI rows showing every node 0 (hidden by the empty-family rule).
 */
import { describe, expect, it } from "vitest";
import type { RunTree, TreeNode } from "../../api/runs";
import { timestampKindLabel } from "../../utils/timeKinds";
import { AI_TYPES } from "../ai/aiLabels";
import { presenceFacets } from "../ai/aiUsage";
import { artifactTypeLabel } from "../filters/typeLabels";
import { categoryOf } from "./categories";
import {
  AI_KIND,
  AI_USAGE_DOMAIN,
  DOMAINS,
  type DomainNodeDef,
  flattenDomainNodes,
  targetKey,
} from "./domains";
import { buildTreeModel, filterEmptyNodes, type TreeModelNode, UNKNOWN_COUNT } from "./model";

const ai = () => DOMAINS.find((d) => d.id === "ai");
const node = (id: string): DomainNodeDef => {
  const found = flattenDomainNodes(ai()?.nodes ?? []).find((n) => n.id === id);
  if (!found) throw new Error(`ai/${id} missing`);
  return found;
};

/** Fixture counts (frontend/e2e/ai-fixture: tests/fixtures/ai_agents/make_fixtures.py run). */
const FIXTURE_COUNTS: Record<string, number> = {
  "ai-tool-presence": 83,
  "ai-agent-message": 45,
  "ai-credential-presence": 35,
  "ai-agent-session": 28,
  "ai-agent-file-touch": 19,
  "ai-agent-tool-call": 19,
  "ai-mcp-server": 17,
  "ai-instruction-file": 12,
  "ai-account": 7,
  "ai-usage-stat": 6,
  "ai-code-attribution": 4,
  "ai-account-switch": 2,
  "ai-retention-cleanup": 1,
};

function kindNode(kind: string, counts: Record<string, number>): TreeNode {
  return {
    id: `artifacts:${kind}`,
    label: kind,
    count: Object.values(counts).reduce((a, b) => a + b, 0),
    kind,
    collection: "artifacts",
    artifact_type_counts: counts,
  };
}

function runTree(kinds: TreeNode[]): RunTree {
  return {
    run_id: "r1",
    nodes: [
      {
        id: "artifacts",
        label: "아티팩트",
        count: 0,
        children: [{ id: "artifacts-group:other", label: "기타", count: 0, children: kinds }],
      },
    ],
  } as unknown as RunTree;
}

function find(model: TreeModelNode[], id: string): TreeModelNode | undefined {
  for (const item of model) {
    if (item.id === id) return item;
    const hit = find(item.children ?? [], id);
    if (hit) return hit;
  }
  return undefined;
}

describe("AI 사용 domain", () => {
  it("is one domain after 웹·브라우저 with the plan's nodes", () => {
    const ids = DOMAINS.map((d) => d.id);
    expect(ids.indexOf("ai")).toBe(ids.indexOf("web") + 1);
    expect(ai()?.label).toBe("AI 사용");
    const labels = (ai()?.nodes ?? []).map((n) => n.label);
    for (const label of [
      "도구·설치",
      "세션",
      "메시지",
      "도구 호출",
      "파일 접촉",
      "MCP 서버",
      "지침·메모리 파일",
      "자격 증명 존재(값 없음)",
      "계정·전환",
      "AI 코드 기여",
      "사용량",
      "보존 정리",
      "웹 AI 방문",
      "로컬 LLM·모델 파일",
      "미분류 후보",
    ]) {
      expect(labels).toContain(label);
    }
  });

  it("gives every ai-agent row type exactly one primary node (the catch-all reaches the rest)", () => {
    const primaries = flattenDomainNodes(DOMAINS.flatMap((d) => d.nodes)).filter(
      (n) =>
        n.target.kind === AI_KIND &&
        !n.crossRef &&
        !n.children?.length &&
        !n.catchAll &&
        !n.target.cf?.length,
    );
    for (const type of AI_TYPES) {
      expect(primaries.filter((n) => n.target.types?.includes(type)).map((n) => n.id)).toHaveLength(1);
    }
    expect(node("ai-all").catchAll).toBe(true);
    expect(categoryOf(AI_KIND)).toBe("application-usage");
  });

  it("absorbs the browser's AI service nodes (still cross-listed under 웹·브라우저)", () => {
    expect(node("ai-web").target).toMatchObject({
      kind: "browser",
      types: ["browser-ai-usage", "browser-ai-conversation"],
    });
    const web = flattenDomainNodes(DOMAINS.find((d) => d.id === "web")?.nodes ?? []).find(
      (n) => n.id === "web-ai",
    );
    expect(web?.crossRef).toBe(true);
    expect(artifactTypeLabel("browser-ai-usage")).toBe("AI 서비스 방문");
  });

  it("names the types and the new time kinds in Korean (no raw id)", () => {
    expect(artifactTypeLabel("ai-agent-session")).toBe("AI 에이전트 세션");
    expect(artifactTypeLabel("ai-account-switch")).toBe("AI 계정 전환");
    expect(artifactTypeLabel("artifact-ai-account-switch-switched")).toBe("AI 계정 전환 · 계정 전환");
    expect(artifactTypeLabel("artifact-ai-retention-cleanup-cleanup")).toBe("AI 기록 보존 정리 · 보존 정리");
    expect(artifactTypeLabel("artifact-ai-code-attribution-committed")).toBe("AI 코드 기여 · AI 기여 커밋");
    expect(timestampKindLabel("switched")).toBe("계정 전환");
    expect(timestampKindLabel("cleanup")).toBe("보존 정리");
    expect(timestampKindLabel("committed")).toBe("AI 기여 커밋");
  });

  it("counts the fixture's rows per node; the domain total adds each primary once", () => {
    const tree = runTree([kindNode(AI_KIND, FIXTURE_COUNTS)]);
    const model = buildTreeModel({
      tree,
      rowFacets: { [AI_KIND]: { "source:install:": 1, "source:execution:": 0, "source:catalog-path": 14 } },
    });
    expect(find(model, "domain:ai:ai-sessions")?.count).toBe(28);
    expect(find(model, "domain:ai:ai-messages")?.count).toBe(45);
    expect(find(model, "domain:ai:ai-accounts")?.count).toBe(9);
    expect(find(model, "domain:ai:ai-tools")?.count).toBe(83);
    expect(find(model, "domain:ai:ai-tools-install")?.count).toBe(1);
    expect(find(model, "domain:ai:ai-tools-path")?.count).toBe(14);
    expect(find(model, "domain:ai:ai-tools-execution")?.disabledReason).toBeTruthy();
    expect(find(model, "domain:ai")?.count).toBe(278);
  });

  it("shows '—' for a 도구·설치 view while the presence facets are unknown", () => {
    const tree = runTree([kindNode(AI_KIND, FIXTURE_COUNTS)]);
    const model = buildTreeModel({ tree });
    expect(find(model, "domain:ai:ai-tools-install")?.count).toBe(UNKNOWN_COUNT);
  });

  it("a run without AI rows: every AI node 0 and the domain hidden by default", () => {
    const tree = runTree([kindNode("browser", { "browser-history": 5 })]);
    const model = buildTreeModel({ tree, rowFacets: { [AI_KIND]: presenceFacets([]) } });
    const domain = find(model, "domain:ai");
    expect(domain?.hiddenReason).toBeTruthy();
    for (const child of flattenDomainNodes(AI_USAGE_DOMAIN.nodes)) {
      const shown = find(model, `domain:ai:${child.id}`);
      expect(shown?.count === 0 || shown?.count === UNKNOWN_COUNT).toBe(true);
    }
    expect(filterEmptyNodes(model, false).nodes.some((n) => n.id === "domain:ai")).toBe(false);
  });

  it("keeps the 도구·설치 views apart in the selection key", () => {
    const keys = ["ai-tools-all", "ai-tools-install", "ai-tools-execution", "ai-tools-path"].map((id) =>
      targetKey(node(id).target),
    );
    expect(new Set(keys).size).toBe(4);
  });

  it("presence facets count rows per source view", () => {
    const rows = [
      { artifact_type: "ai-tool-presence", details: { source: "install:npm-global" } },
      { artifact_type: "ai-tool-presence", details: { source: "install:msix" } },
      { artifact_type: "ai-tool-presence", details: { source: "execution:prefetch" } },
      { artifact_type: "ai-tool-presence", details: { source: "catalog-path" } },
      { artifact_type: "ai-tool-presence", details: { presence_kind: "tool-home" } },
      { artifact_type: "ai-credential-presence", details: { source: "install:pip" } },
    ];
    expect(presenceFacets(rows)).toEqual({
      "source:install:": 2,
      "source:execution:": 1,
      "source:catalog-path": 1,
    });
  });
});
