/** 처리 › 예외 항목 tree nodes (R7 갈래 A, Q-A5): counts per list, routes, empty nodes hidden. */

import { describe, expect, it } from "vitest";
import type { IrregularSummary } from "../../api/families";
import { IRREGULAR_IDS } from "../filters/conditionValues";
import { DOMAINS, flattenDomainNodes, targetKey } from "./domains";
import {
  buildTreeModel,
  domainRoute,
  irregularNodeCount,
  NO_IRREGULAR_REASON,
  type TreeModelNode,
} from "./model";

const SUMMARY: IrregularSummary = {
  categories: IRREGULAR_IDS.map((id) => ({
    id,
    label: id,
    help: "",
    count: id === "encrypted" ? 3 : 0,
    files: id === "encrypted" ? 1 : 0,
    candidates: id === "encrypted" ? 1 : 0,
    inventory: 0,
    artifacts: id === "encrypted" ? 2 : 0,
  })),
  total: 3,
  unique_items: 3,
  unique_by_list: { candidates: 1, inventory: 0, artifacts: 2 },
};

function find(nodes: TreeModelNode[], id: string): TreeModelNode | undefined {
  for (const node of nodes) {
    if (node.id === id) return node;
    const hit = find(node.children ?? [], id);
    if (hit) return hit;
  }
  return undefined;
}

describe("처리 › 예외 항목", () => {
  const domain = DOMAINS.find((item) => item.id === "processing");

  it("has one node per category with a files / 전체 파일 / artifacts leaf", () => {
    const nodes = flattenDomainNodes(domain?.nodes ?? []);
    const categories = nodes.filter((node) => /^proc-irregular-[a-z-]+$/.test(node.id) && node.children);
    expect(categories.map((node) => node.target.irregular)).toEqual([...IRREGULAR_IDS]);
    expect(categories.every((node) => /[가-힣]/.test(node.label))).toBe(true);
    expect(categories[0]?.children?.map((leaf) => leaf.label)).toEqual([
      "파일",
      "전체 파일 목록",
      "아티팩트",
    ]);
  });

  it("counts each leaf from the summary and routes it with irregular=", () => {
    const encrypted = (list: string) =>
      flattenDomainNodes(domain?.nodes ?? []).find((node) => node.id === `proc-irregular-encrypted-${list}`);
    const files = encrypted("files");
    const inventory = encrypted("inventory");
    const artifacts = encrypted("artifacts");
    expect(files && irregularNodeCount(files.target, SUMMARY)).toEqual({ count: 1 });
    expect(artifacts && irregularNodeCount(artifacts.target, SUMMARY)).toEqual({ count: 2 });
    expect(inventory && irregularNodeCount(inventory.target, SUMMARY)).toEqual({
      count: 0,
      disabledReason: NO_IRREGULAR_REASON,
    });
    expect(inventory && domainRoute(inventory.target)).toMatchObject({
      collection: "files",
      category: "inventory",
      irregular: ["encrypted"],
    });
    expect(artifacts && domainRoute(artifacts.target)).toEqual({
      collection: "artifacts",
      irregular: ["encrypted"],
    });
    // The group node: artifacts rows in any category.
    const group = flattenDomainNodes(domain?.nodes ?? []).find((node) => node.id === "proc-irregular");
    expect(group && irregularNodeCount(group.target, SUMMARY)).toEqual({ count: 2 });
    expect(irregularNodeCount({ collection: "artifacts", irregular: "encrypted" }, undefined)).toEqual({
      count: undefined,
    });
    // Each category is its own selection.
    expect(targetKey({ collection: "artifacts", irregular: "encrypted" })).not.toBe(
      targetKey({ collection: "artifacts", irregular: "deleted" }),
    );
    expect(targetKey({ collection: "artifacts", irregular: ["encrypted"] })).toBe(
      targetKey({ collection: "artifacts", irregular: "encrypted" }),
    );
  });

  it("hides empty categories by default (U-F7) once the summary is known", () => {
    const model = buildTreeModel({ irregular: SUMMARY });
    expect(find(model, "domain:processing:proc-irregular-encrypted")?.hiddenReason).toBeUndefined();
    expect(find(model, "domain:processing:proc-irregular-deleted")?.hiddenReason).toBe(NO_IRREGULAR_REASON);
    expect(find(model, "domain:processing:proc-irregular-encrypted-artifacts")?.count).toBe(2);
  });
});
