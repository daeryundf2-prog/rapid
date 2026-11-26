import { describe, expect, it } from "vitest";
import { DOMAINS, flattenDomainNodes } from "../tree/domains";
import { artifactTypeLabel } from "./typeLabels";

describe("artifactTypeLabel", () => {
  it("names every artifact type a tree node targets (no raw ids in the 유형 column)", () => {
    const types = new Set<string>();
    for (const domain of DOMAINS)
      for (const node of flattenDomainNodes(domain.nodes))
        for (const type of node.target.types ?? []) types.add(type);
    const unnamed = [...types].filter((type) => artifactTypeLabel(type) === null).sort();
    expect(unnamed).toEqual([]);
  });
});
