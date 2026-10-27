/** 중복 · 계열 columns (R7 갈래 A): the listing's annotations read in Korean, empty without them. */

import { describe, expect, it } from "vitest";
import { artifactsCollection } from "./artifacts";
import { dedupText, familyDedupColumns, familyText } from "./familyDedup";
import { filesCollection } from "./files";

const ctx = { ref: { id: "artifacts", kind: "email" } } as const;

describe("중복 · 계열 cells", () => {
  it("map the API annotations of artifacts and files rows", () => {
    const attachment = artifactsCollection.mapRow(
      {
        artifact_type: "email-attachment",
        record_index: 2,
        details: { filename: "a.pdf" },
        family: {
          parent: "artifacts:email:/artifacts/1",
          parent_title: "견적서 송부",
          relation: "attachment",
          children: 0,
          top: "artifacts:email:/artifacts/1",
        },
        dedup: { status: "duplicate", count: 6 },
      },
      2,
      ctx,
    );
    expect(familyText(attachment)).toBe("첨부 · 상위: 견적서 송부");
    expect(dedupText(attachment)).toBe("중복(6건 중)");
    const file = filesCollection.mapRow(
      {
        path: "C:\\copy\\a.pdf",
        name: "a.pdf",
        record_index: 2,
        dedup: { status: "original", count: 6 },
        family: {
          parent: null,
          parent_title: null,
          relation: null,
          children: 2,
          top: "files::/candidates/2",
        },
      },
      2,
      { ref: { id: "files" } },
    );
    expect(dedupText(file)).toBe("원본 · 중복 5건");
    expect(familyText(file)).toBe("하위 2개");
    const unique = filesCollection.mapRow(
      { path: "C:\\b", name: "b", record_index: 3, dedup: { status: "original", count: 1 } },
      3,
      {
        ref: { id: "files" },
      },
    );
    expect(dedupText(unique)).toBe("—");
    const plain = filesCollection.mapRow({ path: "C:\\c", name: "c", record_index: 4 }, 4, {
      ref: { id: "files" },
    });
    expect(dedupText(plain)).toBe("");
    expect(familyText(plain)).toBe("");
  });

  it("are default columns that read no raw relation ids", () => {
    const columns = familyDedupColumns();
    expect(columns.map((c) => [c.id, c.header, c.presets])).toEqual([
      ["dedup", "중복", ["analysis"]],
      ["family", "계열", ["analysis"]],
    ]);
    const odd = artifactsCollection.mapRow(
      {
        artifact_type: "x",
        record_index: 0,
        details: {},
        family: {
          parent: "artifacts:k:/artifacts/1",
          parent_title: "",
          relation: "weird-new-relation",
          children: 0,
          top: "artifacts:k:/artifacts/1",
        },
      },
      0,
      ctx,
    );
    expect(familyText(odd)).toBe("상위: 상위 항목");
  });
});
