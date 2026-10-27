import { describe, expect, it } from "vitest";
import { searchCollection } from "./columns/search";

const map = (raw: Record<string, unknown>, index = 0) =>
  searchCollection.mapRow(raw, index, { ref: { id: "search" } });

describe("R7 S2 #6: archive entry hits get their own row key", () => {
  const parents = [3, 4, 5].map((n) => ({
    source: "files",
    kind: "archive",
    path: `C:\\data\\a${n}.zip`,
    locator: { collection: "files", kind: "", pointer: `/candidates/${n}` },
  }));

  it("12 entries (entry_path on the shared parent locator) + 3 parents → 15 distinct keys", () => {
    const entries = Array.from({ length: 12 }, (_, i) => ({
      ...parents[i % 3],
      entry_path: `dir/file-${i}.txt`,
    }));
    const keys = [...parents, ...entries].map((raw, i) => map(raw, i).rowKey);
    expect(new Set(keys).size).toBe(15);
    expect(map(entries[0] as Record<string, unknown>).fields.entryPath).toBe("dir/file-0.txt");
  });

  it("12 entries with an entry locator (<parent>#entry:<n>) + 3 parents → 15 distinct keys", () => {
    const entries = Array.from({ length: 12 }, (_, i) => {
      const parent = parents[i % 3] as (typeof parents)[number];
      return {
        ...parent,
        locator: { ...parent.locator, pointer: `${parent.locator.pointer}#entry:${i}` },
      };
    });
    const keys = [...parents, ...entries].map((raw, i) => map(raw, i).rowKey);
    expect(new Set(keys).size).toBe(15);
    // The entry locator already makes the key unique: no duplicated suffix.
    expect(map(entries[0] as Record<string, unknown>).rowKey).toBe("search:files::/candidates/3#entry:0");
  });

  it("a hit without entry information keeps its old key", () => {
    expect(map(parents[0] as Record<string, unknown>).rowKey).toBe("search:files::/candidates/3");
  });
});
