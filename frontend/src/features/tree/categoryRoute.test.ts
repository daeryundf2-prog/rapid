import { describe, expect, it } from "vitest";
import { collectionChanged, parseHash, serializeRoute } from "../../router";

describe("category route (X11)", () => {
  it("parses and serialises ?category= on the artifacts node only", () => {
    const route = parseHash("#/case/r1/explore/artifacts?category=web");
    expect(route).toMatchObject({ runId: "r1", collection: "artifacts", category: "web" });
    expect(serializeRoute(route)).toBe("#/case/r1/explore/artifacts?category=web");
    // Files take a category too (GET /files?category=<id>).
    expect(parseHash("#/case/r1/explore/files?category=images").category).toBe("images");
    expect(parseHash("#/case/r1/explore/timeline?category=web").category).toBeUndefined();
    expect(parseHash("#/case/r1/explore/artifacts/eventlog?category=web").category).toBeUndefined();
    expect(serializeRoute({ runId: "r1", collection: "artifacts", kind: "eventlog", category: "web" })).toBe(
      "#/case/r1/explore/artifacts/eventlog",
    );
  });

  it("treats a category change as a new grid", () => {
    expect(
      collectionChanged(
        { runId: "r1", collection: "artifacts", category: "web" },
        { runId: "r1", collection: "artifacts", category: "media" },
      ),
    ).toBe(true);
  });
});
