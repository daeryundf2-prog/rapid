/** D.1 address contract (T-001, QA-041): 30 deep links round-trip; the stage words never change. */
import { describe, expect, it } from "vitest";
import { isPopoutWindow, POPOUT_PARAM, POPOUT_VALUE } from "../features/viewer/popout/protocol";
import { EXPLORE_VIEWS, isLegacyCaseHash, parseHash, type Route, STAGES, serializeRoute } from "../router";
import { DEEPLINK_CASES, EXPLORE_VIEW_IDS, POPOUT_ADDRESS, STAGE_WORDS } from "./uiContract";

describe("address contract (D.1)", () => {
  it("lists 30 distinct deep links", () => {
    expect(DEEPLINK_CASES).toHaveLength(30);
    expect(new Set(DEEPLINK_CASES.map((c) => c.id)).size).toBe(30);
  });

  it.each(DEEPLINK_CASES)("$id: input → canonical → same route", ({ input, canonical }) => {
    const route = parseHash(input);
    expect(serializeRoute(route)).toBe(canonical);
    // The canonical form opens the same screen and target, and is a fixed point.
    const again = parseHash(canonical);
    expect(again).toEqual(route);
    expect(serializeRoute(again)).toBe(canonical);
    expect(isLegacyCaseHash(canonical)).toBe(false);
  });

  it("serializeRoute writes exactly the five stage words", () => {
    expect([...STAGES]).toEqual([...STAGE_WORDS]);
    const one = (route: Partial<Route>) =>
      serializeRoute({ runId: "r", collection: null, ...route } as Route)
        .split("?")[0]
        ?.split("/")[3];
    expect(
      [
        one({ collection: "intake" }),
        one({ collection: "process" }),
        one({ collection: "files" }),
        one({ collection: "review" }),
        one({ collection: "outputs" }),
      ].sort(),
    ).toEqual([...STAGE_WORDS].sort());
    const written = new Set(DEEPLINK_CASES.map((c) => c.canonical.split("?")[0]?.split("/")[3]));
    for (const word of written) expect(STAGE_WORDS).toContain(word);
  });

  it("keeps the nine explore view ids (additions only)", () => {
    for (const id of EXPLORE_VIEW_IDS) {
      expect(EXPLORE_VIEWS).toContain(id);
      expect(serializeRoute({ runId: "r", collection: id })).toBe(`#/case/r/explore/${id}`);
    }
  });

  it("keeps the viewer window address ?popout=viewer", () => {
    expect({ param: POPOUT_PARAM, value: POPOUT_VALUE }).toEqual(POPOUT_ADDRESS);
    expect(isPopoutWindow(`?${POPOUT_ADDRESS.param}=${POPOUT_ADDRESS.value}`)).toBe(true);
  });
});
