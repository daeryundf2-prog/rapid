/** D.5 shortcut contract (T-001): every frozen KEY_MAP action keeps its key. */
import { describe, expect, it } from "vitest";
import { KEY_MAP } from "./command";
import { KEY_MAP_CONTRACT } from "./uiContract";

describe("shortcut contract (D.5)", () => {
  it.each(Object.entries(KEY_MAP_CONTRACT))("%s stays %s", (action, key) => {
    expect((KEY_MAP as Record<string, string>)[action]).toBe(key);
  });

  it("a new action never takes a frozen key", () => {
    const frozen = new Set<string>(Object.values(KEY_MAP_CONTRACT));
    for (const [action, key] of Object.entries(KEY_MAP)) {
      if (!(action in KEY_MAP_CONTRACT)) expect(frozen.has(key), `${action} → ${key}`).toBe(false);
    }
  });

  it("Alt+1..5 are the five stages", () => {
    expect([
      KEY_MAP.stageIntake,
      KEY_MAP.stageProcess,
      KEY_MAP.stageExplore,
      KEY_MAP.stageReview,
      KEY_MAP.stageReport,
    ]).toEqual(["Alt+1", "Alt+2", "Alt+3", "Alt+4", "Alt+5"]);
  });
});
