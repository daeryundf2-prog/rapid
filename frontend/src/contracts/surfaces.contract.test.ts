/**
 * D.4 / D.9 / D.11 contracts (T-001): accessible names and landmarks, browser storage keys, popout
 * viewer message kinds — plus the extractor's freshness check (QA-111 ②).
 */
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { GLOBAL_SEARCH_ID, MAIN_ID, VIEWER_ID } from "../commands/builtin";
import { STAGE_HEADING_ID } from "../features/stages/stages";
import { isMainToPopout, isPopoutToMain } from "../features/viewer/popout/protocol";
import { A11Y_NAME_TABLE, A11Y_NAMES, LANDMARK_IDS, POPOUT_MESSAGES, STORAGE_KEYS } from "./uiContract";

const SRC = resolve(__dirname, "..");
const SCRIPT = resolve(SRC, "../../scripts/extract-ui-contract.mjs");
const read = (file: string) => readFileSync(join(SRC, file), "utf8");

function sourceFiles(dir = SRC): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(path));
    else if (/\.(ts|tsx)$/.test(entry.name) && !/\.test\.(ts|tsx)$/.test(entry.name)) out.push(path);
  }
  return out;
}

const SOURCE = sourceFiles()
  .filter((path) => !path.endsWith(join("contracts", "uiContract.ts")))
  .map((path) => ({ file: relative(SRC, path).replace(/\\/g, "/"), text: readFileSync(path, "utf8") }));

describe("accessible-name contract (D.4)", () => {
  it.each(A11Y_NAMES)("$name ($role) is given by $file", ({ name, file }) => {
    expect(read(file)).toContain(`"${name}"`);
  });

  it("every name an e2e spec queries (keep) is still in the source", () => {
    const all = SOURCE.map((s) => s.text).join("\n");
    const missing = A11Y_NAME_TABLE.filter(
      ([, name, use, presence]) => use === "keep" && presence === "source" && !all.includes(name),
    ).map(([role, name]) => `${role}: ${name}`);
    expect(missing).toEqual([]);
  });

  it("keeps the landmark ids", () => {
    expect([MAIN_ID, VIEWER_ID, STAGE_HEADING_ID, GLOBAL_SEARCH_ID]).toEqual([...LANDMARK_IDS]);
  });
});

describe("storage-key contract (D.9)", () => {
  const literal = (key: string) => key.replace(/<…>$/, "");

  it.each(STORAGE_KEYS)("$key ($area) lives in $file", ({ key, area, file }) => {
    const text = read(file);
    expect(text).toContain(literal(key));
    if (area === "session") expect(text).toContain("sessionStorage");
  });

  it("every storage key in the source is registered here", () => {
    const found = new Set<string>();
    for (const { text } of SOURCE) {
      for (const match of text.matchAll(/["`]((?:rapidtriage|rt)\.[A-Za-z0-9_.-]+(?:\$\{[^}]*\})?)["`]/g)) {
        found.add((match[1] ?? "").replace(/\$\{[^}]*\}$/, "<…>"));
      }
    }
    expect([...found].sort()).toEqual(STORAGE_KEYS.map((entry) => entry.key).sort());
    expect(STORAGE_KEYS.filter((entry) => entry.area === "session")).toHaveLength(4);
  });
});

describe("popout message contract (D.11)", () => {
  const sample: Record<string, Record<string, unknown>> = {
    state: { target: null, row: null, tz: "utc", theme: null, runId: null },
    history: { target: null, row: null },
    mode: { mode: "hex" },
    command: { id: "review.mark.relevant" },
    invalidate: { runId: "r" },
    navigate: { hash: "#/case/r/intake" },
  };

  it.each(POPOUT_MESSAGES.mainToPopout)("main → popout: %s", (type) => {
    expect(isMainToPopout({ type, ...sample[type] })).toBe(true);
  });

  it.each(POPOUT_MESSAGES.popoutToMain)("popout → main: %s", (type) => {
    expect(isPopoutToMain({ type, ...sample[type] })).toBe(true);
  });

  it("the protocol declares exactly these kinds", () => {
    const text = read("features/viewer/popout/protocol.ts");
    const kinds = (name: string) =>
      [
        ...(new RegExp(`export type ${name} =([\\s\\S]*?);\\n`).exec(text)?.[1] ?? "").matchAll(
          /type:\s*"([\w-]+)"/g,
        ),
      ].map((m) => m[1]);
    expect(kinds("PopoutToMain")).toEqual([...POPOUT_MESSAGES.popoutToMain]);
    expect(["state", ...kinds("MainToPopout")]).toEqual([...POPOUT_MESSAGES.mainToPopout]);
  });
});

describe("extractor (QA-111 ②)", () => {
  it("uiContract.ts matches scripts/extract-ui-contract.mjs --check", () => {
    const result = spawnSync(process.execPath, [SCRIPT, "--check"], { encoding: "utf8" });
    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
  });
});
