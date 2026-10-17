// scripts/gen-families-fallback.mjs (review #10): --if-available skips only when Python or the
// loader module is missing; a loader error always fails. A shadow `yaml` package on PYTHONPATH
// (ahead of site-packages) simulates both without touching the real catalogue.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const script = resolve(__dirname, "../../../scripts/gen-families-fallback.mjs");
const python = process.env.RAPIDTRIAGE_PYTHON || "python";
const hasPython = spawnSync(python, ["--version"]).status === 0;
const dirs: string[] = [];

function shadowYaml(body: string): string {
  const dir = mkdtempSync(join(tmpdir(), "rt-gen-test-"));
  dirs.push(dir);
  mkdirSync(join(dir, "yaml"));
  writeFileSync(join(dir, "yaml", "__init__.py"), body);
  return dir;
}

function run(args: string[], env: Record<string, string>) {
  return spawnSync(process.execPath, [script, ...args], {
    env: { ...process.env, ...env },
    encoding: "utf8",
  });
}

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe.skipIf(!hasPython)("gen-families-fallback", () => {
  it("a loader error fails even with --if-available (no stale catalogue ships)", () => {
    const result = run(["--if-available", "--check"], {
      PYTHONPATH: shadowYaml("raise ValueError('bad yaml')"),
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("ValueError: bad yaml");
  });

  it("a missing loader module is skipped with --if-available, fails without it", () => {
    const missing = "raise ModuleNotFoundError('No module named yaml', name='yaml')";
    const skipped = run(["--if-available", "--check"], { PYTHONPATH: shadowYaml(missing) });
    expect(skipped.status).toBe(0);
    expect(skipped.stderr).toContain("module missing: yaml");
    expect(run(["--check"], { PYTHONPATH: shadowYaml(missing) }).status).toBe(1);
  });

  it("no Python at all is skipped with --if-available", () => {
    const result = run(["--if-available"], { RAPIDTRIAGE_PYTHON: "no-such-python-binary" });
    expect(result.status).toBe(0);
    expect(result.stderr).toContain("skipped");
  });
});
