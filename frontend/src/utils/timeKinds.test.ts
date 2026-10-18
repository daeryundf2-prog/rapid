import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { timestampKindLabel } from "./timeKinds";

const REPO_ROOT = join(__dirname, "..", "..", "..");
const HANGUL = /[가-힣]/;

/** R2 parsers whose `timestamp_kind` values reach the timeline grid / record chips. */
const PARSER_SOURCES = [
  "rapidtriage/artifacts/windows/messenger.py",
  "rapidtriage/artifacts/kakaotalk_messages.py",
  "rapidtriage/artifacts/kakaotalk_windows.py",
  "rapidtriage/artifacts/email_pst.py",
  "rapidtriage/artifacts/email.py",
  "rapidtriage/artifacts/cloud_sync.py",
  "rapidtriage/artifacts/cloud.py",
  "rapidtriage/artifacts/windows/browser_cache.py",
  "rapidtriage/artifacts/windows/browser_webcache.py",
  "rapidtriage/artifacts/windows/browser.py",
];
const TIMELINE_SOURCE = "rapidtriage/core/timeline.py";
const CATALOG_YAMLS = ["messenger", "email", "cloud", "browser"].map(
  (name) => `rapidtriage/core/triage_rules/catalog/${name}.yaml`,
);

/** Kinds built from f-strings (cloud_sync.py f"cloud-{operation}" over OPERATION_LABELS). */
const CLOUD_OPERATIONS = ["upload", "download", "delete", "rename", "share"];

const R2_KINDS = [
  "sent",
  "message",
  "saved",
  ...CLOUD_OPERATIONS.map((operation) => `cloud-${operation}`),
  "cloud-modified",
  "cloud-viewed",
  "cloud-shared-with-me",
  "cache-response",
  "cache-created",
  "cache-last-used",
  "cache-stored",
  "download-started",
];

function read(relative: string): string {
  return readFileSync(join(REPO_ROOT, relative), "utf8");
}

/** `"a"` or `"a" if <cond> else "b"` right after an assignment / tuple slot. */
const LITERAL_OR_TERNARY = String.raw`"([^"{}]*)"(?:\s+if\s+[^\n]*?\belse\s+"([^"{}]*)")?`;
const PYTHON_KIND_PATTERNS = [
  // timestamp_kind="x" (keyword argument)
  new RegExp(String.raw`\btimestamp_kind\s*=\s*${LITERAL_OR_TERNARY}`, "g"),
  // "timestamp_kind": "x" (dict entry)
  new RegExp(String.raw`["']timestamp_kind["']\s*:\s*${LITERAL_OR_TERNARY}`, "g"),
  // kind = "x" (browser.py cache_entry_record, passed on as timestamp_kind=kind)
  new RegExp(String.raw`^\s*kind\s*=\s*${LITERAL_OR_TERNARY}`, "gm"),
  // return mapped, <time>, "x" [if .. else "y"], common (browser_webcache.py row mappers)
  new RegExp(String.raw`return\s+mapped,\s*[^,\n]+,\s*${LITERAL_OR_TERNARY}`, "g"),
];

function pythonKinds(source: string): string[] {
  const kinds: string[] = [];
  for (const pattern of PYTHON_KIND_PATTERNS) {
    for (const match of source.matchAll(pattern)) {
      for (const value of [match[1], match[2]]) if (value) kinds.push(value);
    }
  }
  return kinds;
}

/** Keys of cloud_sync.py OPERATION_LABELS (the `{operation}` of f"cloud-{operation}"). */
function cloudOperationKinds(source: string): string[] {
  const block = /OPERATION_LABELS[^=]*=\s*\{([\s\S]*?)\}/.exec(source)?.[1] ?? "";
  return [...block.matchAll(/"([a-z-]+)"\s*:/g)].map((match) => `cloud-${match[1]}`);
}

/** Second positional argument (the label) of every F("path", "label", ...) entry. */
function timelineKinds(source: string): string[] {
  return [...source.matchAll(/\bF\(\s*f?"[^"]*",\s*"([^"{}]+)"/g)].map((match) => match[1] as string);
}

function yamlKinds(source: string): string[] {
  return [...source.matchAll(/^\s*ts_kind:\s*["']?([A-Za-z0-9_-]+)/gm)].map((match) => match[1] as string);
}

function unlabeled(kinds: Iterable<string>): string[] {
  return [...new Set(kinds)].filter((kind) => {
    const label = timestampKindLabel(kind);
    return label === kind || !HANGUL.test(label);
  });
}

describe("timestampKindLabel", () => {
  it("gives every R2 timestamp kind a Korean label", () => {
    expect(unlabeled(R2_KINDS)).toEqual([]);
  });

  it("labels numbered run slots and keeps unknown kinds", () => {
    expect(timestampKindLabel("run-3")).toBe("실행 3회차");
    expect(timestampKindLabel("not-a-kind")).toBe("not-a-kind");
    expect(timestampKindLabel("")).toBe("");
  });

  it("labels every literal kind emitted by the R2 parsers", () => {
    const kinds = PARSER_SOURCES.flatMap((path) => pythonKinds(read(path)));
    const cloud = cloudOperationKinds(read("rapidtriage/artifacts/cloud_sync.py"));
    // Guard the extractors themselves: a regex drift must not silently pass with nothing found.
    expect(kinds).toEqual(
      expect.arrayContaining(["sent", "cache-response", "cache-stored", "download-started"]),
    );
    expect(cloud).toEqual(expect.arrayContaining(CLOUD_OPERATIONS.map((operation) => `cloud-${operation}`)));
    expect(unlabeled([...kinds, ...cloud])).toEqual([]);
  });

  it("labels every TIMELINE_FIELD_MAP kind", () => {
    const kinds = timelineKinds(read(TIMELINE_SOURCE));
    expect(kinds).toEqual(expect.arrayContaining(["message", "saved", "cloud-viewed", "run"]));
    expect(unlabeled(kinds)).toEqual([]);
  });

  it("labels every ts_kind of the R2 triage catalogs", () => {
    const kinds = CATALOG_YAMLS.flatMap((path) => yamlKinds(read(path)));
    expect(kinds).toEqual(expect.arrayContaining(["sent", "cache-response"]));
    expect(unlabeled(kinds)).toEqual([]);
  });
});
