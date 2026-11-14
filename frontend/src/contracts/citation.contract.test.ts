/** D.2 citation contract (T-001): one string snapshot per citation kind (12). */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { RegistryValues } from "../api/explorers";
import { linkFromSnapshot, useCaseLinks } from "../features/case/caseLink";
import { useDerivedStore } from "../features/derived/store";
import { derivedCitation } from "../features/derived/tables";
import { citationDisplay } from "../features/explorers/RegistryExplorer";
import { EMPTY_CATALOG_FOR_TESTS, setCatalog } from "../features/flags/catalog";
import { flagCitation, parseFlags } from "../features/flags/flags";
import { citationText } from "../features/grid/gridCommands";
import { buildCitation, MARK_LABELS } from "../features/viewer/citation";
import type { GridRow } from "./collection";
import { CITATION_SNAPSHOTS, type CitationKind, MARK_LABELS_CONTRACT } from "./uiContract";
import type { ViewerTarget } from "./viewer";

const RUN = "run-1";

function gridRow(over: Partial<GridRow> & Pick<GridRow, "ref">): GridRow {
  return {
    rowKey: `${over.ref.collection}:${over.ref.kind ?? ""}:${over.ref.locator}`,
    title: "t",
    sourcePath: null,
    timestamp: null,
    tags: [],
    reviewStatus: null,
    sha256: null,
    fields: {},
    ...over,
  } as unknown as GridRow;
}

const target = (over: Partial<ViewerTarget> & Pick<ViewerTarget, "ref">): ViewerTarget => ({
  runId: RUN,
  sourcePath: null,
  ...over,
});

const FLAGS = [
  { id: "rdp.rdp_enabled", grade: "B", label: "RDP 활성화", version: 1, evidence: { fDenyTSConnections: 0 } },
  {
    id: "eventlog.log_cleared",
    grade: "A",
    label: "로그 삭제",
    version: 1,
    evidence: { event_id: 1102, channel: "Security" },
  },
];

/** The fixture that produces each kind's citation. */
const CASES: Record<CitationKind, () => string> = {
  "viewer.bytes": () =>
    buildCitation(
      target({
        ref: { collection: "files", locator: "/candidates/7" },
        sourcePath: "C:/evidence/file.bin",
        highlight: { offset: 32, length: 4 },
      }),
      "abc123",
    ),
  "viewer.unhashed": () =>
    buildCitation(target({ ref: { collection: "indicators", locator: "/indicators/4" } }), null),
  "viewer.case": () => {
    const link = linkFromSnapshot({
      source: "case-db",
      run_id: "run-case",
      case_id: "c1",
      evidence_citation_id: "e1",
      captured_at: null,
      snapshot: {},
      case: { case_number: "2026-고단-1234" },
      evidence: { evidence_number: "E-01" },
    } as never);
    useCaseLinks.getState().setLink("run-case", link);
    return buildCitation(
      {
        runId: "run-case",
        sourcePath: "C:/x.txt",
        ref: { collection: "files", locator: "/candidates/1" },
      },
      null,
    );
  },
  "viewer.record": () => {
    const row = gridRow({
      ref: { collection: "artifacts", kind: "eventlog", locator: "/artifacts/3" },
      sourcePath: "C:/e/Security.evtx",
      artifactType: "eventlog-event",
      fields: {
        artifact_type: "eventlog-event",
        details: { record_id: "1001", event_id: "4624", timestamp: "2024-04-01T12:34:56.000000+00:00" },
      },
    } as never);
    return buildCitation(
      target({ ref: row.ref, sourcePath: "C:/e/Security.evtx" }),
      "abc",
      row,
      "Asia/Seoul",
    );
  },
  "viewer.search-hit": () =>
    buildCitation(
      target({
        ref: { collection: "search", locator: "/search/0" },
        sourcePath: "C:/Users/kim/계약서.docx",
        review: { collection: "docs", pointer: "/candidates/3" },
      }),
      null,
    ),
  "viewer.sqlite": () =>
    buildCitation(
      target({
        ref: { collection: "files", locator: "/candidates/9" },
        sourcePath: "C:/e/History",
        highlight: { table: "urls", rowid: 42 },
      }),
      "def",
    ),
  "viewer.derived": () => {
    const ref = { collection: "artifacts" as const, kind: "eventlog", locator: "/artifacts/7" };
    useDerivedStore.getState().rememberOrigin(RUN, ref, { table: "people", normalized: "alice" });
    return buildCitation(target({ ref, sourcePath: "C:/x.evtx" }), null);
  },
  "viewer.flags": () => {
    const row = gridRow({
      ref: { collection: "artifacts", kind: "eventlog", locator: "/artifacts/1" },
      sourcePath: "C:/Windows/System32/winevt/Logs/Security.evtx",
      fields: { flags: FLAGS, details: {} },
    });
    return buildCitation(target({ ref: row.ref, sourcePath: row.sourcePath }), "abc", row, "utc");
  },
  "flag.single": () => {
    const [flag] = parseFlags([
      { id: "eventlog.log_cleared", grade: "A", version: 3, evidence: { event_id: 1102 } },
    ]);
    return flagCitation(flag as NonNullable<typeof flag>);
  },
  "derived.value": () => derivedCitation("people", { normalized: "alice", count: 34 }, RUN),
  "registry.display": () =>
    citationDisplay(
      {
        text: "raw",
        hive_path: "HKLM\\SYSTEM",
        key_path: "ControlSet001\\Services",
        last_written_at: "2024-04-01T12:34:56Z",
        cell_offset: 6699,
        kind: "key",
        record_index: null,
        locator: null,
      } satisfies RegistryValues["citation"],
      "utc",
    ),
  "grid.copy": () =>
    citationText(
      gridRow({
        ref: { collection: "files", locator: "/candidates/5" },
        sourcePath: "C:/e/a.pdf",
        sha256: "feed",
      }),
    ),
};

describe("citation contract (D.2)", () => {
  beforeEach(() => setCatalog(EMPTY_CATALOG_FOR_TESTS));
  afterEach(() => {
    useCaseLinks.setState(useCaseLinks.getInitialState());
    useDerivedStore.setState(useDerivedStore.getInitialState());
  });

  it("has 12 citation kinds, each with a fixture", () => {
    expect(Object.keys(CITATION_SNAPSHOTS)).toHaveLength(12);
    expect(Object.keys(CASES).sort()).toEqual(Object.keys(CITATION_SNAPSHOTS).sort());
  });

  it.each(Object.keys(CITATION_SNAPSHOTS) as CitationKind[])("%s", (kind) => {
    expect(CASES[kind]()).toBe(CITATION_SNAPSHOTS[kind]);
  });

  it("keeps the review-judgement labels citations and reports carry", () => {
    expect(MARK_LABELS).toEqual(MARK_LABELS_CONTRACT);
  });
});
