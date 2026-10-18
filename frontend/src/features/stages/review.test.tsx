// Adversarial-review fixes (tree toggles / search / totals / 웹셸, exact 유형 filter, dialog
// bounds, OCR cap, stage heading focus).
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { RunTree } from "../../api/runs";
import type { RunWithProgress } from "../../api/runsProgress";
import { resetCommandRegistry } from "../../commands/registry";
import type { GridRow } from "../../contracts/collection";
import { EMPTY_ROUTE, parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import {
  ANALYSIS_FIELDS,
  buildAnalysisOptions,
  defaultForm,
  validateAnalysisForm,
} from "../analysis/analysisForm";
import { useAnalysisStore } from "../analysis/store";
import { mockFetch, renderWithQuery } from "../case/testUtils";
import { matchesColumnFilter } from "../filters/columnFilters";
import { EMPTY_FILTERS, partitionFilters } from "../filters/filterModel";
import { col, makeRef, makeRow } from "../grid/columns/common";
import {
  buildGridCommands,
  type GridCommandHost,
  OCR_SELECTED_COMMAND,
  OCR_TOO_MANY_REASON,
  ocrLocatorOf,
} from "../grid/gridCommands";
import { EvidenceTree } from "../tree/EvidenceTree";
import { buildTreeModel } from "../tree/model";
import { openStage, STAGE_HEADING_ID } from "./stages";

const announceMock = vi.hoisted(() => vi.fn());
vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: announceMock,
}));

const tree: RunTree = {
  run_id: "r1",
  root: {},
  nodes: [
    { id: "artifacts:eventlog", label: "EVTX", count: 100, collection: "artifacts", kind: "eventlog" },
    {
      id: "artifacts:windows-system",
      label: "Windows 시스템",
      count: 9,
      collection: "artifacts",
      kind: "windows-system",
      artifact_type_counts: { "web-server-log": 5, "wer-report": 4 },
    },
    {
      id: "files",
      label: "파일",
      count: 30,
      collection: "files",
      children: [{ id: "files:images", label: "이미지", count: 7, collection: "files" }],
    },
  ],
};

beforeEach(() => {
  resetCommandRegistry();
  window.location.hash = "";
  useAppStore.setState({ route: { ...EMPTY_ROUTE } });
  useAnalysisStore.setState({ runId: null, analyses: [], available: true, dialog: null });
  announceMock.mockReset();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("domain tree review fixes", () => {
  it("parent totals count each kind once; typed subsets and other views do not add (6)", () => {
    const model = buildTreeModel({ tree, summary: { summary: { counts: { files: 30 } as never } } });
    const incident = model.find((n) => n.id === "domain:incident");
    // Parser-quality r1: a kind with only typed nodes in a domain counts its typed evidence nodes
    // (웹셸 0 + 웹 서버 로그 5 + BITS 0); a kind-wide node elsewhere does not leak in.
    expect(incident?.count).toBe(5);
    const os = model.find((n) => n.id === "domain:os");
    // windows-system (9) once, although WER (4) is a typed child of it.
    expect(os?.count).toBe(9);
    expect(model.find((n) => n.id === "domain:eventlog")?.count).toBe(100);
  });

  it("침해사고 › 웹셸 exists, renders at 0건 dimmed with a reason, and carries kind + artifact_type (17)", () => {
    const model = buildTreeModel({ tree });
    const webshell = model.find((n) => n.id === "domain:incident")?.children?.find((c) => c.label === "웹셸");
    expect(webshell).toMatchObject({
      count: 0,
      disabledReason: "이 런에는 해당 데이터가 없습니다",
      target: { collection: "artifacts", kind: "windows-system", types: ["webshell-source-candidate"] },
    });
    const weblog = model
      .find((n) => n.id === "domain:incident")
      ?.children?.find((c) => c.label === "웹 서버 로그");
    expect(weblog).toMatchObject({ count: 5, disabledReason: undefined });
  });

  it("files type nodes count from /tree files:<category> and route with category= (5)", () => {
    const model = buildTreeModel({ tree });
    const images = model
      .find((n) => n.id === "domain:filesystem")
      ?.children?.find((c) => c.label === "이미지");
    expect(images).toMatchObject({ count: 7, target: { collection: "files", category: "images" } });
  });

  it("domain headers only toggle; the tree search finds nodes inside collapsed domains (4, 10)", async () => {
    mockFetch({
      "GET /api/runs": { runs: [{ run_id: "r1", status: "completed" }] },
      "GET /api/runs/r1/summary": { summary: { counts: { files: 30, artifacts: 109 } } },
      "GET /api/runs/r1/tree": tree,
    });
    renderWithQuery(<EvidenceTree runId="r1" />);
    const domain = await screen.findByRole("treeitem", { name: /^침해사고/ });
    fireEvent.click(domain);
    expect(domain.getAttribute("aria-expanded")).toBe("true");
    expect(window.location.hash).toBe(""); // never navigated to the first child
    fireEvent.keyDown(domain, { key: "Enter" });
    expect(domain.getAttribute("aria-expanded")).toBe("false");
    expect(window.location.hash).toBe("");

    const search = screen.getByRole("searchbox", { name: "트리 검색" });
    fireEvent.change(search, { target: { value: "powershell" } });
    const hit = await screen.findByRole("treeitem", { name: /^PowerShell 히스토리/ });
    expect(screen.getByRole("treeitem", { name: /^실행 흔적/ }).getAttribute("aria-expanded")).toBe("true");
    // Only matches and their ancestors are listed (이벤트 로그 stays: its R3
    // "PowerShell" channel group matches; 파일 has no match).
    expect(screen.queryByRole("treeitem", { name: /^파일(?!시스템)/ })).toBeNull();
    fireEvent.keyDown(search, { key: "Enter" });
    expect(document.activeElement).toBe(hit);
    fireEvent.change(search, { target: { value: "" } });
    await waitFor(() => expect(screen.getByRole("treeitem", { name: /^파일(?!시스템)/ })).toBeTruthy());
  });
});

describe("유형(정확히) column filter (7)", () => {
  const typeCol = col.field("type", "유형", 120, ["analysis"], (r) => r.artifactType);
  const row = (type: string) =>
    makeRow(makeRef("artifacts", "/artifacts/0", "k"), { title: "x", artifactType: type });

  it("matches exactly, never as a substring", () => {
    const filter = { col: "type", op: ":" as const, value: "web-server-log" };
    expect(matchesColumnFilter(typeCol, row("web-server-log") as GridRow, filter)).toBe(true);
    expect(matchesColumnFilter(typeCol, row("web-server-log-archive") as GridRow, filter)).toBe(false);
  });

  it("is AND-ed with the filter-bar types: intersection to the server, empty intersection empties", () => {
    const one = partitionFilters(
      { id: "artifacts", kind: "windows-system" },
      {
        ...EMPTY_FILTERS,
        types: ["web-server-log", "wer-report"],
        columns: [{ col: "type", op: ":", value: "wer-report" }],
      },
    );
    expect(one.server.artifactTypes).toEqual(["wer-report"]);
    expect(one.serverLabels).toContain("유형(정확히)");
    const none = partitionFilters(
      { id: "artifacts", kind: "windows-system" },
      {
        ...EMPTY_FILTERS,
        types: ["web-server-log"],
        columns: [{ col: "type", op: ":", value: "wer-report" }],
      },
    );
    expect(none.server.artifactTypes).toEqual(["web-server-log"]);
    expect(none.clientColumns).toEqual([{ col: "type", op: ":", value: "wer-report" }]);
  });
});

describe("dialog bounds mirror the backend Field limits (3)", () => {
  /**
   * Every bounded option of rapidtriage/api/app/analysis_kinds.py: `[ge, le, default]` of the
   * pydantic Field, in the dialog's unit (MB fields: le / 1 MiB, default / 1 MiB). `le`
   * undefined = no upper bound; default "" = optional (None).
   */
  const BACKEND_INT_FIELDS: Record<string, Record<string, [number, number | undefined, string]>> = {
    carve: {
      max_scan_bytes: [1, 16 * 1024, "256"], // le=16 GiB, DEFAULT_MAX_SCAN_BYTES = 256 MiB
      max_carve_bytes: [1, 1024, "50"], // le=1 GiB, DEFAULT_MAX_CARVE_BYTES = 50 MiB
      max_candidates: [1, 100_000, "250"],
    },
    "vsc-discover": { max_depth: [0, 1, "1"] }, // Field(1, ge=0, le=1)
    "vsc-compare": { max_records: [1, 1_000_000, "10000"] },
    "vsc-extract": { max_file_count: [1, 100_000, "1000"], max_total_bytes: [1, 256 * 1024, "2048"] },
    "ntfs-meta": { partition_start_sector: [0, undefined, ""] },
    "ocr-batch": { max_items: [1, 1000, "50"] },
    "memory-import": {},
    "cross-case": { max_shared: [1, 5000, "500"] },
  };

  it("every int field's bounds and default equal the backend Field; never '0 = unlimited'", () => {
    for (const [kind, fields] of Object.entries(ANALYSIS_FIELDS)) {
      const ints = fields.filter((f) => f.type === "int");
      const expected = BACKEND_INT_FIELDS[kind] ?? {};
      expect(ints.map((f) => f.key).sort(), kind).toEqual(Object.keys(expected).sort());
      const defaults = defaultForm(kind as keyof typeof ANALYSIS_FIELDS);
      for (const field of ints) {
        if (field.type !== "int") continue;
        const [min, max, value] = expected[field.key] as [number, number | undefined, string];
        expect([field.min, field.max], `${kind}.${field.key}`).toEqual([min, max]);
        expect(defaults[field.key], `${kind}.${field.key} default`).toBe(value);
      }
      const errors = validateAnalysisForm(kind as keyof typeof ANALYSIS_FIELDS, defaults);
      for (const key of Object.keys(expected)) expect(errors[key], `${kind}.${key} valid`).toBeUndefined();
    }
    // vsc-discover: the old default 3 (max 8) was a guaranteed 422.
    expect(validateAnalysisForm("vsc-discover", { max_depth: "2" }).max_depth).toMatch(/0~1 사이/);
    expect(buildAnalysisOptions("vsc-discover", defaultForm("vsc-discover"))).toEqual({ max_depth: 1 });
    const helps = Object.values(ANALYSIS_FIELDS).flatMap((fields) => fields.map((f) => f.help));
    expect(helps.some((h) => h.includes("0이면 제한하지 않습니다"))).toBe(false);
  });

  it("list fields mirror min_length / max_length (status, languages ≥1; case_ids 1~20 others)", () => {
    const field = (kind: keyof typeof ANALYSIS_FIELDS, key: string) =>
      ANALYSIS_FIELDS[kind].find((f) => f.key === key) as { minCount?: number; maxCount?: number };
    expect(field("vsc-extract", "status").minCount).toBe(1);
    expect(field("ocr-batch", "languages").minCount).toBe(1);
    expect(field("cross-case", "case_ids")).toMatchObject({ minCount: 1, maxCount: 20 });
  });
});

describe("OCR selection qualification (14)", () => {
  it("only decoded image rows qualify; more than 1,000 images is refused with a reason", () => {
    const media = (i: number, type: string) =>
      makeRow(makeRef("artifacts", `/artifacts/${i}`, "media-image"), {
        title: `m${i}`,
        sourcePath: `C:/m/${i}.jpg`,
        artifactType: type,
      });
    expect(ocrLocatorOf(media(1, "media-image"))).toBe("/artifacts/1");
    expect(ocrLocatorOf(media(2, "media-image-unreadable"))).toBeNull();
    expect(ocrLocatorOf(media(3, "media-video"))).toBeNull();
    useAppStore.setState({ runs: [{ run_id: "r1", status: "completed" }] as unknown as RunWithProgress[] });
    const rows = Array.from({ length: 1001 }, (_, i) =>
      makeRow(
        makeRef("files", `/candidates/${i}`),
        { title: `${i}.png`, sourcePath: `C:/f/${i}.png` },
        { extension: "png" },
      ),
    );
    const host = {
      current: {
        runId: "r1",
        collection: { id: "files" },
        getFocusedRow: () => undefined,
        getSelectedRows: () => rows,
      } as unknown as GridCommandHost,
    };
    const command = buildGridCommands(host).find((c) => c.id === OCR_SELECTED_COMMAND);
    const ctx = {
      runId: "r1",
      collection: "files",
      selectedRowKeys: [],
      focusedRowKey: null,
      viewerHasTarget: false,
      runIsActive: false,
    };
    expect(command?.disabledReason?.(ctx)).toBe(OCR_TOO_MANY_REASON);
    expect(OCR_TOO_MANY_REASON).toBe("한 번에 1,000장까지 OCR할 수 있습니다");
  });
});

describe("stage switch focus (16)", () => {
  it("moves focus to the new stage's panel heading and announces the stage once", async () => {
    window.location.hash = "#/case/r1/explore/files";
    useAppStore.getState().syncRouteFromLocation(parseHash(window.location.hash));
    const heading = document.createElement("h1");
    heading.id = STAGE_HEADING_ID;
    heading.tabIndex = -1;
    document.body.appendChild(heading);
    openStage("process");
    expect(window.location.hash).toBe("#/case/r1/process");
    await waitFor(() => expect(document.activeElement).toBe(heading));
    expect(announceMock).toHaveBeenCalledTimes(1);
    expect(announceMock).toHaveBeenCalledWith("단계: 처리", { hold: true });
    heading.remove();
    void within;
  });
});
