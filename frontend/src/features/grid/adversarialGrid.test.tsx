// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
// Adversarial-review round 2 (grid side): not-joined NTFS statuses, the 유형 menu from /tree,
// and category-filtered files pages whose scan was truncated.

import { cleanup, configure, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchFilesPage, resetArtifactCountsCache } from "../../api/collections";
import { resetCommandRegistry } from "../../commands/registry";
import { EMPTY_ROUTE, parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import { useAnalysisStore } from "../analysis/store";
import { useFilterStore } from "../filters/filterStore";
import { MetaView } from "../viewer/views/MetaView";
import { useGridLocalStore } from "./adapter";
import { filesCollection, ntfsJoinOf } from "./columns/files";
import { DataGrid } from "./DataGrid";
import {
  fileCandidates,
  installFetch,
  jsonResponse,
  mockLayout,
  renderWithClient,
  resetGridStore,
  sortedArtifactsHandler,
} from "./testSupport";
import { artifactTypesOfTree } from "./useCollectionQuery";

configure({ asyncUtilTimeout: 5000 });

const announceMock = vi.hoisted(() => vi.fn());
vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: announceMock,
}));

const RUN = "run-1";
let restoreLayout: () => void = () => undefined;

function setRoute(hash: string) {
  window.location.hash = hash;
  useAppStore.getState().syncRouteFromLocation(parseHash(hash));
}

function gridOn(collection: { id: "files" | "artifacts"; kind?: string }) {
  useGridLocalStore.setState((s) => ({ route: { ...s.route, runId: RUN, collection, q: "", rowRef: null } }));
}

const dataRows = () => screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index"));

beforeEach(() => {
  resetCommandRegistry();
  resetGridStore();
  resetArtifactCountsCache();
  window.localStorage.clear();
  useAppStore.setState({ route: { ...EMPTY_ROUTE }, runs: [] });
  useAnalysisStore.setState({ runId: null, analyses: [], available: true, dialog: null });
  useFilterStore.getState().clearFilters();
  restoreLayout = mockLayout();
});
afterEach(() => {
  cleanup();
  restoreLayout();
  vi.unstubAllGlobals();
  announceMock.mockReset();
  resetCommandRegistry();
  window.localStorage.clear();
});

const TOO_LARGE = {
  analysis_id: "ntfs-123456789",
  status: "too_large",
  matched: 0,
  total: 3,
  reason: "NTFS 조인 색인 예상 크기(900 MB)가 한도(512 MB)를 넘어 조인하지 않습니다",
};

describe("ntfs_join status other than joined (4)", () => {
  it("parses status + reason; too_large / no_volume_prefix / skipped are not joined", () => {
    expect(ntfsJoinOf({ ntfs_join: TOO_LARGE })).toMatchObject({ joined: false, reason: TOO_LARGE.reason });
    expect(
      ntfsJoinOf({ ntfs_join: { analysis_id: "a", status: "no_volume_prefix", matched: 0, total: 1 } }),
    ).toMatchObject({ joined: false, reason: expect.stringContaining("볼륨 루트") });
    expect(
      ntfsJoinOf({ ntfs_join: { analysis_id: "a", status: "joined", matched: 1, total: 1 } })?.joined,
    ).toBe(true);
    // Servers that predate `status`: a set analysis_id meant joined.
    expect(ntfsJoinOf({ ntfs_join: { analysis_id: "a", matched: 1, total: 1 } })?.joined).toBe(true);
    expect(ntfsJoinOf({ ntfs_join: { analysis_id: null, status: "no_analysis" } })).toBeNull();
  });

  it("the grid status line says why instead of '0/3행 일치'", async () => {
    setRoute(`#/case/${RUN}/explore/files`);
    gridOn({ id: "files" });
    installFetch({
      "/files": () =>
        jsonResponse({
          candidates: fileCandidates(0, 3),
          total: 3,
          offset: 0,
          limit: 250,
          ntfs_join: TOO_LARGE,
        }),
    });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(dataRows()).toHaveLength(3));
    expect(screen.getByTestId("grid-ntfs-status").textContent).toBe(
      `NTFS 메타: 조인하지 않음 — ${TOO_LARGE.reason} (분석 ntfs-123)`,
    );
  });

  it("the viewer 출처 shows the reason, not '일치하는 MFT 레코드 없음' nor the run hint", () => {
    const raw = { ...fileCandidates(0, 1)[0], ntfs: null, filesystem: null, source_image: null };
    const row = filesCollection.mapRow(raw, 0, { page: { meta: { ntfs_join: TOO_LARGE } } } as never);
    expect(row.fields.ntfsJoinId).toBeNull();
    render(
      <MetaView
        target={{ ref: row.ref, runId: RUN, sourcePath: row.sourcePath }}
        preview={null}
        metadata={null}
        metadataError={null}
        hashBusy={false}
        row={row}
        sessionMarks={[]}
        onComputeHash={() => {}}
      />,
    );
    const text = document.body.textContent ?? "";
    expect(text).toContain(`NTFS 조인${TOO_LARGE.reason}`);
    expect(text).not.toContain("일치하는 MFT 레코드 없음");
    expect(screen.queryByTestId("ntfs-hint")).toBeNull();
  });
});

describe("유형 menu options come from /tree, not only the loaded rows (8)", () => {
  it("collects exact (case-preserved) artifact types of the kind", () => {
    const nodes = [
      {
        id: "artifacts:windows-prefetch",
        label: "Prefetch",
        collection: "artifacts",
        kind: "windows-prefetch",
        artifact_type_counts: { "prefetch-file": 30, "Prefetch-Layout": 2 },
      },
      {
        id: "artifacts:eventlog",
        label: "EVTX",
        collection: "artifacts",
        kind: "eventlog",
        artifact_type: "evtx",
      },
    ];
    expect(artifactTypesOfTree(nodes as never, "windows-prefetch")).toEqual([
      "Prefetch-Layout",
      "prefetch-file",
    ]);
    expect(artifactTypesOfTree(nodes as never)).toEqual(["Prefetch-Layout", "evtx", "prefetch-file"]);
  });

  it("after picking one type (rows narrowed server-side) the menu still offers the others", async () => {
    setRoute(`#/case/${RUN}/explore/artifacts/windows-prefetch`);
    gridOn({ id: "artifacts", kind: "windows-prefetch" });
    useFilterStore.getState().patchFilters({ types: ["prefetch-file"] });
    installFetch({
      "/tree": () =>
        jsonResponse({
          run_id: RUN,
          root: {},
          nodes: [
            {
              id: "artifacts:windows-prefetch",
              label: "Prefetch",
              count: 32,
              collection: "artifacts",
              kind: "windows-prefetch",
              artifact_type_counts: { "prefetch-file": 30, "Prefetch-Layout": 2 },
            },
          ],
        }),
      "/artifacts": sortedArtifactsHandler({ kind: "windows-prefetch", total: 5 }),
    });
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(dataRows().length).toBeGreaterThan(0));
    await waitFor(() =>
      expect(useFilterStore.getState().typeOptions).toEqual(["Prefetch-Layout", "prefetch-file"]),
    );
  });
});

describe("category-filtered files page with a truncated scan (10)", () => {
  const page = (pagination: Record<string, unknown>, matched: number | null) => () =>
    jsonResponse({
      candidates: fileCandidates(0, 2),
      total: 90_000, // copied from the unfiltered payload by filter_files_by_category
      record_count: 90_000,
      matched,
      pagination: { collection: "candidates", offset: 0, limit: 250, filtered: true, ...pagination },
    });

  it("never shows the unfiltered total; truncated + hasMore come from pagination", async () => {
    installFetch({
      "/files": page({ truncated: true, has_more: true, scanned: 50_000, matched: null }, null),
    });
    const raw = await fetchFilesPage(RUN, 0, 250, undefined, "images");
    expect(raw.total).toBeNull();
    expect(raw.truncated).toBe(true);
    expect(raw.hasMore).toBe(true);
    expect(raw.scanned).toBe(50_000);
  });

  it("an exhausted scan reports its exact match count", async () => {
    installFetch({ "/files": page({ truncated: false, has_more: false, scanned: 90_000, matched: 2 }, 2) });
    const raw = await fetchFilesPage(RUN, 0, 250, undefined, "images");
    expect(raw).toMatchObject({ total: 2, truncated: false, hasMore: false });
    // Unfiltered pages keep the payload total.
    installFetch({ "/files": () => jsonResponse({ candidates: fileCandidates(0, 2), total: 90_000 }) });
    expect((await fetchFilesPage(RUN, 0, 250)).total).toBe(90_000);
  });
});
