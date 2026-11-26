import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  fetchArtifactsPage,
  fetchFilesPage,
  fetchTimelinePage,
  resetArtifactCountsCache,
} from "../../api/collections";
import type { GridRow } from "../../contracts/collection";
import { COLLECTIONS } from "../grid/columns/index";
import { installFetch, jsonResponse } from "../grid/testSupport";
import { resetViewerAdapter, setViewerTarget, useViewerRowContext } from "./adapter";
import { PARTIAL_COPY_REASON, useFullRecordStatus } from "./fullRecord";

const FULL_DETAILS = {
  file_name: "a.txt",
  mft_full_parser_profile: { stages: [{ name: "mft" }] },
  raw: { sender: "kim", nested: { a: 1 } },
};
const LIST_DETAILS = { file_name: "a.txt", raw: { sender: "kim" } };

function listRow(omitted: string[] | undefined, index = 42): GridRow {
  return COLLECTIONS.artifacts.mapRow(
    {
      artifact_type: "mft-entry",
      path: "C:/$MFT",
      details: LIST_DETAILS,
      record_index: index,
      _kind: "windows-filesystem",
      _index: index,
      ...(omitted ? { details_omitted: omitted } : {}),
    },
    0,
    { ref: { id: "artifacts", kind: "windows-filesystem" } },
  );
}

function show(row: GridRow): void {
  act(() => setViewerTarget({ ref: row.ref, runId: "run-1", sourcePath: row.sourcePath ?? null }, row));
}

beforeEach(() => {
  resetViewerAdapter();
  resetArtifactCountsCache();
});
afterEach(() => vi.unstubAllGlobals());

describe("view=list listing requests", () => {
  it("asks for lean artifact, files and timeline pages", async () => {
    const calls = installFetch({
      "/artifacts": () => jsonResponse({ artifacts: { "windows-filesystem": { artifacts: [], total: 0 } } }),
      "/files": () => jsonResponse({ candidates: [], pagination: { total: 0 } }),
      "/timeline": () => jsonResponse({ events: [], pagination: { total: 0 } }),
    });
    await fetchArtifactsPage("run-1", "windows-filesystem", 0, 100);
    await fetchFilesPage("run-1", 0, 100);
    await fetchTimelinePage("run-1", 0, 100);
    expect(calls.map((call) => new URL(call.url, "http://x").searchParams.get("view"))).toEqual([
      "list",
      "list",
      "list",
    ]);
  });

  it("keeps the dropped details keys on the grid row", () => {
    expect(listRow(["mft_full_parser_profile"]).fields.detailsOmitted).toEqual(["mft_full_parser_profile"]);
    expect(listRow(undefined).fields).not.toHaveProperty("detailsOmitted");
  });
});

describe("viewer full record", () => {
  it("loads the full details of a list row once and swaps them in", async () => {
    const calls = installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: { "windows-filesystem": { artifacts: [{ record_index: 42, details: FULL_DETAILS }] } },
        }),
    });
    const row = listRow(["mft_full_parser_profile"]);
    show(row);
    const { result } = renderHook(() => useViewerRowContext());
    expect(result.current?.fields.details).toEqual(LIST_DETAILS);
    await waitFor(() => expect(result.current?.fields.details).toEqual(FULL_DETAILS));
    expect(result.current?.fields).not.toHaveProperty("detailsOmitted");
    expect(result.current?.title).toBe(row.title);
    expect(calls.map((call) => call.url)).toEqual([
      "/api/runs/run-1/artifacts?offset=42&limit=1&kind=windows-filesystem",
    ]);
    // Back to the same row: served from the cache, no second request.
    show(listRow(undefined, 7));
    show(row);
    await waitFor(() => expect(result.current?.fields.details).toEqual(FULL_DETAILS));
    expect(calls).toHaveLength(1);
  });

  it("requests nothing for a row that carries its whole details", () => {
    const calls = installFetch({});
    show(listRow(undefined));
    const { result } = renderHook(() => useViewerRowContext());
    expect(result.current?.fields.details).toEqual(LIST_DETAILS);
    expect(calls).toHaveLength(0);
  });

  it("reports the left-out keys until loaded, and a failure with a retry", async () => {
    let fail = true;
    const calls = installFetch({
      "/artifacts": () =>
        fail
          ? new Response("boom", { status: 500 })
          : jsonResponse({
              artifacts: {
                "windows-filesystem": { artifacts: [{ record_index: 42, details: FULL_DETAILS }] },
              },
            }),
    });
    const row = listRow(["mft_full_parser_profile", "raw.nested"]);
    const { result } = renderHook(() => useFullRecordStatus(row, "run-1"));
    expect(result.current).toMatchObject({
      status: "loading",
      omitted: ["mft_full_parser_profile", "raw.nested"],
    });
    await waitFor(() => expect(result.current?.status).toBe("failed"));
    fail = false;
    act(() => result.current?.retry());
    await waitFor(() => expect(result.current).toBeNull());
    expect(calls).toHaveLength(2);
    expect(PARTIAL_COPY_REASON).toContain("전체 레코드");
  });
});
