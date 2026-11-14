import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { mockFetch } from "../case/testUtils";
import {
  artifactRecordIndex,
  resetFullDetailsCache,
  rowNeedsFullDetails,
  useFullArtifactRow,
} from "./fullRow";

function gridRow(fields: Record<string, unknown>, locator = "/artifacts/7"): GridRow {
  return {
    rowKey: `artifacts:windows-filesystem:${locator}`,
    ref: { collection: "artifacts", kind: "windows-filesystem", locator },
    title: "$MFT",
    sourcePath: null,
    timestamp: null,
    artifactType: "mft-file",
    provider: null,
    sha256: null,
    reviewStatus: "relevant",
    tags: [],
    fields,
  };
}

beforeEach(() => resetFullDetailsCache());
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("full artifact row for the viewer (compact grid rows)", () => {
  it("knows which rows were compacted", () => {
    expect(artifactRecordIndex(gridRow({}))).toBe(7);
    expect(rowNeedsFullDetails(gridRow({ details: {} }))).toBe(false);
    expect(rowNeedsFullDetails(gridRow({ details: {}, detailsOmitted: ["raw"] }))).toBe(true);
    expect(rowNeedsFullDetails(gridRow({ detailsOmitted: ["raw"] }, "/files/3"))).toBe(false);
    expect(rowNeedsFullDetails(null)).toBe(false);
  });

  it("loads the one full row once and merges its details into the live grid row", async () => {
    const { calls } = mockFetch({
      "GET /api/runs/r1/artifacts": {
        artifacts: {
          "windows-filesystem": {
            artifacts: [{ record_index: 7, details: { size: 1, raw: { header: "FILE0" } } }],
          },
        },
      },
    });
    const row = gridRow({ details: { size: 1 }, detailsOmitted: ["raw"] });
    const { result } = renderHook(() => useFullArtifactRow("r1", row));
    expect(result.current).toBe(row); // compact row until the full one arrives
    await waitFor(() =>
      expect(result.current?.fields.details).toEqual({ size: 1, raw: { header: "FILE0" } }),
    );
    expect(result.current?.fields.detailsOmitted).toBeUndefined();
    expect(result.current?.reviewStatus).toBe("relevant");
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toContain("kind=windows-filesystem&offset=7&limit=1");
    expect(calls[0]?.url).not.toContain("compact");
    // A second viewer component reads the cache: no second request.
    const again = renderHook(() => useFullArtifactRow("r1", row));
    expect(again.result.current?.fields.details).toEqual({ size: 1, raw: { header: "FILE0" } });
    expect(calls).toHaveLength(1);
  });

  it("keeps the compact row when the server returns another record", async () => {
    mockFetch({
      "GET /api/runs/r1/artifacts": {
        artifacts: { "windows-filesystem": { artifacts: [{ record_index: 8, details: { x: 1 } }] } },
      },
    });
    const row = gridRow({ details: { size: 1 }, detailsOmitted: ["raw"] });
    const { result } = renderHook(() => useFullArtifactRow("r1", row));
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(result.current).toBe(row);
  });
});
