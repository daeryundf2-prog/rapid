import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { CollectionQuery } from "../../contracts/collection";
import { COPY_TIME_LABEL, COPY_TIME_TITLE } from "./columns/FileCells";
import { FILES_DEFAULT_SORT, filesCollection, filesFetchSort } from "./columns/files";
import { installFetch, jsonResponse } from "./testSupport";

const gridCss = readFileSync(resolve(__dirname, "grid.css"), "utf8");

import type { ColumnSpec } from "./types";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const column = (id: string) => filesCollection.columns.find((c) => c.id === id) as ColumnSpec;
const mapFile = (raw: Record<string, unknown>, position = 0) =>
  filesCollection.mapRow(raw, position, { ref: { id: "files" } });
const filesQuery = (sort?: CollectionQuery["sort"]): CollectionQuery => ({
  ref: { id: "files" },
  offset: 0,
  limit: 250,
  ...(sort ? { sort } : {}),
});

describe("T-173 files default order: live, allocated files first", () => {
  it("asks the server for 수정 newest first while no sort is picked", () => {
    expect(FILES_DEFAULT_SORT).toEqual({ key: "mtime", order: "desc" });
    expect(filesFetchSort(filesQuery())).toEqual(FILES_DEFAULT_SORT);
    // The examiner's server sort wins; a client-only key keeps the default server order.
    expect(filesFetchSort(filesQuery({ key: "size", order: "asc" }))).toEqual({ key: "size", order: "asc" });
    expect(filesFetchSort(filesQuery({ key: "extension", order: "asc" }))).toEqual(FILES_DEFAULT_SORT);
  });

  it("the first page request carries the default sort", async () => {
    const calls = installFetch({ "/files": () => jsonResponse({ candidates: [], total: 0 }) });
    await filesCollection.fetch("run-1", filesQuery());
    const url = new URL(calls[0]?.url ?? "", "http://x");
    expect(url.searchParams.get("sort")).toBe("mtime");
    expect(url.searchParams.get("order")).toBe("desc");
  });

  it("first 50 rows of a server-ordered page hold no recovered item", async () => {
    // Synthetic server: list order puts run-time recovered copies first; its mtime sort puts rows
    // with evidence times (newest first) ahead of copy-only times (files_index `mtime`).
    const recovered = Array.from({ length: 80 }, (_, i) => ({
      path: `D:\\out\\_e01\\fs\\_deleted_mft\\${i}-x.bin`,
      modified_at: "2026-11-12T00:00:00Z",
      modified_at_origin: "acquisition-copy",
      recovery: { candidate_kind: "deleted-entry", deletion_state: "deleted" },
    }));
    const live = Array.from({ length: 120 }, (_, i) => ({
      path: `D:\\out\\_e01\\fs\\Users\\u\\f${i}.txt`,
      fs_modified_at: new Date(Date.UTC(2024, 0, 1) - i * 60_000).toISOString(),
      modified_at_origin: "listing",
      deletion_state: "allocated",
    }));
    installFetch({
      "/files": (url) => {
        const listOrder = [...recovered, ...live];
        const rows =
          url.searchParams.get("sort") === "mtime"
            ? [
                ...listOrder.filter((r) => "fs_modified_at" in r),
                ...listOrder.filter((r) => !("fs_modified_at" in r)),
              ]
            : listOrder;
        return jsonResponse({ candidates: rows.slice(0, 250), total: rows.length });
      },
    });
    const page = await filesCollection.fetch("run-1", filesQuery());
    const first50 = page.rows.slice(0, 50).map((raw, i) => mapFile(raw, i));
    expect(first50.filter((row) => row.fields.recovered === true)).toHaveLength(0);
    expect(first50.every((row) => row.fields.deletion === "allocated")).toBe(true);
  });
});

describe("T-173 copy-time marker: clock + 증거 시각 아님, no italics", () => {
  const copyRow = () =>
    mapFile({
      path: "C:/x/a.txt",
      modified_at: "2026-10-01T00:00:00Z",
      modified_at_origin: "acquisition-copy",
    });

  it("every copy-time cell carries the clock marker and the label", () => {
    const spec = column("timestamp");
    for (let i = 0; i < 20; i += 1) {
      cleanup();
      render(<div>{spec.render?.(copyRow())}</div>);
      const cell = screen.getByTestId("files-copy-time");
      expect(cell.querySelector('svg[data-icon="clock"]')).not.toBeNull();
      expect(cell.textContent).toContain(COPY_TIME_LABEL);
    }
    expect(spec.tooltip?.(copyRow())).toBe(COPY_TIME_TITLE);
    expect(COPY_TIME_TITLE.startsWith(COPY_TIME_LABEL)).toBe(true);
  });

  it("an evidence time has no marker", () => {
    const row = mapFile({ path: "C:/x/a.txt", fs_modified_at: "2020-01-01T00:00:00Z" });
    const { container } = render(<div>{column("timestamp").render?.(row)}</div>);
    expect(container.querySelector('svg[data-icon="clock"]')).toBeNull();
    expect(container.textContent).not.toContain(COPY_TIME_LABEL);
  });

  it("the copy-time style is not italic", () => {
    const block = /\.grid-cell-copytime\s*\{[^}]*\}/.exec(gridCss)?.[0] ?? "";
    expect(block).not.toBe("");
    expect(block).not.toMatch(/italic/);
  });
});
