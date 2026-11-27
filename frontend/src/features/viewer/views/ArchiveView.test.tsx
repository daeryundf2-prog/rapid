import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ArchiveEntryRow } from "../../../api/viewer";
import { installFetch, preview } from "../testSupport";
import { ARCHIVE_PAGE, ArchiveView } from "./ArchiveView";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const ZIP = "C:/evidence/bundle.zip";

function entry(name: string, overrides: Partial<ArchiveEntryRow> = {}): ArchiveEntryRow {
  return {
    name,
    path: `${ZIP}::${name}`,
    is_directory: false,
    size: 2048,
    compressed_size: 512,
    modified_at: "2026-01-02T03:04:05+00:00",
    encrypted: false,
    nested_archive: false,
    openable: true,
    refusal_reason: "",
    ...overrides,
  };
}

function page(entries: ArchiveEntryRow[], total = entries.length, offset = 0) {
  return { total, offset, returned: entries.length, has_next: offset + entries.length < total, entries };
}

const zipPreview = preview({ path: ZIP, name: "bundle.zip", extension: ".zip" });

describe("ArchiveView", () => {
  it("lists name, sizes, the recorded time and why a member does not open", async () => {
    installFetch({
      "source-archive-entries": () =>
        page([
          entry("docs/report.pdf"),
          entry("secret/locked.txt", {
            encrypted: true,
            openable: false,
            refusal_reason: "암호화된 ZIP 항목은 열 수 없습니다",
          }),
          entry("bomb.bin", { openable: false, refusal_reason: "압축률이 비정상적으로 높아 열지 않습니다" }),
          entry("inner.zip", { nested_archive: true }),
        ]),
    });
    render(<ArchiveView runId="r1" preview={zipPreview} onOpenPath={() => undefined} />);
    const rows = await screen.findAllByRole("row");
    expect(screen.getByText("항목 4개")).toBeTruthy();
    const pdf = within(rows[1] as HTMLElement);
    expect(pdf.getByRole("button", { name: "docs/report.pdf" })).toBeTruthy();
    expect(pdf.getByText("2,048")).toBeTruthy();
    expect(pdf.getByText("512")).toBeTruthy();
    expect(pdf.getByText("2026-01-02 03:04:05")).toBeTruthy();
    const locked = within(rows[2] as HTMLElement);
    expect(locked.queryByRole("button")).toBeNull();
    expect(locked.getByText("암호화됨 · 열 수 없음")).toBeTruthy();
    expect(within(rows[3] as HTMLElement).getByText(/압축률이 비정상적으로/)).toBeTruthy();
    expect(within(rows[4] as HTMLElement).getByText("압축 파일(바이트만 표시)")).toBeTruthy();
  });

  it("opens a member by its archive path", async () => {
    installFetch({ "source-archive-entries": () => page([entry("images/dot.png")]) });
    const onOpenPath = vi.fn();
    render(<ArchiveView runId="r1" preview={zipPreview} onOpenPath={onOpenPath} />);
    fireEvent.click(await screen.findByRole("button", { name: "images/dot.png" }));
    expect(onOpenPath).toHaveBeenCalledWith(`${ZIP}::images/dot.png`);
  });

  it("pages through a large archive", async () => {
    const calls = installFetch({
      "source-archive-entries": (url) => {
        const offset = Number(url.searchParams.get("offset"));
        return page([entry(`file-${offset}.txt`)], ARCHIVE_PAGE + 1, offset);
      },
    });
    render(<ArchiveView runId="r1" preview={zipPreview} onOpenPath={() => undefined} />);
    fireEvent.click(await screen.findByRole("button", { name: `다음 ${ARCHIVE_PAGE}개` }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: `file-${ARCHIVE_PAGE}.txt` })).toBeTruthy(),
    );
    expect(calls.map((c) => c.url.searchParams.get("path"))).toEqual([ZIP, ZIP]);
  });

  it("shows the server's reason when the list cannot be read", async () => {
    installFetch({
      "source-archive-entries": () =>
        new Response(JSON.stringify({ detail: "ZIP 형식으로 읽을 수 없는 파일입니다" }), { status: 422 }),
    });
    render(<ArchiveView runId="r1" preview={zipPreview} onOpenPath={() => undefined} />);
    expect(await screen.findByText(/ZIP 형식으로 읽을 수 없는/)).toBeTruthy();
  });
});
