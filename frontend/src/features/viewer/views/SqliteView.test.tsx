import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { installFetch, preview } from "../testSupport";
import { SqliteView } from "./SqliteView";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const TOTAL = 450;

function tablePage(url: URL) {
  const offset = Number(url.searchParams.get("offset"));
  const limit = Number(url.searchParams.get("limit"));
  const returned = Math.max(0, Math.min(limit, TOTAL - offset));
  const rows = Array.from({ length: returned }, (_, i) => ({
    row_number: offset + i + 1,
    rowid: offset + i + 1,
    values: { id: offset + i + 1, body: `메시지 ${offset + i + 1}` },
  }));
  const hasNext = offset + returned < TOTAL;
  return {
    table: url.searchParams.get("table"),
    columns: ["id", "body"],
    column_count: 2,
    primary_key_columns: ["id"],
    rows,
    pagination: {
      offset,
      limit,
      returned,
      total: TOTAL,
      has_next: hasNext,
      next_offset: hasNext ? offset + returned : null,
      max_page_rows: 500,
    },
  };
}

const sqlitePreview = (sidecar: Record<string, unknown> = {}) =>
  preview({
    path: "C:/e/sms.db",
    name: "sms.db",
    extension: ".db",
    preview_type: "sqlite",
    sqlite: {
      table_count: 10,
      tables: [
        { name: "messages", row_count: TOTAL },
        { name: "handles", row_count: 3 },
      ],
      sidecar_state_profile: sidecar,
    },
  });

describe("SqliteView", () => {
  it("lists tables and pages rows 200 at a time", async () => {
    const calls = installFetch({ "source-sqlite-table": tablePage });
    render(<SqliteView runId="r1" preview={sqlitePreview()} />);
    await waitFor(() => expect(screen.getByText("메시지 1")).toBeTruthy());
    expect(calls[0]?.url.searchParams.get("table")).toBe("messages");
    expect(calls[0]?.url.searchParams.get("limit")).toBe("200");
    expect(calls[0]?.url.searchParams.get("offset")).toBe("0");
    expect(screen.getAllByRole("columnheader").map((th) => th.textContent)).toEqual([
      "rowid",
      "id (PK)",
      "body",
    ]);
    expect(screen.getByText(/1–200/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "이전 200행" }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/테이블 8개는/)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "다음 200행" }));
    await waitFor(() => expect(screen.getByText("메시지 201")).toBeTruthy());
    expect(calls.at(-1)?.url.searchParams.get("offset")).toBe("200");

    fireEvent.click(screen.getByRole("button", { name: "다음 200행" }));
    await waitFor(() => expect(screen.getByText("메시지 450")).toBeTruthy());
    expect((screen.getByRole("button", { name: "다음 200행" }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: /handles/ }));
    await waitFor(() => expect(calls.at(-1)?.url.searchParams.get("table")).toBe("handles"));
    expect(calls.at(-1)?.url.searchParams.get("offset")).toBe("0");
  });

  it("opens the highlighted table and marks the target rowid", async () => {
    installFetch({ "source-sqlite-table": tablePage });
    const { container } = render(
      <SqliteView runId="r1" preview={sqlitePreview()} highlight={{ table: "handles", rowid: 2 }} />,
    );
    await waitFor(() => expect(container.querySelector("tr.is-hl-row")).toBeTruthy());
    expect(container.querySelector("tr.is-hl-row td")?.textContent).toBe("2");
  });

  it("shows the WAL banner and loads the WAL frame preview", async () => {
    const calls = installFetch({
      "source-sqlite-table": tablePage,
      "source-sqlite-wal-preview": () => ({
        wal: {
          exists: true,
          status: "parsed",
          estimated_frame_count: 2,
          frames: [{ frame_index: 1, page_number: 4, is_commit_frame: true, salt_matches_header: true }],
        },
        recovery_scope: { deleted_record_candidate_count: 0 },
      }),
    });
    render(
      <SqliteView
        runId="r1"
        preview={sqlitePreview({
          requires_wal_review: true,
          detected_sidecars: ["wal"],
          sidecars: { wal: { exists: true, header: { status: "parsed", page_size: 4096 } } },
        })}
      />,
    );
    expect(screen.getByTestId("sqlite-wal-banner").textContent).toContain("WAL/저널 사이드카가 있습니다");
    fireEvent.click(screen.getByRole("button", { name: "WAL 프레임 미리보기" }));
    await waitFor(() => expect(screen.getByText(/추정 프레임 2/)).toBeTruthy());
    expect(calls.some((c) => c.url.pathname.endsWith("source-sqlite-wal-preview"))).toBe(true);
  });
});
