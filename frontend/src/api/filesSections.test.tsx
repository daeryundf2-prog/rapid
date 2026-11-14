// Lazy files-output sections (R6 S3 follow-up): nothing is fetched until the UI is opened.

import { act, cleanup, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { installFetch, jsonResponse, renderWithClient } from "../features/grid/testSupport";
import { fetchFilesPage } from "./collections";
import { filesSectionQueryKey, filesSectionStatus, useFilesSection } from "./filesSections";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

let openPanel: () => void = () => {};

function DuplicatePanelProbe({ runId }: { runId: string }) {
  const [open, setOpen] = useState(false);
  openPanel = () => setOpen(true);
  const query = useFilesSection<Array<{ group_id: string }>>(runId, "duplicate_content_groups", {
    enabled: open,
  });
  const status = filesSectionStatus("duplicate_content_groups", query);
  return (
    <div>
      {status ? <p data-testid="status">{status}</p> : null}
      {query.data ? (
        <p data-testid="groups">{query.data.value.map((group) => group.group_id).join(",")}</p>
      ) : null}
    </div>
  );
}

const section = {
  run_id: "run-1",
  name: "duplicate_content_groups",
  kind: "list",
  item_count: 2,
  approx_bytes: 40,
  value: [{ group_id: "g0" }, { group_id: "g1" }],
};

describe("useFilesSection", () => {
  it("fetches the section only when the panel opens, then keeps it per run", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const calls = installFetch({
      "/files/sections": async () => {
        await gate;
        return jsonResponse(section);
      },
    });
    const { client } = renderWithClient(<DuplicatePanelProbe runId="run-1" />);
    expect(calls).toHaveLength(0);
    expect(screen.queryByTestId("status")).toBeNull();
    act(() => openPanel());
    await waitFor(() =>
      expect(screen.getByTestId("status").textContent).toBe("중복 파일 묶음을(를) 불러오는 중…"),
    );
    expect(calls.map((call) => call.url)).toEqual([
      "/api/runs/run-1/files/sections?name=duplicate_content_groups",
    ]);
    release();
    await waitFor(() => expect(screen.getByTestId("groups").textContent).toBe("g0,g1"));
    expect(screen.queryByTestId("status")).toBeNull();
    expect(client.getQueryData(filesSectionQueryKey("run-1", "duplicate_content_groups"))).toEqual(section);
  });

  it("says in Korean when the run has no such section (404, no retry)", async () => {
    const calls = installFetch({
      "/files/sections": () =>
        jsonResponse({ detail: "이 런의 files 출력에 'duplicate_content_groups' 섹션이 없습니다" }, 404),
    });
    renderWithClient(<DuplicatePanelProbe runId="run-1" />);
    act(() => openPanel());
    await waitFor(() =>
      expect(screen.getByTestId("status").textContent).toBe(
        "이 런의 파일 목록에는 중복 파일 묶음 정보가 없습니다.",
      ),
    );
    expect(calls).toHaveLength(1);
  });

  it("reports a server error in Korean", async () => {
    installFetch({ "/files/sections": () => jsonResponse({ detail: "내부 오류" }, 500) });
    renderWithClient(<DuplicatePanelProbe runId="run-1" />);
    act(() => openPanel());
    await waitFor(
      () =>
        expect(screen.getByTestId("status").textContent).toBe(
          "중복 파일 묶음을(를) 불러오지 못했습니다: 내부 오류",
        ),
      { timeout: 5000 },
    );
  });
});

describe("files pages", () => {
  it("expose sections_available in the page meta and send no sections parameter", async () => {
    const available = [{ name: "duplicate_content_groups", approx_bytes: 677689, item_count: 604 }];
    const calls = installFetch({
      "/files": () =>
        jsonResponse({
          candidates: [{ path: "a" }],
          pagination: { total: 1, has_more: false },
          sections_available: available,
        }),
    });
    const page = await fetchFilesPage("run-1", 0, 100);
    expect(page.meta?.sections_available).toEqual(available);
    expect(calls[0]?.url).not.toContain("sections");
  });
});
