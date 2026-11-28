// Unscoped picker under server roots (R2): `GET /api/browse` without `scope` answers a
// root-confined listing (`at_roots`) when RAPIDTRIAGE_ANALYSIS_ROOTS / _OUTPUT_ROOTS are set.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, configure, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { installFetch, jsonResponse } from "../grid/testSupport";
import { BrowsePanel } from "./BrowsePanel";

configure({ asyncUtilTimeout: 5000 });

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderPanel(onPick = vi.fn(), initialPath?: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <BrowsePanel initialPath={initialPath} onPick={onPick} />
    </QueryClientProvider>,
  );
  return onPick;
}

describe("BrowsePanel under server roots (no scope)", () => {
  it("starts at the server roots, never goes above a root, and returns to the root list", async () => {
    installFetch({
      "/api/browse": (url) => {
        if (!url.searchParams.get("path")) {
          return jsonResponse({
            scope_label: "서버 허용 루트",
            path: "",
            parent: null,
            at_roots: true,
            home: "",
            roots: [{ name: "/srv/evidence", path: "/srv/evidence", kind: "directory" }],
            entries: [{ name: "/srv/evidence", path: "/srv/evidence", kind: "directory" }],
            entry_count: 1,
            truncated: false,
            hidden_count: 0,
          });
        }
        return jsonResponse({
          scope_label: "서버 허용 루트",
          path: "/srv/evidence",
          parent: null,
          at_roots: false,
          home: "",
          roots: [],
          entries: [{ name: "case1", path: "/srv/evidence/case1", kind: "directory" }],
          entry_count: 1,
          truncated: false,
          hidden_count: 0,
        });
      },
    });
    const onPick = renderPanel();
    const roots = await screen.findByRole("list", { name: "허용 루트" });
    expect(screen.getByTestId("browse-roots-title").textContent).toBe("서버 허용 루트");
    // The root list itself is not a folder to pick ("" would be sent as the path).
    expect(screen.queryByRole("button", { name: "이 폴더 선택" })).toBeNull();
    fireEvent.click(within(roots).getByRole("button", { name: /\/srv\/evidence/ }));
    await screen.findByRole("list", { name: "폴더 목록" });
    expect(screen.queryByRole("button", { name: "상위 폴더" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "이 폴더 선택" }));
    expect(onPick).toHaveBeenCalledWith("/srv/evidence");
    fireEvent.click(screen.getByRole("button", { name: "허용 루트 목록" }));
    expect(await screen.findByRole("list", { name: "허용 루트" })).toBeTruthy();
  });

  it("a remembered path outside the roots (403) offers a way back to the first listing", async () => {
    installFetch({
      "/api/browse": (url) =>
        url.searchParams.get("path")
          ? jsonResponse({ detail: "찾아보기 경로가 허용 범위(서버 허용 루트) 밖에 있습니다: /home/x" }, 403)
          : jsonResponse({
              path: "",
              parent: null,
              at_roots: true,
              roots: [],
              entries: [],
              truncated: false,
            }),
    });
    renderPanel(vi.fn(), "/home/x");
    fireEvent.click(await screen.findByRole("button", { name: "처음 목록 보기" }));
    expect(await screen.findByText("서버에 허용된 루트가 없습니다.")).toBeTruthy();
  });

  it("an unconfined listing (no server roots, local use) keeps the plain folder view", async () => {
    installFetch({
      "/api/browse": () =>
        jsonResponse({
          path: "/Users/me",
          parent: "/Users",
          home: "/Users/me",
          roots: ["/"],
          entries: [],
          entry_count: 0,
          truncated: false,
          hidden_count: 0,
        }),
    });
    renderPanel();
    expect(await screen.findByRole("button", { name: "상위 폴더" })).toBeTruthy();
    expect(screen.queryByTestId("browse-roots-title")).toBeNull();
    expect(screen.queryByRole("button", { name: "허용 루트 목록" })).toBeNull();
  });
});
