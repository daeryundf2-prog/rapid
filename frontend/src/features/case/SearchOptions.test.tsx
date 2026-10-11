import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_SEARCH_OPTIONS } from "../../api/keywordPacks";
import { SearchOptionsButton } from "./SearchOptionsPopover";
import { useSearchState } from "./searchState";
import { mockFetch, renderWithQuery } from "./testUtils";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  useSearchState.setState({ keywords: [], options: DEFAULT_SEARCH_OPTIONS, popoverOpen: false });
});

describe("SearchOptionsButton", () => {
  it("is inert with a reason when no case is open", () => {
    mockFetch({});
    renderWithQuery(<SearchOptionsButton runId={null} />);
    const button = screen.getByRole("button", { name: "검색 옵션" });
    expect(button.getAttribute("title")).toBe("열린 케이스가 없습니다");
    fireEvent.click(button);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("edits options, lists keyword packs, and saves the search via case-db", async () => {
    const { calls } = mockFetch({
      "GET /api/keyword-packs": { packs: [{ name: "pii", label: "개인정보" }] },
      "POST /api/runs/r1/case-db/ensure": { database: "/o/case.db", case_id: "run-r1", imported: false },
      "POST /api/case-db/saved-searches": { name: "내 검색" },
    });
    useSearchState.setState({ keywords: ["password"] });
    renderWithQuery(<SearchOptionsButton runId="r1" />);
    fireEvent.click(screen.getByRole("button", { name: "검색 옵션" }));
    fireEvent.change(screen.getByLabelText("검색 방식"), { target: { value: "regex" } });
    fireEvent.click(screen.getByLabelText("문서"));
    fireEvent.click(await screen.findByLabelText("개인정보"));
    expect(useSearchState.getState().options).toMatchObject({
      mode: "regex",
      sources: ["documents"],
      keywordPacks: ["pii"],
    });

    const save = screen.getByRole("button", { name: "저장" });
    expect(save.getAttribute("title")).toBe("검색 이름을 입력하세요.");
    fireEvent.change(screen.getByLabelText("현재 검색 저장"), { target: { value: "내 검색" } });
    fireEvent.click(save);
    await waitFor(() => expect(calls.some((c) => c.url === "/api/case-db/saved-searches")).toBe(true));
    expect(calls.find((c) => c.url === "/api/case-db/saved-searches")?.body).toEqual({
      database: "/o/case.db",
      case_id: "run-r1",
      name: "내 검색",
      keywords: ["password"],
      limit: 500,
      sources: ["documents"],
      created_by: "web-ui",
    });
  });
});
