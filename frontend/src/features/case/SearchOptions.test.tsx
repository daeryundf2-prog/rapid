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

  it("is on the shared Popover: Tab wraps inside, a press outside closes it (review B2-9)", async () => {
    mockFetch({ "GET /api/keyword-packs": { packs: [] } });
    renderWithQuery(<SearchOptionsButton runId="r1" />);
    fireEvent.click(screen.getByRole("button", { name: "검색 옵션" }));
    const dialog = screen.getByRole("dialog", { name: "검색 옵션" });
    expect(dialog.classList.contains("popover")).toBe(true);
    expect(document.activeElement).toBe(screen.getByLabelText("질문으로 시작"));
    const close = screen.getByRole("button", { name: "닫기" });
    close.focus();
    fireEvent.keyDown(close, { key: "Tab" });
    expect(document.activeElement).toBe(screen.getByLabelText("질문으로 시작"));
    fireEvent.pointerDown(document.body);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("a chosen question fills the search with its keywords, scope and packs", async () => {
    mockFetch({
      "GET /api/keyword-packs": { packs: [] },
      "GET /api/question-packs": {
        categories: ["유출"],
        limits: ["질문 팩은 조사 출발점이다"],
        packs: [
          {
            id: "exfil-cloud-upload",
            question: "클라우드에 자료를 올린 기록이 있나?",
            category: "유출",
            keyword_packs: ["exfiltration"],
            keywords: ["업로드"],
            expanded_keywords: ["mega.nz", "업로드"],
            collections: ["artifacts", "timeline"],
            artifact_kinds: ["cloud-sync"],
            event_ids: [],
            extensions: [".zip"],
            references: [],
            note: "동기화 폴더는 업로드와 구분되지 않는다.",
            source_ref: "builtin",
          },
        ],
      },
    });
    renderWithQuery(<SearchOptionsButton runId="r1" />);
    fireEvent.click(screen.getByRole("button", { name: "검색 옵션" }));
    const picker = await screen.findByLabelText("질문으로 시작");
    await screen.findByRole("option", { name: "클라우드에 자료를 올린 기록이 있나?" });
    fireEvent.change(picker, { target: { value: "exfil-cloud-upload" } });
    expect(useSearchState.getState().keywords).toEqual(["mega.nz", "업로드"]);
    expect(useSearchState.getState().options).toMatchObject({
      sources: ["artifacts", "timeline"],
      keywordPacks: ["exfiltration"],
      extensions: ["zip"],
    });
  });
});
