import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_SEARCH_OPTIONS } from "../../api/keywordPacks";
import { resetCaseDbHandles } from "../grid/reviewActions";
import { DOMAINS } from "../tree/domains";
import { domainRoute } from "../tree/model";
import { consoleKeywords, EntityPanel } from "./EntityPanel";
import { SearchOptionsButton } from "./SearchOptionsPopover";
import { useSearchState } from "./searchState";
import { mockFetch, renderWithQuery } from "./testUtils";

const SHA = "a".repeat(64);
const ROW = {
  doc_id: 7,
  group_id: 7,
  collection: "docs",
  kind: "",
  locator: "/candidates/3",
  domain: "media",
  artifact_type: "document-txt",
  title: "개인정보목록.txt",
  path: "\\Users\\bsh\\Desktop\\개인정보목록.txt",
  snippet: { text: "주민등록번호 901010-1****** 휴대폰 010-****-5678", marks: [] },
  pii: { rrn: 1, phone: 1 },
  masked_preview: ["901010-1******", "010-****-5678"],
  entities: [
    { kind: "rrn", masked: "901010-1******", value_sha256: SHA, verified: true, source: "body" },
    { kind: "ip", masked: "10.1.2.3", value_sha256: "b".repeat(64), verified: true, source: "body" },
  ],
};
const SUMMARY = {
  kinds: [
    { kind: "rrn", rows: 1, values: 2, verified_values: 1, sensitive: true },
    { kind: "ip", rows: 3, values: 2, verified_values: 2, sensitive: false },
  ],
  values: [],
  languages: [{ key: "ko", count: 4 }],
  rows: null,
  rows_total: null,
  postings: 5,
};
const QUERY = {
  rows: [ROW],
  page: { total: 1, total_exact: true, next_cursor: null, returned: 1 },
  facets: { entities: [{ key: "rrn", count: 1 }], lang: [] },
  lists: null,
  query: { raw: "rrn:verified", parsed: { warnings: [] } },
  elapsed_ms: 3,
  truncated: false,
  truncated_reason: null,
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  resetCaseDbHandles();
  window.sessionStorage.clear();
  useSearchState.setState({
    keywords: [],
    options: DEFAULT_SEARCH_OPTIONS,
    popoverOpen: false,
    entityPanelOpen: false,
    entityQuery: "",
  });
});

describe("EntityPanel", () => {
  it("opens from an options chip, lists Korean entity and language chips, and runs the query", async () => {
    const { calls } = mockFetch({
      "GET /api/keyword-packs": { packs: [] },
      "POST /api/runs/r1/search/entities": SUMMARY,
      "POST /api/runs/r1/search/query": QUERY,
    });
    renderWithQuery(<SearchOptionsButton runId="r1" />);
    fireEvent.click(screen.getByRole("button", { name: "검색 옵션" }));
    fireEvent.click(screen.getByRole("button", { name: "주민등록번호" }));
    const dialog = await screen.findByRole("dialog", { name: "개체·언어 검색" });
    expect(await within(dialog).findByRole("button", { name: /주민등록번호 1행/ })).toBeTruthy();
    expect(within(dialog).getByRole("button", { name: /IP 주소 3행/ })).toBeTruthy();
    expect(within(dialog).getByRole("button", { name: /한국어 4행/ })).toBeTruthy();
    expect(within(dialog).getByText(/검증 1개/)).toBeTruthy();
    expect(await within(dialog).findByText("개인정보목록.txt")).toBeTruthy();
    const query = calls.find((call) => call.url === "/api/runs/r1/search/query");
    expect(query?.body).toMatchObject({ q: "rrn:*", aggregates: true, facets: true });
    // no raw id on screen: kinds and languages are labelled
    expect(dialog.textContent).not.toMatch(/\brrn\b|\bko\b/);
  });

  it("reveals one value once per row after a reason (asked once per session), never for IP", async () => {
    let reveals = 0;
    const { calls } = mockFetch({
      "POST /api/runs/r1/search/entities": SUMMARY,
      "POST /api/runs/r1/search/query": QUERY,
      "POST /api/runs/r1/search/entities/reveal": () => {
        reveals += 1;
        return {
          value: "901010-1234567",
          masked: "901010-1******",
          label: "주민등록번호",
          entity_kind: "rrn",
          audit_id: "AUD-1",
        };
      },
    });
    useSearchState.setState({ entityQuery: "rrn:verified" });
    renderWithQuery(<EntityPanel runId="r1" onClose={() => {}} />);
    const dialog = await screen.findByRole("dialog", { name: "개체·언어 검색" });
    await within(dialog).findByText("개인정보목록.txt");
    const buttons = within(dialog).getAllByRole("button", { name: "값 보기" });
    expect(buttons).toHaveLength(1); // the IP has none
    fireEvent.click(buttons[0] as HTMLElement);
    const confirm = within(dialog).getByRole("form", { name: "값 공개 확인" });
    expect(confirm.textContent).toContain("감사 기록 1건");
    const submit = within(confirm).getByRole("button", { name: "감사 기록 남기고 공개" });
    fireEvent.click(submit);
    expect(reveals).toBe(0); // no reason yet
    fireEvent.change(within(confirm).getByLabelText(/공개 사유/), { target: { value: "수사 협조" } });
    fireEvent.click(submit);
    expect(await within(dialog).findByText("901010-1234567")).toBeTruthy();
    expect(reveals).toBe(1);
    const body = calls.find((call) => call.url === "/api/runs/r1/search/entities/reveal")?.body;
    expect(body).toEqual({
      collection: "docs",
      kind: "",
      locator: "/candidates/3",
      value_sha256: SHA,
      reason: "수사 협조",
    });
    expect(within(dialog).queryByRole("button", { name: "값 보기" })).toBeNull();
    expect(window.sessionStorage.getItem("rapidtriage.reveal-reason")).toBe("수사 협조");
  });

  it("shows the server's Korean refusal (reveal switched off)", async () => {
    mockFetch({
      "POST /api/runs/r1/search/entities": SUMMARY,
      "POST /api/runs/r1/search/query": QUERY,
      "POST /api/runs/r1/search/entities/reveal": new Response(
        JSON.stringify({
          detail: "개인정보 원값 보기가 꺼져 있습니다(RAPIDTRIAGE_PII_REVEAL=off). 관리자에게 문의하세요",
        }),
        { status: 403, headers: { "content-type": "application/json" } },
      ),
    });
    window.sessionStorage.setItem("rapidtriage.reveal-reason", "점검");
    useSearchState.setState({ entityQuery: "rrn:verified" });
    renderWithQuery(<EntityPanel runId="r1" onClose={() => {}} />);
    const dialog = await screen.findByRole("dialog", { name: "개체·언어 검색" });
    await within(dialog).findByText("개인정보목록.txt");
    fireEvent.click(within(dialog).getByRole("button", { name: "값 보기" }));
    expect(await within(dialog).findByText(/꺼져 있습니다/)).toBeTruthy();
    expect(within(dialog).queryByText("901010-1234567")).toBeNull();
  });

  it("shows the syntax help and per-item list counts", async () => {
    mockFetch({
      "POST /api/runs/r1/search/entities": SUMMARY,
      "POST /api/runs/r1/search/query": {
        ...QUERY,
        lists: [
          { id: "ioc-50", name: "IOC 50", omitted: 0, items: [{ item: "10.0.0.0/8", type: "ip", count: 3 }] },
        ],
      },
    });
    useSearchState.setState({ entityQuery: "list:ioc-50" });
    renderWithQuery(<EntityPanel runId="r1" onClose={() => {}} />);
    const dialog = await screen.findByRole("dialog", { name: "개체·언어 검색" });
    expect(await within(dialog).findByText("검색 목록 IOC 50 항목별 건수")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "문법 도움말" }));
    expect(within(dialog).getByText("pre:(계약 해지)/3")).toBeTruthy();
    expect(within(dialog).getByText(/알려진 정상 해시 집합/)).toBeTruthy();
  });

  it("moves only bar-compatible queries to the search grid", async () => {
    expect(consoleKeywords("rrn:verified 계약")).toBe("rrn:verified 계약");
    expect(consoleKeywords("-hashset:known-good lang:ko")).toBe("-hashset:known-good lang:ko");
    expect(consoleKeywords("pre:(계약 해지)/3")).toBeNull();
    expect(consoleKeywords("a OR b")).toBeNull();
    expect(consoleKeywords("in:docs rrn:*")).toBeNull();
    expect(consoleKeywords("")).toBeNull();
  });
});

describe("해시 집합 tree block", () => {
  it("routes each category to the search view with its hashset query", () => {
    const filesystem = DOMAINS.find((domain) => domain.id === "filesystem");
    const group = filesystem?.nodes.find((node) => node.id === "fs-hash-sets");
    expect(group?.label).toBe("해시 집합");
    const routes = (group?.children ?? []).map((node) => domainRoute(node.target));
    expect(routes).toEqual([
      { collection: "search", q: "hashset:known-bad" },
      { collection: "search", q: "hashset:known-good" },
      { collection: "search", q: "hashset:custom" },
    ]);
    expect((group?.children ?? []).every((node) => node.detail)).toBe(true);
  });
});

describe("console field keywords", () => {
  it("never fall back to the literal v1 search", async () => {
    const { fetchSearchRows } = await import("../../api/collections");
    mockFetch({ "GET /api/runs/r1/search/index": { status: "none" } });
    await waitFor(() =>
      expect(fetchSearchRows("r1", { search: { keywords: ["rrn:*"], mode: "exact" } }, 50)).rejects.toThrow(
        /검색 색인으로만/,
      ),
    );
  });
});
