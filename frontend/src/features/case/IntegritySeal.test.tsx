// Top-bar evidence integrity seal (design overhaul F8): shape + word for each state, nothing for a
// caseless run, 미검증 over never-hashed (folder) evidence, per-evidence details with the check time
// and 검증 실행 / 다시 검증 on the existing hash route.

import { cleanup, configure, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CaseEvidence } from "../../api/cases";
import { resetAppStore } from "../../state/store";
import { IntegritySeal } from "./IntegritySeal";
import { mockFetch, type RecordedCall, renderWithQuery } from "./testUtils";

configure({ asyncUtilTimeout: 5000 });

const SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

function item(overrides: Partial<CaseEvidence>): CaseEvidence {
  return {
    citation_id: "C-EVID-000001",
    case_id: "case-1",
    evidence_number: "E-01",
    display_name: "disk.dd",
    source_type: "raw",
    path: "/ev/disk.dd",
    size_bytes: 2048,
    hash_verify: true,
    hash_expected: "",
    hash_status: "not-requested",
    hash_status_label: "해시 검증 안 함",
    hash_message: "",
    hashes: {},
    added_at: null,
    runs: [],
    ...overrides,
  };
}

function routes(evidence: CaseEvidence[], linked = true, evidenceCitationId: string | null = null) {
  return {
    "GET /api/runs/r1/processing-snapshot": linked
      ? {
          source: "case-db",
          run_id: "r1",
          case_id: "case-1",
          evidence_citation_id: evidenceCitationId,
          snapshot: {},
          case: null,
          evidence: null,
        }
      : { source: "run-request", run_id: "r1", case_id: null, snapshot: {}, case: null, evidence: null },
    "GET /api/cases/case-1": {
      case: {
        case_id: "case-1",
        case_number: "2026-1",
        name: "",
        status: "open",
        evidence_count: evidence.length,
        run_count: 0,
        note_count: 0,
        evidence,
      },
    },
    "POST /api/cases/case-1/evidence/C-EVID-000001/hash": (_call: RecordedCall) => ({
      evidence: item({ hash_status: "hashing" }),
    }),
  };
}

beforeEach(() => resetAppStore({ route: { runId: "r1", collection: "intake" } }));
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("IntegritySeal (F8)", () => {
  it("shows 대조 일치 with the SHA-256 prefix, its check time and 다시 검증 (review #101 P2-1)", async () => {
    const { calls } = mockFetch(
      routes([
        item({
          hash_status: "matched",
          hash_expected: SHA,
          hashes: { sha256: SHA, md5: "m" },
          hash_checked_at: "2026-11-01T01:02:03Z",
        }),
      ]),
    );
    renderWithQuery(<IntegritySeal />);
    const seal = await screen.findByTestId("integrity-seal");
    expect(seal.getAttribute("data-seal")).toBe("matched");
    expect(seal.getAttribute("aria-label")).toMatch(
      /^증거 무결성: 대조 일치, SHA-256 a1b2c3d4, 마지막 검증 2026-11-01 \d\d:02:03 \S+ — 증거별 해시 보기$/,
    );
    expect(seal.getAttribute("title")).toMatch(/^마지막 검증 2026-11-01/);
    expect(seal.querySelector(".seal-word-long")?.textContent).toBe("대조 일치");
    expect(seal.querySelector(".seal-word-short")?.textContent).toBe("일치");
    expect(seal.querySelector(".seal-stamp")?.textContent).toBe("a1b2c3d4");
    // A shape, not only a colour.
    expect(seal.querySelector("svg")).toBeTruthy();

    fireEvent.click(seal);
    const dialog = screen.getByRole("dialog", { name: "증거 무결성" });
    expect(within(dialog).getAllByText(SHA).length).toBeGreaterThan(0);
    expect(within(dialog).getByText("MD5")).toBeTruthy();
    expect(within(dialog).getByRole("button", { name: "증거 E-01 SHA-256 복사" })).toBeTruthy();
    // A past result with its time, never a timeless present-tense claim.
    expect(within(dialog).getByTestId("seal-checked").textContent).toMatch(/^마지막 검증 2026-11-01/);
    expect(dialog.textContent).toContain("마지막 검증 때");
    expect(dialog.textContent).not.toContain("일치합니다");
    fireEvent.click(within(dialog).getByRole("button", { name: "증거 E-01 다시 검증" }));
    await waitFor(() =>
      expect(
        calls.some((c) => c.method === "POST" && c.url === "/api/cases/case-1/evidence/C-EVID-000001/hash"),
      ).toBe(true),
    );
  });

  it("reads 계산만 됨 differently from 대조 일치 and shows no stamp", async () => {
    mockFetch(routes([item({ hash_status: "computed", hashes: { sha256: SHA } })]));
    renderWithQuery(<IntegritySeal />);
    const seal = await screen.findByTestId("integrity-seal");
    expect(seal.getAttribute("data-seal")).toBe("computed");
    expect(seal.textContent).toContain("계산만 됨 (대조 없음)");
    expect(seal.querySelector(".seal-stamp")).toBeNull();
  });

  it("offers 검증 실행 for unverified evidence and posts the existing hash request", async () => {
    const { calls } = mockFetch(routes([item({ hash_status: "not-requested" })]));
    renderWithQuery(<IntegritySeal />);
    const seal = await screen.findByTestId("integrity-seal");
    expect(seal.getAttribute("data-seal")).toBe("unverified");
    expect(seal.textContent).toContain("해시 미검증");
    fireEvent.click(seal);
    fireEvent.click(screen.getByRole("button", { name: "증거 E-01 검증 실행" }));
    await waitFor(() =>
      expect(
        calls.some((c) => c.method === "POST" && c.url === "/api/cases/case-1/evidence/C-EVID-000001/hash"),
      ).toBe(true),
    );
  });

  it("shows 깨짐 for a mismatch and 검증 중 while hashing", async () => {
    mockFetch(routes([item({ hash_status: "mismatched", hash_message: "SHA256 기대값 x / 계산값 y" })]));
    renderWithQuery(<IntegritySeal />);
    const seal = await screen.findByTestId("integrity-seal");
    expect(seal.getAttribute("data-seal")).toBe("broken");
    expect(seal.textContent).toContain("무결성 깨짐");
    fireEvent.click(seal);
    expect(screen.getByText("SHA256 기대값 x / 계산값 y")).toBeTruthy();
    cleanup();

    mockFetch(routes([item({ hash_status: "hashing" })]));
    renderWithQuery(<IntegritySeal />);
    expect((await screen.findByTestId("integrity-seal")).textContent).toContain("해시 검증 중");
  });

  it("renders nothing for a caseless run", async () => {
    const caseless = mockFetch(routes([item({})], false));
    renderWithQuery(<IntegritySeal />);
    await waitFor(() => expect(caseless.calls.some((c) => c.url.includes("processing-snapshot"))).toBe(true));
    expect(screen.queryByTestId("integrity-seal")).toBeNull();
    expect(caseless.calls.some((c) => c.url.startsWith("/api/cases/"))).toBe(false);
  });

  it("never shows 대조 일치 over a folder run whose evidence was never hashed (review #101 P1-1)", async () => {
    // The review's repro: evidence 1 = the run's folder, evidence 2 = a matched zip of the same case.
    const folder = item({
      citation_id: "C-EVID-000001",
      source_type: "folder",
      size_bytes: null,
      display_name: "folder1",
    });
    const zip = item({
      citation_id: "C-EVID-000002",
      evidence_number: "E-02",
      hash_status: "matched",
      hash_expected: SHA,
      hashes: { sha256: SHA },
    });
    mockFetch(routes([folder, zip], true, "C-EVID-000001"));
    renderWithQuery(<IntegritySeal />);
    const seal = await screen.findByTestId("integrity-seal");
    expect(seal.getAttribute("data-seal")).toBe("unverified");
    expect(seal.querySelector(".seal-stamp")).toBeNull();
    expect(seal.getAttribute("aria-label")).toContain("폴더 증거 1건 해시 없음");
    fireEvent.click(seal);
    const dialog = screen.getByRole("dialog", { name: "증거 무결성" });
    expect(within(dialog).getByTestId("seal-unhashable").textContent).toContain(
      "폴더 증거 1건은 해시가 없습니다",
    );
    expect(within(dialog).getByText("해당 없음 (폴더)")).toBeTruthy();
    // Only the run's own evidence is listed, and a folder has no hash button.
    expect(within(dialog).queryByText("E-02", { exact: false })).toBeNull();
    expect(within(dialog).queryByRole("button", { name: /검증/ })).toBeNull();
    cleanup();

    // An older snapshot without the citation: the whole case, still not matched.
    mockFetch(routes([folder, zip]));
    renderWithQuery(<IntegritySeal />);
    expect((await screen.findByTestId("integrity-seal")).getAttribute("data-seal")).toBe("unverified");
  });
});
