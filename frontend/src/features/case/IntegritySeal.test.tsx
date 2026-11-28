// Top-bar evidence integrity seal (design overhaul F8): shape + word for each state, nothing for a
// caseless run or folder-only evidence, per-evidence details with 검증 실행 on the existing hash route.

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

function routes(evidence: CaseEvidence[], linked = true) {
  return {
    "GET /api/runs/r1/processing-snapshot": linked
      ? { source: "case-db", run_id: "r1", case_id: "case-1", snapshot: {}, case: null, evidence: null }
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
  it("shows 대조 일치 with the SHA-256 prefix and a compact word for phones", async () => {
    mockFetch(
      routes([item({ hash_status: "matched", hash_expected: SHA, hashes: { sha256: SHA, md5: "m" } })]),
    );
    renderWithQuery(<IntegritySeal />);
    const seal = await screen.findByTestId("integrity-seal");
    expect(seal.getAttribute("data-seal")).toBe("matched");
    expect(seal.getAttribute("aria-label")).toBe(
      "증거 무결성: 대조 일치, SHA-256 a1b2c3d4 — 증거별 해시 보기",
    );
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
    // Nothing to run on a match.
    expect(within(dialog).queryByRole("button", { name: /검증 실행/ })).toBeNull();
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

  it("renders nothing for a caseless run or folder-only evidence (해당 없음)", async () => {
    const caseless = mockFetch(routes([item({})], false));
    renderWithQuery(<IntegritySeal />);
    await waitFor(() => expect(caseless.calls.some((c) => c.url.includes("processing-snapshot"))).toBe(true));
    expect(screen.queryByTestId("integrity-seal")).toBeNull();
    expect(caseless.calls.some((c) => c.url.startsWith("/api/cases/"))).toBe(false);
    cleanup();

    const folder = mockFetch(routes([item({ source_type: "folder", size_bytes: null })]));
    renderWithQuery(<IntegritySeal />);
    await waitFor(() => expect(folder.calls.some((c) => c.url === "/api/cases/case-1")).toBe(true));
    expect(screen.queryByTestId("integrity-seal")).toBeNull();
  });
});
