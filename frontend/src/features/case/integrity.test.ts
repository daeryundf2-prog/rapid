import { describe, expect, it } from "vitest";
import type { CaseEvidence } from "../../api/cases";
import {
  canRehash,
  itemSeal,
  itemSealWord,
  runEvidence,
  SEAL_META,
  sealSentence,
  sealState,
  unhashableSentence,
} from "./integrity";

function evidence(overrides: Partial<CaseEvidence> = {}): CaseEvidence {
  return {
    citation_id: "C-EVID-000001",
    case_id: "case-1",
    evidence_number: "E-01",
    display_name: "disk.E01",
    source_type: "e01",
    path: "/ev/disk.E01",
    size_bytes: 1024,
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

const SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

describe("sealState (F8)", () => {
  it("is 깨짐 when any item mismatched or failed, whatever the others are", () => {
    for (const status of ["mismatched", "failed"]) {
      const seal = sealState([
        evidence({ citation_id: "a", hash_status: "matched", hashes: { sha256: SHA } }),
        evidence({ citation_id: "b", evidence_number: "E-02", hash_status: status }),
      ]);
      expect(seal.kind).toBe("broken");
      expect(seal.pending.map((item) => item.citation_id)).toEqual(["b"]);
      expect(seal.stamp).toBeUndefined();
    }
    // Every file state but a running hash can be checked again (review #101 P2-1, P3-2).
    expect(canRehash(evidence({ hash_status: "mismatched" }))).toBe(true);
    expect(canRehash(evidence({ hash_status: "failed" }))).toBe(true);
    expect(canRehash(evidence({ hash_status: "matched" }))).toBe(true);
    expect(canRehash(evidence({ hash_status: "computed" }))).toBe(true);
    expect(canRehash(evidence({ hash_status: "hashing" }))).toBe(false);
    expect(canRehash(evidence({ size_bytes: null }))).toBe(false);
  });

  it("is 미검증 for not-requested and interrupted items (both re-hashable)", () => {
    for (const status of ["not-requested", "interrupted"]) {
      const seal = sealState([evidence({ hash_status: status })]);
      expect(seal.kind).toBe("unverified");
      expect(seal.rehashable).toHaveLength(1);
      expect(seal.pending).toHaveLength(1);
    }
  });

  it("is 검증 중 while a hash runs and nothing is broken or unverified", () => {
    const seal = sealState([
      evidence({ citation_id: "a", hash_status: "hashing" }),
      evidence({ citation_id: "b", hash_status: "matched", hashes: { sha256: SHA } }),
    ]);
    expect(seal.kind).toBe("hashing");
    expect(seal.pending).toEqual([]);
    expect(seal.rehashable.map((item) => item.citation_id)).toEqual(["b"]);
  });

  it("is 대조 일치 only when every item matched, stamped with the SHA-256 prefix", () => {
    const seal = sealState([
      evidence({ hash_status: "matched", hash_expected: SHA, hashes: { sha256: SHA } }),
    ]);
    expect(seal.kind).toBe("matched");
    expect(seal.stamp).toBe("a1b2c3d4");
    expect(sealSentence(seal)).toBe("증거 무결성: 대조 일치, SHA-256 a1b2c3d4");
  });

  it("keeps 계산만 됨 apart from 대조 일치: one computed item downgrades the seal, no stamp", () => {
    const computed = sealState([evidence({ hash_status: "computed", hashes: { sha256: SHA } })]);
    expect(computed.kind).toBe("computed");
    expect(computed.stamp).toBeUndefined();
    const mixed = sealState([
      evidence({ citation_id: "a", hash_status: "matched", hashes: { sha256: SHA } }),
      evidence({ citation_id: "b", hash_status: "computed", hashes: { sha256: SHA } }),
    ]);
    expect(mixed.kind).toBe("computed");
    expect(SEAL_META.computed.label).not.toBe(SEAL_META.matched.label);
    expect(SEAL_META.computed.label).toContain("대조 없음");
  });

  it("is 해당 없음 only with no evidence at all", () => {
    expect(sealState([]).kind).toBe("na");
    expect(sealSentence(sealState([]))).toBe("증거 무결성: 증거 없음");
  });

  it("never claims 대조 일치 over evidence that was never hashed, folders included (review #101 P1-1)", () => {
    const folder = evidence({ citation_id: "d", source_type: "folder", size_bytes: null });
    expect(itemSeal(folder)).toBe("na");
    expect(itemSealWord(folder)).toBe("해당 없음 (폴더)");
    const only = sealState([folder]);
    expect(only.kind).toBe("unverified");
    expect(only.unhashable).toEqual([folder]);
    expect(only.rehashable).toEqual([]);
    expect(unhashableSentence(only)).toContain("폴더 증거 1건은 해시가 없습니다");
    // A folder next to a matched file keeps the seal at 미검증, with no stamp.
    const mixed = sealState([
      folder,
      evidence({ citation_id: "f", hash_status: "matched", hashes: { sha256: SHA } }),
    ]);
    expect(mixed.kind).toBe("unverified");
    expect(mixed.stamp).toBeUndefined();
    expect(sealSentence(mixed)).toContain("폴더 증거 1건 해시 없음");
    expect(sealState([evidence({ hash_status: "not-applicable" })]).kind).toBe("unverified");
  });

  it("speaks for the run's own evidence when the snapshot names it", () => {
    const folder = evidence({ citation_id: "d", size_bytes: null });
    const file = evidence({ citation_id: "f", hash_status: "matched", hashes: { sha256: SHA } });
    expect(sealState(runEvidence([folder, file], "d")).kind).toBe("unverified");
    expect(sealState(runEvidence([folder, file], "f")).kind).toBe("matched");
    // No (or an unknown) citation: the whole case, still never matched over the folder.
    expect(runEvidence([folder, file], null)).toHaveLength(2);
    expect(runEvidence([folder, file], "gone")).toHaveLength(2);
  });

  it("dates a match by its oldest check and words it as a past result (review #101 P2-1)", () => {
    const seal = sealState([
      evidence({ citation_id: "a", hash_status: "matched", hash_checked_at: "2026-11-02T01:00:00Z" }),
      evidence({ citation_id: "b", hash_status: "matched", hash_checked_at: "2026-11-01T01:00:00Z" }),
    ]);
    expect(seal.checkedAt).toBe("2026-11-01T01:00:00Z");
    expect(sealState([evidence({ hash_status: "matched" })]).checkedAt).toBeUndefined();
    expect(SEAL_META.matched.description).toContain("마지막 검증 때");
    expect(SEAL_META.matched.description).not.toContain("일치합니다");
  });

  it("never reads an unknown server status as verified", () => {
    expect(sealState([evidence({ hash_status: "something-new" })]).kind).toBe("unverified");
  });

  it("orders items by evidence number and counts each state", () => {
    const seal = sealState([
      evidence({ citation_id: "b", evidence_number: "E-10", hash_status: "matched" }),
      evidence({ citation_id: "a", evidence_number: "E-2", hash_status: "computed" }),
    ]);
    expect(seal.items.map((item) => item.evidence_number)).toEqual(["E-2", "E-10"]);
    expect(seal.counts).toEqual({ broken: 0, unverified: 0, hashing: 0, computed: 1, matched: 1 });
  });
});
