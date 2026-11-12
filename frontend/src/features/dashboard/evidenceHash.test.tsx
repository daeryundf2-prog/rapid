// Evidence hash display honesty (R8 T-129): E01 labels name the container bytes, a mismatch is
// amber, segment values come first and the recorded acquisition hash (T-181) is the third line;
// file evidence keeps its wording.

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { CaseEvidence } from "../../api/cases";
import { EvidenceHashValues, EWF_HASH_SCOPE, evidenceHashLabel } from "./evidenceHash";

afterEach(cleanup);

const MD5 = "a".repeat(32);
const SHA1 = "b".repeat(40);

function evidence(over: Partial<CaseEvidence> = {}): CaseEvidence {
  return {
    citation_id: "C-EVID-000001",
    case_id: "case-1",
    evidence_number: "E-01",
    display_name: "disk.E01",
    source_type: "e01",
    path: "D:/ev/disk.E01",
    size_bytes: 10,
    hash_verify: true,
    hash_expected: "",
    hash_status: "computed",
    hash_status_label: "",
    hash_message: "",
    hashes: { sha256: "f".repeat(64) },
    hash_scope: EWF_HASH_SCOPE,
    hash_segments: [],
    hash_recorded: null,
    added_at: null,
    runs: [],
    ...over,
  };
}

const segment = (n: number) => ({
  name: `disk.E0${n}`,
  segment_number: n,
  size_bytes: 5,
  md5: "",
  sha1: "",
  sha256: `${n}`.repeat(64),
});

describe("evidence hash labels (T-129)", () => {
  it("names container bytes for E01 and keeps mismatch amber", () => {
    expect(evidenceHashLabel(evidence({ hash_status: "matched" }))).toEqual(["컨테이너 해시 일치", "ok"]);
    expect(evidenceHashLabel(evidence())).toEqual(["컨테이너 해시 계산됨", "ok"]);
    expect(evidenceHashLabel(evidence({ hash_status: "mismatched", hash_expected: "0".repeat(64) }))).toEqual(
      ["컨테이너 해시가 입력값과 다름 — 매체 해시 미대조", "warn"],
    );
  });

  it("reads the recorded acquisition hash comparison without claiming a media hash", () => {
    const recorded = { md5: MD5, sha1: SHA1, reason: "" };
    expect(evidenceHashLabel(evidence({ hash_expected: MD5, hash_recorded: recorded }))).toEqual([
      "입력값 = 기록된 취득 해시 — 매체 재계산 안 함",
      "info",
    ]);
    expect(
      evidenceHashLabel(
        evidence({ hash_status: "mismatched", hash_expected: "1".repeat(40), hash_recorded: recorded }),
      ),
    ).toEqual(["입력값이 기록된 취득 해시와 다름 — 매체 해시 미대조", "warn"]);
    // WB-8 P1-1: SHA-256 input (E01 records none) or no recorded hash is not-comparable, never red.
    const notComparable = ["입력값 대조 불가 — 이미지에 같은 종류의 기록된 취득 해시 없음", "info"];
    expect(evidenceHashLabel(evidence({ hash_expected: "0".repeat(64), hash_recorded: recorded }))).toEqual(
      notComparable,
    );
    expect(
      evidenceHashLabel(
        evidence({ hash_expected: MD5, hash_recorded: { md5: "", sha1: "", reason: "없음" } }),
      ),
    ).toEqual(notComparable);
  });

  it("keeps the file-evidence wording (dd, raw, exports)", () => {
    const file = { source_type: "dd", hash_scope: "file-bytes" };
    expect(evidenceHashLabel(evidence({ ...file, hash_status: "mismatched" }))).toEqual([
      "해시 불일치",
      "danger",
    ]);
    expect(evidenceHashLabel(evidence({ ...file, hash_status: "matched" }))).toEqual(["해시 일치", "ok"]);
    // Before the hash finished there is no scope: the evidence type decides.
    expect(evidenceHashLabel(evidence({ hash_scope: "", hash_status: "matched" }))[0]).toBe(
      "컨테이너 해시 일치",
    );
    expect(
      evidenceHashLabel(evidence({ hash_scope: "", source_type: "export", hash_status: "matched" }))[0],
    ).toBe("해시 일치");
  });
});

describe("evidence hash values (T-129)", () => {
  it("lists segment SHA-256 first and the recorded acquisition hash third", () => {
    render(
      <EvidenceHashValues
        item={evidence({
          hash_segments: [segment(1), segment(2)],
          hash_recorded: { md5: MD5, sha1: "", reason: "" },
        })}
      />,
    );
    const box = screen.getByTestId("evidence-hash-values");
    const lines = [...box.children].map((el) => el.textContent ?? "");
    expect(lines[0]).toContain(`세그먼트 1 disk.E01 · SHA-256 ${"1".repeat(64)}`);
    expect(lines[0]).toContain(`세그먼트 2 disk.E02 · SHA-256 ${"2".repeat(64)}`);
    expect(lines[1]).toBe(`이미지에 기록된 취득 해시 MD5 ${MD5} (다시 계산하지 않음)`);
    expect(lines[2]).toContain("취득 로그의 매체(디스크) 해시와는 값이 다른 것이 정상입니다");
  });

  it("folds many segments and says when no acquisition hash was recorded", () => {
    render(
      <EvidenceHashValues
        item={evidence({
          hash_segments: [1, 2, 3, 4].map(segment),
          hash_recorded: { md5: "", sha1: "", reason: "hash 섹션 없음" },
        })}
      />,
    );
    expect(screen.getByText("세그먼트 4개 컨테이너 SHA-256")).toBeTruthy();
    expect(screen.getByTestId("evidence-recorded-hash").textContent).toBe(
      "이미지에 기록된 취득 해시 없음 (hash 섹션 없음)",
    );
  });

  it("shows a file's SHA-256 alone and nothing before a hash exists", () => {
    const { container, rerender } = render(
      <EvidenceHashValues item={evidence({ source_type: "dd", hash_scope: "file-bytes" })} />,
    );
    expect(container.textContent).toBe(`SHA-256 ${"f".repeat(64)}`);
    rerender(<EvidenceHashValues item={evidence({ hash_status: "hashing", hash_scope: "", hashes: {} })} />);
    expect(container.textContent).toBe("");
  });
});
