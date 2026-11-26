import { describe, expect, it } from "vitest";
import { artifactTypeLabel } from "../filters/typeLabels";
import { recordHighlight, summarizeArtifact } from "../grid/columns/artifactSummary";
import { makeRow } from "../grid/columns/common";
import { FIELD_LABELS } from "../grid/columns/fieldColumns";
import { recordCitationParts } from "../viewer/citation";
import { recordByteRange } from "../viewer/record";
import { DOMAINS } from "./domains";

describe("로그인 및 작업 표시줄 기록", () => {
  it("opens the provider rows with Korean labels for each type and detail column", () => {
    const nodes = DOMAINS.flatMap((domain) => domain.nodes);
    for (const [kind, type] of [
      ["linux-system", "linux-utmp"],
      ["linux-system", "linux-wtmp"],
      ["linux-system", "linux-btmp"],
      ["linux-system", "linux-lastlog"],
      ["linux-system", "linux-login-accounting-summary"],
      ["windows-registry", "registry-taskband-pin"],
      ["windows-registry", "registry-taskband-summary"],
      ["windows-registry", "execution-feature-usage"],
    ] as const) {
      const matches = nodes.filter((node) => node.target.kind === kind && node.target.types?.includes(type));
      expect(matches).toHaveLength(1);
      expect(artifactTypeLabel(type)).toMatch(/[가-힣]/);
      const cols = matches[0]?.target.cols ?? [];
      expect(cols.length).toBeGreaterThan(0);
      for (const col of cols) expect(FIELD_LABELS[col.slice("details.".length)]).toMatch(/[가-힣]/);
    }
  });

  it("presents an application and an unresolved UID without relying on a source filename", () => {
    const details = { application: "예시", value_name: "Favorites" };
    const pin = summarizeArtifact("registry-taskband-pin", details, null);
    expect(pin).toEqual({ title: "예시", detail: "Favorites" });
    expect(summarizeArtifact("linux-lastlog", { uid: 0, tty: "tty1" }, null)).toEqual({
      title: "UID 0",
      detail: "tty1",
    });
  });

  it("highlights the Linux record byte range and preserves .reg line offset semantics", () => {
    const ref = { collection: "artifacts", locator: "/artifacts/0" } as const;
    const login = { source_offset: 384, source_length: 384, record_sha256: "a".repeat(64) };
    const loginRow = makeRow(ref, { title: "예시", artifactType: "linux-wtmp" }, { details: login });
    const range = { offset: 384, length: 384 };
    expect(recordHighlight(login)).toEqual(range);
    expect(recordByteRange(loginRow)).toEqual(range);
    expect(recordCitationParts(loginRow, "utc")).toContain(`레코드 sha256=${login.record_sha256}`);

    const pin = { source_offset: 3, source_offset_unit: "line", key_path: "HKCU", value_name: "Favorites" };
    const pinRow = makeRow(ref, { title: "예시", artifactType: "registry-taskband-pin" }, { details: pin });
    expect(recordHighlight(pin)).toBeUndefined();
    expect(recordByteRange(pinRow)).toBeNull();
    expect(recordCitationParts(pinRow, "utc")).toEqual(
      expect.arrayContaining(["원본 줄=3", "키=HKCU", "값=Favorites"]),
    );
  });
});
