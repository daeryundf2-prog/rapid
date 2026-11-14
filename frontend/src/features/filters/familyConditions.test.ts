/**
 * 계열 · 중복 · 예외 항목 conditions (R7 갈래 A): URL round trip, filter state, server params,
 * Korean chips (never a ref or a category id), saved condition sets and the client fallback.
 */

import { describe, expect, it } from "vitest";
import type { GridRow } from "../../contracts/collection";
import { parseHash, serializeRoute } from "../../router";
import { normalizeFilters } from "./conditionMemory";
import { IRREGULAR_IDS, IRREGULAR_LABELS, isFamilyRef, normalizeFamilyRefs } from "./conditionValues";
import {
  activeChips,
  EMPTY_FILTERS,
  filtersEqual,
  filtersFromRoute,
  filtersToRoutePatch,
  partitionFilters,
  removeChip,
  rowMatchesRowSets,
} from "./filterModel";

const REF = "artifacts:email:/artifacts/3";

describe("URL (family= · dup= · dup_mode= · irregular=)", () => {
  it("round-trips and drops invalid values", () => {
    const hash = serializeRoute({
      runId: "r1",
      collection: "artifacts",
      family: [REF, "files::/candidates/2"],
      dup: "duplicate",
      dupMode: "family",
      irregular: ["encrypted", "deleted"],
    });
    expect(hash).toContain(`family=${encodeURIComponent(REF)}`);
    expect(hash).toContain("dup=duplicate");
    expect(hash).toContain("dup_mode=family");
    expect(hash).toContain("irregular=encrypted,deleted");
    const route = parseHash(hash);
    expect(route.family).toEqual([REF, "files::/candidates/2"]);
    expect(route.dup).toBe("duplicate");
    expect(route.dupMode).toBe("family");
    expect(route.irregular).toEqual(["deleted", "encrypted"]);
    const junk = parseHash(
      "#/case/r1/explore/artifacts?family=bogus&dup=maybe&dup_mode=team&irregular=haunted",
    );
    expect(junk.family).toBeUndefined();
    expect(junk.dup).toBeUndefined();
    expect(junk.dupMode).toBeUndefined();
    expect(junk.irregular).toBeUndefined();
    // dup_mode without dup means nothing; item (the default) is never written.
    expect(parseHash("#/case/r1/explore/files?dup_mode=family").dupMode).toBeUndefined();
    expect(
      serializeRoute({ runId: "r1", collection: "files", dup: "original", dupMode: "item" }),
    ).not.toContain("dup_mode");
  });

  it("validates item refs like the server", () => {
    expect(isFamilyRef(REF)).toBe(true);
    expect(isFamilyRef("artifacts:generic-documents:/artifacts/0#entry:3")).toBe(true);
    expect(isFamilyRef("analysis:20260101T000000-abc:/rows/0")).toBe(true);
    expect(isFamilyRef("source::C:\\x")).toBe(false);
    expect(isFamilyRef("artifacts::/artifacts/1")).toBe(false);
    expect(normalizeFamilyRefs([REF, REF, 3, "x"])).toEqual([REF]);
  });
});

describe("filter state, server params and chips", () => {
  const filters = filtersFromRoute({
    runId: "r1",
    collection: "artifacts",
    family: [REF],
    dup: "original",
    dupMode: "custodian",
    irregular: ["encrypted"],
  });

  it("maps the route and back", () => {
    expect(filters).toMatchObject({
      family: [REF],
      dup: "original",
      dupMode: "custodian",
      irregular: ["encrypted"],
    });
    expect(filtersToRoutePatch(filters)).toMatchObject({
      family: [REF],
      dup: "original",
      dupMode: "custodian",
      irregular: ["encrypted"],
    });
    expect(filtersEqual(filters, EMPTY_FILTERS)).toBe(false);
    expect(filtersEqual(filters, { ...filters })).toBe(true);
  });

  it("goes to the server on artifacts / files / timeline only", () => {
    for (const id of ["artifacts", "files", "timeline"] as const) {
      const plan = partitionFilters({ id }, filters);
      expect(plan.server.conditions).toMatchObject({
        family: [REF],
        dup: "original",
        dup_mode: "custodian",
        irregular: "encrypted",
      });
      expect(plan.serverLabels).toEqual(expect.arrayContaining(["계열", "중복", "예외 항목"]));
      expect(plan.clientLabels).not.toContain("중복");
    }
    const docs = partitionFilters({ id: "docs" }, filters);
    expect(docs.server.conditions).toBeUndefined();
    expect(docs.clientLabels).toEqual(expect.arrayContaining(["계열", "중복", "예외 항목"]));
  });

  it("chips read Korean names only and remove their condition", () => {
    const chips = activeChips(filters, (s) => s);
    const labels = chips.map((chip) => chip.label);
    expect(labels).toEqual(
      expect.arrayContaining(["계열 1개 항목", "중복 원본만 (보관자 순위별)", "예외 암호화"]),
    );
    for (const label of labels) {
      expect(label).not.toMatch(/artifacts:|encrypted|original|custodian/);
    }
    const dup = chips.find((chip) => chip.key === "dup");
    expect(dup && removeChip(filters, dup)).toMatchObject({ dup: undefined, dupMode: undefined });
    const family = chips.find((chip) => chip.key === "family");
    expect(family && removeChip(filters, family).family).toBeUndefined();
    const irregular = chips.find((chip) => chip.key === "irregular");
    expect(irregular && removeChip(filters, irregular).irregular).toBeUndefined();
  });

  it("every category has a Korean label", () => {
    expect(IRREGULAR_IDS).toHaveLength(9);
    for (const id of IRREGULAR_IDS) expect(IRREGULAR_LABELS[id]).toMatch(/[가-힣]/);
  });
});

describe("saved condition sets and the client fallback", () => {
  it("keeps valid values of a saved set", () => {
    const saved = normalizeFilters({
      family: [REF, "nope"],
      dup: "any",
      dupMode: "family",
      irregular: ["empty", "haunted"],
    });
    expect(saved).toMatchObject({ family: [REF], dup: "any", dupMode: "family", irregular: ["empty"] });
    expect(normalizeFilters({ dupMode: "family" }).dupMode).toBeUndefined();
  });

  it("checks rows by their annotations; 예외 항목 is server-only", () => {
    const row = (fields: Record<string, unknown>) => ({ fields }) as unknown as GridRow;
    const annotated = row({ family: { top: REF }, dedup: { status: "duplicate", count: 3 } });
    expect(rowMatchesRowSets(annotated, { family: [REF] })).toBe(true);
    expect(rowMatchesRowSets(annotated, { family: ["files::/candidates/1"] })).toBe(false);
    expect(rowMatchesRowSets(annotated, { dup: "duplicate" })).toBe(true);
    expect(rowMatchesRowSets(annotated, { dup: "any" })).toBe(true);
    expect(rowMatchesRowSets(annotated, { dup: "original" })).toBe(false);
    expect(rowMatchesRowSets(row({}), { dup: "original" })).toBe(false);
    expect(rowMatchesRowSets(annotated, { irregular: ["empty"] })).toBe(false);
    expect(rowMatchesRowSets(row({}), {})).toBe(true);
  });
});
