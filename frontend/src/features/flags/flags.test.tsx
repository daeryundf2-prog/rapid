import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { RunTree } from "../../api/runs";
import type { GridRow } from "../../contracts/collection";
import {
  activeChips,
  EMPTY_FILTERS,
  type FilterState,
  partitionFilters,
  removeChip,
} from "../filters/filterModel";
import { catalogColumn, familyLayout, flagsColumn, tsKindLabel } from "../grid/columns/families";
import { flagsSectionNode, treeFlagsSection } from "../tree/model";
import { buildCitation } from "../viewer/citation";
import {
  type FamilyCatalog,
  familyForKind,
  familyForType,
  getCatalog,
  normalizeCatalog,
  noteKindTypeCounts,
  resetKindTypeCounts,
  setCatalog,
} from "./catalog";
import { FlagBanner, FlagCell } from "./FlagCell";
import fallbackJson from "./families.fallback.json";
import { flagCitation, flagsAccessibleName, parseFlags, rowMatchesFlagFilter } from "./flags";

afterEach(() => {
  cleanup();
  setCatalog(null);
  resetKindTypeCounts();
});

function row(fields: Record<string, unknown>): GridRow {
  return {
    rowKey: "artifacts:eventlog:/artifacts/1",
    ref: { collection: "artifacts", kind: "eventlog", locator: "/artifacts/1" },
    title: "1102",
    sourcePath: "C:/Windows/System32/winevt/Logs/Security.evtx",
    timestamp: "2026-03-01T12:00:00Z",
    tags: [],
    reviewStatus: null,
    fields,
  } as unknown as GridRow;
}

const RAW_FLAGS = [
  { id: "rdp.rdp_enabled", grade: "B", label: "RDP 활성화", evidence: { fDenyTSConnections: 0 } },
  {
    id: "eventlog.log_cleared",
    grade: "A",
    label: "로그 삭제",
    evidence: { event_id: 1102, channel: "Security" },
  },
  { id: "eventlog.log_cleared", grade: "A", label: "중복" },
  { id: "", grade: "A" },
  "junk",
];

describe("bundled catalogue (copy of the backend YAML)", () => {
  it("is a valid catalogue: every family's rules exist, sources are https, versions are set", () => {
    const catalog = normalizeCatalog(fallbackJson) as FamilyCatalog;
    expect(catalog.families.length).toBeGreaterThan(20);
    expect(catalog.rules.length).toBeGreaterThan(100);
    expect(catalog.version).toMatch(/^[0-9a-f]{16}$/);
    const ids = new Set(catalog.rules.map((rule) => rule.id));
    for (const family of catalog.families) {
      for (const id of family.rules) expect(ids.has(id), `${family.id} → ${id}`).toBe(true);
      expect(family.core_columns.length, family.id).toBeGreaterThan(0);
    }
    for (const rule of catalog.rules) {
      expect(
        rule.sources.every((url) => url.startsWith("https://")),
        rule.id,
      ).toBe(true);
      expect(String(rule.version), rule.id).not.toBe("");
      expect(rule.label_ko, rule.id).not.toBe("");
    }
  });
});

it("every ts_kind of the bundled catalogue has a Korean chip label", () => {
  const catalog = normalizeCatalog(fallbackJson) as FamilyCatalog;
  const kinds = new Set(
    catalog.families
      .flatMap((f) => [...f.core_columns, ...f.aux_columns])
      .flatMap((c) => (c.ts_kind ? [c.ts_kind] : [])),
  );
  expect(kinds.size).toBeGreaterThan(10);
  for (const kind of kinds) expect(tsKindLabel(kind), kind).not.toMatch(/^시각 종류: /);
});

describe("family resolution (U-F3)", () => {
  const catalog: FamilyCatalog = {
    version: "t",
    families: [
      {
        id: "strings",
        label: "문자열 후보",
        types: [],
        suffixes: ["-string-candidate"],
        core_columns: [{ key: "s", label: "S" }],
        aux_columns: [],
        rules: [],
      },
      {
        id: "kakao",
        label: "카카오톡",
        types: ["kakaotalk-windows-message"],
        prefixes: ["kakaotalk-windows-"],
        core_columns: [{ key: "k", label: "K" }],
        aux_columns: [],
        rules: [],
      },
      {
        id: "evt",
        label: "이벤트 로그",
        types: ["eventlog-event"],
        kinds: ["eventlog"],
        core_columns: [{ key: "e", label: "E" }],
        aux_columns: [],
        rules: [],
      },
    ],
    rules: [],
  };

  it("suffix first (like the backend), then the exact type, then the longest prefix", () => {
    setCatalog(catalog);
    expect(familyForType("kakaotalk-windows-string-candidate")?.id).toBe("strings");
    expect(familyForType("kakaotalk-windows-message")?.id).toBe("kakao");
    expect(familyForType("kakaotalk-windows-attachment")?.id).toBe("kakao");
    expect(familyForType("unknown")).toBeUndefined();
  });

  it("a kind without a claim takes the family holding more than half its rows", () => {
    setCatalog(catalog);
    expect(familyForKind("eventlog")?.id).toBe("evt");
    expect(familyForKind("kakaotalk-windows")).toBeUndefined();
    expect(
      noteKindTypeCounts("kakaotalk-windows", {
        "kakaotalk-windows-message": 120,
        "kakaotalk-windows-db": 29,
        "x-string-candidate": 3,
      }),
    ).toBe(true);
    expect(
      noteKindTypeCounts("kakaotalk-windows", {
        "kakaotalk-windows-message": 120,
        "kakaotalk-windows-db": 29,
        "x-string-candidate": 3,
      }),
    ).toBe(false);
    expect(familyForKind("kakaotalk-windows")?.id).toBe("kakao");
    noteKindTypeCounts("mixed", { "kakaotalk-windows-message": 5, "a-string-candidate": 5 });
    expect(familyForKind("mixed")).toBeUndefined();
  });
});

describe("catalogue columns (U-F3)", () => {
  const details = {
    event_created_at: "2026-03-01T12:00:00Z",
    event_data: { LogonType: "10", IpAddress: "203.0.113.7" },
  };

  it("reads the key, then aliases (event_data.X reads EVTX EventData), and says which key", () => {
    const ip = catalogColumn({
      key: "ip_address",
      label: "원격 IP",
      format: "mono",
      aliases: ["event_data.IpAddress"],
    });
    const r = row({ details });
    expect(ip.format?.(r)).toBe("203.0.113.7");
    expect(ip.tooltip?.(r)).toBe("203.0.113.7 — event_data.IpAddress");
    expect(ip.mono).toBe(true);
    const logon = catalogColumn({
      key: "logon_type",
      label: "로그온 유형",
      format: "logonType",
      aliases: ["event_data.LogonType"],
    });
    expect(logon.format?.(r)).toMatch(/10/);
    expect(logon.format?.(r)).toMatch(/원격/);
  });

  it("time columns show their ts_kind chip with a Korean name", () => {
    const time = catalogColumn({
      key: "time_created",
      label: "시각",
      format: "time",
      ts_kind: "logged",
      aliases: ["event_created_at"],
    });
    render(<div>{time.render?.(row({ details }))}</div>);
    const chip = screen.getByTitle("기록 시각 (logged)");
    expect(chip.textContent).toBe("기록 시각");
    expect(time.tooltip?.(row({ details }))).toContain("기록 시각(logged)");
    expect(time.sortKey).toBe("details.time_created");
  });

  it("family layout: time · 항목 · 특이사항 · core in catalogue order · 선별 · 유형, aux hidden", () => {
    const family = getCatalog().families.find((f) => f.id === "eventlog");
    expect(family).toBeDefined();
    const stub = (id: string) => ({
      id,
      header: id,
      width: 100,
      presets: ["analysis" as const],
      value: () => null,
    });
    const layout = familyLayout(family as NonNullable<typeof family>, {
      title: stub("title"),
      review: stub("review"),
      type: stub("type"),
      rest: [],
    });
    const ids = layout.map((c) => c.id);
    expect(ids.slice(0, 4)).toEqual(["d:time_created", "title", "flags", "d:channel"]);
    const core = (family?.core_columns ?? []).slice(1).map((c) => `d:${c.key}`);
    expect(ids.slice(3, 3 + core.length)).toEqual(core);
    expect(ids.indexOf("review")).toBe(3 + core.length);
    const aux = layout.find((c) => c.id === "d:provider_name");
    expect(aux?.presets).toEqual([]);
  });
});

describe("특이사항 (U-F4)", () => {
  it("parses flags: drops junk and duplicates, A first", () => {
    const flags = parseFlags(RAW_FLAGS);
    expect(flags.map((f) => f.id)).toEqual(["eventlog.log_cleared", "rdp.rdp_enabled"]);
    expect(flagsAccessibleName(flags)).toBe("특이사항 A 1건, B 1건: 로그 삭제, RDP 활성화");
    expect(flagsAccessibleName([])).toBe("특이사항 없음");
  });

  it("the row's own rule version and status win over the catalogue (a later catalogue may differ)", () => {
    const [flag] = parseFlags([
      {
        id: "eventlog.log_cleared",
        grade: "A",
        label: "로그 삭제",
        version: 3,
        status: "provisional",
        evidence: { event_id: 1102 },
      },
    ]);
    expect(flagCitation(flag as NonNullable<typeof flag>)).toBe("eventlog.log_cleared@3 (event_id=1102)");
    render(
      <FlagBanner
        row={row({ flags: [{ id: "eventlog.log_cleared", grade: "A", status: "provisional" }] })}
      />,
    );
    expect(screen.getByText("검증 필요")).toBeTruthy();
  });

  it("cites rule_id@version with the evidence fields (U-F6)", () => {
    const [cleared] = parseFlags(RAW_FLAGS);
    expect(flagCitation(cleared as NonNullable<typeof cleared>)).toBe(
      "eventlog.log_cleared@1 (event_id=1102, channel=Security)",
    );
    const r = row({ flags: RAW_FLAGS, details: {} });
    const citation = buildCitation({ runId: "r1", ref: r.ref, sourcePath: r.sourcePath }, "abc", r, "utc");
    expect(citation).toContain(
      "특이사항=eventlog.log_cleared@1 (event_id=1102, channel=Security) | rdp.rdp_enabled@1 (fDenyTSConnections=0)",
    );
  });

  it("the column cell names grades and labels; the popover shows evidence, 오탐 주의, 출처, 검증 필요", () => {
    const r = row({ flags: RAW_FLAGS });
    const column = flagsColumn();
    expect(column.sortKey).toBe("flags");
    render(<div>{column.render?.(r)}</div>);
    const button = screen.getByRole("button", { name: "특이사항 A 1건, B 1건: 로그 삭제, RDP 활성화" });
    fireEvent.click(button);
    const dialog = screen.getByRole("dialog", { name: "특이사항 근거" });
    expect(within(dialog).getByText("1102")).toBeTruthy();
    expect(within(dialog).getAllByText(/오탐 주의/).length).toBe(2);
    // rdp.rdp_enabled is provisional in the fixture.
    expect(within(dialog).getByText("검증 필요")).toBeTruthy();
    const source = within(dialog).getAllByRole("link")[0] as HTMLAnchorElement;
    expect(source.href).toMatch(/^https:\/\//);
    expect(source.rel).toContain("noopener");
  });

  it("rows without flags show a dash, not a button", () => {
    render(<FlagCell row={row({})} />);
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("viewer banner: open for an A flag, summary carries the accessible name", () => {
    render(<FlagBanner row={row({ flags: RAW_FLAGS })} />);
    const banner = screen.getByTestId("viewer-flag-banner") as HTMLDetailsElement;
    expect(banner.open).toBe(true);
    expect(banner.querySelector("summary")?.getAttribute("aria-label")).toBe(
      "특이사항 A 1건, B 1건: 로그 삭제, RDP 활성화 — 근거 보기",
    );
    cleanup();
    render(<FlagBanner row={row({ flags: [RAW_FLAGS[0]] })} />);
    expect((screen.getByTestId("viewer-flag-banner") as HTMLDetailsElement).open).toBe(false);
  });

  it("filter conditions: grade/rule chips, server flag= / flag_grade= on artifacts, × removes one", () => {
    const filters: FilterState = { ...EMPTY_FILTERS, flags: ["eventlog.log_cleared"], flagGrade: "B" };
    const chips = activeChips(filters, (s) => s);
    expect(chips.map((c) => c.label)).toEqual(["특이사항 B 이상", "특이사항 로그 삭제"]);
    const plan = partitionFilters({ id: "artifacts", kind: "eventlog" }, filters);
    expect(plan.server.flags).toEqual(["eventlog.log_cleared"]);
    expect(plan.server.flagGrade).toBe("B");
    expect(plan.serverLabels).toContain("특이사항");
    expect(partitionFilters({ id: "timeline" }, filters).clientLabels).toContain("특이사항");
    const after = removeChip(filters, chips[1] as (typeof chips)[number]);
    expect(after.flags).toEqual([]);
    expect(after.flagGrade).toBe("B");
    expect(rowMatchesFlagFilter(row({ flags: RAW_FLAGS }), [], "A")).toBe(true);
    expect(rowMatchesFlagFilter(row({ flags: [RAW_FLAGS[0]] }), [], "A")).toBe(false);
  });
});

describe("tree 특이사항 section (U-F4)", () => {
  const base: RunTree = { run_id: "r1", root: {}, nodes: [] };

  it("reads D1's group node (grades = rows by best grade) and counts grade nodes cumulatively", () => {
    const tree: RunTree = {
      ...base,
      nodes: [
        {
          id: "flags",
          label: "특이사항",
          count: 9,
          collection: "flags",
          grades: { A: 2, B: 3, C: 4 },
          rules: [
            { id: "eventlog.log_cleared", label: "로그 삭제", grade: "A", status: "verified", count: 2 },
            { id: "rdp.rdp_enabled", label: "RDP 활성화", grade: "B", status: "provisional", count: 3 },
          ],
          source: { status: "joined" },
        } as never,
      ],
    };
    const section = treeFlagsSection(tree);
    expect(section?.total).toBe(9);
    const node = flagsSectionNode(tree);
    expect(node.children?.map((c) => [c.label, c.count])).toEqual([
      ["A 등급", 2],
      ["B 등급 이상", 5],
      ["C 등급 이상", 9],
    ]);
    const rdp = node.children?.[1]?.children?.[0];
    expect(rdp?.label).toBe("RDP 활성화");
    expect(rdp?.note).toMatch(/검증 필요/);
    expect(rdp?.target).toEqual({ collection: "artifacts", flags: ["rdp.rdp_enabled"] });
  });

  it("no flag set (no section, or a skipped source): hidden with the reason", () => {
    expect(treeFlagsSection(base)).toBeUndefined();
    const skipped: RunTree = {
      ...base,
      nodes: [{ id: "flags", label: "특이사항", source: { status: "skipped" } } as never],
    };
    expect(treeFlagsSection(skipped)).toBeUndefined();
    const node = flagsSectionNode(base);
    expect(node.hiddenReason).toMatch(/특이사항 분석 결과가 없습니다/);
    expect(node.disabledReason).toBe(node.hiddenReason);
  });

  it("also reads the {total, by_grade, by_rule} section form", () => {
    const tree = {
      ...base,
      flags: { total: 1, by_grade: { A: 1 }, by_rule: { "eventlog.log_cleared": 1 } },
    } as RunTree;
    expect(flagsSectionNode(tree).children?.[0]?.children?.[0]?.label).toBe("로그 삭제");
  });
});
