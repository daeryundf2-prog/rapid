import { describe, expect, it } from "vitest";
import type { ReviewCounts } from "../../api/caseDb";
import type { EvidenceSource } from "../../api/dashboard";
import type { RunSummary, RunTree } from "../../api/runs";
import { formatRoute, parseRoute, sameRoute } from "./adapter";
import { artifactKindNodes, buildTreeModel, flattenVisible } from "./model";

const summary = (over: Record<string, number> = {}): RunSummary => ({
  summary: {
    counts: {
      validation_issues: 2,
      outputs: 9,
      artifacts: 120,
      docs: 4,
      files: 30,
      timeline_events: 0,
      review_items: 0,
      indicators: 3,
      ...over,
    },
  },
});

const tree: RunTree = {
  run_id: "r1",
  root: {},
  nodes: [
    {
      id: "artifacts",
      label: "아티팩트",
      count: 120,
      collection: "artifacts",
      children: [
        {
          id: "artifacts-group:event-log",
          label: "이벤트 로그",
          count: 100,
          children: [
            {
              id: "artifacts:eventlog",
              label: "EVTX",
              count: 100,
              collection: "artifacts",
              kind: "eventlog",
              children: [
                {
                  id: "artifacts:eventlog:4624",
                  label: "4624",
                  count: 5,
                  collection: "artifacts",
                  kind: "eventlog",
                  artifact_type: "4624",
                },
              ],
            },
          ],
        },
        {
          id: "artifacts-group:browser",
          label: "브라우저",
          count: 20,
          children: [
            {
              id: "artifacts:browser",
              label: "브라우저",
              count: 20,
              collection: "artifacts",
              kind: "browser",
            },
          ],
        },
        {
          id: "artifacts-group:cloud",
          label: "클라우드",
          count: 0,
          children: [
            {
              id: "artifacts:cloud-export",
              label: "클라우드",
              count: 0,
              collection: "artifacts",
              kind: "cloud-export",
            },
          ],
        },
      ],
    },
  ],
};

const review: ReviewCounts = {
  run_id: "r1",
  database: "/x/case.db",
  case_id: "run-r1",
  exists: true,
  by_status: { relevant: 3, excluded: 1 },
  include_in_report: 2,
  case_json: { bookmarks: 0, include_in_report: 0 },
  report_candidates: 2,
};

describe("routes", () => {
  it("round-trips #/case/{run}/{collection}[/{kind}]", () => {
    const route = { runId: "abc", collection: "artifacts" as const, kind: "eventlog" };
    expect(formatRoute(route)).toBe("#/case/abc/artifacts/eventlog");
    expect(parseRoute("#/case/abc/artifacts/eventlog")).toEqual(route);
    expect(parseRoute("#/case/abc/review/needs-review")).toEqual({
      runId: "abc",
      collection: "review",
      status: "needs-review",
    });
    expect(parseRoute("#/case/abc/files?q=x&row=y")).toEqual({ runId: "abc", collection: "files" });
    expect(parseRoute("#/case/abc")).toEqual({ runId: "abc", collection: "intake" });
    expect(parseRoute("#/other")).toBeNull();
    expect(parseRoute("#/case/abc/bogus")).toBeNull();
  });

  it("compares routes", () => {
    expect(sameRoute({ runId: "a", collection: "files" }, { runId: "a", collection: "files" })).toBe(true);
    expect(sameRoute(null, { runId: "a", collection: "files" })).toBe(false);
  });
});

describe("tree model", () => {
  it("lists the plan 4.2 nodes in order with counts and artifact kinds", () => {
    const model = buildTreeModel({ summary: summary(), tree, review, saved: [] });
    expect(model.map((n) => n.label)).toEqual([
      "증거 소스",
      "접수",
      "검색 결과",
      "파일/미디어",
      "문서/메일",
      "아티팩트",
      "타임라인",
      "IOC/위험",
      "리뷰보드",
      "산출물",
    ]);
    expect(model.map((n) => n.count)).toEqual([undefined, 2, undefined, 30, 4, 120, 0, 3, 4, 9]);
    const artifacts = model.find((n) => n.id === "artifacts");
    // X11: 아티팩트 → category (bold summed count) → kind (route unchanged).
    expect(artifacts?.children?.map((c) => [c.label, c.count, c.route.category, c.strongCount])).toEqual([
      ["웹 관련", 20, "web", true],
      ["운영 체제", 100, "operating-system", true],
    ]);
    const os = artifacts?.children?.find((c) => c.id === "artifacts-category:operating-system");
    expect(os?.children?.map((c) => [c.label, c.count, c.route.kind, c.icon])).toEqual([
      ["EVTX", 100, "eventlog", "list"],
    ]);
    expect(artifacts?.children?.[0]?.children?.[0]?.route).toEqual({
      collection: "artifacts",
      kind: "browser",
    });
  });

  it("skips zero-count and artifact_type nodes", () => {
    expect(artifactKindNodes(tree).map((n) => n.kind)).toEqual(["eventlog", "browser"]);
  });

  it("review board children carry state counts from case-db", () => {
    const model = buildTreeModel({ summary: summary(), tree, review });
    const board = model.find((n) => n.id === "review");
    expect(board?.children?.map((c) => [c.label, c.count, c.route.status])).toEqual([
      ["관련 있음", 3, "relevant"],
      ["재검토", 0, "needs-review"],
      ["제외", 1, "excluded"],
      ["보고서 포함", 2, "include-in-report"],
    ]);
  });

  it("disables empty data nodes with a Korean reason once counts are loaded", () => {
    const model = buildTreeModel({ summary: summary(), tree });
    expect(model.find((n) => n.id === "timeline")?.disabledReason).toBe(
      "이 런에는 타임라인 산출물이 없습니다",
    );
    expect(model.find((n) => n.id === "files")?.disabledReason).toBeUndefined();
    const before = buildTreeModel({});
    expect(before.every((n) => n.disabledReason === undefined)).toBe(true);
  });

  it("shows live provider progress on the intake node while a run is active", () => {
    const model = buildTreeModel({ live: { active: true, completed: 17, total: 24 } });
    expect(model.find((n) => n.id === "intake")?.count).toBe("17/24");
  });

  it("flattens only expanded branches", () => {
    const model = buildTreeModel({ summary: summary(), tree, review });
    const collapsed = flattenVisible(model, new Set());
    expect(collapsed).toHaveLength(10);
    const open = flattenVisible(model, new Set(["artifacts"]));
    expect(open.filter((f) => f.level === 2).map((f) => f.node.label)).toEqual(["웹 관련", "운영 체제"]);
    const deep = flattenVisible(model, new Set(["artifacts", "artifacts-category:operating-system"]));
    expect(deep.filter((f) => f.level === 3).map((f) => f.node.label)).toEqual(["EVTX"]);
  });
});

const evidence: EvidenceSource = {
  path: "D:/ev/case1.E01",
  name: "case1.E01",
  kind: "image",
  image_output: "e01",
  size_bytes: 1024 ** 3,
  selected_partition: 2,
  partitions: [
    {
      number: 1,
      description: "FAT32",
      filesystem: "fat32",
      size_bytes: 100 * 1024 ** 2,
      start_sector: 63,
      byte_offset: 32256,
      selected: false,
      recommended: false,
    },
    {
      number: 2,
      description: "NTFS",
      filesystem: "ntfs",
      size_bytes: 930 * 1024 ** 3,
      start_sector: 2048,
      byte_offset: 1048576,
      selected: true,
      recommended: true,
    },
  ],
};

describe("evidence source node (X2/X17)", () => {
  it("puts 증거 소스 → image (files + artifacts) → partitions at the top", () => {
    const model = buildTreeModel({ summary: summary(), tree, evidence });
    const root = model[0];
    expect(root?.id).toBe("evidence");
    expect(root?.count).toBe(1);
    const image = root?.children?.[0];
    expect(image?.label).toBe("case1.E01");
    expect(image?.count).toBe(150);
    expect(image?.route).toEqual({ collection: "files" });
    expect(image?.children?.map((c) => [c.label, c.marker, c.disabledReason === undefined])).toEqual([
      ["파티션 1 (FAT32, 100 MB)", undefined, false],
      ["파티션 2 (NTFS, 930 GB)", "선택됨", true],
    ]);
    expect(image?.children?.[1]?.route).toEqual({ collection: "files" });
    expect(model.flatMap((n) => [n, ...(n.children ?? [])]).filter((n) => n.noSelect).length).toBeGreaterThan(
      0,
    );
  });

  it("shows a bare 증거 소스 node until the dashboard data arrives", () => {
    const root = buildTreeModel({})[0];
    expect(root?.label).toBe("증거 소스");
    expect(root?.children).toBeUndefined();
    expect(root?.disabledReason).toBeUndefined();
  });
});

describe("category routes", () => {
  it("round-trips ?category= on the artifacts node", () => {
    const route = { runId: "abc", collection: "artifacts" as const, category: "web" };
    expect(formatRoute(route)).toBe("#/case/abc/artifacts?category=web");
    expect(parseRoute("#/case/abc/artifacts?category=web")).toEqual(route);
    expect(sameRoute(route, { runId: "abc", collection: "artifacts" })).toBe(false);
    expect(parseRoute("#/case/abc/artifacts/eventlog?category=web")).toEqual({
      runId: "abc",
      collection: "artifacts",
      kind: "eventlog",
    });
  });
});
