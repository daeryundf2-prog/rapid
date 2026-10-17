import { describe, expect, it } from "vitest";
import type { ReviewCounts } from "../../api/caseDb";
import type { EvidenceSource } from "../../api/dashboard";
import type { RunSummary, RunTree } from "../../api/runs";
import { formatRoute, parseRoute, sameRoute } from "./adapter";
import { DOMAINS } from "./domains";
import { artifactKindNodes, buildTreeModel, flattenVisible, NO_DATA_REASON, reviewCount } from "./model";

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
  it("round-trips #/case/{run}/{stage}/{view}[/{kind}] and still reads legacy links", () => {
    const route = { runId: "abc", collection: "artifacts" as const, kind: "eventlog" };
    expect(formatRoute(route)).toBe("#/case/abc/explore/artifacts/eventlog");
    expect(parseRoute("#/case/abc/explore/artifacts/eventlog")).toEqual(route);
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

describe("tree model (탐색 domain tree, console-ia §4)", () => {
  it("lists 증거 소스, the 전체 보기 views, 통합 보기 and the 15 forensic domains", () => {
    const model = buildTreeModel({ summary: summary(), tree, review, saved: [] });
    // 특이사항 (U-F4) follows 전체 보기; with no flag set it is hidden by default (U-F7).
    expect(model.map((n) => n.label)).toEqual([
      "증거 소스",
      "전체 보기",
      "특이사항",
      ...DOMAINS.map((d) => d.label),
    ]);
    // 통합 보기 (axiom-adoption §3.2) leads the 15 forensic domains.
    expect(DOMAINS).toHaveLength(16);
    expect(DOMAINS[0]?.label).toBe("통합 보기");
    // Workflow places are rail stages, not tree nodes.
    const ids = flattenVisible(model, new Set(model.map((n) => n.id))).map((f) => f.node.id);
    for (const gone of ["intake", "review", "outputs", "analyses"]) expect(ids).not.toContain(gone);
    const views = model.find((n) => n.id === "views");
    expect(views?.children?.map((c) => [c.label, c.count])).toEqual([
      ["전체 파일", 30],
      ["전체 아티팩트", 120],
      ["전체 타임라인", 0],
      ["문서/메일", 4],
      ["검색 결과", undefined],
      ["IOC/위험", 3],
    ]);
  });

  it("maps each node to its request (kind / artifact_type / ext / analysis) with /tree counts", () => {
    const model = buildTreeModel({ summary: summary(), tree });
    const node = (id: string) =>
      model.flatMap((n) => n.children ?? []).find((c) => c.id === id) as ReturnType<typeof model.find>;
    expect(node("domain:eventlog:evt-all")).toMatchObject({
      count: 100,
      target: { collection: "artifacts", kind: "eventlog" },
    });
    expect(node("domain:web:web-all")).toMatchObject({ count: 20 });
    // A kind the run lacks is dimmed with a reason.
    expect(node("domain:cloud:cloud-export")).toMatchObject({ count: 0, disabledReason: NO_DATA_REASON });
    // Typed node: the per-type counts of /tree (eventlog has type children, so 0 is known).
    expect(node("domain:incident:ir-webshell")).toMatchObject({
      count: 0,
      target: { collection: "artifacts", kind: "windows-system", types: ["webshell-source-candidate"] },
      disabledReason: NO_DATA_REASON,
    });
    // File types use the server category filter (GET /files?category=), not client extensions.
    expect(node("domain:filesystem:fs-documents")?.target).toEqual({
      collection: "files",
      category: "documents",
    });
    // Analysis result nodes are never disabled; a never-ran job only shows its marker.
    expect(node("domain:filesystem:fs-carve")).toMatchObject({
      target: { collection: "analysis", kind: "carve" },
      disabledReason: undefined,
      marker: "미실행",
    });
  });

  it("every typed node carries its kind (one kind per request, so paging works)", () => {
    for (const domain of DOMAINS) {
      for (const node of domain.nodes) {
        if (node.target.types?.length) expect(node.target.kind, `${domain.id}/${node.id}`).toBeTruthy();
      }
    }
  });

  it("typed counts come from the kind node's artifact_type_counts", () => {
    const withTypes: RunTree = {
      run_id: "r1",
      root: {},
      nodes: [
        {
          id: "artifacts:windows-system",
          label: "Windows 시스템",
          count: 9,
          collection: "artifacts",
          kind: "windows-system",
          artifact_type_counts: { "web-server-log": 5, "wer-report": 4 },
        },
        {
          id: "artifacts:windows-registry",
          label: "레지스트리",
          count: 3,
          collection: "artifacts",
          kind: "windows-registry",
        },
      ],
    };
    const model = buildTreeModel({ summary: summary(), tree: withTypes });
    const node = (id: string) => model.flatMap((n) => n.children ?? []).find((c) => c.id === id);
    expect(node("domain:incident:ir-weblog")).toMatchObject({ count: 5, disabledReason: undefined });
    expect(node("domain:incident:ir-webshell")).toMatchObject({ count: 0, disabledReason: NO_DATA_REASON });
    expect(node("domain:os:os-wer")?.count).toBe(4);
    // A kind without per-type counts: unknown, not zero; a missing kind: no data.
    expect(node("domain:registry:reg-recovery")?.count).toBe("—");
    expect(node("domain:execution:exec-srum")).toMatchObject({ count: 0, disabledReason: NO_DATA_REASON });
  });

  it("analysis result nodes take the newest completed job's row count and show running state", () => {
    const job = (kind: string, status: string, row_count: number) => ({
      analysis_id: `${kind}-${status}`,
      kind,
      status,
      options: {},
      created_at: "",
      progress: { done: 0, total: null, unit: "", message: "", percent: null },
      row_count,
    });
    const model = buildTreeModel({
      tree,
      analyses: [
        job("carve", "running", 1),
        job("carve", "completed", 12),
        job("ntfs-meta", "failed", 0),
      ] as never,
    });
    const fs = model.find((n) => n.id === "domain:filesystem");
    const carve = fs?.children?.find((c) => c.id === "domain:filesystem:fs-carve");
    expect(carve).toMatchObject({ count: 12, marker: "실행 중", disabledReason: undefined });
    const mft = fs?.children?.find((c) => c.id === "domain:filesystem:fs-mft");
    expect(mft?.marker).toBe("실패");
    expect(mft?.disabledReason).toBeUndefined();
  });

  it("disables empty views with a Korean reason once counts are loaded", () => {
    const model = buildTreeModel({ summary: summary(), tree });
    const views = model.find((n) => n.id === "views");
    expect(views?.children?.find((n) => n.id === "timeline")?.disabledReason).toBe(
      "이 런에는 타임라인 산출물이 없습니다",
    );
    expect(views?.children?.find((n) => n.id === "files")?.disabledReason).toBeUndefined();
    const before = buildTreeModel({});
    expect(
      before
        .flatMap((n) => n.children ?? [])
        .filter((n) => n.target?.collection === "artifacts")
        .every((n) => n.disabledReason === undefined),
    ).toBe(true);
  });

  it("flattens only expanded branches", () => {
    const model = buildTreeModel({ summary: summary(), tree, review });
    expect(flattenVisible(model, new Set())).toHaveLength(19);
    const open = flattenVisible(model, new Set(["domain:eventlog"]));
    expect(open.filter((f) => f.level === 2).map((f) => f.node.label)).toEqual([
      "전체 이벤트 로그(EVTX·ETL)",
      "EVTX 이벤트",
      "탐지 규칙 일치",
      "로그온 세션",
      "슬랙 복구 레코드",
      "오래된 레코드(첫 레코드 이전)",
      "EVTX 파일·요약",
      "ETL 추적 파일",
      "방화벽 로그",
    ]);
  });

  it("artifactKindNodes skips zero-count and artifact_type nodes", () => {
    expect(artifactKindNodes(tree).map((n) => n.kind)).toEqual(["eventlog", "browser"]);
  });

  it("review counts for the 검토 panel", () => {
    expect(reviewCount(review, "relevant")).toBe(3);
    expect(reviewCount(review, "include-in-report")).toBe(2);
    expect(reviewCount(undefined, "relevant")).toBeUndefined();
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
    expect(formatRoute(route)).toBe("#/case/abc/explore/artifacts?category=web");
    expect(parseRoute("#/case/abc/artifacts?category=web")).toEqual(route);
    expect(sameRoute(route, { runId: "abc", collection: "artifacts" })).toBe(false);
    expect(parseRoute("#/case/abc/artifacts/eventlog?category=web")).toEqual({
      runId: "abc",
      collection: "artifacts",
      kind: "eventlog",
    });
  });
});
