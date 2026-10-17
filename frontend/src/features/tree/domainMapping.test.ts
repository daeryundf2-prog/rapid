import { describe, expect, it } from "vitest";
import type { RunTree, TreeNode } from "../../api/runs";
import { artifactTypeLabel } from "../filters/typeLabels";
import { DOMAINS, type DomainNodeDef, flattenDomainNodes, NON_EVIDENCE_NOTE, targetKey } from "./domains";
import {
  artifactKindNodes,
  buildTreeModel,
  docsCount,
  domainNodeCount,
  domainTotal,
  inventoryTotal,
  mergedKindNode,
  NO_DATA_REASON,
  NO_INVENTORY_REASON,
  type TreeModelNode,
  zeroReason,
} from "./model";

// Evidence types of the parser-quality r1 + r2 data model, per emitting kind (rapid-parsers branch:
// artifacts/windows/*.py, browser.py, generic.py, media.py, memory.py; api/app/tree.py).
const EVIDENCE: Record<string, string[]> = {
  "windows-execution": [
    "amcache-schema-row",
    "shimcache-schema-entry",
    "bam-schema-entry",
    "userassist-schema-entry",
    // r2: Amcache extended inventory sections (execution.py AMCACHE_EXTENDED_SECTIONS).
    "amcache-driver-binary",
    "amcache-driver-package",
    "amcache-device-pnp",
    "amcache-device-container",
    "amcache-application-shortcut",
    "amcache-device-census",
  ],
  "windows-prefetch": ["prefetch-file", "prefetch-invalid-content"],
  "recent-files": [
    "recent-shortcut",
    "jumplist-entry",
    "shell-shortcut",
    "recent-shortcut-invalid-content",
    "shell-shortcut-invalid-content",
  ],
  "windows-registry": [
    "registry-key-tree-node",
    "windows-usb-device",
    "windows-mounted-device",
    "windows-service-config",
    "windows-timezone",
    "windows-computer-name",
    "windows-os-version",
    "windows-control-set",
    "windows-network-interface",
    "windows-profile-list-entry",
    "windows-installed-program",
    "registry-persistence-entry",
    "registry-user-activity",
  ],
  "windows-os-account": [
    "windows-sam-account",
    "windows-sam-group",
    "windows-mounted-device",
    "windows-service-config",
    "windows-user-profile",
  ],
  "windows-system": [
    "notification-database",
    "notification-row-candidate",
    "activities-cache-db",
    "activities-cache-row-candidate",
    "thumbnail-cache-file",
    "icon-cache-file",
    "thumbnail-cache-entry-candidate",
    "icon-cache-entry-candidate",
  ],
  "kakaotalk-windows": [
    "kakaotalk-windows-user-id-candidate",
    "kakaotalk-windows-app-database",
    "kakaotalk-windows-source-candidate",
    "kakaotalk-windows-crypto-material-candidate",
  ],
  "windows-shellbags": ["shellbag-entry", "shellbag-hive-summary"],
  browser: [
    "browser-history",
    "browser-visit",
    "browser-download",
    "browser-search",
    "browser-cookie",
    "browser-login",
    "browser-autofill",
    "browser-credit-card",
    "browser-autofill-address",
    "browser-bookmark",
    "browser-omnibox-shortcut",
    "browser-top-site",
    "browser-session-tab",
    "browser-extension",
    "browser-profile-account",
    "browser-acquisition-anomaly",
    "browser-parse-error",
    "browser-ai-usage",
    "browser-ai-conversation",
    "browser-storage-inventory",
    "browser-history-downloads",
  ],
  "generic-documents": ["document-metadata-risk", "document-lock-owner", "archive-file-inventory"],
  "media-image": ["media-image", "media-video", "media-audio"],
  "memory-volatility": ["crash-dump-indicators"],
  eventlog: ["eventlog-detection", "eventlog-event", "etl-trace-file", "eventlog-file", "eventlog-summary"],
  "synthetic-media": ["synthetic-media-scan-status", "synthetic-media-scan-summary"],
  // R2 M4: desktop cloud sync clients (rapidtriage/artifacts/cloud_sync.py).
  "cloud-sync": ["cloud-sync-account", "cloud-sync-file", "cloud-sync-event", "cloud-sync-inventory"],
};

/** r2 types (and kinds) that must be reachable from the tree: a typed node or the kind's catch-all. */
const REACHABLE: Record<string, string[]> = {
  "windows-registry": [
    "registry-hive",
    "registry-hive-strings",
    "registry-summary",
    "registry-key",
    "registry-usb",
  ],
  "windows-os-account": [
    "windows-user-profile",
    "windows-os-account-summary",
    "windows-privilege-assignment",
  ],
  eventlog: ["eventlog-file", "eventlog-summary", "eventlog-chunk"],
  "generic-documents": ["archive-file-inventory", "sticky-note"],
  "windows-execution": ["amcache-hive", "amcache-inventory-row", "srum-schema-row"],
  browser: [
    "browser-history-downloads",
    "browser-ai-usage",
    "browser-storage-inventory",
    "browser-sync-inventory",
  ],
  "windows-system": ["thumbnail-cache-media-candidate", "notification-row-candidate", "print-spooler-job"],
  "windows-filesystem": ["mft-file", "usn-journal-file"],
  "synthetic-media": ["synthetic-media-image", "synthetic-media-scan-error"],
  "kakaotalk-windows": [
    "kakaotalk-windows-crypto-material-candidate",
    "kakaotalk-windows-correlation-summary",
  ],
  "memory-volatility": ["memory-process", "process-string-candidate"],
};

const NON_EVIDENCE: Record<string, string[]> = {
  "windows-execution": ["amcache-string-candidate", "shimcache-string-candidate", "bam-string-candidate"],
  "windows-registry": ["registry-hive-string-candidate"],
};

/**
 * Types the r1 round removed or renamed: no node may still request them. (browser-history-downloads
 * is emitted again in r2 as the per-profile aggregate row: a detail node.)
 */
const REMOVED = [
  "amcache-entry",
  "shimcache-entry",
  "bam-entry",
  "userassist-entry",
  "shellbag-native-candidate",
  "document-pattern",
];

/** Every node, sub-nodes included. */
const allNodes = (): Array<DomainNodeDef & { domain: string }> =>
  DOMAINS.flatMap((domain) =>
    flattenDomainNodes(domain.nodes).map((node) => ({ ...node, domain: domain.id })),
  );

/** Leaf nodes that are a type's home: not a cross-listing, a group or a column-filtered view. */
function primaryNodes(kind: string, type: string) {
  return allNodes().filter(
    (node) =>
      node.target.collection === "artifacts" &&
      node.target.kind === kind &&
      node.target.types?.includes(type) &&
      !node.crossRef &&
      !node.children?.length &&
      !node.target.cf?.length,
  );
}

function reachingNodes(kind: string, type: string) {
  return allNodes().filter(
    (node) =>
      node.target.collection === "artifacts" &&
      node.target.kind === kind &&
      (!node.target.types?.length || node.target.types.includes(type)),
  );
}

describe("domain mapping table (parser-quality r1)", () => {
  for (const [kind, types] of Object.entries(EVIDENCE)) {
    for (const type of types) {
      it(`${kind} › ${type} resolves to exactly one primary evidence node`, () => {
        const nodes = primaryNodes(kind, type);
        expect(nodes.map((n) => `${n.domain}/${n.id}`)).toHaveLength(1);
        expect(nodes[0]?.nonEvidence).toBeFalsy();
      });
    }
  }

  it("string candidates resolve to one dimmed non-evidence node each", () => {
    for (const [kind, types] of Object.entries(NON_EVIDENCE)) {
      for (const type of types) {
        const nodes = primaryNodes(kind, type);
        expect(nodes, `${kind}/${type}`).toHaveLength(1);
        expect(nodes[0]?.nonEvidence).toBe(true);
        expect(nodes[0]?.label).toBe("문자열 후보(증거 아님)");
      }
    }
    // Every *-string-candidate type anywhere in the table is flagged.
    for (const node of allNodes()) {
      if (node.target.types?.some((type) => type.endsWith("-string-candidate"))) {
        expect(node.nonEvidence, node.id).toBe(true);
      }
    }
  });

  for (const [kind, types] of Object.entries(REACHABLE)) {
    it(`${kind}: every r2 type is reachable (typed node or kind-wide node)`, () => {
      for (const type of types)
        expect(reachingNodes(kind, type).length, `${kind}/${type}`).toBeGreaterThan(0);
    });
  }

  it("places the six Amcache types under 실행 흔적 › Amcache (드라이버/장치/바로가기/센서스)", () => {
    const amcache = DOMAINS.find((d) => d.id === "execution")?.nodes.find((n) => n.id === "exec-amcache");
    expect(amcache?.label).toBe("Amcache");
    expect(amcache?.children?.map((c) => [c.label, c.target.types])).toEqual([
      ["응용 프로그램 파일", ["amcache-schema-row"]],
      ["드라이버", ["amcache-driver-binary", "amcache-driver-package"]],
      ["장치", ["amcache-device-pnp", "amcache-device-container"]],
      ["바로가기", ["amcache-application-shortcut"]],
      ["센서스", ["amcache-device-census"]],
      ["하이브 파일", ["amcache-hive", "amcache-inventory-row"]],
    ]);
    // The group requests the union of its evidence leaves; ShimCache has its own node.
    expect(amcache?.target.types).toEqual(
      (amcache?.children ?? []).filter((c) => !c.detail).flatMap((c) => c.target.types ?? []),
    );
    for (const type of amcache?.target.types ?? []) {
      expect(primaryNodes("windows-execution", type)[0]?.domain).toBe("execution");
    }
    // The server tree routes PnP/container to 연결 장치 and DeviceCensus to 운영체제: cross-listed there.
    const cross = allNodes().filter((n) => n.crossRef && n.target.kind === "windows-execution");
    expect(cross.map((n) => [n.domain, n.target.types])).toEqual([
      ["os", ["amcache-device-census"]],
      ["devices", ["amcache-device-pnp", "amcache-device-container"]],
    ]);
  });

  it("windows-network-interface lives under 시스템 정보 (server routes it to os now)", () => {
    const nodes = primaryNodes("windows-registry", "windows-network-interface");
    expect(nodes.map((n) => `${n.domain}/${n.id}`)).toEqual(["os/os-sysinfo"]);
    const devices = DOMAINS.find((d) => d.id === "devices")?.nodes ?? [];
    expect(devices.some((n) => n.target.types?.includes("windows-network-interface"))).toBe(false);
  });

  it("파일시스템 lists the inventory (전체 파일(인벤토리), 기타 (스캔 제외)) as scope=inventory routes", () => {
    const fs = DOMAINS.find((d) => d.id === "filesystem")?.nodes ?? [];
    const inv = fs.find((n) => n.id === "fs-inventory");
    const other = fs.find((n) => n.id === "fs-other");
    expect(inv).toMatchObject({
      label: "전체 파일(인벤토리)",
      target: { collection: "files", fileScope: "inventory" },
    });
    expect(other).toMatchObject({
      label: "기타 (스캔 제외)",
      target: { collection: "files", fileScope: "inventory", fileCategory: "other" },
    });
    expect(targetKey(other?.target ?? { collection: "files" })).toBe("files|inventory:other|||");
    expect(targetKey({ collection: "files", category: "inventory:other" })).toBe("files|inventory:other|||");
  });

  it("오래된 레코드 is a column-filtered eventlog view on evtx_record_id_position", () => {
    const stale = allNodes().find((n) => n.id === "evt-stale");
    expect(stale?.domain).toBe("eventlog");
    expect(stale?.target).toMatchObject({
      kind: "eventlog",
      cols: ["details.evtx_record_id_position"],
      cf: [{ col: "f:evtx_record_id_position", op: ":", value: "stale-below-first" }],
    });
  });

  it("removed junk types are no longer requested", () => {
    for (const node of allNodes()) {
      for (const gone of REMOVED) expect(node.target.types ?? [], `${node.id}`).not.toContain(gone);
    }
  });

  it("prefetch-reference and the key tree stay out of the main counts", () => {
    const refs = primaryNodes("windows-prefetch", "prefetch-reference");
    expect(refs).toHaveLength(1);
    expect(refs[0]?.detail).toBe(true);
    expect(primaryNodes("windows-registry", "registry-key-tree-node")[0]).toMatchObject({
      label: "키 트리",
      detail: true,
    });
    expect(primaryNodes("windows-prefetch", "prefetch-invalid-content")[0]?.label).toBe(
      "손상/비정상 Prefetch",
    );
    expect(primaryNodes("recent-files", "shell-shortcut-invalid-content")[0]?.label).toBe("비정상 바로가기");
  });

  it("cross-lists persistence and eventlog detections under 침해사고", () => {
    const incident = DOMAINS.find((d) => d.id === "incident")?.nodes ?? [];
    expect(incident.filter((n) => n.crossRef).map((n) => [n.target.kind, n.target.types?.[0]])).toEqual([
      ["windows-registry", "registry-persistence-entry"],
      ["eventlog", "eventlog-detection"],
    ]);
    expect(primaryNodes("windows-registry", "registry-persistence-entry")[0]?.domain).toBe("registry");
  });

  it("labels crash dumps, kakaotalk traces and ETL apart from Volatility / EVTX", () => {
    expect(primaryNodes("memory-volatility", "crash-dump-indicators")[0]?.label).toBe("크래시 덤프");
    expect(primaryNodes("eventlog", "etl-trace-file")[0]?.label).toBe("ETL 추적 파일");
    const kakao = allNodes().find((n) => n.id === "msg-kakao");
    expect(kakao?.label).toContain("레지스트리 흔적");
    expect(artifactTypeLabel("browser-credit-card")).toBe("저장된 카드(메타데이터)");
  });
});

const kindNode = (id: string, kind: string, count: number, extra: Partial<TreeNode> = {}): TreeNode => ({
  id,
  label: kind,
  count,
  collection: "artifacts",
  kind,
  ...extra,
});

const routedTree: RunTree = {
  run_id: "r1",
  root: {},
  nodes: [
    {
      id: "artifacts",
      label: "아티팩트",
      count: 40,
      children: [
        {
          id: "artifacts-group:registry",
          label: "레지스트리",
          count: 30,
          children: [
            kindNode("artifacts:windows-registry", "windows-registry", 30, {
              domain: "registry",
              artifact_type_counts: {
                "registry-key-tree-node": 20,
                "registry-persistence-entry": 4,
                "registry-hive-string-candidate": 2,
                "windows-usb-device": 3,
                "windows-timezone": 1,
              },
              domain_artifact_type_counts: {
                "registry-key-tree-node": 20,
                "registry-persistence-entry": 4,
                "registry-hive-string-candidate": 2,
              },
            }),
          ],
        },
        {
          id: "artifacts-group:devices",
          label: "연결 장치·원격",
          count: 3,
          children: [
            kindNode("artifacts:windows-registry@devices", "windows-registry", 3, {
              domain: "devices",
              artifact_type_counts: { "windows-usb-device": 3 },
              domain_artifact_type_counts: { "windows-usb-device": 3 },
            }),
          ],
        },
        {
          id: "artifacts-group:os",
          label: "운영체제·계정",
          count: 1,
          children: [
            kindNode("artifacts:windows-registry@os", "windows-registry", 1, {
              domain: "os",
              artifact_type_counts: { "windows-timezone": 1 },
              domain_artifact_type_counts: { "windows-timezone": 1 },
            }),
          ],
        },
        {
          id: "artifacts-group:execution",
          label: "실행 흔적",
          count: 6,
          children: [
            kindNode("artifacts:windows-prefetch", "windows-prefetch", 6, {
              artifact_type_counts: {
                "prefetch-file": 2,
                "prefetch-invalid-content": 1,
                "prefetch-reference": 3,
              },
            }),
            kindNode("artifacts:windows-shellbags", "windows-shellbags", 0, {
              collection_status: "skipped",
              collection_notes: ["NTUSER.DAT 없음"],
            }),
          ],
        },
      ],
    },
    { id: "docs", label: "문서", count: 3, collection: "docs", candidate_count: 41, match_count: 3 },
    { id: "indicators", label: "지표 후보", count: 7, collection: "indicators", rule_count: 0 },
  ],
};

describe("r2 tree: inventory, Amcache sub-nodes, stale records", () => {
  const r2Tree: RunTree = {
    run_id: "r2",
    root: {},
    nodes: [
      {
        id: "files",
        label: "파일",
        count: 10,
        collection: "files",
        inventory_count: 90,
        children: [
          { id: "files:documents", label: "문서", count: 10, collection: "files", category: "documents" },
          {
            id: "files:other",
            label: "기타",
            count: 70,
            collection: "files",
            category: "other",
            source: "inventory",
            inventory_only: true,
          },
          {
            id: "files:images",
            label: "이미지",
            count: 20,
            collection: "files",
            category: "images",
            source: "inventory",
            inventory_only: true,
          },
        ],
      },
      {
        id: "artifacts",
        label: "아티팩트",
        count: 30,
        children: [
          kindNode("artifacts:windows-execution", "windows-execution", 20, {
            artifact_type_counts: {
              "amcache-schema-row": 5,
              "amcache-driver-binary": 3,
              "amcache-driver-package": 1,
              "amcache-device-pnp": 4,
              "amcache-device-container": 2,
              "amcache-application-shortcut": 2,
              "amcache-device-census": 1,
              "amcache-hive": 1,
              "shimcache-schema-entry": 1,
            },
          }),
          kindNode("artifacts:eventlog", "eventlog", 10, {
            artifact_type_counts: { "eventlog-event": 8, "eventlog-record-candidate": 2 },
            stale_below_first_record_count: 2,
          }),
        ],
      },
    ],
  };
  const model = buildTreeModel({ tree: r2Tree });
  const find = (id: string): TreeModelNode | undefined => {
    const visit = (nodes: TreeModelNode[]): TreeModelNode | undefined => {
      for (const n of nodes) {
        if (n.id === id) return n;
        const hit = n.children ? visit(n.children) : undefined;
        if (hit) return hit;
      }
      return undefined;
    };
    return visit(model);
  };

  it("기타 (스캔 제외) counts the inventory node and opens scope=inventory", () => {
    expect(find("domain:filesystem:fs-other")).toMatchObject({
      label: "기타 (스캔 제외)",
      count: 70,
      route: { collection: "files", category: "inventory:other" },
      selectKey: "files|inventory:other|||",
    });
    expect(find("domain:filesystem:fs-inventory")).toMatchObject({
      count: 100,
      route: { collection: "files", category: "inventory" },
    });
    // A selected-category node whose server node is inventory-only opens the inventory too.
    expect(find("domain:filesystem:fs-images")?.route).toEqual({
      collection: "files",
      category: "inventory:images",
    });
    expect(find("domain:filesystem:fs-documents")?.route).toEqual({
      collection: "files",
      category: "documents",
    });
    // Old outputs (no inventory): dimmed with a reason.
    expect(inventoryTotal({ tree: routedTree })).toEqual({ count: 0, disabledReason: NO_INVENTORY_REASON });
  });

  it("Amcache group counts its evidence leaves; sub-nodes count their types", () => {
    const amcache = find("domain:execution:exec-amcache");
    expect(amcache?.count).toBe(18);
    expect(amcache?.children?.map((c) => [c.label, c.count])).toEqual([
      ["응용 프로그램 파일", 5],
      ["드라이버", 4],
      ["장치", 6],
      ["바로가기", 2],
      ["센서스", 1],
      ["하이브 파일", 1],
    ]);
    expect(find("domain:devices:dev-amcache")?.count).toBe(6);
    // 실행 흔적 total = the kind-wide node (20) minus the detail 하이브 파일 row (1): the group and
    // its leaves never add twice.
    expect(find("domain:execution")?.count).toBe(19);
  });

  it("오래된 레코드 takes the kind node's stale count and never adds to the eventlog total", () => {
    const stale = find("domain:eventlog:evt-stale");
    expect(stale).toMatchObject({ count: 2 });
    expect(stale?.target?.cf).toEqual([
      { col: "f:evtx_record_id_position", op: ":", value: "stale-below-first" },
    ]);
    expect(stale?.note).toContain("evtx_record_id_position");
    expect(find("domain:eventlog")?.count).toBe(10);
    const unknown = domainNodeCount(
      { collection: "artifacts", kind: "windows-execution", countField: "stale_below_first_record_count" },
      { tree: r2Tree },
    );
    expect(unknown.count).toBe("—");
  });
});

describe("domain counts over the r1 tree (routed kind nodes, zero reasons)", () => {
  const model = buildTreeModel({ tree: routedTree });
  const node = (id: string) => model.flatMap((n) => n.children ?? []).find((c) => c.id === id);

  it("merges artifacts:<kind> and artifacts:<kind>@<domain> into one kind count", () => {
    const merged = mergedKindNode(routedTree, "windows-registry");
    expect(merged?.count).toBe(34);
    expect(merged?.artifact_type_counts?.["windows-usb-device"]).toBe(3);
    expect(artifactKindNodes(routedTree).filter((n) => n.kind === "windows-registry")).toHaveLength(1);
    expect(node("domain:devices:dev-usb-registry")?.count).toBe(3);
    expect(node("domain:os:os-sysinfo")?.count).toBe(1);
    expect(node("domain:incident:ir-persistence")?.count).toBe(4);
  });

  it("domain totals leave out key tree, string candidates and prefetch references", () => {
    expect(model.find((n) => n.id === "domain:registry")?.count).toBe(4);
    // Prefetch 2 + 손상 1 (참조 경로 3 excluded); recent-files etc. are absent from the run.
    expect(model.find((n) => n.id === "domain:execution")?.count).toBe(3);
    const strings = node("domain:registry:reg-strings");
    expect(strings).toMatchObject({ count: 2, dimmed: true, note: NON_EVIDENCE_NOTE });
    expect(strings?.disabledReason).toBeUndefined();
  });

  it("a kind-wide node minus its non-evidence nodes counts once", () => {
    const nodes: DomainNodeDef[] = [
      { id: "all", label: "전체", target: { collection: "artifacts", kind: "k" } },
      { id: "a", label: "A", target: { collection: "artifacts", kind: "k", types: ["a"] } },
      {
        id: "s",
        label: "S",
        target: { collection: "artifacts", kind: "k", types: ["s"] },
        nonEvidence: true,
      },
    ];
    expect(domainTotal(nodes, [10, 7, 3])).toBe(7);
    expect(domainTotal(nodes, [undefined, undefined, undefined])).toBeUndefined();
  });

  it("zero counts say 데이터 없음 or 제공자 건너뜀(사유)", () => {
    expect(node("domain:registry:reg-shellbags")).toMatchObject({
      count: 0,
      disabledReason: "제공자 건너뜀(NTUSER.DAT 없음)",
    });
    expect(node("domain:execution:exec-lnk")).toMatchObject({ count: 0, disabledReason: NO_DATA_REASON });
    expect(zeroReason(kindNode("x", "x", 0, { collection_status: "failed-isolated" }))).toBe(
      "제공자 실패(사유 미기재)",
    );
    expect(
      zeroReason(kindNode("x", "x", 0, { skip_reasons: { "no-hive": 2 }, collection_status: "skipped" })),
    ).toBe("제공자 건너뜀(no-hive)");
    expect(
      domainNodeCount(
        { collection: "artifacts", kind: "windows-prefetch", types: ["prefetch-file"] },
        { tree: routedTree },
      ).count,
    ).toBe(2);
  });

  it("문서/메일 counts every candidate; the indicators label comes from the server", () => {
    expect(docsCount({ tree: routedTree })).toBe(41);
    const views = model.find((n) => n.id === "views");
    expect(views?.children?.find((c) => c.id === "docs")?.count).toBe(41);
    expect(views?.children?.find((c) => c.id === "indicators")?.label).toBe("지표 후보");
    expect(node("domain:incident:ir-ioc")?.label).toBe("지표 후보");
    expect(node("domain:messaging:msg-docs")?.count).toBe(41);
  });
});

describe("R2 M4 cloud sync nodes", () => {
  const cloud = DOMAINS.find((domain) => domain.id === "cloud");

  it("lists the sync client nodes under 클라우드 in Korean order, the export node kept", () => {
    const labels = (cloud?.nodes ?? []).map((node) => node.label);
    expect(labels).toEqual([...labels].sort((left, right) => left.localeCompare(right, "ko")));
    expect(cloud?.nodes.map((node) => node.id)).toEqual([
      "cloud-sync-accounts",
      "cloud-sync-events",
      "cloud-sync-inventory",
      "cloud-sync-files",
      "cloud-export",
    ]);
    expect(cloud?.nodes.find((node) => node.id === "cloud-export")?.target).toEqual({
      collection: "artifacts",
      kind: "cloud-export",
    });
  });

  it("keeps the inventory rows out of the domain total and names every type in Korean", () => {
    const inventory = cloud?.nodes.find((node) => node.id === "cloud-sync-inventory");
    expect(inventory?.detail).toBe(true);
    for (const type of [
      "cloud-sync-account",
      "cloud-sync-file",
      "cloud-sync-event",
      "cloud-sync-inventory",
    ]) {
      expect(artifactTypeLabel(type), type).toMatch(/[가-힣]/);
    }
  });
});
