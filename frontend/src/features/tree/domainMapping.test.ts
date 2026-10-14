import { describe, expect, it } from "vitest";
import type { RunTree, TreeNode } from "../../api/runs";
import { artifactTypeLabel } from "../filters/typeLabels";
import { DOMAINS, type DomainNodeDef, NON_EVIDENCE_NOTE } from "./domains";
import {
  artifactKindNodes,
  buildTreeModel,
  docsCount,
  domainNodeCount,
  domainTotal,
  mergedKindNode,
  NO_DATA_REASON,
  zeroReason,
} from "./model";

// Evidence types of the parser-quality r1 data model, per emitting kind (rapid-parsers branch:
// artifacts/windows/*.py, browser.py, generic.py, media.py, memory.py; api/app/tree.py).
const EVIDENCE: Record<string, string[]> = {
  "windows-execution": [
    "amcache-schema-row",
    "shimcache-schema-entry",
    "bam-schema-entry",
    "userassist-schema-entry",
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
  ],
  "generic-documents": ["document-metadata-risk", "document-lock-owner"],
  "media-image": ["media-image", "media-video", "media-audio"],
  "memory-volatility": ["crash-dump-indicators"],
  eventlog: ["eventlog-detection", "eventlog-event", "etl-trace-file"],
};

const NON_EVIDENCE: Record<string, string[]> = {
  "windows-execution": ["amcache-string-candidate", "shimcache-string-candidate", "bam-string-candidate"],
  "windows-registry": ["registry-hive-string-candidate"],
};

/** Types the r1 round removed or renamed: no node may still request them. */
const REMOVED = [
  "amcache-entry",
  "shimcache-entry",
  "bam-entry",
  "userassist-entry",
  "shellbag-native-candidate",
  "document-pattern",
  "browser-history-downloads",
];

const allNodes = (): Array<DomainNodeDef & { domain: string }> =>
  DOMAINS.flatMap((domain) => domain.nodes.map((node) => ({ ...node, domain: domain.id })));

function primaryNodes(kind: string, type: string) {
  return allNodes().filter(
    (node) =>
      node.target.collection === "artifacts" &&
      node.target.kind === kind &&
      node.target.types?.includes(type) &&
      !node.crossRef,
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
