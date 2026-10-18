/**
 * r2 console fix (M2 · M4): server-filtered nodes (`browser=` / `service=`) counted from `/tree`
 * `field_type_counts`, per-app 데스크톱 메신저 nodes, and the inventory reasons of empty nodes.
 */
import { describe, expect, it } from "vitest";
import type { RunTree, TreeNode } from "../../api/runs";
import { parseHash, serializeRoute } from "../../router";
import {
  activeChips,
  applyFiltersToQuery,
  filtersFromRoute,
  partitionFilters,
  removeChip,
} from "../filters/filterModel";
import { DOMAINS, flattenDomainNodes, targetKey } from "./domains";
import {
  buildTreeModel,
  domainNodeCount,
  domainRoute,
  domainTotal,
  fieldCount,
  inventoryReason,
  type TreeModelNode,
} from "./model";

const kind = (id: string, kindName: string, count: number, extra: Partial<TreeNode> = {}): TreeNode => ({
  id,
  label: kindName,
  count,
  collection: "artifacts",
  kind: kindName,
  ...extra,
});

const DISABLED_REASON =
  "외부 도구 실행 꺼짐(기본값) — RAPIDTRIAGE_EMAIL_EXTERNAL_TOOLS=1로 켜면 설치된 pffexport/readpst로 내보냅니다";

const tree: RunTree = {
  run_id: "r2",
  root: {},
  nodes: [
    {
      id: "artifacts",
      label: "아티팩트",
      count: 40,
      collection: "artifacts",
      children: [
        kind("artifacts:browser", "browser", 20, {
          artifact_type_counts: {
            "browser-history": 12,
            "browser-cache-entry": 5,
            "browser-cookie": 2,
            "webcachev01-ese-file": 1,
          },
          field_type_counts: {
            browser: {
              chrome: { "browser-history": 10, "browser-cookie": 2 },
              "ie-edge-legacy": { "browser-history": 2, "browser-cache-entry": 5, "webcachev01-ese-file": 1 },
            },
          },
        }),
        kind("artifacts:windows-messenger", "windows-messenger", 9, {
          artifact_type_counts: { "chat-message": 6, "chat-contact": 1, "chat-app-inventory": 2 },
          field_type_counts: {
            service: {
              Slack: { "chat-message": 4, "chat-contact": 1 },
              "Microsoft Teams (new)": { "chat-message": 2 },
              WeChat: { "chat-app-inventory": 1 },
              Discord: { "chat-app-inventory": 1 },
            },
          },
        }),
        kind("artifacts:email", "email", 3, {
          artifact_type_counts: { "email-container-inventory": 2, "email-mailbox": 1 },
          inventory_notes: [
            {
              artifact_type: "email-container-inventory",
              status: "disabled",
              status_label: "외부 도구 꺼짐",
              count: 2,
              reason: DISABLED_REASON,
            },
          ],
        }),
        kind("artifacts:kakaotalk-windows", "kakaotalk-windows", 1, {
          artifact_type_counts: { "kakaotalk-app-inventory": 1 },
          inventory_notes: [
            {
              artifact_type: "kakaotalk-app-inventory",
              status: "no-key-material",
              status_label: "복호 키 없음",
              count: 1,
              reason: "복호 키 없음 — 키 재료 후보로 키를 만들 수 없음",
            },
          ],
        }),
      ],
    },
  ],
};

const def = (id: string) => {
  for (const domain of DOMAINS) {
    const found = flattenDomainNodes(domain.nodes).find((node) => node.id === id);
    if (found) return found;
  }
  throw new Error(id);
};

function flatModel(nodes: TreeModelNode[]): TreeModelNode[] {
  return nodes.flatMap((node) => [node, ...flatModel(node.children ?? [])]);
}

describe("M2: legacy Edge/IE is a server-filtered node counted from field_type_counts", () => {
  const legacy = def("web-legacy-ie");

  it("asks the server for browser=ie-edge-legacy and counts only those rows of its types", () => {
    expect(legacy.target.fields).toEqual({ browser: ["ie-edge-legacy"] });
    expect(legacy.target.cf).toBeUndefined();
    // 2 history + 5 cache entries (the WebCacheV01 file row is not one of the node's types),
    // never the 20 rows of every browser.
    expect(domainNodeCount(legacy.target, { tree }).count).toBe(7);
    const route = domainRoute(legacy.target);
    expect(route.fields).toEqual({ browser: ["ie-edge-legacy"] });
    const hash = serializeRoute({ runId: "r2", ...route });
    expect(hash).toContain("browser=ie-edge-legacy");
    expect(parseHash(hash).fields).toEqual({ browser: ["ie-edge-legacy"] });
    expect(targetKey(legacy.target)).toContain("|r=browser=ie-edge-legacy");
  });

  it("an older server without field counts shows an unknown count, not the whole browser", () => {
    const old: RunTree = { run_id: "o", root: {}, nodes: [kind("artifacts:browser", "browser", 20)] };
    expect(domainNodeCount(legacy.target, { tree: old }).count).toBe("—");
    expect(fieldCount(kind("x", "browser", 1), legacy.target)).toBeUndefined();
  });

  it("is a view: never in the domain total", () => {
    const history = def("web-history");
    expect(domainTotal([history, legacy], [12, 7])).toBe(12);
  });

  it("the route's fields become a server filter of the artifacts query with a Korean chip", () => {
    const filters = filtersFromRoute({
      runId: "r2",
      collection: "artifacts",
      kind: "browser",
      fields: { browser: ["ie-edge-legacy"] },
    });
    const ref = { id: "artifacts" as const, kind: "browser" };
    const plan = partitionFilters(ref, filters);
    expect(plan.server.fields).toEqual({ browser: ["ie-edge-legacy"] });
    expect(plan.serverLabels).toContain("브라우저");
    const query = applyFiltersToQuery({ ref, offset: 0, limit: 50 }, filters);
    expect(query.fields).toEqual({ browser: ["ie-edge-legacy"] });
    const chips = activeChips(filters, (s) => s);
    expect(chips).toEqual([
      { key: "field", value: "browser:ie-edge-legacy", label: "브라우저 ie-edge-legacy" },
    ]);
    expect(removeChip(filters, chips[0] as (typeof chips)[number]).fields).toBeUndefined();
  });
});

describe("M2: 데스크톱 메신저 › 앱별 보기 lists one server-filtered node per app", () => {
  const model = flatModel(buildTreeModel({ tree }));
  const byApp = model.find((node) => node.id === "domain:messaging:msg-desktop-by-app");

  it("one node per app with evidence rows, Korean order, hidden apps with only inventory rows", () => {
    expect(byApp?.children?.map((node) => [node.label, node.count])).toEqual([
      ["Microsoft Teams (new)", 2],
      ["Slack", 5],
    ]);
    const slack = byApp?.children?.find((node) => node.label === "Slack");
    expect(slack?.target?.fields).toEqual({ service: ["Slack"] });
    expect(slack?.target?.types).toEqual(["chat-message", "chat-contact", "chat-attachment"]);
    expect(slack?.note).toBe("서버 필터: service=Slack");
  });

  it("app views and the per-app group never add to the domain total", () => {
    const messaging = model.find((node) => node.id === "domain:messaging");
    // 6 messages + 1 contact (앱 목록 is a detail node, the app views repeat the rows).
    expect(messaging?.count).toBe(7);
  });

  it("without field counts the per-app group has no children", () => {
    const old: RunTree = {
      run_id: "o",
      root: {},
      nodes: [kind("artifacts:windows-messenger", "windows-messenger", 9)],
    };
    const node = flatModel(buildTreeModel({ tree: old })).find(
      (n) => n.id === "domain:messaging:msg-desktop-by-app",
    );
    expect(node?.children).toBeUndefined();
  });
});

describe("M4: empty typed nodes say why (PST tools off, KakaoTalk key missing)", () => {
  const model = flatModel(buildTreeModel({ tree }));
  const reason = (id: string) => model.find((node) => node.id === id)?.hiddenReason;

  it("메일·첨부·연락처·일정 read the container inventory status and reason", () => {
    const expected = `메일 컨테이너(PST/OST) 2개: ${DISABLED_REASON}`;
    for (const id of ["msg-email-messages", "msg-email-attachments", "msg-contacts", "msg-calendar"]) {
      expect(reason(`domain:messaging:${id}`), id).toBe(expected);
      expect(model.find((node) => node.id === `domain:messaging:${id}`)?.disabledReason).toBe(expected);
    }
    // The inventory node itself has rows; the mailbox strings node is not explained by it.
    expect(reason("domain:messaging:msg-email-containers")).toBeUndefined();
  });

  it("카카오톡 메시지 reads the decryption status", () => {
    expect(reason("domain:messaging:msg-kakao-messages")).toBe(
      "카카오톡 프로필 1개: 복호 키 없음 — 키 재료 후보로 키를 만들 수 없음",
    );
  });

  it("statuses that produced rows are no reason", () => {
    const node = kind("k", "email", 1, {
      inventory_notes: [
        { artifact_type: "email-container-inventory", status: "normalized", count: 1, reason: "ok" },
      ],
    });
    expect(inventoryReason(node, ["email-message"])).toBeUndefined();
    expect(inventoryReason(node, undefined)).toBeUndefined();
  });
});
