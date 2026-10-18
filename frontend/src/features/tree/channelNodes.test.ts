/** 이벤트 로그 › 채널별 nodes (plan r3-os-depth §3.2 O2): counts from `/tree`, server `channel=`. */
import { describe, expect, it } from "vitest";
import { artifactsQueryString, type RunTree } from "../../api/runs";
import {
  applyFiltersToQuery,
  CHANNEL_FILTER_COLUMN,
  type FilterState,
  partitionFilters,
} from "../filters/filterModel";
import { DOMAINS, EVENTLOG_CHANNEL_NODES, targetKey } from "./domains";
import { buildTreeModel, NO_CHANNEL_COUNTS_REASON, type TreeModelNode } from "./model";

const BASE_FILTERS: FilterState = { statuses: [], types: [], tags: [], ext: [], path: "", columns: [] };

const GROUPS = [
  {
    id: "other",
    label: "기타 채널",
    count: 1,
    channels: ["Microsoft-Windows-Bits-Client/Operational"],
    partition: true,
  },
  {
    id: "firewall",
    label: "방화벽",
    count: 0,
    channels: ["Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"],
    partition: true,
  },
  { id: "security", label: "보안", count: 40, channels: ["Security"], partition: true },
  {
    id: "user-pnp",
    label: "사용자 PNP",
    count: 0,
    channels: ["Microsoft-Windows-UserPnp/DeviceInstall"],
    partition: true,
  },
  {
    id: "services",
    label: "서비스(SCM)",
    count: 3,
    channels: ["System"],
    partition: false,
    provider: "Service Control Manager",
  },
  {
    id: "storage",
    label: "스토리지",
    count: 2,
    channels: ["Microsoft-Windows-Ntfs/Operational", "Microsoft-Windows-Storage-ClassPnP/Operational"],
    partition: true,
  },
  { id: "system", label: "시스템", count: 30, channels: ["System"], partition: true },
  {
    id: "rdp",
    label: "원격 데스크톱",
    count: 4,
    channels: ["Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"],
    partition: true,
  },
  { id: "application", label: "응용 프로그램", count: 10, channels: ["Application"], partition: true },
  {
    id: "task-scheduler",
    label: "작업 스케줄러",
    count: 0,
    channels: ["Microsoft-Windows-TaskScheduler/Operational"],
    partition: true,
  },
  { id: "none", label: "채널 없음", count: 3, channels: [], partition: true },
  { id: "office-alerts", label: "Office Alerts", count: 0, channels: ["OAlerts"], partition: true },
  {
    id: "powershell",
    label: "PowerShell",
    count: 10,
    channels: ["Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"],
    partition: true,
  },
  {
    id: "defender",
    label: "Windows Defender",
    count: 0,
    channels: ["Microsoft-Windows-Windows Defender/Operational"],
    partition: true,
  },
];

function runTree(withGroups: boolean): RunTree {
  return {
    run_id: "r1",
    root: {},
    nodes: [
      {
        id: "artifacts",
        label: "아티팩트",
        count: 100,
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
                artifact_type_counts: { "eventlog-event": 97, "eventlog-file": 2, "eventlog-summary": 1 },
                ...(withGroups ? { channel_groups: GROUPS } : {}),
              },
            ],
          },
        ],
      },
    ],
  };
}

function eventlogDomain(tree: RunTree): TreeModelNode {
  const domain = buildTreeModel({ tree }).find((node) => node.id === "domain:eventlog");
  if (!domain) throw new Error("no eventlog domain");
  return domain;
}

function channelNode(domain: TreeModelNode, id: string): TreeModelNode {
  const node = domain.children?.find((child) => child.id === `domain:eventlog:${id}`);
  if (!node) throw new Error(`no node ${id}`);
  return node;
}

describe("event-log channel nodes", () => {
  it("are listed under 이벤트 로그, Korean-sorted (Hangul before Latin)", () => {
    const labels = EVENTLOG_CHANNEL_NODES.map((node) => node.label);
    expect(labels).toEqual([...labels].sort((x, y) => x.localeCompare(y, "ko")));
    expect(labels).toEqual(
      expect.arrayContaining([
        "보안",
        "시스템",
        "응용 프로그램",
        "PowerShell",
        "Windows Defender",
        "방화벽",
        "작업 스케줄러",
        "서비스(SCM)",
        "스토리지",
        "사용자 PNP",
        "Office Alerts",
        "원격 데스크톱",
      ]),
    );
    const eventlog = DOMAINS.find((domain) => domain.id === "eventlog");
    expect(eventlog?.nodes.slice(-EVENTLOG_CHANNEL_NODES.length)).toEqual(EVENTLOG_CHANNEL_NODES);
  });

  it("take counts and exact channel names from /tree channel_groups", () => {
    const domain = eventlogDomain(runTree(true));
    const security = channelNode(domain, "evt-ch-security");
    expect(security.count).toBe(40);
    expect(security.target?.cf).toEqual([{ col: CHANNEL_FILTER_COLUMN, op: ":", value: "Security" }]);
    const storage = channelNode(domain, "evt-ch-storage");
    expect(storage.count).toBe(2);
    expect(storage.target?.cf?.[0]?.value).toBe(
      "Microsoft-Windows-Ntfs/Operational|Microsoft-Windows-Storage-ClassPnP/Operational",
    );
    expect(storage.note).toContain("서버 채널 필터");
    const services = channelNode(domain, "evt-ch-services");
    expect(services.count).toBe(3);
    expect(services.target?.cf).toEqual([
      { col: CHANNEL_FILTER_COLUMN, op: ":", value: "System" },
      { col: "f:provider_name", op: ":", value: "Service Control Manager" },
    ]);
    expect(services.note).toContain("불러온 행에 열 필터 적용");
    expect(channelNode(domain, "evt-ch-defender").disabledReason).toBeDefined(); // count 0
    // Channel views never add to the domain header (the kind-wide node already counts the rows).
    expect(domain.count).toBe(97); // 100 rows minus the 3 EVTX 파일·요약 detail rows
  });

  it("select keys tell the channel views apart from the whole kind and each other", () => {
    const domain = eventlogDomain(runTree(true));
    const keys = ["evt-all", "evt-ch-system", "evt-ch-services", "evt-ch-security"].map(
      (id) => channelNode(domain, id).selectKey,
    );
    expect(new Set(keys).size).toBe(keys.length);
    const security = channelNode(domain, "evt-ch-security");
    expect(targetKey({ collection: "artifacts", kind: "eventlog", cf: security.target?.cf })).toBe(
      security.selectKey,
    );
  });

  it("are hidden with a Korean reason on outputs without channel counts", () => {
    const security = channelNode(eventlogDomain(runTree(false)), "evt-ch-security");
    expect(security.count).toBe(0);
    expect(security.disabledReason).toBe(NO_CHANNEL_COUNTS_REASON);
    expect(security.target?.cf?.[0]?.value).toBe("Security"); // canonical fallback
  });

  it("send the channel filter to the server as repeated channel=", () => {
    const filters = {
      ...BASE_FILTERS,
      columns: [
        {
          col: CHANNEL_FILTER_COLUMN,
          op: ":" as const,
          value: "Windows PowerShell|Microsoft-Windows-PowerShell/Operational",
        },
      ],
    };
    const ref = { id: "artifacts" as const, kind: "eventlog" };
    const plan = partitionFilters(ref, filters);
    expect(plan.server.channels).toEqual(["Windows PowerShell", "Microsoft-Windows-PowerShell/Operational"]);
    expect(plan.clientColumns).toEqual([]);
    expect(plan.serverLabels).toContain("채널");
    expect(plan.serverLabels).not.toContain("열 필터");
    const query = applyFiltersToQuery({ ref, offset: 0, limit: 50 }, filters);
    expect(query.channels).toEqual(["Windows PowerShell", "Microsoft-Windows-PowerShell/Operational"]);
    const qs = new URLSearchParams(
      artifactsQueryString({ kind: ["eventlog"], limit: 50, channel: query.channels }),
    );
    expect(qs.getAll("channel")).toEqual(["Windows PowerShell", "Microsoft-Windows-PowerShell/Operational"]);
    // Another collection cannot filter channels on the server: it stays a client column.
    expect(partitionFilters({ id: "timeline" }, filters).clientColumns).toHaveLength(1);
  });

  it("leave the 채널 grid column's header filter on the loaded rows", () => {
    const filters = { ...BASE_FILTERS, columns: [{ col: "channel", op: ":" as const, value: "Sec" }] };
    const plan = partitionFilters({ id: "artifacts", kind: "eventlog" }, filters);
    expect(plan.server.channels).toBeUndefined();
    expect(plan.clientColumns).toHaveLength(1);
  });
});
