/** 이벤트 로그 › 채널별 nodes (plan r3-os-depth §3.2 O2): counts from `/tree`, server channel filters. */
import { describe, expect, it } from "vitest";
import { artifactsQueryString, type ChannelGroupNode, type RunTree } from "../../api/runs";
import {
  applyFiltersToQuery,
  CHANNEL_FILTER_COLUMN,
  CHANNEL_GROUP_FILTER_COLUMN,
  type FilterState,
  partitionFilters,
} from "../filters/filterModel";
import {
  DOMAINS,
  EVENTLOG_CHANNEL_NODES,
  EVENTLOG_CHANNELS_GROUP,
  EVENTLOG_PARTITION_GROUPS,
  targetKey,
} from "./domains";
import { buildTreeModel, NO_CHANNEL_COUNTS_REASON, type TreeModelNode } from "./model";

const BASE_FILTERS: FilterState = { statuses: [], types: [], tags: [], ext: [], path: "", columns: [] };

const group = (
  id: string,
  label: string,
  count: number | null,
  channels: string[],
  partition = true,
): ChannelGroupNode => ({
  id,
  label,
  count,
  channels,
  partition,
});

// Partition counts sum to the kind's 100 rows; 서비스(SCM) is a view inside 시스템.
const GROUPS: ChannelGroupNode[] = [
  group("other", "기타 채널", 1, ["Microsoft-Windows-Bits-Client/Operational"]),
  group("firewall", "방화벽", 0, ["Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"]),
  group("security", "보안", 40, ["Security"]),
  group("user-pnp", "사용자 PNP", 0, ["Microsoft-Windows-UserPnp/DeviceInstall"]),
  group("services", "서비스(SCM)", 3, ["System"], false),
  group("storage", "스토리지", 2, [
    "Microsoft-Windows-Ntfs/Operational",
    "Microsoft-Windows-Storage-ClassPnP/Operational",
  ]),
  group("system", "시스템", 30, ["System"]),
  group("rdp", "원격 데스크톱", 4, ["Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"]),
  group("application", "응용 프로그램", 10, ["Application"]),
  group("task-scheduler", "작업 스케줄러", 0, ["Microsoft-Windows-TaskScheduler/Operational"]),
  group("none", "채널 없음", 3, []),
  group("office-alerts", "Office Alerts", 0, ["OAlerts"]),
  group("powershell", "PowerShell", 10, ["Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"]),
  group("defender", "Windows Defender", 0, ["Microsoft-Windows-Windows Defender/Operational"]),
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

function node(domain: TreeModelNode, id: string): TreeModelNode {
  const found = [
    ...(domain.children ?? []),
    ...(domain.children ?? []).flatMap((child) => child.children ?? []),
  ].find((child) => child.id === `domain:eventlog:${id}`);
  if (!found) throw new Error(`no node ${id}`);
  return found;
}

describe("event-log channel nodes", () => {
  it("are listed under 이벤트 로그 › 채널별, Korean-sorted with 기타 채널 · 채널 없음 last", () => {
    const labels = EVENTLOG_CHANNEL_NODES.map((item) => item.label);
    // R3 console fix #4: the remainder buckets close the list.
    expect(labels.slice(-2)).toEqual(["기타 채널", "채널 없음"]);
    const named = labels.slice(0, -2);
    expect(named).toEqual([...named].sort((x, y) => x.localeCompare(y, "ko")));
    expect(labels).toEqual(
      expect.arrayContaining([
        "보안",
        "시스템",
        "응용 프로그램",
        "PowerShell",
        "Windows Defender",
        // The EVTX channel, apart from 방화벽 로그 (pfirewall.log).
        "방화벽(이벤트 채널)",
        "작업 스케줄러",
        "서비스(SCM)",
        "스토리지",
        "사용자 PNP",
        "Office Alerts",
        "원격 데스크톱",
      ]),
    );
    const eventlog = DOMAINS.find((domain) => domain.id === "eventlog");
    // One "채널별" group, not 14 nodes at the domain level.
    expect(eventlog?.nodes.at(-1)).toBe(EVENTLOG_CHANNELS_GROUP);
    expect(EVENTLOG_CHANNELS_GROUP.label).toBe("채널별");
    expect(EVENTLOG_CHANNELS_GROUP.children).toEqual(EVENTLOG_CHANNEL_NODES);
    expect(eventlog?.nodes.some((item) => item.id.startsWith("evt-ch-"))).toBe(false);
  });

  it("the 채널별 group opens every partition group and is selected apart from 전체 이벤트 로그", () => {
    expect(EVENTLOG_PARTITION_GROUPS).not.toContain("services");
    expect(EVENTLOG_PARTITION_GROUPS).toHaveLength(EVENTLOG_CHANNEL_NODES.length - 1);
    const domain = eventlogDomain(runTree(true));
    const group = node(domain, "evt-channels");
    expect(group.count).toBe(100);
    expect(group.children?.map((child) => child.label).slice(-2)).toEqual(["기타 채널", "채널 없음"]);
    expect(group.selectKey).not.toBe(node(domain, "evt-all").selectKey);
    const plan = partitionFilters(
      { id: "artifacts", kind: "eventlog" },
      { ...BASE_FILTERS, columns: group.target?.cf ?? [] },
    );
    expect(plan.server.channelGroups).toEqual([...EVENTLOG_PARTITION_GROUPS]);
  });

  it("a column filter typed on a channel view keeps the node selected (R3 console fix #5)", () => {
    const domain = eventlogDomain(runTree(true));
    const security = node(domain, "evt-ch-security");
    const typed = [...(security.target?.cf ?? []), { col: "message", op: ":" as const, value: "logon" }];
    expect(targetKey({ collection: "artifacts", kind: "eventlog", cf: typed })).toBe(security.selectKey);
  });

  it("count from /tree channel_groups and open the kind with the server group filter", () => {
    const domain = eventlogDomain(runTree(true));
    const security = node(domain, "evt-ch-security");
    expect(security.count).toBe(40);
    expect(security.target).toMatchObject({
      collection: "artifacts",
      kind: "eventlog",
      cf: [{ col: CHANNEL_GROUP_FILTER_COLUMN, op: ":", value: "security" }],
    });
    expect(node(domain, "evt-ch-services").count).toBe(3);
    expect(node(domain, "evt-ch-services").note).toContain("Service Control Manager");
    const storage = node(domain, "evt-ch-storage");
    expect(storage.count).toBe(2);
    expect(storage.note).toContain("Microsoft-Windows-Ntfs/Operational");
    expect(node(domain, "evt-ch-defender").disabledReason).toBeDefined(); // count 0
    // The partition nodes add up to the kind's rows (Q-R3-4) …
    const partition = EVENTLOG_CHANNEL_NODES.filter((item) => item.id !== "evt-ch-services").map(
      (item) => node(domain, item.id).count as number,
    );
    expect(partition.reduce((sum, value) => sum + value, 0)).toBe(100);
    // … but channel views never add to the domain header (100 rows minus 3 EVTX 파일·요약 detail rows).
    expect(domain.count).toBe(97);
  });

  it("select keys tell the channel views apart from the whole kind and each other", () => {
    const domain = eventlogDomain(runTree(true));
    const keys = ["evt-all", "evt-ch-system", "evt-ch-services", "evt-ch-security"].map(
      (id) => node(domain, id).selectKey,
    );
    expect(new Set(keys).size).toBe(keys.length);
    const security = node(domain, "evt-ch-security");
    expect(targetKey({ collection: "artifacts", kind: "eventlog", cf: security.target?.cf })).toBe(
      security.selectKey,
    );
  });

  it("are hidden with a Korean reason on outputs without channel counts", () => {
    const security = node(eventlogDomain(runTree(false)), "evt-ch-security");
    expect(security.count).toBe(0);
    expect(security.disabledReason).toBe(NO_CHANNEL_COUNTS_REASON);
  });

  it("send channel filters to the server as repeated channel= / channel_group=", () => {
    const filters: FilterState = {
      ...BASE_FILTERS,
      columns: [
        { col: CHANNEL_GROUP_FILTER_COLUMN, op: ":", value: "powershell|rdp" },
        { col: CHANNEL_FILTER_COLUMN, op: ":", value: "Windows PowerShell|OAlerts" },
      ],
    };
    const ref = { id: "artifacts" as const, kind: "eventlog" };
    const plan = partitionFilters(ref, filters);
    expect(plan.server.channelGroups).toEqual(["powershell", "rdp"]);
    expect(plan.server.channels).toEqual(["Windows PowerShell", "OAlerts"]);
    expect(plan.clientColumns).toEqual([]);
    expect(plan.serverLabels).toContain("채널");
    expect(plan.serverLabels).not.toContain("열 필터");
    const query = applyFiltersToQuery({ ref, offset: 0, limit: 50 }, filters);
    const qs = new URLSearchParams(
      artifactsQueryString({
        kind: ["eventlog"],
        limit: 50,
        channel: query.channels,
        channel_group: query.channelGroups,
      }),
    );
    expect(qs.getAll("channel")).toEqual(["Windows PowerShell", "OAlerts"]);
    expect(qs.getAll("channel_group")).toEqual(["powershell", "rdp"]);
    // Another collection cannot filter channels on the server: they stay client columns.
    expect(partitionFilters({ id: "timeline" }, filters).clientColumns).toHaveLength(2);
  });

  it("leave the 채널 grid column's header filter on the loaded rows", () => {
    const filters: FilterState = { ...BASE_FILTERS, columns: [{ col: "channel", op: ":", value: "Sec" }] };
    const plan = partitionFilters({ id: "artifacts", kind: "eventlog" }, filters);
    expect(plan.server.channels).toBeUndefined();
    expect(plan.server.channelGroups).toBeUndefined();
    expect(plan.clientColumns).toHaveLength(1);
  });
});
