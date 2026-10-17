// biome-ignore-all lint/a11y: tests drive the ARIA grid through its DOM roles
/**
 * 통합 보기 (axiom-adoption §3.2): derived catalogue columns (event summary · RDP direction · EXIF
 * state · auto logon), the derived pane (keyboard, chips, search, original rows → family grid) and
 * the citation / route / tree contracts.
 */

import { act, cleanup, configure, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getCommand, resetCommandRegistry, runCommand } from "../../commands/registry";
import type { GridRow } from "../../contracts/collection";
import type { ViewerTarget } from "../../contracts/viewer";
import { parseHash, serializeRoute } from "../../router";
import { useAppStore } from "../../state/store";
import { formatGridTime } from "../../utils/time";
import { FALLBACK_CATALOG, familyById, setCatalog } from "../flags/catalog";
import { catalogColumn } from "../grid/columns/families";
import { installFetch, jsonResponse, renderWithClient } from "../grid/testSupport";
import type { DomainNodeDef } from "../tree/domains";
import { domainNodeCount, domainTotal, NO_DERIVED_REASON } from "../tree/model";
import { buildCitation } from "../viewer/citation";
import type { DerivedRow } from "./api";
import { registerDerivedCommands } from "./commands";
import { DerivedPane } from "./DerivedPane";
import {
  AUTO_LOGON_REASON,
  deriveColumn,
  EVENT_TEMPLATE_IDS,
  eventSummaryKo,
  exifStatus,
  RDP_INBOUND,
  RDP_OUTBOUND,
  rdpDirection,
} from "./derivedFields";
import { useDerivedStore } from "./store";
import { derivedCitation, sampleRoute } from "./tables";

configure({ asyncUtilTimeout: 5000 });

const announceMock = vi.hoisted(() => vi.fn());
vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: announceMock,
}));

const RUN = "run-1";

/** The 60 event IDs of plan §3.2 (41 is listed twice there: Kernel-Power and the RDP session manager). */
const PLAN_IDS =
  "4624/4625/4634/4647/4648/4672/4688/4698/4702/4720/4722/4724/4726/4728/4732/4756/4768/4769/4771/4776/4778/4779/1102/104/7045/7034/7036/4697/1149/21/22/23/24/25/40/41/1000/1001/6005/6006/6008/41/12/13/20001/20003/4100/4103/4104/400/403/800/1116/1117/5001/5007/5140/5145/4663/4656".split(
    "/",
  );

function security(id: string, extra: Record<string, unknown> = {}) {
  return {
    event_id: id,
    channel: "Security",
    provider_name: "Microsoft-Windows-Security-Auditing",
    ...extra,
  };
}

describe("event summary sentence (Q-X7)", () => {
  it("covers every event ID of the plan", () => {
    expect(PLAN_IDS).toHaveLength(60);
    for (const id of PLAN_IDS) expect(EVENT_TEMPLATE_IDS).toContain(id);
  });

  it("fills 4624/4625/4672/4688 from the row's own fields (top-level and EventData)", () => {
    expect(
      eventSummaryKo(
        security("4624", { target_user_name: "alice", logon_type: "10", source_ip: "203.0.113.7" }),
      ),
    ).toBe("계정 alice 로그온 성공 (로그온 유형 10 — 원격 대화형(RDP)), 원격 203.0.113.7");
    expect(
      eventSummaryKo(
        security("4625", {
          event_data: { TargetUserName: "bob", LogonType: "3", IpAddress: "10.0.0.9", Status: "0xc000006d" },
        }),
      ),
    ).toBe(
      "계정 bob 로그온 실패 (로그온 유형 3 — 네트워크), 원격 10.0.0.9 — 상태 잘못된 사용자 이름 또는 인증 정보(0xc000006d)",
    );
    expect(eventSummaryKo(security("4672", { subject_user_name: "SYSTEM" }))).toBe(
      "계정 SYSTEM 로그온에 특수 권한 할당",
    );
    expect(
      eventSummaryKo(
        security("4688", {
          event_data: {
            NewProcessName: "C:\\Windows\\System32\\cmd.exe",
            ParentProcessName: "C:\\x\\explorer.exe",
            SubjectUserName: "alice",
          },
        }),
      ),
    ).toBe("프로세스 생성: C:\\Windows\\System32\\cmd.exe (부모 C:\\x\\explorer.exe) — 계정 alice");
    // Missing fields read as unknown, never "undefined".
    expect(eventSummaryKo(security("4624"))).toBe("계정 (계정 미상) 로그온 성공");
  });

  it("picks the template of the event's channel; unknown IDs say so", () => {
    expect(eventSummaryKo(security("9999"))).toBe("요약 없음 (ID 9999)");
    expect(eventSummaryKo({ event_id: "21", channel: "Microsoft-Windows-Audio/PlaybackManager" })).toBe(
      "요약 없음 (ID 21)",
    );
    expect(
      eventSummaryKo({
        event_id: "21",
        channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        user_data: { User: "CORP\\alice", Address: "198.51.100.4" },
      }),
    ).toBe("원격 데스크톱 세션 로그온: CORP\\alice (주소 198.51.100.4)");
    expect(
      eventSummaryKo({ event_id: "41", channel: "System", provider_name: "Microsoft-Windows-Kernel-Power" }),
    ).toContain("정상 종료 없이");
    expect(
      eventSummaryKo({
        event_id: "41.0",
        channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
      }),
    ).toContain("세션 중재");
    expect(deriveColumn("event_summary_ko", {}, "eventlog-event")).toEqual({ missing: "이벤트 ID 없음" });
  });
});

describe("RDP direction · EXIF state · auto logon", () => {
  it("reads the direction from the channel and event", () => {
    expect(
      rdpDirection(
        {
          event_id: "1149",
          channel: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        },
        "eventlog-event",
      ),
    ).toBe(RDP_INBOUND);
    expect(
      rdpDirection(
        { event_id: "1024", channel: "Microsoft-Windows-TerminalServices-RDPClient/Operational" },
        "eventlog-event",
      ),
    ).toBe(RDP_OUTBOUND);
    expect(rdpDirection(security("4624", { logon_type: "10" }), "eventlog-event")).toBe(RDP_INBOUND);
    expect(rdpDirection(security("4624", { logon_type: "2" }), "eventlog-event")).toBeNull();
    expect(rdpDirection({}, "rdp-mru-entry")).toBe(RDP_OUTBOUND);
    expect(deriveColumn("rdp_direction", security("4688"), "eventlog-event")).toBeNull();
  });

  it("reports the EXIF state or why there is none", () => {
    expect(
      exifStatus({ exif_gps_profile: { status: "no-gps-ifd", exif_block_present: true } }, "media-image"),
    ).toMatchObject({ value: "완료" });
    expect(
      exifStatus({ exif_gps_profile: { status: "no-exif", has_exif: false } }, "media-image"),
    ).toMatchObject({ value: "없음" });
    expect(exifStatus({}, "media-image-unreadable")).toMatchObject({ value: "오류" });
    expect(exifStatus({}, "media-video")).toEqual({ missing: "동영상·오디오에는 EXIF 추출을 하지 않음" });
    expect(exifStatus({}, "media-image")).toEqual({ missing: "파서가 EXIF 추출 상태를 남기지 않음" });
    expect(deriveColumn("auto_logon", {}, "windows-sam-account")).toEqual({ missing: AUTO_LOGON_REASON });
  });

  it("the catalogue's derived columns render the value or '없음 — 사유' (backend YAML)", () => {
    setCatalog(FALLBACK_CATALOG, "server");
    try {
      const sam = familyById("sam-account");
      const auto = sam?.core_columns.find((c) => c.derive === "auto_logon");
      expect(auto?.label).toBe("자동 로그온");
      const row = { fields: { details: {} }, artifactType: "windows-sam-account" } as unknown as GridRow;
      const column = catalogColumn(auto as NonNullable<typeof auto>);
      expect(column.format?.(row)).toBe(`없음 — ${AUTO_LOGON_REASON}`);
      expect(column.sortKey).toBeUndefined();
      const event = familyById("eventlog-event")?.core_columns.find((c) => c.derive === "event_summary_ko");
      const eventRow = {
        fields: { details: security("4672", { subject_user_name: "admin" }) },
        artifactType: "eventlog-event",
      } as unknown as GridRow;
      expect(catalogColumn(event as NonNullable<typeof event>).format?.(eventRow)).toBe(
        "계정 admin 로그온에 특수 권한 할당",
      );
      expect(familyById("media-image")?.core_columns.some((c) => c.derive === "exif_status")).toBe(true);
      expect(familyById("rdp")?.core_columns.some((c) => c.derive === "rdp_direction")).toBe(true);
      // Every family of the backend catalogue was reviewed for semantic tags: 54 + r2 M1 (3) + r2 M4 (1) + r2 M2 (6).
      expect(FALLBACK_CATALOG.families).toHaveLength(64);
      expect(familyById("sam-account")?.core_columns.find((c) => c.key === "user_name")?.semantic).toBe(
        "account",
      );
    } finally {
      setCatalog(null);
    }
  });
});

describe("route · citation · tree contracts", () => {
  it("round-trips the derived route", () => {
    const route = parseHash("#/case/run-1/explore/derived/paths?q=cmd");
    expect(route).toMatchObject({ runId: "run-1", collection: "derived", kind: "paths", q: "cmd" });
    expect(serializeRoute(route)).toBe("#/case/run-1/explore/derived/paths?q=cmd");
  });

  it("routes a sample to its family grid with the row selected", () => {
    expect(
      sampleRoute(RUN, {
        kind: "eventlog",
        record_index: 42,
        field: "target_user_name",
        family: "eventlog-event",
        artifact_type: "eventlog-event",
        time: null,
        collection: "artifacts",
        locator: "/artifacts/42",
      }),
    ).toEqual({
      runId: RUN,
      collection: "artifacts",
      kind: "eventlog",
      row: { collection: "artifacts", kind: "eventlog", locator: "/artifacts/42" },
    });
    const inventory = sampleRoute(RUN, {
      kind: "files:inventory",
      record_index: 3,
      field: "path",
      family: "file",
      artifact_type: "file",
      time: null,
      collection: "files",
      scope: "inventory",
      locator: "/inventory/3",
    });
    expect(inventory).toMatchObject({
      collection: "files",
      category: "inventory",
      row: { locator: "/inventory/3" },
    });
  });

  it("cites a value as 통합:<표>/<정규화 값> and carries it into the viewer citation", () => {
    expect(derivedCitation("people", { normalized: "alice", count: 34 }, RUN)).toBe(
      "통합:사람 식별자/alice; 건수=34; 런=run-1",
    );
    const ref = { collection: "artifacts" as const, kind: "eventlog", locator: "/artifacts/7" };
    useDerivedStore.getState().rememberOrigin(RUN, ref, { table: "people", normalized: "alice" });
    const target = { runId: RUN, ref, sourcePath: "C:/x.evtx" } as unknown as ViewerTarget;
    expect(buildCitation(target, null)).toContain("통합=통합:사람 식별자/alice");
    const other = { runId: RUN, ref: { ...ref, locator: "/artifacts/8" } } as unknown as ViewerTarget;
    expect(buildCitation(other, null)).not.toContain("통합=");
  });

  it("forgets the 통합 origin as soon as the row is reached any other way (no stale provenance)", () => {
    useDerivedStore.setState({ active: null });
    const ref = { collection: "artifacts" as const, kind: "eventlog", locator: "/artifacts/7" };
    const route = { runId: RUN, collection: "artifacts" as const, kind: "eventlog", row: ref };
    const cite = () =>
      buildCitation({ runId: RUN, ref, sourcePath: "C:/x.evtx" } as unknown as ViewerTarget, null);
    // The pane remembers, then navigates to the family grid with the row selected.
    useDerivedStore.getState().rememberOrigin(RUN, ref, { table: "people", normalized: "alice" });
    useAppStore.getState().navigate(route);
    expect(cite()).toContain("통합=통합:사람 식별자/alice");
    // A filter / sort on the same grid keeps it (the path is still the same).
    useAppStore.getState().patchRoute({ q: "4624" });
    expect(cite()).toContain("통합=통합:사람 식별자/alice");
    // J/K to another row (grid publish from user navigation): gone …
    useAppStore.getState().setViewerTarget({
      runId: RUN,
      ref: { ...ref, locator: "/artifacts/8" },
      sourcePath: "C:/x.evtx",
    });
    expect(useDerivedStore.getState().active).toBeNull();
    // … and coming back to the same row later cites no 통합 value.
    useAppStore.getState().setViewerTarget({ runId: RUN, ref, sourcePath: "C:/x.evtx" });
    expect(cite()).not.toContain("통합=");

    // A route change that keeps the row (tree → another node) also clears it.
    useAppStore.getState().navigate({ runId: RUN, collection: "derived", kind: "people" });
    useDerivedStore.getState().rememberOrigin(RUN, ref, { table: "people", normalized: "alice" });
    useAppStore.getState().navigate(route);
    expect(cite()).toContain("통합=");
    useAppStore.getState().openCollection("timeline");
    expect(useAppStore.getState().route.row).toEqual(ref);
    expect(cite()).not.toContain("통합=");
  });

  it("the 통합 보기 domain header sums its tables' value counts", () => {
    const nodes = [
      { id: "people", label: "사람 식별자", target: { collection: "derived", kind: "people" } },
      { id: "paths", label: "접근 경로", target: { collection: "derived", kind: "paths" } },
      { id: "urls", label: "URL 분류", target: { collection: "derived", kind: "urls" } },
    ] as unknown as DomainNodeDef[];
    expect(domainTotal(nodes, [273, 1200, undefined])).toBe(1473);
    expect(domainTotal(nodes, [undefined, undefined, undefined])).toBeUndefined();
    expect(domainTotal(nodes, [0, 0, 0])).toBe(0);
  });

  it("counts the tree nodes from /tree and explains a run without a set", () => {
    const tree = {
      run_id: RUN,
      nodes: [
        {
          id: "derived",
          label: "통합 보기",
          count: 3,
          children: [{ id: "derived:people", label: "사람 식별자", count: 273 }],
        },
      ],
    } as never;
    expect(domainNodeCount({ collection: "derived", kind: "people" }, { tree })).toEqual({ count: 273 });
    expect(
      domainNodeCount(
        { collection: "derived", kind: "people" },
        { tree: { run_id: RUN, nodes: [] } as never },
      ),
    ).toEqual({
      count: 0,
      disabledReason: NO_DERIVED_REASON,
    });
  });
});

// ---- pane ------------------------------------------------------------------------------------

function row(normalized: string, count: number, extra: Partial<DerivedRow> = {}): DerivedRow {
  return {
    value: normalized.toUpperCase(),
    normalized,
    semantic: "account",
    semantics: { account: count },
    count,
    kinds: { eventlog: count - 1, "windows-os-account": 1 },
    families: { "eventlog-event": count - 1, "sam-account": 1 },
    first_seen: "2024-01-01T00:00:00+00:00",
    last_seen: "2024-05-01T00:00:00+00:00",
    sample_count: 2,
    ...extra,
  };
}

const META = {
  run_id: RUN,
  source: {
    status: "ready",
    analysis_id: "run-derived-1",
    source: "run-stage",
    generated_at: "2026-10-17T00:00:00Z",
    coverage: "complete",
  },
  tables: [
    {
      table: "people",
      label: "사람 식별자",
      rows: 3,
      occurrences: 40,
      capped: false,
      cap_reason: null,
      dropped_values: 0,
      by_kind: { eventlog: 37, "windows-os-account": 3 },
      by_semantic: { account: 40 },
    },
  ],
};

function page(rows: DerivedRow[], next: string | null = null, matched = rows.length) {
  return {
    run_id: RUN,
    table: "people",
    label: "사람 식별자",
    source: META.source,
    total: 3,
    matched,
    limit: 200,
    sort: "count",
    q: null,
    kind: null,
    rows,
    next_cursor: next,
  };
}

function openPane(hash = `#/case/${RUN}/explore/derived/people`) {
  window.location.hash = hash;
  useAppStore.getState().syncRouteFromLocation(parseHash(hash));
  return renderWithClient(<DerivedPane />);
}

describe("DerivedPane (Q-X5 / Q-X12)", () => {
  beforeEach(() => {
    resetCommandRegistry();
    announceMock.mockClear();
    useDerivedStore.setState({
      selected: null,
      loadMore: null,
      focusRows: null,
      rebuilding: null,
      active: null,
    });
    setCatalog(FALLBACK_CATALOG, "server");
  });
  afterEach(() => {
    cleanup();
    setCatalog(null);
    vi.unstubAllGlobals();
  });

  it("lists values; keyboard moves, Enter opens the original rows, a row opens the family grid selected", async () => {
    const calls = installFetch({
      "/derived/people/rows": () =>
        jsonResponse({
          ...row("alice", 34),
          run_id: RUN,
          table: "people",
          label: "사람 식별자",
          samples: [
            {
              kind: "eventlog",
              record_index: 12,
              field: "target_user_name",
              family: "eventlog-event",
              artifact_type: "eventlog-event",
              time: null,
              collection: "artifacts",
              locator: "/artifacts/12",
            },
            {
              kind: "windows-os-account",
              record_index: 0,
              field: "user_name",
              family: "sam-account",
              artifact_type: "windows-sam-account",
              time: null,
              collection: "artifacts",
              locator: "/artifacts/0",
            },
          ],
        }),
      "/derived/people": () => jsonResponse(page([row("alice", 34), row("bob", 5), row("carol", 1)])),
      "/derived": () => jsonResponse(META),
    });
    const { client } = openPane();
    registerDerivedCommands(client);
    const grid = await screen.findByRole("grid", { name: "사람 식별자 표" });
    // The header row renders first; wait for the three value rows.
    await waitFor(() => expect(within(grid).getAllByRole("row")).toHaveLength(4));
    const rows = within(grid).getAllByRole("row");
    expect(grid.getAttribute("aria-rowcount")).toBe("4");
    expect(rows[1]?.getAttribute("aria-label")).toContain("값 ALICE");
    expect(screen.getByRole("searchbox", { name: "값 검색" })).toBeTruthy();
    expect(announceMock).toHaveBeenCalledWith("사람 식별자: 값 3개");
    // Before a value is chosen the citation command says why.
    expect(getCommand("derived.copy-citation")?.disabledReason?.({} as never)).toBe(
      "통합 보기 표에서 값을 먼저 고르세요",
    );
    const first = rows[1] as HTMLElement;
    first.focus();
    fireEvent.keyDown(first, { key: "j" });
    expect(document.activeElement).toBe(rows[2]);
    fireEvent.keyDown(rows[2] as HTMLElement, { key: "k" });
    expect(document.activeElement).toBe(rows[1]);
    fireEvent.keyDown(first, { key: "Enter" });
    const panel = screen.getByTestId("derived-rows");
    const buttons = await within(panel).findAllByRole("button");
    expect(buttons).toHaveLength(2);
    await waitFor(() => expect(document.activeElement).toBe(buttons[0]));
    expect(first.getAttribute("aria-selected")).toBe("true");
    expect(buttons[1]?.getAttribute("aria-label")).toContain("SAM 계정");
    expect(calls.some((call) => call.url.includes("/derived/people/rows?value=alice"))).toBe(true);
    // Esc returns to the value.
    fireEvent.keyDown(buttons[0] as HTMLElement, { key: "Escape" });
    expect(document.activeElement).toBe(first);
    expect(getCommand("derived.copy-citation")?.disabledReason?.({} as never)).toBeUndefined();
    fireEvent.click(buttons[1] as HTMLElement);
    const route = useAppStore.getState().route;
    expect(route).toMatchObject({
      collection: "artifacts",
      kind: "windows-os-account",
      row: { locator: "/artifacts/0" },
    });
    expect(useDerivedStore.getState().active).toEqual({
      key: `${RUN}|artifacts|windows-os-account|/artifacts/0`,
      origin: { table: "people", normalized: "alice" },
      // Pinned to the family grid it was opened in.
      context: `${RUN}|artifacts|windows-os-account||`,
    });
  });

  it("kind chips and the search box filter on the server; load more follows the cursor", async () => {
    const calls = installFetch({
      "/derived/people": (url) => {
        if (url.searchParams.get("after") === "c1") return jsonResponse(page([row("carol", 1)]));
        if (url.searchParams.get("kind")) return jsonResponse(page([row("alice", 34)], null, 1));
        return jsonResponse(page([row("alice", 34), row("bob", 5)], "c1"));
      },
      "/derived": () => jsonResponse(META),
    });
    const { client } = openPane();
    registerDerivedCommands(client);
    const grid = await screen.findByRole("grid", { name: "사람 식별자 표" });
    await within(grid).findByText("ALICE");
    await waitFor(() =>
      expect(getCommand("derived.load-more")?.disabledReason?.({} as never)).toBeUndefined(),
    );
    await act(async () => {
      await runCommand("derived.load-more");
    });
    await within(grid).findByText("CAROL");
    expect(calls.some((call) => call.url.includes("after=c1"))).toBe(true);
    const chips = screen.getByRole("group", { name: "출처 종류 필터" });
    // Korean label order: EVTX, OS 계정 (collator "ko").
    const labels = within(chips)
      .getAllByRole("button")
      .map((b) => b.textContent);
    expect(labels[0]).toBe("전체");
    fireEvent.click(within(chips).getByRole("button", { name: /OS 계정 3건만 보기/ }));
    await waitFor(() =>
      expect(calls.some((call) => call.url.includes("kind=windows-os-account"))).toBe(true),
    );
    fireEvent.change(screen.getByRole("searchbox", { name: "값 검색" }), { target: { value: "ali" } });
    await waitFor(() => expect(calls.some((call) => call.url.includes("q=ali"))).toBe(true));
    await waitFor(() => expect(useAppStore.getState().route.q).toBe("ali"));
  });

  it("switching tables starts with an empty search and never writes the old q into the new table's URL", async () => {
    const calls = installFetch({
      "/derived/people": () => jsonResponse(page([row("alice", 34)])),
      "/derived/paths": () =>
        jsonResponse({ ...page([row("c:/windows", 3)]), table: "paths", label: "접근 경로" }),
      "/derived": () =>
        jsonResponse({
          ...META,
          tables: [...META.tables, { ...META.tables[0], table: "paths", label: "접근 경로", by_kind: {} }],
        }),
    });
    openPane();
    await screen.findByRole("grid", { name: "사람 식별자 표" });
    fireEvent.change(screen.getByRole("searchbox", { name: "값 검색" }), { target: { value: "ali" } });
    await waitFor(() => expect(useAppStore.getState().route.q).toBe("ali"));
    fireEvent.click(within(screen.getByRole("navigation", { name: "통합 보기 표" })).getByText("접근 경로"));
    await screen.findByRole("grid", { name: "접근 경로 표" });
    expect((screen.getByRole("searchbox", { name: "값 검색" }) as HTMLInputElement).value).toBe("");
    // Past the debounce: the URL has no q and no request for the new table carried it.
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(useAppStore.getState().route).toMatchObject({ collection: "derived", kind: "paths" });
    expect(useAppStore.getState().route.q).toBeUndefined();
    expect(window.location.hash).not.toContain("q=");
    expect(calls.filter((call) => call.url.includes("/derived/paths") && call.url.includes("q="))).toEqual(
      [],
    );
  });

  it("shows the set's generation time in the chosen timezone (grid format), not the browser locale", async () => {
    installFetch({
      "/derived/people": () => jsonResponse(page([row("alice", 34)])),
      "/derived": () => jsonResponse(META),
    });
    openPane();
    await screen.findByRole("grid", { name: "사람 식별자 표" });
    const status = document.querySelector(".derived-status")?.textContent ?? "";
    const tz = useAppStore.getState().route.tz ?? useAppStore.getState().timezone ?? "local";
    expect(status).toContain(`생성 ${formatGridTime(META.source.generated_at, tz)}`);
    expect(status).not.toContain(new Date(META.source.generated_at).toLocaleString("ko-KR"));
  });

  it("a run without a set explains why and offers the rebuild command", async () => {
    const calls = installFetch({
      "/analyses": () => jsonResponse({ analysis_id: "a-1", kind: "derived", status: "queued" }, 202),
      "/derived": () =>
        jsonResponse({ run_id: RUN, source: null, reason: "통합 보기 결과가 없습니다.", tables: [] }),
    });
    const { client } = openPane();
    registerDerivedCommands(client);
    expect(await screen.findByText("통합 보기 결과가 없습니다.")).toBeTruthy();
    const button = screen.getByRole("button", { name: /통합 보기 만들기/ });
    fireEvent.click(button);
    await waitFor(() =>
      expect(calls.some((call) => call.method === "POST" && call.url.endsWith("/analyses"))).toBe(true),
    );
    expect(calls.find((call) => call.method === "POST")?.body).toEqual({ kind: "derived", options: {} });
    await waitFor(() => expect(useDerivedStore.getState().rebuilding).toBe("a-1"));
    expect(getCommand("derived.rebuild")?.disabledReason?.({} as never)).toBe("통합 보기를 만드는 중입니다");
  });

  it("credentials show only the masked value, length and digest", async () => {
    installFetch({
      "/derived/credentials": () =>
        jsonResponse({
          ...page([
            row(`sha256:${"a".repeat(64)}`, 1, {
              value: "Su••••••••••••0",
              length: 27,
              sha256: "a".repeat(64),
              semantic: "credential",
            }),
          ]),
          table: "credentials",
        }),
      "/derived": () =>
        jsonResponse({
          ...META,
          tables: [{ ...META.tables[0], table: "credentials", label: "자격 증명/토큰" }],
        }),
    });
    openPane(`#/case/${RUN}/explore/derived/credentials`);
    const grid = await screen.findByRole("grid", { name: "자격 증명/토큰 표" });
    await within(grid).findByText("Su••••••••••••0");
    expect(within(grid).getByText("27")).toBeTruthy();
    expect(within(grid).getByText("a".repeat(64))).toBeTruthy();
    expect(
      within(grid)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual(["가린 값", "길이", "SHA-256", "건수", "출처 계열", "처음 본 시각", "마지막 본 시각"]);
  });
});
