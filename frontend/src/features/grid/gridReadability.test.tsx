// biome-ignore-all lint/a11y: tests drive a virtualized ARIA grid through its DOM roles
/**
 * Timeline / grid readability fixes (Fable examiner-experience review, R6 follow-up): timeline
 * columns (C4/C5), server search and display groups on the wire and in the grid (C1/C3), the USB
 * node and the primary-family rule (C6), time column width (C7), ShimCache labels (C8), Korean
 * readings (C9), the timeline viewer's 메타 tab (C10) and empty-column hiding (P1).
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchTimelinePage } from "../../api/collections";
import type { GridRow } from "../../contracts/collection";
import type { ViewerTarget } from "../../contracts/viewer";
import { timestampKindLabel } from "../../utils/timeKinds";
import { eventSummaryKo } from "../derived/derivedFields";
import { artifactTypeLabel, timelineEventTypeLabel } from "../filters/typeLabels";
import {
  type CatalogFamily,
  FALLBACK_CATALOG,
  familyForType,
  familyForTypes,
  majorityFamilyForTypes,
  noteKindTypeCounts,
  resetKindTypeCounts,
  setCatalog,
} from "../flags/catalog";
import { DOMAINS, flattenDomainNodes } from "../tree/domains";
import { resolveModes } from "../viewer/modes";
import { MetaView } from "../viewer/views/MetaView";
import { useGridLocalStore } from "./adapter";
import { artifactsCollection, resolveArtifactFamily } from "./columns/artifacts";
import {
  catalogColumn,
  familyCoreFacts,
  keyTail,
  rowTimestampKind,
  TIME_COLUMN_WIDTH,
  tsKindLabel,
} from "./columns/families";
import {
  sourceRowText,
  timelineAreaLabel,
  timelineCollection,
  timelineTarget,
  urlHostPath,
} from "./columns/timeline";
import { DataGrid, KEPT_EMPTY_COLUMN_NOTE, TIMELINE_LEGACY_HINT } from "./DataGrid";
import { installFetch, jsonResponse, mockLayout, renderWithClient, resetGridStore } from "./testSupport";

vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: vi.fn(),
}));

let restoreLayout: () => void;
beforeEach(() => {
  resetGridStore();
  restoreLayout = mockLayout(1600, 600);
  // The catalogue as the backend YAML defines it (the families this fix changes).
  setCatalog(FALLBACK_CATALOG, "server");
});
afterEach(() => {
  cleanup();
  restoreLayout();
  vi.unstubAllGlobals();
  resetKindTypeCounts();
  setCatalog(null);
});

/** Artifact types of a real Windows run (type names only): every one reads in Korean (C9). */
const REAL_RUN_TYPES = (
  "amcache-application-shortcut amcache-device-census amcache-device-container amcache-device-pnp " +
  "amcache-driver-binary amcache-driver-package amcache-hive amcache-schema-row archive-file-inventory " +
  "bam-schema-entry browser-acquisition-anomaly browser-ai-usage browser-autofill browser-autofill-address " +
  "browser-bookmark browser-cookie browser-credit-card browser-download browser-extension browser-history " +
  "browser-history-downloads browser-login browser-omnibox-shortcut browser-search browser-session-tab " +
  "browser-storage-inventory browser-top-site browser-visit crash-dump-indicators document-lock-owner " +
  "document-metadata-risk etl-trace-file eventlog-detection eventlog-event eventlog-file " +
  "eventlog-logon-session eventlog-summary file-signature-mismatch icon-cache-entry-candidate icon-cache-file " +
  "icon-cache-media-candidate jumplist-automatic jumplist-custom jumplist-entry " +
  "kakaotalk-windows-correlation-summary kakaotalk-windows-crypto-material-candidate " +
  "kakaotalk-windows-source-candidate kakaotalk-windows-user-id-candidate media-audio media-image " +
  "media-image-unreadable media-video notification-database notification-row-candidate prefetch-file " +
  "prefetch-invalid-content prefetch-reference recent-shortcut recent-shortcut-invalid-content " +
  "registry-deleted-cell-candidate registry-hive registry-hive-strings registry-key-recovery-candidate " +
  "registry-key-tree-node registry-persistence-entry registry-summary registry-user-activity " +
  "registry-value-recovery-candidate shell-shortcut shellbag-entry shellbag-hive-summary " +
  "shimcache-schema-entry synthetic-media-image synthetic-media-scan-summary synthetic-media-text " +
  "third-party-remote-control-artifact thumbnail-cache-entry-candidate thumbnail-cache-file " +
  "thumbnail-cache-media-candidate userassist-schema-entry wer-report windows-computer-name " +
  "windows-control-set windows-execution-summary windows-installed-program windows-mounted-device " +
  "windows-network-interface windows-sam-account windows-sam-group windows-service-config windows-timezone " +
  "windows-usb-device windows-user-profile"
).split(" ");

/** Time kinds of a real Windows run's timeline (kind names only). */
const REAL_RUN_TIME_KINDS = (
  "event target-created target-modified created last-written destlist-last-modified target-accessed " +
  "accessed item-created visited last-visited file-last-modified item-modified run-1 item-accessed started " +
  "ended installed navigated last-run last-execution last-written-mru-head last-written-recovered " +
  "ai-usage-visited exif-datetime-original notification modified added last-accessed typed-url-time " +
  "process-created crash first-install last-arrival last-removal password-last-set last-logon gps-fix " +
  "mp4-mvhd-creation run shutdown last-failed-logon last-access"
).split(" ");

const AUTO =
  "D:\\case\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\a.automaticDestinations-ms";

const jumplistEvent = {
  timestamp: "2024-03-01T10:00:00+00:00",
  timestamp_kind: "target-created",
  source: "artifacts",
  event_type: "artifact-jumplist-entry-target-created",
  path: AUTO,
  summary: "E:\\보고서\\A.docx",
  record_index: 7,
  source_count: 3,
  group_id: "g4",
  group_members: [7, 9, 12],
  sources: [
    {
      artifact_type: "jumplist-entry",
      event_type: "artifact-jumplist-entry-target-created",
      path: AUTO,
      record_index: 7,
    },
    {
      artifact_type: "recent-shortcut",
      event_type: "artifact-recent-shortcut-target-created",
      path: "D:\\case\\r\\A.lnk",
      record_index: 9,
    },
    {
      artifact_type: "shell-shortcut",
      event_type: "artifact-shell-shortcut-target-created",
      path: "D:\\case\\s\\A.lnk",
      record_index: 12,
    },
  ],
  details: {
    artifact_type: "jumplist-entry",
    target_path: "E:\\보고서\\A.docx",
    destlist_access_count: 3,
    source_record: { output: "artifacts_recent-files", row_index: 4 },
  },
};

const eventlogEvent = {
  timestamp: "2024-03-01T10:00:00+00:00",
  timestamp_kind: "event",
  source: "artifacts",
  event_type: "eventlog-logon-success",
  path: "D:\\case\\Windows\\System32\\winevt\\Logs\\Security.evtx",
  summary: "로그온 성공 · 계정 SYSTEM → alice · 컴퓨터 PC-01",
  details: {
    artifact_type: "eventlog-event",
    event_id: "4624",
    channel: "Security",
    event_label_ko: "로그온 성공",
  },
};

const mapEvent = (raw: Record<string, unknown>, root?: string) =>
  timelineCollection.mapRow(raw, 0, {
    ref: { id: "timeline" },
    ...(root
      ? {
          page: {
            rows: [],
            total: 1,
            offset: 0,
            backend: "file",
            truncated: false,
            elapsedMs: 0,
            meta: { root },
          },
        }
      : {}),
  });
const column = (id: string) => timelineCollection.columns.find((c) => c.id === id);

describe("C9 Korean labels", () => {
  it("names every artifact type of a real Windows run", () => {
    expect(REAL_RUN_TYPES.filter((type) => !artifactTypeLabel(type))).toEqual([]);
  });

  it("names every time kind of a real Windows timeline (never the raw id)", () => {
    expect(REAL_RUN_TIME_KINDS.filter((kind) => timestampKindLabel(kind) === kind)).toEqual([]);
    expect(timestampKindLabel("file-last-modified")).toBe("파일 수정(실행 아님)");
  });

  it("reads timeline event types as type name · time kind (유형 filter list)", () => {
    expect(timelineEventTypeLabel("artifact-jumplist-entry-target-created")).toBe(
      "점프 목록 항목 · 대상 생성",
    );
    expect(artifactTypeLabel("artifact-shimcache-schema-entry-file-last-modified")).toContain(
      "파일 수정(실행 아님)",
    );
    expect(timelineEventTypeLabel("artifact-unknown-thing-created")).toBeNull();
  });
});

describe("C4/C5 timeline columns", () => {
  it("defaults: 시각 · 시각 종류 · 영역·유형 · 대상 · 상세 · 출처 수 · 특이사항 · 출처 행 (+ 선별 when marked)", () => {
    const defaults = timelineCollection.columns
      .filter((c) => c.presets.includes("analysis"))
      .map((c) => c.id);
    expect(defaults).toEqual([
      "timestamp",
      "tsKind",
      "area",
      "target",
      "detail",
      "sourceCount",
      "flags",
      "sourceRow",
      "review",
    ]);
    // 출처 수 · 특이사항 · 선별 go when no loaded row has a value (empty-column hiding).
    const priority = timelineCollection.widthPriority?.({ id: "timeline" }) ?? [];
    expect(priority).toEqual(expect.arrayContaining(["sourceCount", "flags", "review"]));
    expect(column("timestamp")?.width).toBe(190);
    expect(column("tsKind")?.width).toBe(140); // C-D14: "마지막 방문 +2" whole
    // 출처 (constant "artifacts") and 이벤트 (raw id) stay selectable, off by default.
    expect(column("source")?.presets).toEqual([]);
    expect(column("eventType")?.presets).toEqual([]);
  });

  it("maps 대상 / 상세 / 영역·유형 / 출처 행 / 출처 수 of a grouped Jump List event", () => {
    const row = mapEvent(jumplistEvent, "D:\\case");
    expect(row.ref.locator).toBe("/events/7");
    expect(row.fields.target).toBe("A.docx");
    expect(column("target")?.tooltip?.(row)).toBe("E:\\보고서\\A.docx");
    expect(row.fields.area).toBe("점프 목록 항목");
    expect(column("area")?.tooltip?.(row)).toContain("jumplist-entry");
    expect(row.fields.sourceRow).toBe("…\\Recent\\AutomaticDestinations\\a.automaticDestinations-ms");
    expect(row.fields.sourceCount).toBe(3);
    expect(column("sourceCount")?.format?.(row)).toBe("출처 3");
    expect(column("sourceCount")?.tooltip?.(row)).toContain("D:\\case\\r\\A.lnk");
    render(<div>{column("sourceCount")?.render?.(row)}</div>);
    expect(screen.getByTestId("timeline-source-count").textContent).toBe("출처 3");
  });

  it("event logs: 대상 = channel · event ID, 상세 = the readable summary", () => {
    const row = mapEvent(eventlogEvent);
    expect(row.fields.detail).toBe(eventlogEvent.summary);
    expect(row.fields.target).toBe("Security · 4624");
    expect(timelineAreaLabel("eventlog-event")).toBeTruthy();
    expect(column("sourceCount")?.value(row)).toBeNull(); // single source: the column stays empty
    // An event with neither a target nor an event ID reads its summary as 대상.
    expect(mapEvent({ ...eventlogEvent, details: { artifact_type: "wer-report" } }).fields.target).toBe(
      eventlogEvent.summary,
    );
  });

  it("targets: URL host + path, key tail, file name; source rows without the acquisition root", () => {
    expect(urlHostPath("https://mail.example.com/v2/folders?id=3#x")).toBe("mail.example.com/v2/folders");
    expect(timelineTarget({ details: { key_path: "HKU\\S-1\\Software\\Microsoft\\RecentDocs" } })?.text).toBe(
      "…\\Microsoft\\RecentDocs",
    );
    expect(timelineTarget({ details: { executable_path: "D:\\YSR2000\\Exe\\LiveUpdate.exe" } })?.text).toBe(
      "LiveUpdate.exe",
    );
    expect(sourceRowText("D:\\case\\Windows\\System32\\config\\SYSTEM", "D:\\case\\")).toBe(
      "…\\System32\\config\\SYSTEM",
    );
    expect(sourceRowText("C:\\x\\SYSTEM", null)).toBe("C:\\x\\SYSTEM");
  });
});

describe("C1/C3 server search and display groups on the wire", () => {
  it("sends q= and group=1; the server total is the match count", async () => {
    const calls = installFetch({
      "/timeline": () =>
        jsonResponse({
          root: "D:\\case",
          events: [jumplistEvent],
          matched: 1,
          pagination: { total: 1, matched: 1, filtered: true, grouped: true },
        }),
    });
    const page = await fetchTimelinePage("r1", 0, 250, undefined, undefined, {
      q: " LiveUpdate.exe ",
      group: true,
    });
    const url = new URL(calls[0]?.url ?? "", "http://x");
    expect(url.searchParams.get("q")).toBe("LiveUpdate.exe");
    expect(url.searchParams.get("group")).toBe("1");
    expect(page.total).toBe(1);
    expect(page.meta?.root).toBe("D:\\case");
    await fetchTimelinePage("r1", 0, 250, undefined, undefined, {});
    expect(calls[1]?.url).not.toContain("q=");
    expect(calls[1]?.url).not.toContain("group=");
  });

  it("the timeline grid searches on the server, never filters loaded rows, and groups by default", async () => {
    const calls = installFetch({
      "/timeline": () =>
        jsonResponse({
          events: [eventlogEvent],
          matched: 1,
          pagination: { total: 1, matched: 1, filtered: true },
        }),
    });
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, collection: { id: "timeline" }, q: "LiveUpdate.exe" },
    }));
    renderWithClient(<DataGrid />);
    await waitFor(() => expect(calls.length).toBeGreaterThan(0));
    const url = new URL(calls[0]?.url ?? "", "http://x");
    expect(url.searchParams.get("q")).toBe("LiveUpdate.exe");
    expect(url.searchParams.get("group")).toBe("1");
    // The returned row does not contain the text in any column: it is still shown (server match).
    await waitFor(() =>
      expect(screen.queryAllByRole("row").filter((r) => r.hasAttribute("data-index")).length).toBe(1),
    );
    expect(screen.getByText(/서버 검색: 전체 이벤트/)).toBeTruthy();
    expect(screen.getByTestId("grid-group-status").textContent).toContain("한 행으로 묶어");
    screen.getByTestId("grid-group-toggle").click();
    await waitFor(() => expect(calls.some((call) => !call.url.includes("group=1"))).toBe(true));
  });
});

describe("timeline deep links while grouped", () => {
  it("asks the server where the linked event's row is and focuses it (a group member too)", async () => {
    const calls = installFetch({
      "/timeline": (url: URL) =>
        url.searchParams.has("locate")
          ? jsonResponse({ events: [], pagination: { total: 2, locate: { record_index: 9, position: 1 } } })
          : jsonResponse({
              events: [{ ...eventlogEvent, record_index: 3 }, jumplistEvent],
              matched: 2,
              pagination: { total: 2, matched: 2, filtered: true, grouped: true },
            }),
    });
    useGridLocalStore.setState((s) => ({
      route: {
        ...s.route,
        collection: { id: "timeline" },
        rowRef: { collection: "timeline", locator: "/events/9" },
      },
    }));
    renderWithClient(<DataGrid />);
    await waitFor(() => {
      const focused = screen
        .queryAllByRole("row")
        .filter((r) => r.hasAttribute("data-index") && r.tabIndex === 0)
        .map((r) => r.getAttribute("data-index"));
      expect(focused).toEqual(["1"]);
    });
    const locate = calls.find((call) => call.url.includes("locate=9"));
    expect(locate?.url).toContain("group=1");
  });
});

describe("C6 USB node and the primary-family rule", () => {
  const nodes = DOMAINS.flatMap((domain) => flattenDomainNodes(domain.nodes));

  it("the USB node lists one type and resolves to the USB family layout", () => {
    const usb = nodes.find((node) => node.id === "dev-usb-registry");
    expect(usb?.target.types).toEqual(["windows-usb-device"]);
    expect(nodes.find((node) => node.id === "dev-mounted-registry")?.target.types).toEqual([
      "windows-mounted-device",
    ]);
    expect(resolveArtifactFamily("windows-registry", usb?.target.types)?.id).toBe("usb");
    const keys = familyForType("windows-usb-device")?.core_columns.map((def) => def.key);
    expect(keys).toEqual(
      expect.arrayContaining(["first_install_at", "friendly_name", "serial_number", "vid", "pid"]),
    );
  });

  it("several types of one kind take the family holding most of their rows", () => {
    const types = ["windows-usb-device", "windows-mounted-device"];
    expect(familyForTypes(types)).toBeUndefined();
    noteKindTypeCounts("windows-registry", { "windows-usb-device": 40, "windows-mounted-device": 4 });
    expect(majorityFamilyForTypes("windows-registry", types)?.id).toBe("usb");
    expect(resolveArtifactFamily("windows-registry", types)?.id).toBe("usb");
    noteKindTypeCounts("windows-registry", { "windows-usb-device": 5, "windows-mounted-device": 5 });
    expect(majorityFamilyForTypes("windows-registry", types)).toBeUndefined(); // no majority: mixed layout
  });
});

describe("C7 / C8 / C9 family cells", () => {
  const timeDef = { key: "timestamp", label: "시각", format: "time", ts_kind: "event" } as const;

  it("time columns are 200 px wide by default", () => {
    expect(TIME_COLUMN_WIDTH).toBe(200);
    expect(catalogColumn(timeDef).width).toBe(200);
    expect(catalogColumn({ ...timeDef, width: 170 }).width).toBe(170);
  });

  it("ShimCache rows read 파일 수정(실행 아님), not 이벤트 시각", () => {
    expect(rowTimestampKind({ timestamp_label: "file_last_modified" })).toBe("file-last-modified");
    expect(tsKindLabel("file-last-modified")).toBe("파일 수정(실행 아님)");
    const shimcache = familyForType("shimcache-schema-entry") as CatalogFamily;
    expect(shimcache.id).toBe("shimcache");
    expect(shimcache.core_columns.map((def) => def.key)).toEqual([
      "timestamp",
      "executable_path",
      "cache_order",
      "evidence_strength",
    ]);
    expect(shimcache.core_columns.some((def) => def.key === "exec_flag")).toBe(false);
  });

  it("booleans read 예 / 아니오, digit-string sizes as bytes, key paths by their tail", () => {
    const flag = catalogColumn({ key: "pinned", label: "고정" });
    const row = {
      fields: { details: { pinned: false, size_bytes: "3146520", key: "HKLM\\A\\B\\C\\D" } },
    } as unknown as GridRow;
    expect(flag.format?.(row)).toBe("아니오");
    expect(catalogColumn({ key: "size_bytes", label: "크기", format: "bytes" }).format?.(row)).toBe("3.0 MB");
    const key = catalogColumn({ key: "key", label: "키 경로", format: "key_tail" });
    expect(key.format?.(row)).toBe("…\\B\\C\\D");
    expect(key.tooltip?.(row)).toContain("HKLM\\A\\B\\C\\D");
    expect(keyTail("A\\B")).toBe("A\\B");
  });

  it("an event-log ID without a sentence reads its message (요약)", () => {
    expect(
      eventSummaryKo({
        event_id: "5615",
        channel: "Application",
        event_message: "Provider=InvProv;  Namespace=ROOT",
      }),
    ).toBe("Provider=InvProv; Namespace=ROOT");
    expect(eventSummaryKo({ event_id: "5615", channel: "Application" })).toBe("요약 없음 (ID 5615)");
  });
});

describe("P1 empty columns", () => {
  it("a family's empty core columns hide like any empty column; only the leading time stays (C-D7/C-E4)", () => {
    noteKindTypeCounts("eventlog", { "eventlog-event": 10 });
    const keep = artifactsCollection.keepWhenEmpty?.({ id: "artifacts", kind: "eventlog" }) ?? [];
    expect(keep).not.toContain("d:target_user_name");
    expect(keep).not.toContain("d:computer");
    expect(keep.length).toBeLessThanOrEqual(1);
  });
});

describe("UX-round review follow-ups", () => {
  it("an empty core column hides (값이 없어 숨김) while a column with values stays", async () => {
    noteKindTypeCounts("eventlog", { "eventlog-event": 2 });
    installFetch({
      "/artifacts": () =>
        jsonResponse({
          artifacts: {
            eventlog: {
              artifacts: [0, 1].map((i) => ({
                artifact_type: "eventlog-event",
                path: "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
                record_index: i,
                details: {
                  event_id: "7036",
                  channel: "System",
                  computer: "PC-1",
                  timestamp: "2024-03-01T10:00:00Z",
                },
              })),
              total: 2,
            },
          },
        }),
    });
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, collection: { id: "artifacts", kind: "eventlog" } },
    }));
    renderWithClient(<DataGrid />);
    // 대상 계정 has no value in any loaded row: hidden (listed in 열 설정); 컴퓨터 has values: shown.
    await waitFor(() =>
      expect(document.querySelector('[role="columnheader"][data-col="d:computer"]')).not.toBeNull(),
    );
    expect(document.querySelector('[role="columnheader"][data-col="d:target_user_name"]')).toBeNull();
    expect(screen.queryByTestId("grid-novalue-d:target_user_name")).toBeNull();
    expect(KEPT_EMPTY_COLUMN_NOTE).toBe("이 페이지 값 없음");
  });

  it("a timeline written before the readability builder shows the regenerate hint", async () => {
    installFetch({
      "/timeline": () =>
        jsonResponse({
          summary: { event_count: 1 },
          events: [eventlogEvent],
          matched: 1,
          pagination: { total: 1, matched: 1, filtered: true, grouped: true },
        }),
    });
    useGridLocalStore.setState((s) => ({ route: { ...s.route, collection: { id: "timeline" } } }));
    renderWithClient(<DataGrid />);
    const hint = await screen.findByTestId("grid-timeline-legacy");
    expect(hint.textContent).toBe(TIMELINE_LEGACY_HINT);
    expect(TIMELINE_LEGACY_HINT).toBe(
      "이 런의 타임라인은 이전 형식입니다 — 다시 생성하면 요약·중복 제거가 적용됩니다",
    );
  });

  it("a current timeline (summary with jumplist_lnk_merges) shows no hint", async () => {
    const page = await (async () => {
      installFetch({
        "/timeline": () =>
          jsonResponse({ summary: { event_count: 1, jumplist_lnk_merges: 0 }, events: [eventlogEvent] }),
      });
      return fetchTimelinePage("r1", 0, 250, undefined, undefined, {});
    })();
    expect(page.meta?.timeline_legacy).toBeUndefined();
  });
});

describe("C10 timeline viewer", () => {
  const target: ViewerTarget = {
    runId: "run-1",
    ref: { collection: "timeline", locator: "/events/7" },
    sourcePath: AUTO,
  } as ViewerTarget;

  it("opens the 메타 tab first (not the hex of the source file)", () => {
    const preview = { preview_type: "binary", size: 25_000_000, extension: "", hex: { rows: [{}] } };
    const resolved = resolveModes({ target, preview, previewError: null, loading: false } as Parameters<
      typeof resolveModes
    >[0]);
    expect(resolved.best).toBe("meta");
  });

  it("shows the source family's core facts and the grouped sources at the top", () => {
    const row = mapEvent(jumplistEvent);
    const facts = familyCoreFacts("jumplist-entry", row.fields.details as Record<string, unknown>);
    render(
      <MetaView
        target={target}
        preview={null}
        metadata={null}
        metadataError={null}
        hashBusy={false}
        row={row}
        sessionMarks={[]}
        onComputeHash={() => {}}
      />,
    );
    const section = screen.getByTestId("timeline-event-section");
    expect(section.textContent).toContain("E:\\보고서\\A.docx");
    for (const fact of facts?.facts ?? []) expect(section.textContent).toContain(fact.value);
    expect(screen.getByTestId("timeline-group-sources").querySelectorAll("li")).toHaveLength(3);
    // 출처: Korean readings only (C9; R7 L3: the raw id is not shown).
    expect(screen.getAllByText("시각 종류").length).toBeGreaterThan(0);
    // R-10: the record 핵심 "출처" reads it in Korean too (was the raw "artifacts").
    expect(screen.getAllByText("아티팩트 출력").length).toBe(2);
    expect(screen.queryByText("artifacts")).toBeNull();
    expect(screen.queryByText(/\(artifacts\)/)).toBeNull();
  });
});
