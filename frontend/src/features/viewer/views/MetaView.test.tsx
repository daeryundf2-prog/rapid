import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../../contracts/collection";
import { EMPTY_CATALOG_FOR_TESTS, setCatalog } from "../../flags/catalog";
import { useGridLocalStore } from "../../grid/adapter";
import { evidenceInfo, timelineWindowHash } from "../evidenceInfo";
import { MetaView } from "./MetaView";

afterEach(cleanup);

const row = (fields: Record<string, unknown>): GridRow => ({
  rowKey: "artifacts:artifacts_browser:row:1",
  ref: { collection: "artifacts", kind: "browser", locator: "artifacts_browser:row:1" },
  title: "history",
  sourcePath: "C:/e/History",
  timestamp: null,
  artifactType: "browser_history",
  provider: null,
  sha256: null,
  reviewStatus: null,
  tags: [],
  fields,
});

function show(fields: Record<string, unknown>) {
  return render(
    <MetaView
      target={{ ref: row(fields).ref, runId: "r1", sourcePath: "C:/e/History" }}
      preview={null}
      metadata={null}
      metadataError={null}
      hashBusy={false}
      row={row(fields)}
      sessionMarks={[]}
      onComputeHash={() => {}}
    />,
  );
}

describe("MetaView record values", () => {
  it("renders hash bundles as rows with copy, nested objects as key/value rows, scalar arrays as lists", () => {
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    show({
      source_hashes: { md5: "m".repeat(32), sha1: "s".repeat(40), sha256: "a".repeat(64) },
      browser_validation_checks: { history_rows_present: true, schema: "v3" },
      event_tags: ["a", "b"],
    });
    const text = document.body.textContent ?? "";
    expect(text).not.toContain('{"md5"');
    expect(text).not.toContain('{"history_rows_present"');
    // Unknown nested keys read humanised, the raw key on the term (data-key / tooltip).
    expect(document.querySelector('dt[data-key="history_rows_present"]')).toBeTruthy();
    expect(text).toContain("a, b");
    fireEvent.click(screen.getByRole("button", { name: "source_hashes.sha256 복사" }));
    expect(writeText).toHaveBeenCalledWith("a".repeat(64));
  });

  it("collapses nested objects with many keys", () => {
    const big = Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`k${i}`, i]));
    show({ profile: big });
    expect(screen.getByText("12개 항목")).toBeTruthy();
  });
});

describe("MetaView nested labels and value readings (visual-polish B2 #5)", () => {
  it("labels keys inside expanded groups and reads booleans / enums in Korean, recursively", () => {
    show({
      cloud_validation_matrix: {
        status: "validation-required",
        cloud_family: "microsoft-365",
        service: "exchange",
        blockers: [{ blocker_id: "b-1", severity: "high", passed: false }],
        nested: { inner: { report_grade_ready: true } },
      },
      commercial_grade_ready: false,
    });
    const dts = Array.from(document.querySelectorAll("dt")).map((dt) => dt.textContent);
    expect(dts).toContain("상태");
    expect(dts).toContain("클라우드 계열");
    expect(dts).toContain("서비스");
    expect(dts).toContain("차단 요인");
    expect(dts).toContain("심각도");
    // Recursion: a group inside a group, and items inside a folded list, keep labels.
    expect(dts).toContain("보고서 등급 준비됨");
    expect(dts).toContain("차단 요인 ID");
    const status = document.querySelector('[data-raw="validation-required"]');
    expect(status?.textContent).toBe("검증 필요");
    expect(status?.getAttribute("title")).toBe("validation-required");
    expect(document.querySelector('[data-raw="false"]')?.textContent).toBe("아니요");
    expect(document.querySelector('[data-raw="true"]')?.textContent).toBe("예");
    expect(document.querySelector('[data-raw="high"]')?.textContent).toBe("높음");
    // Unknown token: raw, in mono. Unknown key: raw, in mono.
    const raw = screen.getByText("exchange");
    expect(raw.className).toContain("mono");
    expect(screen.getByText("inner").className).toContain("mono");
  });
});

describe("MetaView label collisions (review B2-8)", () => {
  it("shows the raw key next to labels two fields share, as visible text", () => {
    show({ details: { application_name: "a.exe", app_name: "b.exe" } });
    const dts = Array.from(document.querySelectorAll("dt")).map((dt) => dt.textContent);
    expect(dts).toContain("앱 이름 (application_name)");
    expect(dts).toContain("앱 이름 (app_name)");
  });
});

describe("MetaView output rows (review nit)", () => {
  it("labels an output file's kind 종류, not 아티팩트 유형", () => {
    const out: GridRow = {
      ...row({}),
      rowKey: "outputs:output:report.md",
      ref: { collection: "outputs", locator: "output:report.md" },
      artifactType: "보고서",
    };
    render(
      <MetaView
        target={{ ref: out.ref, runId: "r1", sourcePath: "C:/o/report.md" }}
        preview={null}
        metadata={null}
        metadataError={null}
        hashBusy={false}
        row={out}
        sessionMarks={[]}
        onComputeHash={() => {}}
      />,
    );
    const text = document.body.textContent ?? "";
    expect(text).toContain("종류");
    expect(text).not.toContain("아티팩트 유형");
  });
});

describe("MetaView 증거 정보", () => {
  it("maps recovery source, deletion state, offset and evidence number", () => {
    show({
      recovery: { source_id: "icat-long-path-fallback", deletion_state: "deleted", source_offset: 4096 },
    });
    const block = screen.getByTestId("evidence-info");
    const text = block.textContent ?? "";
    expect(text).toContain("복구(icat)");
    expect(text).toContain("삭제됨");
    expect(text).toContain("0x1000");
    expect(text).toContain("r1");
  });

  it("maps each recovery source id", () => {
    expect(evidenceInfo(row({ recovery: { source_id: "carving" } })).recovery).toBe("카빙");
    expect(evidenceInfo(row({ recovery: { source_id: "filesystem-scan" } })).recovery).toBe("파싱됨");
    expect(evidenceInfo(row({ recovery: { source_id: "fls-listing-zero-byte" } })).recovery).toBe("목록");
    expect(evidenceInfo(row({ recovery: "carved" })).recovery).toBe("카빙");
  });

  it("shows the yellow notice when the source is missing", () => {
    render(
      <MetaView
        target={{ ref: row({}).ref, runId: "r1", sourcePath: "C:/e/History" }}
        preview={null}
        metadata={null}
        metadataError="404 not found"
        hashBusy={false}
        row={row({})}
        sessionMarks={[]}
        onComputeHash={() => {}}
      />,
    );
    expect(screen.getByTestId("source-missing").textContent).toContain("소스를 찾을 수 없습니다");
    expect(screen.getByTestId("source-missing").textContent).toContain("C:/e/History");
  });

  it("builds the ±1h timeline window", () => {
    const hash = timelineWindowHash("r1", "2026-03-01T12:00:00Z") ?? "";
    expect(hash).toContain("#/case/r1/explore/timeline?");
    expect(decodeURIComponent(hash)).toContain("from=2026-03-01T11:00:00.000Z");
    expect(decodeURIComponent(hash)).toContain("to=2026-03-01T13:00:00.000Z");
  });
});

describe("MetaView long values and 열로 표시 (artifact-columns U-C1/U-C3)", () => {
  // KIND_COLUMNS layouts: a catalogue that does not claim these kinds (the fallback path);
  // catalogue family layouts are covered by families.test.ts.
  beforeEach(() => setCatalog(EMPTY_CATALOG_FOR_TESTS, "server"));
  const artifactRow = (details: Record<string, unknown>): GridRow => ({
    rowKey: "artifacts:eventlog:/artifacts/3",
    ref: { collection: "artifacts", kind: "eventlog", locator: "/artifacts/3" },
    title: "4624",
    sourcePath: "C:/e/Security.evtx",
    timestamp: null,
    artifactType: "eventlog-event",
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: { detail: "summary", details },
  });
  const showArtifact = (details: Record<string, unknown>) => {
    const r = artifactRow(details);
    return render(
      <MetaView
        target={{ ref: r.ref, runId: "r1", sourcePath: r.sourcePath }}
        preview={null}
        metadata={null}
        metadataError={null}
        hashBusy={false}
        row={r}
        sessionMarks={[]}
        onComputeHash={() => {}}
      />,
    );
  };

  afterEach(() => {
    setCatalog(null);
    window.localStorage.clear();
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, collection: { id: "files" }, cols: undefined },
      visibleColumnIds: null,
    }));
  });

  it("folds a 5,000-char value: 전체 보기 (5,000자) ↔ 접기, copy takes the full value", async () => {
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const long = `${"a".repeat(4990)}TAILMARKER`;
    showArtifact({ event_message: long });
    expect(document.body.textContent).not.toContain("TAILMARKER");
    const expand = screen.getByRole("button", { name: "event_message 전체 보기 (5,000자)" });
    expect(expand.textContent).toBe("전체 보기 (5,000자)");
    expect(expand.getAttribute("aria-expanded")).toBe("false");
    expand.focus();
    fireEvent.click(expand);
    expect(document.querySelector("pre.viewer-break")?.textContent).toBe(long);
    const collapse = screen.getByRole("button", { name: "event_message 접기" });
    expect(collapse.getAttribute("aria-expanded")).toBe("true");
    await waitFor(() => expect(document.activeElement).toBe(collapse));
    fireEvent.click(screen.getByRole("button", { name: "event_message 복사" }));
    expect(writeText).toHaveBeenCalledWith(long);
    fireEvent.click(collapse);
    expect(document.body.textContent).not.toContain("TAILMARKER");
  });

  it("열로 표시 toggles the field as a grid column (aria-pressed, route cols, kind storage)", () => {
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, collection: { id: "artifacts", kind: "eventlog" } },
    }));
    showArtifact({ volume_label: "SYS", nested: { a: 1 } });
    const button = screen.getByRole("button", { name: "volume_label 열로 표시" });
    expect(button.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(button);
    expect(useGridLocalStore.getState().route.cols).toEqual(["details.volume_label"]);
    expect(window.localStorage.getItem("rapidtriage.grid.fieldColumns.artifacts.eventlog")).toBe(
      JSON.stringify(["details.volume_label"]),
    );
    const pressed = screen.getByRole("button", { name: "volume_label 열에서 제거" });
    expect(document.activeElement).toBe(pressed); // focus stays on the toggle
    expect(pressed.getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(pressed);
    expect(useGridLocalStore.getState().route.cols).toBeUndefined();
    // Objects and non-details fields (grid summary `detail`) are never promotable.
    expect(screen.queryByRole("button", { name: /^nested.*열로 표시/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^detail.*열로 표시/ })).toBeNull();
  });

  it("…but only while that default column is visible; hidden, the key promotes normally", () => {
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, collection: { id: "artifacts", kind: "eventlog" } },
      visibleColumnIds: ["title", "review", "timestamp"],
    }));
    showArtifact({ level: 4 });
    const button = screen.getByRole("button", { name: "level(레벨) 열로 표시" });
    expect(button.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(button);
    expect(useGridLocalStore.getState().route.cols).toEqual(["details.level"]);
  });

  it("long strings inside nested objects and object lists fold with 전체 보기 / 복사 too", () => {
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    const long = `${"n".repeat(990)}NESTEDTAIL`;
    showArtifact({ profile: { note: long }, items: [{ a: 1 }, long] });
    expect(document.body.textContent).not.toContain("NESTEDTAIL");
    fireEvent.click(screen.getByRole("button", { name: "profile.note 전체 보기 (1,000자)" }));
    expect(document.body.textContent).toContain("NESTEDTAIL");
    fireEvent.click(screen.getByRole("button", { name: "profile.note 복사" }));
    expect(writeText).toHaveBeenCalledWith(long);
    expect(screen.getByRole("button", { name: "items[1] 전체 보기 (1,000자)" })).toBeTruthy();
  });

  it("a key a DEFAULT column already shows is pressed and disabled with the column name", () => {
    useGridLocalStore.setState((s) => ({
      route: { ...s.route, collection: { id: "artifacts", kind: "eventlog" } },
    }));
    showArtifact({ level: 4 });
    const button = screen.getByRole("button", { name: "레벨 열로 표시 중" });
    expect(button.getAttribute("aria-pressed")).toBe("true");
    expect(button.getAttribute("aria-disabled")).toBe("true");
    expect(button.getAttribute("data-disabled-reason")).toBe("기본 열 '레벨'에 이미 표시됩니다");
    fireEvent.click(button);
    expect(useGridLocalStore.getState().route.cols).toBeUndefined();
  });

  it("is absent for fields that are not record (details) keys", () => {
    show({ level: 4 });
    expect(screen.queryByRole("button", { name: /열로 표시/ })).toBeNull();
  });
});

describe("MetaView NTFS provenance (plan analysis-workbench-p1 U-P1-3)", () => {
  const fileRow = (fields: Record<string, unknown>): GridRow => ({
    ...row(fields),
    rowKey: "files:/candidates/0",
    ref: { collection: "files", locator: "/candidates/0" },
  });
  const showFile = (fields: Record<string, unknown>) =>
    render(
      <MetaView
        target={{ ref: fileRow(fields).ref, runId: "r1", sourcePath: "C:/e/a.txt" }}
        preview={null}
        metadata={null}
        metadataError={null}
        hashBusy={false}
        row={fileRow(fields)}
        sessionMarks={[]}
        onComputeHash={() => {}}
      />,
    );

  it("before an NTFS-meta analysis: 출처 says how to fill it and links to the run command", () => {
    showFile({ ntfs: null, filesystem: null, sourceImage: null, ntfsJoinId: null });
    const hint = screen.getByTestId("ntfs-hint");
    expect(hint.textContent).toContain("NTFS 메타 분석을 실행하면 채워집니다");
    const link = screen.getByRole("button", { name: /NTFS 메타 분석 실행|실행/ });
    expect(link.getAttribute("data-command")).toBe("analysis.run.ntfs-meta");
    expect(screen.getByText("파일 시스템")).toBeTruthy();
  });

  it("after the join: file system, source image, MFT entry and NTFS times are listed", () => {
    showFile({
      ntfs: {
        entry_number: 77,
        created_at: "2025-01-02T03:04:05Z",
        accessed_at: null,
        mft_modified_at: null,
        in_use: true,
      },
      filesystem: "NTFS",
      sourceImage: "C:/rapid-qa/BSH.E01",
      ntfsJoinId: "a1",
    });
    expect(screen.queryByTestId("ntfs-hint")).toBeNull();
    const text = document.body.textContent ?? "";
    expect(text).toContain("MFT 엔트리77");
    expect(text).toContain("소스 이미지 경로C:/rapid-qa/BSH.E01");
    expect(text).toContain("MFT 사용 중예");
  });
});

describe("MetaView evidence-first record (viewer redesign)", () => {
  const evtx = (details: Record<string, unknown>, type = "eventlog-event"): GridRow => ({
    rowKey: "artifacts:eventlog:/artifacts/0",
    ref: { collection: "artifacts", kind: "eventlog", locator: "/artifacts/0" },
    title: "4624",
    sourcePath: "C:/e/Security.evtx",
    timestamp: "2024-04-01T12:34:56.000000+00:00",
    artifactType: type,
    provider: "windows-eventlog",
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: { details, artifact_record: { confidence: 0.9 } },
  });
  const render4624 = (details: Record<string, unknown>, type?: string) => {
    const row = evtx(details, type);
    return render(
      <MetaView
        target={{ ref: row.ref, runId: "r1", sourcePath: row.sourcePath }}
        preview={null}
        metadata={null}
        metadataError={null}
        hashBusy={false}
        row={row}
        sessionMarks={[]}
        onComputeHash={() => {}}
      />,
    );
  };
  const LOGON = {
    timestamp: "2024-04-01T12:34:56.000000+00:00",
    event_id: "4624",
    record_id: "1001",
    provider_name: "Microsoft-Windows-Security-Auditing",
    channel: "Security",
    level: "0",
    computer: "WIN-CASE01",
    user_name: "alice",
    logon_type: "10",
    source_ip: "10.0.0.5",
    event_data: { TargetUserName: "alice", IpAddress: "10.0.0.5", LogonType: "10", TargetLogonId: "0x3e7" },
    coverage_status: "mapped",
    reportability: "reportable",
    commercial_grade_ready: false,
    commercial_grade_blockers: ["needs trusted diff"],
    validation_required: true,
    unknown_new_field: "kept",
  };

  it("4624: 핵심 holds 로그온 유형 · 출발지 IP · 로그온 ID and the EventData table; no 상용 above evidence", () => {
    render4624(LOGON);
    const core = screen.getByRole("region", { name: "레코드 핵심" });
    const text = core.textContent ?? "";
    expect(text).toContain("로그온 유형10 — 원격 대화형(RDP)");
    expect(text).toContain("출발지 IP10.0.0.5");
    expect(text).toContain("로그온 ID0x3e7");
    expect(text).toContain("레벨로그 항상(0)");
    // Evidence time: local (zone) · UTC — whatever the test machine's zone is.
    expect(text).toMatch(/생성 시각2024-04-01 \d{2}:34:56 \((UTC|[A-Z]{2,5}[+-]\d{2}:\d{2})\)/);
    const table = screen.getByRole("table", { name: "EventData" });
    expect(table.textContent).toContain("TargetLogonId");
    // ±5분 next to the record time.
    expect(screen.getByRole("button", { name: "생성 시각 타임라인 ±5분" })).toBeTruthy();
    // Unknown keys are visible (기타 필드), governance is folded at the very bottom.
    expect(screen.getByRole("region", { name: "레코드 기타 필드" }).textContent).toContain("kept");
    const governance = screen.getByTestId("record-governance") as HTMLDetailsElement;
    expect(governance.open).toBe(false);
    expect(governance.textContent).toContain("내부 검증 정보(증거 아님)");
    const view = document.querySelector(".meta-view") as HTMLElement;
    expect(view.lastElementChild).toBe(governance);
    const before = (view.textContent ?? "").split("내부 검증 정보(증거 아님)")[0] ?? "";
    expect(before).not.toContain("상용");
    // Record XML (reconstruction) and the 컨테이너 파일 해시 heading.
    expect(screen.getByTestId("record-xml").textContent).toContain("디코딩된 레코드(재구성)");
    expect(screen.getByRole("region", { name: "컨테이너 파일 해시" })).toBeTruthy();
    // Per-field copy and the record JSON copy.
    expect(screen.getByRole("button", { name: "출발지 IP 복사" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "레코드 JSON 복사" })).toBeTruthy();
  });

  it("detection: banners for record state, 탐지 심각도 apart from the event level", () => {
    render4624(
      {
        ...LOGON,
        evtx_record_state: "slack-recovered",
        rule: { title: "Remote interactive logon", level: "medium", mitre_tags: ["attack.t1021.001"] },
      },
      "eventlog-detection",
    );
    const banners = screen.getByTestId("record-banners");
    expect(banners.textContent).toContain("슬랙 영역에서 복구한 레코드");
    const core = screen.getByRole("region", { name: "레코드 핵심" }).textContent ?? "";
    expect(core).toContain("탐지 심각도중간(medium)");
    expect(core).toContain("레벨로그 항상(0)");
  });

  it("registry .reg binary values open as a hex dump with UTF-16 strings; garbage strings are hidden", () => {
    const row: GridRow = {
      ...evtx({}),
      ref: { collection: "artifacts", kind: "windows-registry", locator: "/artifacts/2" },
      artifactType: "registry-user-activity",
      fields: {
        details: {
          key: String.raw`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`,
          values: { MRUListEx: "hex:43,00,3a,00,5c,00,57,00,69,00,6e,00,00,00" },
          decoded_values: {
            a: { binary_payload: { utf16le_strings: ["report.pdf", "\u4e00\u9fa5\ua000\u4e8c\u4e09"] } },
          },
        },
      },
    };
    render(
      <MetaView
        target={{ ref: row.ref, runId: "r1", sourcePath: row.sourcePath }}
        preview={null}
        metadata={null}
        metadataError={null}
        hashBusy={false}
        row={row}
        sessionMarks={[]}
        onComputeHash={() => {}}
      />,
    );
    const panel = screen.getByTestId("binary-panel");
    expect(panel.textContent).toContain("이진 값 14바이트");
    expect(panel.textContent).toContain(String.raw`C:\Win`);
    expect(screen.getByTestId("utf16-hidden").textContent).toContain("1개는 숨겼습니다");
    expect(document.body.textContent).not.toContain("\u4e00\u9fa5\ua000");
  });
});
