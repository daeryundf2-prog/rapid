import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../../contracts/collection";
import { EMPTY_CATALOG_FOR_TESTS, setCatalog } from "../../flags/catalog";
import { matchesFilter } from "../gridUtils";
import { summarizeArtifact } from "./artifactSummary";
import { artifactColumnsForKind, KIND_COLUMNS, SORT_LIST_REASON, TIME_KEYS } from "./artifacts";
import {
  colsToKeys,
  discoverFields,
  effectiveFieldCols,
  fieldColumnsStorageKey,
  fieldMenuEntries,
  isShareableFieldKey,
  keysToCols,
  LIST_FIELD_SORT_REASON,
  promotedColumn,
  readStoredFieldColumns,
  toggleFieldCol,
  writeStoredFieldColumns,
} from "./fieldColumns";
import { COLLECTIONS } from "./index";

function artifactRow(details: Record<string, unknown>, kind = "windows-prefetch"): GridRow {
  return COLLECTIONS.artifacts.mapRow(
    { artifact_type: "prefetch-file", path: "C:/Windows/Prefetch/A.pf", details, _kind: kind, _index: 7 },
    0,
    { ref: { id: "artifacts", kind } },
  );
}

afterEach(() => {
  window.localStorage.clear();
  vi.restoreAllMocks();
});

describe("record-field columns: discovery and promotion", () => {
  it("discovers scalar / scalar-array details keys by frequency, skipping keys the kind columns show", () => {
    const rows = [
      artifactRow({ run_count: 3, volume_serial: "AB", hashes: { md5: "x" }, tags: ["a", "b"], empty: "" }),
      artifactRow({ run_count: 1, volume_serial: "CD", tags: ["c"] }),
      artifactRow({ volume_serial: "EF", nested_list: [{ a: 1 }] }),
    ];
    const fields = discoverFields(rows, artifactColumnsForKind("windows-prefetch"));
    // run_count is a prefetch kind column: not offered again. Objects / object lists are skipped;
    // a key present only with empty values is still listed (count 0).
    expect(fields).toEqual([
      { key: "volume_serial", count: 3, present: 3 },
      { key: "tags", count: 2, present: 2, list: true },
      { key: "empty", count: 0, present: 1 },
    ]);
    // Generic kinds have no kind columns: run_count is offered there.
    expect(discoverFields(rows, artifactColumnsForKind("other-kind")).map((f) => f.key)).toContain(
      "run_count",
    );
  });

  it("unions the keys of every loaded row across artifact types (not the first row / a template)", () => {
    const file = artifactRow({ executable_hint: "A.EXE", prefetch_version: 30 });
    const ref = (i: number) =>
      COLLECTIONS.artifacts.mapRow(
        {
          artifact_type: "prefetch-reference",
          details: {
            referenced_path: `C:/x${i}`,
            referenced_extension: i === 0 ? ".DLL" : "",
          },
          _kind: "windows-prefetch",
          _index: i + 1,
        },
        i + 1,
        { ref: { id: "artifacts", kind: "windows-prefetch" } },
      );
    const fields = discoverFields([file, ref(0), ref(1), ref(2)], artifactColumnsForKind("windows-prefetch"));
    expect(fields.find((f) => f.key === "referenced_extension")).toEqual({
      key: "referenced_extension",
      count: 1,
      present: 3,
    });
    expect(fields.find((f) => f.key === "prefetch_version")).toEqual({
      key: "prefetch_version",
      count: 1,
      present: 1,
    });
    expect(fieldMenuEntries(fields, [], "extension").map((f) => f.key)).toEqual(["referenced_extension"]);
  });

  it("menu entries add promoted keys absent from the loaded rows and filter by key or Korean label", () => {
    const entries = fieldMenuEntries([{ key: "volume_serial", count: 2 }], ["run_count"], "");
    expect(entries.map((e) => e.key)).toEqual(["volume_serial", "run_count"]);
    expect(fieldMenuEntries(entries, [], "SERIAL").map((e) => e.key)).toEqual(["volume_serial"]);
    expect(fieldMenuEntries(entries, [], "실행 횟수").map((e) => e.key)).toEqual(["run_count"]);
  });

  it("toggles keys in URL form and converts between cols and keys", () => {
    expect(toggleFieldCol([], "run_count")).toEqual(["details.run_count"]);
    expect(toggleFieldCol(["details.run_count"], "run_count")).toEqual([]);
    expect(toggleFieldCol(["details.a"], "a", true)).toEqual(["details.a"]);
    expect(colsToKeys(["details.a", "timestamp", "details.b"])).toEqual(["a", "b"]);
    expect(keysToCols(["a"])).toEqual(["details.a"]);
  });

  it("round-trips the per-kind localStorage set; the URL wins when it has columns", () => {
    expect(fieldColumnsStorageKey("windows-prefetch")).toBe(
      "rapidtriage.grid.fieldColumns.artifacts.windows-prefetch",
    );
    expect(readStoredFieldColumns("windows-prefetch")).toBeNull();
    writeStoredFieldColumns("windows-prefetch", ["details.run_count", "details.x"]);
    expect(readStoredFieldColumns("windows-prefetch")).toEqual(["details.run_count", "details.x"]);
    expect(effectiveFieldCols(undefined, "windows-prefetch")).toEqual(["details.run_count", "details.x"]);
    expect(effectiveFieldCols(["details.y"], "windows-prefetch")).toEqual(["details.y"]);
    expect(effectiveFieldCols(undefined, "eventlog")).toEqual([]);
    expect(effectiveFieldCols(["details.y"], undefined)).toEqual([]);
    window.localStorage.setItem(fieldColumnsStorageKey("bad"), "{not json");
    expect(readStoredFieldColumns("bad")).toBeNull();
  });

  it("storage failures never throw", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("denied");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("denied");
    });
    expect(() => writeStoredFieldColumns("k", ["details.a"])).not.toThrow();
    expect(readStoredFieldColumns("k")).toBeNull();
    expect(effectiveFieldCols(undefined, "k")).toEqual([]);
  });

  it("a promoted column is f:<key>, sorts on details.<key>, shows in every preset, mono for hashes", () => {
    const col = promotedColumn("run_count");
    expect(col.id).toBe("f:run_count");
    expect(col.sortKey).toBe("details.run_count");
    expect(col.header).toBe("실행 횟수");
    expect(col.presets).toEqual(["analysis", "compact", "source", "axiom"]);
    const row = artifactRow({ run_count: 12, long_text: "x".repeat(700), list: ["a", "b"] });
    expect(col.value(row)).toBe(12);
    expect(promotedColumn("list").format?.(row)).toBe("a, b");
    expect(promotedColumn("long_text").format?.(row)).toHaveLength(601);
    expect(promotedColumn("volume_serial").header).toBe("volume_serial");
    expect(promotedColumn("file_sha256").mono).toBe(true);
    expect(promotedColumn("run_count").mono).toBe(false);
  });
});

describe("kind default columns (§4.3) and sort keys", () => {
  // KIND_COLUMNS layouts: a catalogue that does not claim these kinds (the fallback path);
  // catalogue family layouts are covered by families.test.ts.
  beforeEach(() => setCatalog(EMPTY_CATALOG_FOR_TESTS, "server"));
  afterEach(() => setCatalog(null));
  const headers = (kind: string) => artifactColumnsForKind(kind).map((c) => c.header);

  it("each listed kind shows its own columns", () => {
    expect(headers("eventlog")).toEqual(
      expect.arrayContaining(["이벤트ID", "채널", "메시지", "레벨", "컴퓨터", "사용자", "시각", "유형"]),
    );
    expect(headers("windows-prefetch")).toEqual(
      expect.arrayContaining(["실행 파일", "실행 횟수", "최근 실행", "볼륨", "참조 경로", "파싱 상태"]),
    );
    expect(headers("windows-registry")).toEqual(
      expect.arrayContaining(["키 경로", "값 이름", "값 종류", "마지막 기록", "하이브", "셀 오프셋"]),
    );
    expect(headers("windows-shellbags")).toEqual(
      expect.arrayContaining(["경로", "MRU", "키 기록 시각", "키 경로", "신뢰도"]),
    );
    expect(headers("recent-files")).toEqual(
      expect.arrayContaining([
        "대상",
        "대상 수정",
        "볼륨 시리얼",
        "머신 ID",
        "대상 크기",
        "파싱 상태",
        "작업 폴더",
      ]),
    );
    expect(headers("windows-execution")).toEqual(
      expect.arrayContaining(["실행 경로", "프로그램", "게시자", "버전", "SHA-1", "키 기록"]),
    );
    // WER Report.wer is decoded as UTF-16 since 2026-10-12, so the app fields are defaults again.
    expect(headers("windows-system")).toEqual(
      expect.arrayContaining([
        "앱",
        "앱 경로",
        "오류 모듈",
        "이벤트 시각",
        "보고서 ID",
        "크기",
        "수정",
        "시각",
      ]),
    );
    expect(headers("recent-files")).not.toEqual(expect.arrayContaining(["인수"]));
    expect(headers("windows-os-account")).toEqual(
      expect.arrayContaining(["계정", "RID", "마지막 로그온", "로그온 수", "역할", "마지막 기록"]),
    );
    expect(headers("windows-filesystem")).toEqual(
      expect.arrayContaining(["감지 서명", "기대 확장자", "크기", "수정", "위험"]),
    );
    expect(headers("media-image")).toEqual(
      expect.arrayContaining(["이름", "크기", "형식", "용량", "유사 묶음"]),
    );
    expect(headers("media-image")).not.toEqual(expect.arrayContaining(["수정"]));
    expect(headers("mobile-export")).toEqual(
      expect.arrayContaining(["메시지·앱", "앱", "이벤트 유형", "출처 도구", "시각"]),
    );
    expect(headers("cloud-export")).toEqual(
      expect.arrayContaining(["서비스", "이벤트 유형", "클라우드", "시각"]),
    );
    expect(headers("kakaotalk-windows")).toEqual(
      expect.arrayContaining(["후보 종류", "후보 값", "위험 점수", "원본 오프셋"]),
    );
    expect(headers("generic-documents")).toEqual(
      expect.arrayContaining(["항목 수", "암호화 항목", "크기", "수정", "위험"]),
    );
    // Browser: the visit columns (viewer redesign §7) — URL · 제목 · 방문 수 · 전환.
    expect(headers("browser")).toEqual(expect.arrayContaining(["URL", "제목", "방문 수", "전환", "시각"]));
    // Kinds without a layout use the generic one (visual-polish S4): 시각 · 유형 · 항목 · 경로 · 선별 first.
    const generic = artifactColumnsForKind("android-apk");
    expect(generic.map((c) => c.header)).toEqual([
      "시각",
      "유형",
      "항목",
      "특이사항",
      "경로",
      "검토",
      "내용",
      "파서",
      "탐지 규칙",
      "지원",
      "SHA-256",
      // R7 갈래 A: 중복 · 계열, default but hidden while no loaded row has a value.
      "중복",
      "계열",
    ]);
    // 특이사항 is a default column, hidden while no loaded row is flagged (ARTIFACT_PRIORITY).
    expect(generic.filter((c) => c.presets.includes("analysis")).map((c) => c.header)).toEqual([
      "시각",
      "유형",
      "항목",
      "특이사항",
      "경로",
      "검토",
      "중복",
      "계열",
    ]);
  });

  it("kind columns sort on their first details key (multi-key ones say which); computed ones do not", () => {
    // List-valued columns (live data) and computed ones carry no sortKey.
    const unsortable = new Set([
      "d:shell_path",
      "d:volume_device_path",
      "d:trigger_types",
      "d:value_type",
      "d:expected_extensions",
      "d:risk_flags",
    ]);
    for (const kind of Object.keys(KIND_COLUMNS)) {
      for (const column of artifactColumnsForKind(kind)) {
        if (!column.id.startsWith("d:")) continue;
        const first = column.fieldKeys?.[0];
        if (kind === "windows-registry" && column.header === "값 종류") {
          expect(column.sortKey).toBeUndefined();
          continue;
        }
        if (unsortable.has(column.id)) {
          expect(column.sortKey, `${kind}/${column.id}`).toBeUndefined();
          if (column.id === "d:expected_extensions" || column.id === "d:risk_flags") {
            expect(column.unsortableReason, `${kind}/${column.id}`).toBe(SORT_LIST_REASON);
          }
          continue;
        }
        expect(column.sortKey, `${kind}/${column.id}`).toBe(`details.${first}`);
        const multi = (column.fieldKeys?.length ?? 0) > 1;
        expect(column.sortHint, `${kind}/${column.id}`).toBe(
          multi ? `${column.header} 정렬 (${first} 기준)` : undefined,
        );
      }
      const byId = new Map(artifactColumnsForKind(kind).map((c) => [c.id, c]));
      for (const id of ["title", "review", "type", "provider", "path", "sha256"]) {
        expect(byId.get(id)?.sortKey, `${kind}/${id}`).toBeUndefined();
      }
      expect(byId.get("timestamp")?.sortKey).toBe("timestamp");
    }
    const prefetch = new Map(artifactColumnsForKind("windows-prefetch").map((c) => [c.header, c]));
    expect(prefetch.get("실행 횟수")?.sortKey).toBe("details.run_count");
    expect(prefetch.get("실행 파일")?.sortKey).toBe("details.executable_hint");
    expect(prefetch.get("실행 파일")?.sortHint).toBe("실행 파일 정렬 (executable_hint 기준)");
    const eventlog = artifactColumnsForKind("eventlog");
    expect(eventlog.find((c) => c.id === "eventId")?.sortKey).toBe("details.event_id");
    const message = eventlog.find((c) => c.id === "detail");
    expect(message?.sortCandidates).toEqual(["message", "rendered_message", "event_message"]);
    expect(message?.sortHintFor?.("event_message")).toBe("메시지 정렬 (원문 event_message 기준)");
    expect(message?.sortHintFor?.("message")).toBe("메시지 정렬 (message 기준)");
    expect(eventlog.find((c) => c.id === "channel")?.sortKey).toBeUndefined();
  });

  it("registry: 키 경로 · 값 이름 · 값 종류 · 마지막 기록; 값 종류 fits key and value cells", () => {
    const cols = new Map(artifactColumnsForKind("windows-registry").map((c) => [c.header, c]));
    const visible = artifactColumnsForKind("windows-registry")
      .filter((c) => c.id.startsWith("d:") && c.presets.includes("analysis"))
      .map((c) => c.header);
    expect(visible).toEqual(["키 경로", "값 이름", "값 종류", "마지막 기록"]);
    const kind = cols.get("값 종류");
    const value = artifactRow({ cell_kind: 1, value_type: 1, value_data_size: 24 }, "windows-registry");
    const key = artifactRow({ cell_kind: 0, subkey_count: 2, value_count: 5 }, "windows-registry");
    expect(kind?.format?.(value)).toBe("REG_SZ · 24 B");
    expect(kind?.format?.(key)).toBe("하위키 2 · 값 5");
    expect(kind?.sortKey).toBeUndefined();
    const reg = artifactRow(
      { key: "HKLM\\SOFTWARE\\Run", last_written_at: "2025-01-02T03:04:05Z" },
      "windows-registry",
    );
    expect(cols.get("키 경로")?.format?.(reg)).toBe("HKLM\\SOFTWARE\\Run");
    expect(cols.get("마지막 기록")?.filterKind).toBe("time");
  });

  it("os-account (SAM): 계정 · RID · 마지막 로그온 · 로그온 수; RID tooltip carries rid_hex", () => {
    const cols = artifactColumnsForKind("windows-os-account").filter(
      (c) => c.id.startsWith("d:") && c.presets.includes("analysis"),
    );
    expect(cols.map((c) => c.header)).toEqual(["계정", "RID", "마지막 로그온", "로그온 수"]);
    const row = artifactRow({ rid_decimal: 500, rid_hex: "0x1f4" }, "windows-os-account");
    expect(cols[1]?.tooltip?.(row)).toBe("500 (0x1f4)");
  });

  it("kind columns read details (first non-empty key, list element, width×height, bytes)", () => {
    const pf = artifactRow({ header_executable_name: "CMD.EXE", run_count: 4 });
    const pfCols = new Map(artifactColumnsForKind("windows-prefetch").map((c) => [c.header, c]));
    expect(pfCols.get("실행 파일")?.format?.(pf)).toBe("CMD.EXE");
    expect(pfCols.get("실행 횟수")?.value(pf)).toBe(4);
    const sb = artifactRow({ shellbag_path_candidates: ["C:/a", "C:/b"] }, "windows-shellbags");
    expect(artifactColumnsForKind("windows-shellbags")[2]?.format?.(sb)).toBe("C:/a");
    const media = artifactRow({ width: 640, height: 480, source_size: 2048 }, "media-image");
    const mediaCols = new Map(artifactColumnsForKind("media-image").map((c) => [c.header, c]));
    expect(mediaCols.get("크기")?.format?.(media)).toBe("640×480");
    expect(mediaCols.get("용량")?.format?.(media)).toBe("2.0 KB");
  });

  it("TIME_KEYS include last_written_at and target_modified_at (same list as the server)", () => {
    expect(TIME_KEYS).toContain("last_written_at");
    expect(TIME_KEYS).toContain("target_modified_at");
    expect(artifactRow({ last_written_at: "2026-01-02T00:00:00Z" }).timestamp).toBe("2026-01-02T00:00:00Z");
    expect(artifactRow({ target_modified_at: "2026-01-03T00:00:00Z" }).timestamp).toBe(
      "2026-01-03T00:00:00Z",
    );
  });
});

describe("summary rules (§4.3)", () => {
  it("registry-hive-cell: name · cell kind, hive", () => {
    expect(
      summarizeArtifact("registry-hive-cell", { name: "Run", cell_kind: 0, hive_name: "NTUSER" }, null),
    ).toEqual({ title: "Run · 키", detail: "NTUSER" });
  });
  it("wer-report: app · fault module", () => {
    expect(
      summarizeArtifact(
        "wer-report",
        { application_name: "C:/x/app.exe", fault_module_name: "ntdll.dll", report_id: "r1" },
        null,
      ),
    ).toEqual({ title: "app.exe · ntdll.dll", detail: "r1" });
  });
  it("windows-sam-*: account candidate · RID", () => {
    expect(
      summarizeArtifact(
        "windows-sam-account-candidate",
        { user_name_candidate: "admin", rid_decimal: 500, candidate_role: "builtin-admin" },
        null,
      ),
    ).toEqual({ title: "admin", detail: "RID 500 · builtin-admin" });
    expect(summarizeArtifact("windows-sam-group-candidate", { alias_rid_decimal: 544 }, null).title).toBe(
      "RID 544",
    );
  });
  it("file-signature-mismatch: file name, detected → expected", () => {
    expect(
      summarizeArtifact(
        "file-signature-mismatch",
        { detected_signature_kind: "zip", expected_extensions: [".jpg", ".jpeg"] },
        "C:/u/photo.jpg",
      ),
    ).toEqual({ title: "photo.jpg", detail: "zip → .jpg, .jpeg" });
  });
  it("document-metadata-risk: file name · document family", () => {
    expect(summarizeArtifact("document-metadata-risk", { document_family: "xlsx" }, "C:/d/a.xlsx")).toEqual({
      title: "a.xlsx",
      detail: "xlsx",
    });
  });
  it("kakaotalk-windows-*: candidate kind, value preview", () => {
    const s = summarizeArtifact(
      "kakaotalk-windows-source-candidate",
      { candidate_kind: "chat-log", candidate_value: "v".repeat(200) },
      null,
    );
    expect(s.title).toBe("chat-log");
    expect(s.detail.length).toBeLessThanOrEqual(80);
  });
  it("cloud-message: service · event type, cloud family", () => {
    expect(
      summarizeArtifact(
        "cloud-message",
        { service: "teams", event_type: "message", cloud_family: "m365" },
        null,
      ),
    ).toEqual({ title: "teams · message", detail: "m365" });
  });

  it("cloud-message: chat_id · message_id", () => {
    expect(summarizeArtifact("cloud-message", { chat_id: "c1", message_id: "m9" }, "C:/x.json")).toEqual({
      title: "c1 · m9",
      detail: "",
    });
    expect(
      summarizeArtifact("cloud-message", { chat_id: "c1", message_id: "m9", message_text: "hello" }, null),
    ).toEqual({ title: "hello", detail: "c1 · m9" });
  });
});

describe("grid text filter uses full record values", () => {
  it("matches text beyond the 600-char clip of a details value", () => {
    const row = artifactRow({ event_message: `${"x".repeat(5000)} needle-at-the-end` });
    expect(matchesFilter(row, "needle-at-the-end")).toBe(true);
    expect(matchesFilter(row, "absent-term")).toBe(false);
  });
});

describe("review fixes: list keys, unshareable keys, header collisions, time keys", () => {
  it("promoted list keys get no sortKey and say why; colliding labels become 라벨 (key)", () => {
    const list = promotedColumn("tags", { list: true });
    expect(list.sortKey).toBeUndefined();
    expect(list.unsortableReason).toBe(LIST_FIELD_SORT_REASON);
    const taken = new Set(artifactColumnsForKind("windows-prefetch").map((c) => c.header));
    expect(promotedColumn("header_executable_name", { takenHeaders: taken }).header).toBe(
      "실행 파일 (header_executable_name)",
    );
    expect(promotedColumn("volume_serial", { takenHeaders: taken }).header).toBe("volume_serial");
  });

  it("keys with whitespace / comma / colon are flagged unshareable, like the URL", () => {
    expect(isShareableFieldKey("run_count")).toBe(true);
    for (const bad of ["a b", "a,b", "a:b"]) expect(isShareableFieldKey(bad)).toBe(false);
    const fields = discoverFields([artifactRow({ "a b": 1, ok: 2 })], artifactColumnsForKind("browser"));
    expect(fields.find((f) => f.key === "a b")?.unshareable).toBe(true);
    expect(fields.find((f) => f.key === "ok")?.unshareable).toBeUndefined();
  });

  it("the row time skips list / object values (like the server)", () => {
    expect(artifactRow({ timestamp: ["x"], modified_at: "2026-01-04T00:00:00Z" }).timestamp).toBe(
      "2026-01-04T00:00:00Z",
    );
  });
});
