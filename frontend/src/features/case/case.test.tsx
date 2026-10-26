import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_SEARCH_OPTIONS, searchQueryString } from "../../api/keywordPacks";
import { DeleteCaseDialog } from "./CasePicker";
import { buildCaseCommands } from "./commands";
import { DoctorDialog } from "./DoctorDialog";
import { useCaseDialogs } from "./dialogs";
import { ImportDialog } from "./ImportDialog";
import { ReportDialog } from "./ReportDialog";
import { RunDialog } from "./RunDialog";
import { buildRunBody, DEFAULT_RUN_FORM, validateRunForm } from "./runForm";
import { mockFetch, renderWithQuery } from "./testUtils";
import { WriteConfirmHost } from "./WriteConfirm";

/** Field names of RunCreateRequest in rapidtriage/api/app/models.py. */
const RUN_CREATE_FIELDS = [
  "root",
  "mode",
  "output_dir",
  "input_kind",
  "rules",
  "dry_run",
  "read_only",
  "max_extract_size_bytes",
  "max_file_count",
  "memory_cap_bytes",
  "e01_partition_start_sector",
  "overwrite",
  "resume",
  "extract",
  "known_good_hash_feeds",
  "hide_known_good",
  "known_good_max_hash_bytes",
  "wait",
];

const ctx = {
  runId: "r1",
  collection: null,
  selectedRowKeys: [],
  focusedRowKey: null,
  viewerHasTarget: false,
  runIsActive: false,
};

beforeEach(() => {
  window.location.hash = "";
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  useCaseDialogs.setState({ open: null, deleteRunId: null, notice: "" });
});

describe("run form", () => {
  it("is invalid until a path is given, with Korean messages", () => {
    expect(validateRunForm(DEFAULT_RUN_FORM).root).toBe("증거 경로를 입력하세요.");
    expect(validateRunForm({ ...DEFAULT_RUN_FORM, root: "D:/e", maxExtractMb: "-1" }).maxExtractMb).toBe(
      "최대 추출 크기는 0 이상의 정수(MB)여야 합니다.",
    );
    expect(validateRunForm({ ...DEFAULT_RUN_FORM, root: "D:/e", partitionSector: "x" }).partitionSector).toBe(
      "파티션 시작 섹터는 0 이상의 정수여야 합니다.",
    );
    expect(validateRunForm({ ...DEFAULT_RUN_FORM, root: "D:/e", hideKnownGood: true }).hideKnownGood).toBe(
      "known-good 해시 목록을 지정해야 숨길 수 있습니다.",
    );
    expect(Object.keys(validateRunForm({ ...DEFAULT_RUN_FORM, root: "D:/e" }))).toEqual([]);
  });

  it("builds the exact POST /api/runs body (only RunCreateRequest fields)", () => {
    const body = buildRunBody({
      ...DEFAULT_RUN_FORM,
      root: " D:/evidence/a.E01 ",
      mode: "seizure",
      inputKind: "e01-derived",
      maxExtractMb: "2",
      maxFileCount: "100",
      partitionSector: "2048",
      knownGoodFeeds: "a.txt\n\n b.txt \n",
      hideKnownGood: true,
      extract: true,
    });
    expect(body).toEqual({
      root: "D:/evidence/a.E01",
      mode: "seizure",
      input_kind: "e01-derived",
      output_dir: null,
      dry_run: false,
      read_only: true,
      overwrite: false,
      extract: true,
      max_extract_size_bytes: 2 * 1024 * 1024,
      max_file_count: 100,
      e01_partition_start_sector: 2048,
      known_good_hash_feeds: ["a.txt", "b.txt"],
      hide_known_good: true,
      wait: false,
    });
    for (const key of Object.keys(body)) expect(RUN_CREATE_FIELDS).toContain(key);
  });
});

describe("RunDialog", () => {
  it("keeps 실행 inert with a reason until valid, then POSTs and navigates", async () => {
    const { calls } = mockFetch({
      "POST /api/runs": { run_id: "new1", status: "queued" },
      "GET /api/collect/profiles": { profiles: ["intrusion"] },
    });
    const onClose = vi.fn();
    renderWithQuery(<RunDialog runIsActive={false} onClose={onClose} />);
    const submit = screen.getByRole("button", { name: "실행" });
    expect(submit.getAttribute("aria-disabled")).toBe("true");
    expect(submit.getAttribute("title")).toBe("증거 경로를 입력하세요.");
    fireEvent.click(submit);
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(0);

    fireEvent.change(screen.getByLabelText(/증거 경로/), { target: { value: "D:/case/img.E01" } });
    fireEvent.change(screen.getByLabelText("모드"), { target: { value: "hacking" } });
    expect(submit.getAttribute("aria-disabled")).toBeNull();
    fireEvent.click(submit);
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    const post = calls.find((c) => c.method === "POST");
    expect(post?.url).toBe("/api/runs");
    expect(post?.body).toEqual({
      root: "D:/case/img.E01",
      mode: "hacking",
      input_kind: null,
      output_dir: null,
      dry_run: false,
      read_only: true,
      overwrite: false,
      extract: false,
      max_extract_size_bytes: 0,
      max_file_count: 0,
      e01_partition_start_sector: null,
      known_good_hash_feeds: [],
      hide_known_good: false,
      wait: false,
    });
    expect(window.location.hash).toBe("#/case/new1/intake");
  });

  it("is blocked while a run is active", () => {
    mockFetch({});
    renderWithQuery(<RunDialog runIsActive onClose={() => undefined} />);
    const submit = screen.getByRole("button", { name: "실행" });
    expect(submit.getAttribute("aria-disabled")).toBe("true");
    expect(submit.getAttribute("title")).toBe("실행 중 런이 있습니다");
    expect(screen.getByRole("button", { name: "샘플 실행…" }).getAttribute("title")).toBe(
      "실행 중 런이 있습니다",
    );
  });

  it("browses the server filesystem and picks a path", async () => {
    const { calls } = mockFetch({
      "GET /api/browse": {
        path: "/ev",
        parent: "/",
        home: "/home",
        separator: "/",
        roots: [],
        entries: [{ name: "disk.E01", path: "/ev/disk.E01", kind: "file", evidence_candidate: true }],
        entry_count: 1,
        truncated: false,
        hidden_count: 0,
      },
    });
    renderWithQuery(<RunDialog runIsActive={false} onClose={() => undefined} />);
    fireEvent.click(screen.getByRole("button", { name: "찾아보기" }));
    fireEvent.click(await screen.findByRole("button", { name: /disk\.E01/ }));
    expect((screen.getByLabelText(/증거 경로/) as HTMLInputElement).value).toBe("/ev/disk.E01");
    // The 처리 그룹 preview loads on open too (R4 V1); the browse call is the only other one.
    expect(calls.filter((c) => !c.url.startsWith("/api/run-plan/preview"))[0]?.url).toBe("/api/browse");
  });

  it("sample run posts to /api/sample-case/run", async () => {
    const { calls } = mockFetch({
      "POST /api/sample-case/run": { command: "sample-case.run", run: { run_id: "s1", status: "completed" } },
    });
    renderWithQuery(
      <>
        <RunDialog runIsActive={false} onClose={() => undefined} />
        <WriteConfirmHost />
      </>,
    );
    fireEvent.click(screen.getByRole("button", { name: "샘플 실행…" }));
    // A write (r7 L4, C-G6): nothing is sent until the confirmation says where and is accepted.
    await waitFor(() => expect(screen.getByTestId("write-confirm")).toBeTruthy());
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    fireEvent.click(screen.getByTestId("write-confirm-ok"));
    await waitFor(() => expect(window.location.hash).toBe("#/case/s1/intake"));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({});
  });
});

describe("ImportDialog", () => {
  it("requires a folder and posts { output_dir }", async () => {
    const { calls } = mockFetch({ "POST /api/runs/import": { run_id: "imp1", status: "completed" } });
    renderWithQuery(<ImportDialog runIsActive={false} onClose={() => undefined} />);
    const submit = screen.getByRole("button", { name: "불러오기" });
    expect(submit.getAttribute("aria-disabled")).toBe("true");
    fireEvent.change(screen.getByLabelText(/출력 폴더/), { target: { value: "D:/out/run1" } });
    fireEvent.click(submit);
    await waitFor(() => expect(window.location.hash).toBe("#/case/imp1/intake"));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ output_dir: "D:/out/run1" });
  });
});

describe("DeleteCaseDialog", () => {
  it("issues DELETE /api/runs/{id} after confirmation", async () => {
    const { calls } = mockFetch({ "DELETE /api/runs/r9": new Response(null, { status: 204 }) });
    const onClose = vi.fn();
    renderWithQuery(<DeleteCaseDialog runId="r9" currentRunId="r9" onClose={onClose} />);
    expect(calls).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "삭제" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(calls[0]).toMatchObject({ method: "DELETE", url: "/api/runs/r9" });
  });
});

describe("DoctorDialog", () => {
  it("renders /api/doctor as a checklist", async () => {
    mockFetch({
      "GET /api/doctor": {
        command: "doctor",
        status: "warn",
        summary: { ok: 1, warn: 1, error: 0, check_count: 2 },
        checks: [
          { name: "python", category: "runtime", status: "ok", summary: "Python 3.12" },
          { name: "tesseract", category: "tool", status: "warn", summary: "없음", remediation: "설치하세요" },
        ],
      },
    });
    renderWithQuery(<DoctorDialog onClose={() => undefined} />);
    const list = await screen.findByRole("list", { name: "점검 항목" });
    expect(list.querySelectorAll("li")).toHaveLength(2);
    expect(list.textContent).toContain("조치: 설치하세요");
  });
});

describe("ReportDialog / export commands", () => {
  const review = (candidates: number) => ({
    run_id: "r1",
    database: "/o/case.db",
    case_id: "run-r1",
    exists: true,
    by_status: {},
    include_in_report: candidates,
    case_json: { bookmarks: 0, include_in_report: 0 },
    report_candidates: candidates,
  });

  it("disables report exports with 보고 후보 0건 but keeps the validation package", async () => {
    mockFetch({ "GET /api/runs/r1/review-counts": review(0) });
    renderWithQuery(<ReportDialog runId="r1" runIsActive={false} onClose={() => undefined} />);
    await screen.findByText("보고 후보 0건");
    // One radio group + one primary 내보내기 carrying the chosen kind's single reason (review #4).
    const submit = screen.getByRole("button", { name: "내보내기" });
    expect(screen.getByRole("radio", { name: "보고서" })).toHaveProperty("checked", true);
    await waitFor(() => expect(submit.getAttribute("aria-disabled")).toBe("true"));
    expect(submit.getAttribute("title")).toContain("보고 후보 0건");
    expect(screen.getAllByTestId("disabled-reason")).toHaveLength(1);
    fireEvent.click(screen.getByRole("radio", { name: "검증 패키지" }));
    expect(submit.getAttribute("aria-disabled")).toBeNull();
    expect(screen.queryByLabelText("보고서 형식")).toBeNull();
  });

  it("creates the case report then downloads the chosen format", async () => {
    const { calls } = mockFetch({
      "GET /api/runs/r1/review-counts": review(3),
      "POST /api/runs/r1/case-report": { report_path: "/o/r.md", exports: {} },
      "GET /api/runs/r1/case-report/file/docx": new Response("x", {
        status: 200,
        headers: { "content-disposition": 'attachment; filename="r.docx"' },
      }),
    });
    URL.createObjectURL = vi.fn(() => "blob:x");
    URL.revokeObjectURL = vi.fn();
    renderWithQuery(<ReportDialog runId="r1" runIsActive={false} onClose={() => undefined} />);
    await screen.findByText("보고 후보 3건");
    fireEvent.change(screen.getByLabelText("보고서 형식"), { target: { value: "docx" } });
    fireEvent.change(screen.getByLabelText(/보고서 제목/), { target: { value: "최종" } });
    fireEvent.click(screen.getByRole("button", { name: "내보내기" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/case-report/file/docx"))).toBe(true));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({
      template: "legal-handoff",
      title: "최종",
      case_number: null,
      investigator: null,
      include_all: false,
      max_items: 500,
    });
  });

  it("export commands carry the same disabled reasons", () => {
    const withZero = buildCaseCommands({ reportCandidates: 0 });
    const reason = (id: string, over = {}) =>
      withZero.find((c) => c.id === id)?.disabledReason?.({ ...ctx, ...over });
    expect(reason("export.case-report")).toBe("보고 후보 0건 — 표시된 항목이 없습니다");
    expect(reason("export.reviewer-bundle")).toBe("보고 후보 0건 — 표시된 항목이 없습니다");
    expect(reason("export.submission-manifest")).toBe("보고 후보 0건 — 표시된 항목이 없습니다");
    expect(reason("export.validation-package")).toBeUndefined();
    expect(reason("export.case-report", { runId: null })).toBe("케이스를 먼저 선택하세요");
    expect(
      buildCaseCommands({ reportCandidates: 2 })
        .find((c) => c.id === "export.case-report")
        ?.disabledReason?.(ctx),
    ).toBeUndefined();
  });
});

describe("case / search commands", () => {
  const commands = buildCaseCommands({ reportCandidates: 1 });
  const find = (id: string) => commands.find((c) => c.id === id);

  it("registers every action id", () => {
    expect(commands.map((c) => c.id).sort()).toEqual(
      [
        "case.create",
        "case.delete",
        "case.doctor",
        "case.edit",
        "case.evidence.add",
        "case.import",
        "case.link",
        "case.run",
        "case.run.add",
        "case.run.new",
        "case.sample",
        "case.switch",
        "export.case-report",
        "export.open",
        "export.reviewer-bundle",
        "export.submission-manifest",
        "export.validation-package",
        "search.options",
        "search.save",
      ].sort(),
    );
  });

  it("run/import/sample are disabled while a run is active", () => {
    for (const id of ["case.run", "case.import", "case.sample"]) {
      expect(find(id)?.disabledReason?.({ ...ctx, runIsActive: true })).toBe("실행 중 런이 있습니다");
      expect(find(id)?.disabledReason?.(ctx)).toBeUndefined();
    }
  });

  it("delete and search options need an open case", () => {
    expect(find("case.delete")?.disabledReason?.({ ...ctx, runId: null })).toBe("케이스를 먼저 선택하세요");
    expect(find("search.options")?.disabledReason?.({ ...ctx, runId: null })).toBe(
      "케이스를 먼저 선택하세요",
    );
    expect(find("search.save")?.disabledReason?.(ctx)).toBe("저장할 검색어가 없습니다");
  });

  it("case.run opens the run dialog; case.doctor the doctor", () => {
    find("case.run")?.run(ctx);
    expect(useCaseDialogs.getState().open).toBe("run");
    find("case.doctor")?.run(ctx);
    expect(useCaseDialogs.getState().open).toBe("doctor");
  });
});

describe("search options", () => {
  it("serialises to the /search query parameters", () => {
    const qs = searchQueryString(["a", "b"], {
      ...DEFAULT_SEARCH_OPTIONS,
      mode: "fuzzy",
      sources: ["documents"],
      extensions: ["pdf"],
      pathContains: " Users ",
      proximityWindow: 5,
      hideKnownGood: true,
      keywordPacks: ["pii"],
      ocr: false,
    });
    const params = new URLSearchParams(qs);
    expect(params.getAll("keyword")).toEqual(["a", "b"]);
    expect(params.get("search_mode")).toBe("fuzzy");
    expect(params.get("fuzzy_distance")).toBe("1");
    expect(params.getAll("source")).toEqual(["documents"]);
    expect(params.getAll("extension")).toEqual(["pdf"]);
    expect(params.get("path_contains")).toBe("Users");
    expect(params.get("proximity_window")).toBe("5");
    expect(params.get("hide_known_good")).toBe("true");
    expect(params.getAll("keyword_pack")).toEqual(["pii"]);
    expect(params.get("ocr")).toBe("false");
  });
});
