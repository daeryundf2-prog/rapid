import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../../contracts/collection";
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
    expect(screen.getByText("history_rows_present")).toBeTruthy();
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
    expect(hash).toContain("#/case/r1/timeline?");
    expect(decodeURIComponent(hash)).toContain("from=2026-03-01T11:00:00.000Z");
    expect(decodeURIComponent(hash)).toContain("to=2026-03-01T13:00:00.000Z");
  });
});

describe("MetaView long values and 열로 표시 (artifact-columns U-C1/U-C3)", () => {
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
