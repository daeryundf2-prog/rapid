import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { GridRow } from "../../../contracts/collection";
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
