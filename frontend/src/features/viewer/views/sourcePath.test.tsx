import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GridRow } from "../../../contracts/collection";
import { EMPTY_CATALOG_FOR_TESTS, setCatalog } from "../../flags/catalog";
import { col } from "../../grid/columns/common";
import { buildCitation } from "../citation";
import { MetaView, sourcePathText } from "./MetaView";

// T-172 (r8 C.9.1, IS-128 / GAP-335): 원본 경로 and the citation name the path INSIDE the evidence.
const EXTRACTED = "D:\\cases\\out\\r1\\_e01\\fs\\Users\\kim\\Desktop\\plan.xlsx";
const IN_EVIDENCE = "\\Users\\kim\\Desktop\\plan.xlsx";
const RESULT_FOLDER = "_e01";

afterEach(cleanup);
beforeEach(() => setCatalog(EMPTY_CATALOG_FOR_TESTS));

function fileRow(sourcePath: string | null): GridRow {
  return {
    rowKey: "files:/candidates/3",
    ref: { collection: "files", locator: "/candidates/3" },
    title: "plan.xlsx",
    sourcePath,
    timestamp: null,
    artifactType: null,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: {},
  };
}

function show(sourcePath: string | null) {
  const row = fileRow(sourcePath);
  return render(
    <MetaView
      target={{ ref: row.ref, runId: "r1", sourcePath }}
      preview={null}
      metadata={null}
      metadataError={null}
      hashBusy={false}
      row={row}
      sessionMarks={[]}
      onComputeHash={() => {}}
    />,
  );
}

describe("viewer 원본 경로 = in-evidence path (T-172)", () => {
  it("출처 shows the in-evidence path; the result folder only under 기술 정보", () => {
    show(EXTRACTED);
    const source = screen.getByRole("region", { name: "출처" });
    expect(within(source).getByTestId("meta-source-path").textContent).toBe(IN_EVIDENCE);
    const tech = within(source).getByTestId("meta-tech-info");
    expect(tech.textContent).toContain("기술 정보");
    expect(tech.textContent).toContain(EXTRACTED);
    // Outside 기술 정보 nothing names the analysis PC's result folder.
    const outside = (source.textContent ?? "").replace(tech.textContent ?? "", "");
    expect(outside).not.toContain(RESULT_FOLDER);
    expect(screen.getByTestId("evidence-info").textContent).toContain(IN_EVIDENCE);
    expect(screen.getByTestId("evidence-info").textContent).not.toContain(RESULT_FOLDER);
    expect(screen.getByRole("region", { name: "파일 정보" }).textContent).not.toContain(RESULT_FOLDER);
  });

  it("a folder-input path is already an evidence path: no 기술 정보", () => {
    show("E:\\collect\\a.txt");
    expect(screen.getByTestId("meta-source-path").textContent).toBe("E:\\collect\\a.txt");
    expect(screen.queryByTestId("meta-tech-info")).toBeNull();
  });

  it("a recovery pseudo folder reads 원래 위치 알 수 없음; no path reads the derived wording", () => {
    expect(sourcePathText("D:\\out\\_e01\\fs\\_deleted_mft\\12-a.doc")).toBe("원래 위치 알 수 없음");
    expect(sourcePathText(null)).toBe("원본 경로 없음(파생 항목)");
    show(null);
    expect(screen.getByTestId("meta-source-path").textContent).toBe("원본 경로 없음(파생 항목)");
  });
});

describe("citation 원본= (T-172)", () => {
  const target = (sourcePath: string | null) => ({
    ref: { collection: "files" as const, locator: "/candidates/3" },
    runId: "r1",
    sourcePath,
  });

  it("cites the in-evidence path with the key order unchanged", () => {
    const text = buildCitation(target(EXTRACTED), null);
    expect(text).toBe(`원본=${IN_EVIDENCE}; sha256=미계산; 위치=files:/candidates/3; 런=r1`);
    expect(text).not.toContain(RESULT_FOLDER);
  });

  it("no path and an unknown location keep the 원본= key", () => {
    expect(buildCitation(target(null), null)).toMatch(/^원본=\(원본 경로 없음\); /);
    expect(buildCitation(target("E:\\tsk\\$OrphanFiles\\x"), null)).toMatch(
      /^원본=\(원래 위치 알 수 없음\); /,
    );
  });
});

describe("grid 경로 column tooltip / copy (T-172 follow-up of T-171)", () => {
  it("tooltip and copy text are the in-evidence path", () => {
    const spec = col.path();
    const row = fileRow(EXTRACTED);
    expect(spec.format?.(row)).toBe(IN_EVIDENCE);
    expect(spec.tooltip?.(row)).toBe(IN_EVIDENCE);
    expect(spec.value(row)).toBe(EXTRACTED);
  });
});
