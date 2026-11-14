import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { MiddlePath } from "../../components/MiddlePath";
import { fileRecoveryOf, filesCollection } from "./columns/files";
import { LOCATION_UNKNOWN_TEXT, pathCell, RECOVERED_MARK } from "./columns/PathCell";
import type { ColumnSpec } from "./types";

afterEach(() => cleanup());

const column = (id: string) => filesCollection.columns.find((c) => c.id === id) as ColumnSpec;
const mapFile = (raw: Record<string, unknown>) => filesCollection.mapRow(raw, 0, { ref: { id: "files" } });

// Synthetic result folders only (no real case paths).
const STAGE = "D:\\out\\case-1\\_e01\\fs";

describe("T-171 files 경로 = path inside the evidence (r8 C.9.1)", () => {
  it("strips the result folder and shows the in-evidence folder only", () => {
    const row = mapFile({ path: `${STAGE}\\Users\\kim\\Desktop\\report.docx`, name: "report.docx" });
    const spec = column("path");
    expect(spec.value(row)).toBe("\\Users\\kim\\Desktop\\report.docx");
    expect(spec.format?.(row)).toBe("\\Users\\kim\\Desktop");
    expect(spec.tooltip?.(row)).toBe("\\Users\\kim\\Desktop\\report.docx");
    const { container } = render(<div>{spec.render?.(row)}</div>);
    expect(container.textContent).toBe("\\Users\\kim\\Desktop");
    expect(container.innerHTML).not.toContain("_e01");
    expect(container.innerHTML).not.toContain("D:\\out");
  });

  it("a row of a legacy `filesystem` stage under any image kind is stripped too", () => {
    for (const stage of [
      "_e01\\filesystem",
      "_disk_image\\filesystem",
      "_virtual_disk\\fs",
      "_archive_image\\filesystem",
    ]) {
      const row = mapFile({ path: `C:\\r\\${stage}\\Windows\\System32\\config\\SAM` });
      expect(column("path").format?.(row)).toBe("\\Windows\\System32\\config");
    }
  });

  it("uses the volume letter when the row names one", () => {
    const row = mapFile({ path: `${STAGE}\\Users\\a.txt`, volume_letter: "c" });
    expect(column("path").value(row)).toBe("C:\\Users\\a.txt");
    expect(column("path").format?.(row)).toBe("C:\\Users");
  });

  it("a folder input's own path is already an evidence path and stays as it is", () => {
    const row = mapFile({ path: "E:\\collect\\Users\\kim\\a.txt" });
    expect(column("path").format?.(row)).toBe("E:\\collect\\Users\\kim");
  });

  it("a `_deleted_mft` item gets the 복구 marker and '원래 위치 알 수 없음', never the pseudo folder", () => {
    const row = mapFile({ path: `${STAGE}\\_deleted_mft\\1234-old.doc`, name: "1234-old.doc" });
    expect(row.fields.recovered).toBe(true);
    expect(row.fields.locationUnknown).toBe(true);
    const spec = column("path");
    expect(spec.value(row)).toBeNull();
    expect(spec.tooltip?.(row)).toBe(`${RECOVERED_MARK} — ${LOCATION_UNKNOWN_TEXT}`);
    const { container, getByTestId } = render(<div>{spec.render?.(row)}</div>);
    const cell = getByTestId("path-cell-recovered");
    expect(cell.textContent).toBe(`${RECOVERED_MARK}${LOCATION_UNKNOWN_TEXT}`);
    expect(container.innerHTML).not.toContain("_deleted_mft");
  });

  it("carved / orphan rows have no original location; a deleted entry keeps its folder", () => {
    expect(fileRecoveryOf({ recovery: { candidate_kind: "carved" } }, "D:\\out\\carved\\x.jpg")).toEqual({
      recovered: true,
      locationUnknown: true,
    });
    expect(fileRecoveryOf({ recovery: { candidate_kind: "orphan-record" } }, null).locationUnknown).toBe(
      true,
    );
    expect(fileRecoveryOf({ recovery: { candidate_kind: "existing" } }, `${STAGE}\\a.txt`)).toEqual({
      recovered: false,
      locationUnknown: false,
    });
    const row = mapFile({
      path: `${STAGE}\\Users\\kim\\old.txt`,
      recovery: { candidate_kind: "deleted-entry", deletion_state: "deleted" },
    });
    const { getByTestId } = render(<div>{column("path").render?.(row)}</div>);
    const cell = getByTestId("path-cell-recovered");
    expect(cell.querySelector(".tone-chip")?.textContent).toBe(RECOVERED_MARK);
    expect(cell.querySelector(".mid-path")?.textContent).toBe("\\Users\\kim");
  });

  it("a carved row's result-folder path never shows", () => {
    const row = mapFile({
      path: "D:\\out\\case-1\\carved\\00012.jpg",
      recovery: { candidate_kind: "carved" },
    });
    const { container } = render(<div>{column("path").render?.(row)}</div>);
    expect(container.textContent).toBe(`${RECOVERED_MARK}${LOCATION_UNKNOWN_TEXT}`);
    expect(container.innerHTML).not.toContain("carved\\");
  });

  it("500 synthetic image rows show no result-folder text anywhere in their cells", () => {
    const spec = column("path");
    const paths = Array.from({ length: 500 }, (_, i) =>
      i % 7 === 0
        ? `${STAGE}\\_deleted_mft\\${i}-f.bin`
        : `${STAGE}\\Users\\u${i % 5}\\AppData\\Local\\Temp\\f${i}.tmp`,
    );
    const { container } = render(
      <div>
        {paths.map((path) => (
          <div key={path}>{spec.render?.(mapFile({ path }))}</div>
        ))}
      </div>,
    );
    expect(container.innerHTML).not.toMatch(/_e01|_deleted_mft|D:\\out/);
  });

  it("artifact path cells (shared pathCell) strip the result folder too, whole path kept", () => {
    const { container } = render(<div>{pathCell(`${STAGE}\\Users\\kim\\NTUSER.DAT`)}</div>);
    expect(container.textContent).toBe("\\Users\\kim\\NTUSER.DAT");
  });
});

describe("T-171 one front ellipsis (never a double middle ellipsis)", () => {
  it("MiddlePath is one right-to-left box with a single isolated LTR run", () => {
    const { container } = render(<MiddlePath path={"C:\\Users\\kim\\AppData\\Local\\x.db"} />);
    const root = container.querySelector(".mid-path") as HTMLElement;
    expect(root.classList.contains("mid-path-front")).toBe(true);
    // Exactly one text run child: the box can only draw its one ellipsis at the front.
    expect(root.children).toHaveLength(1);
    const run = root.firstElementChild as HTMLElement;
    expect(run.tagName).toBe("BDI");
    expect(run.getAttribute("dir")).toBe("ltr");
    expect(run.textContent).toBe("C:\\Users\\kim\\AppData\\Local\\x.db");
    expect(root.getAttribute("title")).toBe("C:\\Users\\kim\\AppData\\Local\\x.db");
  });

  it("takes a tooltip override", () => {
    const { container } = render(<MiddlePath path={"\\Users"} title={"\\Users\\a.txt"} />);
    expect(container.querySelector(".mid-path")?.getAttribute("title")).toBe("\\Users\\a.txt");
  });
});
