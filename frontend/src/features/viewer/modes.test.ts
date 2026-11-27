import { describe, expect, it } from "vitest";
import type { SourcePreview } from "../../api/viewer";
import type { ViewerMode } from "../../contracts/viewer";
import { naturalMode, REASONS, resolveModes } from "./modes";
import { preview, target } from "./testSupport";

function available(result: ReturnType<typeof resolveModes>): ViewerMode[] {
  return result.modes.filter((m) => m.available).map((m) => m.mode);
}

function reason(result: ReturnType<typeof resolveModes>, mode: ViewerMode): string | undefined {
  return result.modes.find((m) => m.mode === mode)?.reason;
}

describe("resolveModes — one case per preview_type", () => {
  it("text (.log) → source", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "text", extension: ".log" }),
    });
    expect(result.best).toBe("source");
    expect(available(result)).toEqual(["source", "hex", "meta"]);
    expect(reason(result, "document")).toBe(REASONS.notDocument);
  });

  it("text from .pdf extraction → document", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "text", extension: ".pdf" }),
    });
    expect(result.best).toBe("document");
    expect(available(result)).toEqual(["hex", "document", "meta"]);
    expect(reason(result, "source")).toBe(REASONS.documentHere);
  });

  it("text from .docx extraction → document", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "text", extension: ".docx" }),
    });
    expect(result.best).toBe("document");
  });

  it("json → source", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "json", extension: ".json" }),
    });
    expect(result.best).toBe("source");
  });

  it("xml → source", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "xml", extension: ".xml" }),
    });
    expect(result.best).toBe("source");
  });

  it("image → image", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "image", extension: ".png" }),
    });
    expect(result.best).toBe("image");
    expect(available(result)).toEqual(["hex", "image", "meta"]);
    expect(reason(result, "sqlite")).toBe(REASONS.notSqlite);
    expect(reason(result, "source")).toBe(REASONS.notText);
  });

  it("sqlite → sqlite", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "sqlite", extension: ".db" }),
    });
    expect(result.best).toBe("sqlite");
    expect(available(result)).toEqual(["hex", "sqlite", "meta"]);
    expect(reason(result, "image")).toBe(REASONS.notImage);
  });

  it("email (.eml) → email", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "email", extension: ".eml" }),
    });
    expect(result.best).toBe("email");
    expect(reason(result, "source")).toBe(REASONS.emailHere);
  });

  it("media (mp4/wav) → media", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "media", extension: ".mp4" }),
    });
    expect(result.best).toBe("media");
    expect(reason(result, "email")).toBe(REASONS.notEmail);
  });

  it("hex (.evtx) → hex + meta", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "hex", extension: ".evtx" }),
    });
    expect(result.best).toBe("hex");
    expect(available(result)).toEqual(["hex", "meta"]);
    expect(reason(result, "media")).toBe(REASONS.notMedia);
  });

  it("binary (registry hive) → hex", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "binary", extension: "" }),
    });
    expect(result.best).toBe("hex");
  });

  it("pdf whose extraction failed → document (its pages still render from the bytes)", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({
        preview_type: "binary",
        extension: ".pdf",
        message: "Text extraction failed: bad xref",
      }),
    });
    expect(result.best).toBe("document");
    expect(available(result)).toEqual(["hex", "document", "meta"]);
    expect(reason(result, "source")).toBe(REASONS.documentHere);
  });

  it("docx whose extraction failed → hex; document disabled with the API message", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({
        preview_type: "binary",
        extension: ".docx",
        message: "Text extraction failed: bad zip",
      }),
    });
    expect(result.best).toBe("hex");
    expect(reason(result, "document")).toBe("Text extraction failed: bad zip");
  });

  it("plain-text kind over the server's size limit → source (read as a capped prefix)", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({
        preview_type: "binary",
        extension: ".log",
        size: 30_000_000,
        message: "Text extraction failed: log file exceeds text extraction size limit",
      }),
    });
    expect(result.best).toBe("source");
    expect(available(result)).toEqual(["source", "hex", "meta"]);
  });
});

describe("naturalMode — the viewer each file type opens in", () => {
  const zipEntry = { path: "C:/evidence/a.zip::x.pdf", container_path: "C:/evidence/a.zip" };
  it.each<[string, ViewerMode, Partial<SourcePreview>]>([
    ["pdf with extracted text", "document", { preview_type: "text", extension: ".pdf" }],
    ["pdf with no text layer", "document", { preview_type: "hex", extension: ".pdf" }],
    [
      "pdf by MIME type only",
      "document",
      { preview_type: "hex", extension: "", mime_type: "application/pdf" },
    ],
    ["upper-case .PDF", "document", { preview_type: "hex", extension: ".PDF" }],
    ["empty pdf", "hex", { preview_type: "hex", extension: ".pdf", size: 0 }],
    [
      "pdf in a zip, no text (pages from the entry's bytes)",
      "document",
      { preview_type: "hex", extension: ".pdf", ...zipEntry },
    ],
    ["pdf in a zip, with text", "document", { preview_type: "text", extension: ".pdf", ...zipEntry }],
    ["png", "image", { preview_type: "image", extension: ".png" }],
    ["tiff", "image", { preview_type: "image", extension: ".tiff" }],
    ["txt", "source", { preview_type: "text", extension: ".txt" }],
    ["log", "source", { preview_type: "text", extension: ".log" }],
    ["csv", "source", { preview_type: "text", extension: ".csv" }],
    ["json", "source", { preview_type: "json", extension: ".json" }],
    ["csv over the size limit", "source", { preview_type: "binary", extension: ".csv" }],
    ["json over the size limit", "source", { preview_type: "binary", extension: ".json" }],
    [
      "log in a zip over the size limit",
      "source",
      { preview_type: "binary", extension: ".log", ...zipEntry },
    ],
    ["png in a zip", "image", { preview_type: "image", extension: ".png", ...zipEntry }],
    ["zip archive", "archive", { preview_type: "hex", extension: ".zip" }],
    ["upper-case .ZIP", "archive", { preview_type: "hex", extension: ".ZIP" }],
    ["zip inside a zip (not listed)", "hex", { preview_type: "hex", extension: ".zip", ...zipEntry }],
    ["wav", "media", { preview_type: "media", extension: ".wav" }],
    ["mp4", "media", { preview_type: "media", extension: ".mp4" }],
    ["docx with extracted text", "document", { preview_type: "text", extension: ".docx" }],
    ["xlsx whose extraction failed", "hex", { preview_type: "binary", extension: ".xlsx" }],
    ["xls with no extractable text", "hex", { preview_type: "hex", extension: ".xls" }],
    ["unknown binary", "hex", { preview_type: "hex", extension: ".bin" }],
    ["no extension", "hex", { preview_type: "binary", extension: "" }],
  ])("%s → %s", (_name, expected, overrides) => {
    expect(naturalMode(preview(overrides))).toBe(expected);
  });
});

describe("resolveModes — edge cases", () => {
  it("no target → every mode disabled", () => {
    const result = resolveModes({ target: null, preview: null });
    expect(result.best).toBeNull();
    expect(available(result)).toEqual([]);
  });

  it("row without a source file → meta only", () => {
    const result = resolveModes({ target: target({ sourcePath: null }), preview: null });
    expect(result.best).toBe("meta");
    expect(available(result)).toEqual(["meta"]);
    expect(reason(result, "hex")).toBe(REASONS.noPath);
  });

  it("preferredMode wins when available", () => {
    const result = resolveModes({
      target: target({ preferredMode: "hex" }),
      preview: preview({ preview_type: "text", extension: ".txt" }),
    });
    expect(result.best).toBe("hex");
  });

  it("empty file disables hex", () => {
    const result = resolveModes({ target: target(), preview: preview({ preview_type: "binary", size: 0 }) });
    expect(reason(result, "hex")).toBe(REASONS.emptyFile);
    expect(result.best).toBe("meta");
  });

  it("while loading, modes carry the loading reason", () => {
    const result = resolveModes({ target: target(), preview: null, loading: true });
    expect(result.best).toBeNull();
    expect(reason(result, "source")).toBe(REASONS.loading);
  });

  it("preview error keeps hex + meta, and explains the rest", () => {
    const result = resolveModes({ target: target(), preview: null, previewError: "403" });
    expect(result.best).toBe("hex");
    expect(reason(result, "image")).toContain("403");
  });

  it("zip entry keeps hex: its bytes come from the entry range API", () => {
    const result = resolveModes({
      target: target({ sourcePath: "C:/a.zip::x.json" }),
      preview: preview({ preview_type: "json", container_path: "C:/a.zip" }),
    });
    expect(available(result)).toEqual(["source", "hex", "meta"]);
  });

  it("zip container → entry list first, hex still available", () => {
    const result = resolveModes({
      target: target({ sourcePath: "C:/a.zip" }),
      preview: preview({ path: "C:/a.zip", preview_type: "hex", extension: ".zip" }),
    });
    expect(result.best).toBe("archive");
    expect(available(result)).toEqual(["hex", "archive", "meta"]);
    expect(reason(result, "source")).toBe(REASONS.notText);
  });

  it("zip inside a zip: no entry list, says why", () => {
    const result = resolveModes({
      target: target({ sourcePath: "C:/a.zip::b.zip" }),
      preview: preview({
        path: "C:/a.zip::b.zip",
        preview_type: "hex",
        extension: ".zip",
        container_path: "C:/a.zip",
      }),
    });
    expect(result.best).toBe("hex");
    expect(reason(result, "archive")).toBe(REASONS.nestedArchive);
    expect(reason(resolveModes({ target: target(), preview: preview({}) }), "archive")).toBe(
      REASONS.notArchive,
    );
  });
});
