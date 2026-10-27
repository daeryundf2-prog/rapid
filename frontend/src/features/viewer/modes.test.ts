import { describe, expect, it } from "vitest";
import type { ViewerMode } from "../../contracts/viewer";
import { REASONS, resolveModes } from "./modes";
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
    expect(available(result)).toEqual(["source", "hex", "meta", "family"]);
    expect(reason(result, "document")).toBe(REASONS.notDocument);
  });

  it("text from .pdf extraction → document", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "text", extension: ".pdf" }),
    });
    expect(result.best).toBe("document");
    expect(available(result)).toEqual(["hex", "document", "meta", "family"]);
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
    expect(available(result)).toEqual(["hex", "image", "meta", "family"]);
    expect(reason(result, "sqlite")).toBe(REASONS.notSqlite);
    expect(reason(result, "source")).toBe(REASONS.notText);
  });

  it("sqlite → sqlite", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "sqlite", extension: ".db" }),
    });
    expect(result.best).toBe("sqlite");
    expect(available(result)).toEqual(["hex", "sqlite", "meta", "family"]);
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
    expect(available(result)).toEqual(["hex", "meta", "family"]);
    expect(reason(result, "media")).toBe(REASONS.notMedia);
  });

  it("binary (registry hive) → hex", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({ preview_type: "binary", extension: "" }),
    });
    expect(result.best).toBe("hex");
  });

  it("pdf whose extraction failed → document disabled with the API message", () => {
    const result = resolveModes({
      target: target(),
      preview: preview({
        preview_type: "binary",
        extension: ".pdf",
        message: "Text extraction failed: bad xref",
      }),
    });
    expect(result.best).toBe("hex");
    expect(reason(result, "document")).toBe("Text extraction failed: bad xref");
  });
});

describe("resolveModes — edge cases", () => {
  it("no target → every mode disabled", () => {
    const result = resolveModes({ target: null, preview: null });
    expect(result.best).toBeNull();
    expect(available(result)).toEqual([]);
  });

  it("row without a source file → meta only (+ 계열 of a files row)", () => {
    const result = resolveModes({ target: target({ sourcePath: null }), preview: null });
    expect(result.best).toBe("meta");
    expect(available(result)).toEqual(["meta", "family"]);
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

  it("zip entry without preview rows disables hex", () => {
    const result = resolveModes({
      target: target({ sourcePath: "C:/a.zip::x.json" }),
      preview: preview({ preview_type: "json", container_path: "C:/a.zip" }),
    });
    expect(reason(result, "hex")).toBe(REASONS.archiveHex);
  });
});

describe("계열 tab (R7 갈래 A)", () => {
  it("is available for item rows and never chosen automatically", () => {
    const files = resolveModes({
      target: target(),
      preview: preview({ preview_type: "text", extension: ".log" }),
    });
    expect(files.modes.find((m) => m.mode === "family")?.available).toBe(true);
    expect(files.best).toBe("source");
    const artifact = resolveModes({
      target: target({
        ref: { collection: "artifacts", kind: "email", locator: "/artifacts/3" },
        sourcePath: null,
      }),
      preview: null,
    });
    expect(available(artifact)).toEqual(["meta", "family"]);
    const entry = resolveModes({
      target: target({
        ref: { collection: "artifacts", kind: "generic-documents", locator: "/artifacts/0#entry:2" },
      }),
      preview: null,
    });
    expect(entry.modes.find((m) => m.mode === "family")?.available).toBe(true);
  });

  it("is disabled with a Korean reason for other rows; a requested 계열 wins when available", () => {
    const timeline = resolveModes({
      target: target({ ref: { collection: "timeline", locator: "/events/3" }, sourcePath: null }),
      preview: null,
    });
    expect(reason(timeline, "family")).toBe(REASONS.notFamily);
    const hit = resolveModes({
      target: target({
        ref: { collection: "search", locator: "search:artifacts:email:/artifacts/1" },
        review: { collection: "artifacts", kind: "email", pointer: "/artifacts/1" },
        sourcePath: null,
      }),
      preview: null,
    });
    expect(hit.modes.find((m) => m.mode === "family")?.available).toBe(true);
    const asked = resolveModes({ target: target({ preferredMode: "family" }), preview: null });
    expect(asked.best).toBe("family");
  });
});
