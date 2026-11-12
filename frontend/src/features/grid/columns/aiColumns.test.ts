/**
 * R7 AI 사용 (갈래 D) grid columns: every AI 사용 node opens its own column set (Korean headers),
 * enum cells read through the AI value labels (no raw id), time columns are 176 px (T-175), paths are
 * drawn tail first, and the 항목 title of every AI type is a sentence, not an id.
 */
import { isValidElement } from "react";
import { describe, expect, it } from "vitest";
import type { GridRow } from "../../../contracts/collection";
import { AI_TYPES } from "../../ai/aiLabels";
import { AI_SAMPLE_ROWS } from "../../ai/aiSampleRows";
import { FALLBACK_CATALOG, setCatalog } from "../../flags/catalog";
import { AI_USAGE_DOMAIN, flattenDomainNodes } from "../../tree/domains";
import { AI_TYPE_FAMILY_COLUMNS } from "./ai";
import { artifactColumnsForKind, artifactTypeFamily, resolveArtifactFamily } from "./artifacts";
import { COLLECTIONS } from "./index";

const RAW_ID = /^[a-z0-9_-]{3,}$/;
/** Product names the vendor writes in lower case (catalog names, not ids of ours). */
const PRODUCT_NAMES = new Set(["claude-swap", "ccusage", "gptme", "smolagents"]);

function rowsOf(type: string): GridRow[] {
  return AI_SAMPLE_ROWS.filter((raw) => raw.artifact_type === type).map((raw, i) =>
    COLLECTIONS.artifacts.mapRow({ ...raw, _kind: "ai-agent", _index: i }, i, {
      ref: { id: "artifacts", kind: "ai-agent" },
    }),
  );
}

const nodes = flattenDomainNodes(AI_USAGE_DOMAIN.nodes).filter(
  (node) => node.target.kind === "ai-agent" && node.target.types?.length && !node.children?.length,
);

describe("AI 사용 columns", () => {
  it("each typed AI node resolves to one AI column family", () => {
    for (const node of nodes) {
      const family = artifactTypeFamily(node.target.types);
      expect(family, node.id).toBeTruthy();
      expect(AI_TYPE_FAMILY_COLUMNS[family as string], node.id).toBeDefined();
    }
    for (const type of AI_TYPES) {
      expect(artifactTypeFamily([type]), type).toBeTruthy();
    }
  });

  it("headers are Korean; time columns 176 px (T-175); paths render tail first", () => {
    for (const node of nodes) {
      const columns = artifactColumnsForKind("ai-agent", node.target.types);
      for (const column of columns.filter((c) => c.id.startsWith("d:"))) {
        expect(column.header, `${node.id} ${column.id}`).toMatch(/[가-힣]|^(MCP|JSONL|SQLite|Git)/);
        if (column.filterKind === "time") expect(column.width).toBe(176);
      }
    }
    const touch = rowsOf("ai-agent-file-touch")[0] as GridRow;
    const pathColumn = artifactColumnsForKind("ai-agent", ["ai-agent-file-touch"]).find(
      (c) => c.id === "d:touched_path",
    );
    expect(pathColumn?.render?.(touch)).toSatisfy(isValidElement);
  });

  it("no default cell of the sample rows is a raw id (labelled enums, product names)", () => {
    const offenders: string[] = [];
    for (const node of nodes) {
      const types = node.target.types as string[];
      const rows = types.flatMap(rowsOf);
      const columns = artifactColumnsForKind("ai-agent", types).filter(
        (c) => c.id.startsWith("d:") && c.presets.includes("analysis"),
      );
      for (const row of rows) {
        for (const column of columns) {
          // Evidence text (ids, paths, names, free text) is never an id.
          if (
            /(_id|path|text|title|name|key|account|command|file|server|endpoint|line|model|cwd|version|period|commit)/.test(
              column.id,
            )
          )
            continue;
          const shown = column.format ? column.format(row) : String(column.value(row) ?? "");
          for (const item of String(shown).split(/,\s*/)) {
            if (RAW_ID.test(item.trim()) && /[a-z]/.test(item) && !PRODUCT_NAMES.has(item.trim()))
              offenders.push(`${node.id} ${column.header}: ${item}`);
          }
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("labels tool names, roles, call kinds, ops and presence kinds", () => {
    const message = rowsOf("ai-agent-message").find(
      (r) => (r.fields.details as Record<string, unknown>).role === "user",
    );
    const columns = artifactColumnsForKind("ai-agent", ["ai-agent-message"]);
    const role = columns.find((c) => c.id === "d:role");
    expect(role?.format?.(message as GridRow)).toBe("사용자");
    expect(role?.tooltip?.(message as GridRow)).toContain("원래 값: user");
    const tool = columns.find((c) => c.id === "d:tool_label");
    expect(tool?.format?.(message as GridRow)).toMatch(/^[A-Z]/);
    const call = rowsOf("ai-agent-tool-call")[0] as GridRow;
    const kind = artifactColumnsForKind("ai-agent", ["ai-agent-tool-call"]).find(
      (c) => c.id === "d:tool_kind",
    );
    expect(kind?.format?.(call)).toMatch(/[가-힣]/);
    const presence = rowsOf("ai-tool-presence")[0] as GridRow;
    const presenceKind = artifactColumnsForKind("ai-agent", ["ai-tool-presence"]).find(
      (c) => c.id === "d:install_kind",
    );
    expect(presenceKind?.format?.(presence)).toMatch(/[가-힣]/);
  });

  it("gives every AI row a sentence title (never the artifact type)", () => {
    for (const raw of AI_SAMPLE_ROWS) {
      const [row] = [raw].map((r, i) =>
        COLLECTIONS.artifacts.mapRow({ ...r, _kind: "ai-agent", _index: i }, i, {
          ref: { id: "artifacts", kind: "ai-agent" },
        }),
      );
      expect(row?.title, String(raw.artifact_type)).toBeTruthy();
      expect(row?.title).not.toBe(raw.artifact_type);
    }
    const session = rowsOf("ai-agent-session")[0] as GridRow;
    expect(session.title).not.toMatch(/^sess-/);
  });

  it("keeps the AI column sets when the backend catalogue carries ai-* families (R7 gate)", () => {
    // The served catalogue (and the bundled fallback) holds lane C's ai-* families; they used to win
    // over ai.ts, so the session grid lost 종료 and credential rows lost 값 (수집 안 함).
    setCatalog(FALLBACK_CATALOG);
    try {
      expect(FALLBACK_CATALOG.families.some((family) => family.id === "ai-session")).toBe(true);
      expect(resolveArtifactFamily("ai-agent", ["ai-agent-session"])).toBeUndefined();
      expect(resolveArtifactFamily("ai-agent", undefined)).toBeUndefined();
      expect(artifactTypeFamily(["ai-agent-session"])).toBe("ai-session");
      const session = artifactColumnsForKind("ai-agent", ["ai-agent-session"]).map((c) => c.header);
      expect(session).toEqual(expect.arrayContaining(["도구", "시작", "종료"]));
      const credential = artifactColumnsForKind("ai-agent", ["ai-credential-presence"]);
      expect(credential.some((c) => c.id === "d:value_collected")).toBe(true);
      for (const node of nodes) {
        expect(
          AI_TYPE_FAMILY_COLUMNS[artifactTypeFamily(node.target.types) as string],
          node.id,
        ).toBeDefined();
      }
      // Non-AI types still resolve to their catalogue family.
      expect(resolveArtifactFamily("windows-prefetch", ["prefetch-file"])).toBeDefined();
    } finally {
      setCatalog(null);
    }
  });
});
