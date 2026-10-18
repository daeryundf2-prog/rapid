/**
 * r2 console fix M7 / m7 / m8 / m11: catalogue `value_labels` (발신/수신/불명 for every app's raw
 * spelling) in the grid cell, column filter, viewer meta and citation; type-name cells; the row's
 * own timestamp kind on the time chip; the "(이름 미해석)" hint of numeric ids.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { GridRow } from "../../../contracts/collection";
import { matchesColumnFilter } from "../../filters/columnFilters";
import { FALLBACK_CATALOG, familyById, setCatalog, typeValueLabel } from "../../flags/catalog";
import { flagCitation } from "../../flags/flags";
import { recordLayout } from "../../viewer/fieldSheets";
import { KIND_COLUMNS, MESSENGER_DIRECTION_KO } from "./artifacts";
import { catalogColumn, cellTsKind, tsKindLabel } from "./families";

beforeEach(() => setCatalog(FALLBACK_CATALOG, "server"));
afterEach(() => setCatalog(null));

function row(artifactType: string, details: Record<string, unknown>): GridRow {
  return {
    rowKey: "r0",
    ref: { collection: "artifacts", locator: "/artifacts/0", kind: "windows-messenger" },
    title: "x",
    sourcePath: null,
    timestamp: null,
    artifactType,
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: { details },
  };
}

const column = (family: string, key: string) => {
  const def = [...(familyById(family)?.core_columns ?? []), ...(familyById(family)?.aux_columns ?? [])].find(
    (c) => c.key === key,
  );
  if (!def) throw new Error(`${family}.${key}`);
  return catalogColumn(def);
};

describe("M7: value_labels", () => {
  it("방향 reads 발신/수신/불명 for every app's raw spelling, the raw value in the tooltip", () => {
    const direction = column("messenger", "direction");
    const cases: Array<[string, string]> = [
      ["outgoing", "발신"],
      ["sent", "발신"],
      ["발신", "발신"],
      ["incoming", "수신"],
      ["received", "수신"],
      ["unknown", "불명"],
    ];
    for (const [raw, shown] of cases) {
      const r = row("chat-message", { direction: raw });
      expect(direction.format?.(r), raw).toBe(shown);
      if (raw !== shown) expect(direction.tooltip?.(r)).toContain(`원래 값: ${raw}`);
    }
    // Unmapped values are shown as written.
    expect(direction.format?.(row("chat-message", { direction: "sideways" }))).toBe("sideways");
  });

  it("a 방향 column filter on 발신 matches both raw spellings (client-side filter on the shown text)", () => {
    const direction = column("messenger", "direction");
    const filter = { col: direction.id, op: ":" as const, value: "발신" };
    expect(matchesColumnFilter(direction, row("chat-message", { direction: "outgoing" }), filter)).toBe(true);
    expect(matchesColumnFilter(direction, row("kakaotalk-message", { direction: "발신" }), filter)).toBe(
      true,
    );
    expect(matchesColumnFilter(direction, row("chat-message", { direction: "incoming" }), filter)).toBe(
      false,
    );
    // The raw spelling still matches too.
    expect(
      matchesColumnFilter(direction, row("chat-message", { direction: "outgoing" }), {
        ...filter,
        value: "outgoing",
      }),
    ).toBe(true);
  });

  it("deleted / encryption / sync / cache format values read Korean", () => {
    expect(
      column("messenger", "deleted_state").format?.(row("chat-message", { deleted_state: "live" })),
    ).toBe("활성");
    expect(
      column("messenger-app", "encryption_state").format?.(
        row("chat-app-inventory", { encryption_state: "encrypted-sqlcipher" }),
      ),
    ).toBe("암호화(SQLCipher)");
    expect(
      column("cloud-sync", "sync_state").format?.(row("cloud-sync-file", { sync_state: "mirror" })),
    ).toBe("로컬 미러");
    expect(
      column("browser-cache-entry", "cache_format").format?.(
        row("browser-cache-entry", { cache_format: "chromium-simple" }),
      ),
    ).toBe("Chromium 단순 캐시");
  });

  it("원본 행 유형 reads the Korean type name", () => {
    const source = column("web-upload-candidate", "source_artifact_type");
    const r = row("web-upload-candidate", { source_artifact_type: "browser-cache-entry" });
    expect(source.format?.(r)).toBe("캐시 항목");
    expect(source.tooltip?.(r)).toContain("원래 값: browser-cache-entry");
  });

  it("the viewer meta and the flag citation show the reading, keeping the raw value", () => {
    const layout = recordLayout(
      row("chat-message", { direction: "incoming", source_artifact_type: "browser-history" }),
    );
    const entries = [...layout.core, ...layout.other, ...layout.provenance];
    expect(entries.find((e) => e.key === "direction")?.valueLabel).toBe("수신");
    expect(entries.find((e) => e.key === "direction")?.raw).toBe("incoming");
    expect(typeValueLabel("chat-attachment", "direction", "outgoing")).toBe("발신");
    const citation = flagCitation(
      { id: "messenger.external_file_transfer", grade: "B", label: "x", evidence: { direction: "outgoing" } },
      { id: "messenger.external_file_transfer", family: "messenger-attachment" } as never,
    );
    expect(citation).toContain("direction=발신(outgoing)");
  });

  it("the 데스크톱 메신저 group (mixed types) has its own columns with 방향 in Korean (m7)", () => {
    const defs = KIND_COLUMNS["windows-messenger"] ?? [];
    expect(defs.map((d) => d.header)).toEqual(["앱", "대화방", "발화자·이름", "방향", "본문·파일"]);
    const direction = defs.find((d) => d.header === "방향");
    expect(direction?.display?.("outgoing", {})).toBe("발신");
    expect(MESSENGER_DIRECTION_KO.unknown).toBe("불명");
  });
});

describe("m3 / m8 / m11 cell details", () => {
  it("KakaoTalk attachments read as names, not JSON", () => {
    const attachments = column("messenger", "attachments");
    const r = row("kakaotalk-message", {
      attachments: [{ name: "a.jpg", size: 1 }, { name: "b.pdf" }],
      attachment_name: "a.jpg, b.pdf",
    });
    expect(attachments.format?.(r)).toBe("a.jpg, b.pdf");
  });

  it("the time chip reads the row's own timestamp kind (cache fallback, cloud events)", () => {
    const time = familyById("browser-cache-entry")?.core_columns[0];
    expect(time?.key).toBe("timestamp");
    const def = time as NonNullable<typeof time>;
    expect(cellTsKind(def, { timestamp_kind: "cache-created" }, "timestamp")).toBe("cache-created");
    expect(cellTsKind(def, {}, "timestamp")).toBe("cache-response");
    expect(tsKindLabel("cache-created")).toBe("캐시 생성");
    expect(tsKindLabel("cloud-upload")).toBe("클라우드 업로드");
    expect(tsKindLabel("cloud-modified")).toBe("클라우드 수정");
    const cell = catalogColumn(def);
    const r = row("browser-cache-entry", {
      timestamp: "2026-10-01T00:00:00Z",
      timestamp_kind: "cache-last-used",
    });
    expect(cell.tooltip?.(r)).toContain("cache-last-used");
  });

  it("numeric KakaoTalk ids carry '(이름 미해석)' in the cell tooltip", () => {
    const sender = column("messenger", "sender");
    expect(sender.tooltip?.(row("kakaotalk-message", { sender: "4412345678" }))).toContain("(이름 미해석)");
    expect(sender.tooltip?.(row("kakaotalk-message", { sender: "김철수" }))).not.toContain("이름 미해석");
  });
});
