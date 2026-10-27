import { describe, expect, it } from "vitest";
import { isIconName } from "../../icons";
import {
  ARTIFACT_CATEGORIES,
  categoryOf,
  groupByCategory,
  isArtifactCategoryId,
  KIND_CATEGORY,
  kindIcon,
  kindsForCategory,
} from "./categories";

/** `artifact_collectors()` keys in rapidtriage/core/artifacts (25 kinds + R5 L1 email-clients, media-player, windows-phone-link). */
const ENGINE_KINDS = [
  // R7 AI 사용
  "ai-agent",
  "android-apk",
  "browser",
  "cloud-export",
  "cloud-sync",
  "email",
  "email-clients",
  "eventlog",
  "generic-documents",
  "kakaotalk-macos",
  "kakaotalk-windows",
  "linux-system",
  "macos-system",
  "media-image",
  "media-player",
  "memory-volatility",
  "mobile-export",
  // R5 L3
  "p2p",
  "recent-files",
  "synthetic-media",
  "windows-execution",
  "windows-filesystem",
  "windows-messenger",
  "windows-os-account",
  "windows-phone-link",
  "windows-prefetch",
  "windows-registry",
  "windows-remote-access",
  "windows-search-index",
  "windows-shellbags",
  "windows-system",
];

describe("artifact categories (X11)", () => {
  it("maps every engine kind to a named category (none fall into 기타)", () => {
    for (const kind of ENGINE_KINDS) {
      expect(KIND_CATEGORY[kind], kind).toBeDefined();
      expect(categoryOf(kind), kind).not.toBe("other");
    }
    expect(Object.keys(KIND_CATEGORY).sort()).toEqual([...ENGINE_KINDS].sort());
  });

  it("sends unknown kinds to 기타 with a generic icon", () => {
    expect(categoryOf("plugin-xyz")).toBe("other");
    expect(categoryOf("")).toBe("other");
    expect(kindIcon("plugin-xyz")).toBe("package");
  });

  it("uses real icons and the AXIOM label set", () => {
    expect(ARTIFACT_CATEGORIES.map((c) => c.label)).toEqual([
      "웹 관련",
      "커뮤니케이션",
      "미디어",
      "이메일·캘린더",
      "문서",
      "클라우드",
      "애플리케이션 사용량",
      "운영 체제",
      "암호화·로그인",
      "연결된 디바이스",
      "위치·여행",
      "기타",
    ]);
    for (const category of ARTIFACT_CATEGORIES) expect(isIconName(category.icon), category.id).toBe(true);
    for (const kind of ENGINE_KINDS) expect(isIconName(kindIcon(kind)), kind).toBe(true);
    expect(isArtifactCategoryId("web")).toBe(true);
    expect(isArtifactCategoryId("nope")).toBe(false);
  });

  it("resolves a category to its kinds (all known, or limited to the run's kinds)", () => {
    expect(kindsForCategory("communication").sort()).toEqual([
      "kakaotalk-macos",
      "kakaotalk-windows",
      "windows-messenger",
      "windows-phone-link",
    ]);
    expect(kindsForCategory("other", ["browser", "plugin-xyz"])).toEqual(["plugin-xyz"]);
    expect(kindsForCategory("web", ["browser", "eventlog"])).toEqual(["browser"]);
  });

  it("groups entries in display order with summed totals", () => {
    const groups = groupByCategory(
      [
        { kind: "eventlog", count: 10 },
        { kind: "browser", count: 3 },
        { kind: "plugin-xyz", count: 1 },
        { kind: "windows-registry", count: 5 },
      ],
      (e) => e.kind,
      (e) => e.count,
    );
    expect(groups.map((g) => [g.category.id, g.total, g.items.map((i) => i.kind)])).toEqual([
      ["web", 3, ["browser"]],
      ["operating-system", 15, ["eventlog", "windows-registry"]],
      ["other", 1, ["plugin-xyz"]],
    ]);
  });
});
