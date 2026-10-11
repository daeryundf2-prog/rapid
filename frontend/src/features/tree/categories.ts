/**
 * Artifact category taxonomy (plan §9-B X11): provider / artifact kind →
 * AXIOM-style category. The tree groups the 아티팩트 node by these
 * categories, the 접수 dashboard charts them, and the grid resolves
 * `#/case/{run}/artifacts?category=<id>` to the kinds below.
 *
 * Kind ids are the run's `artifacts_<kind>` outputs (rapidtriage/core/artifacts
 * collectors). A kind missing from KIND_CATEGORY falls into 기타 (`other`).
 */

import type { IconName } from "../../icons";

export type ArtifactCategoryId =
  | "web"
  | "communication"
  | "media"
  | "email-calendar"
  | "documents"
  | "cloud"
  | "application-usage"
  | "operating-system"
  | "encryption-login"
  | "connected-devices"
  | "location-travel"
  | "other";

export interface ArtifactCategory {
  id: ArtifactCategoryId;
  label: string;
  icon: IconName;
}

/** Display order (AXIOM order; 기타 last). */
export const ARTIFACT_CATEGORIES: readonly ArtifactCategory[] = [
  { id: "web", label: "웹 관련", icon: "globe" },
  { id: "communication", label: "커뮤니케이션", icon: "message" },
  { id: "media", label: "미디어", icon: "image" },
  { id: "email-calendar", label: "이메일·캘린더", icon: "mail" },
  { id: "documents", label: "문서", icon: "file-text" },
  { id: "cloud", label: "클라우드", icon: "cloud" },
  { id: "application-usage", label: "애플리케이션 사용량", icon: "app" },
  { id: "operating-system", label: "운영 체제", icon: "cpu" },
  { id: "encryption-login", label: "암호화·로그인", icon: "key" },
  { id: "connected-devices", label: "연결된 디바이스", icon: "smartphone" },
  { id: "location-travel", label: "위치·여행", icon: "map-pin" },
  { id: "other", label: "기타", icon: "package" },
];

export interface KindMeta {
  category: ArtifactCategoryId;
  icon: IconName;
}

/** Every artifact collector kind the engine ships (keep in sync with `artifact_collectors()`). */
export const KIND_CATEGORY: Readonly<Record<string, KindMeta>> = {
  browser: { category: "web", icon: "globe" },
  "kakaotalk-windows": { category: "communication", icon: "message" },
  "kakaotalk-macos": { category: "communication", icon: "message" },
  "media-image": { category: "media", icon: "image" },
  "synthetic-media": { category: "media", icon: "film" },
  email: { category: "email-calendar", icon: "mail" },
  "generic-documents": { category: "documents", icon: "file-text" },
  "cloud-export": { category: "cloud", icon: "cloud" },
  "windows-execution": { category: "application-usage", icon: "play" },
  "windows-remote-access": { category: "application-usage", icon: "monitor" },
  "android-apk": { category: "application-usage", icon: "app" },
  "windows-prefetch": { category: "operating-system", icon: "play" },
  eventlog: { category: "operating-system", icon: "list" },
  "windows-registry": { category: "operating-system", icon: "database" },
  "windows-shellbags": { category: "operating-system", icon: "folder" },
  "recent-files": { category: "operating-system", icon: "clock" },
  "windows-search-index": { category: "operating-system", icon: "search" },
  "windows-filesystem": { category: "operating-system", icon: "hard-drive" },
  "windows-system": { category: "operating-system", icon: "settings" },
  "linux-system": { category: "operating-system", icon: "cpu" },
  "macos-system": { category: "operating-system", icon: "cpu" },
  "memory-volatility": { category: "operating-system", icon: "layers" },
  "windows-os-account": { category: "encryption-login", icon: "key" },
  "mobile-export": { category: "connected-devices", icon: "smartphone" },
};

const BY_ID = new Map(ARTIFACT_CATEGORIES.map((category) => [category.id, category]));

export function isArtifactCategoryId(value: string | null | undefined): value is ArtifactCategoryId {
  return !!value && BY_ID.has(value as ArtifactCategoryId);
}

export function categoryOf(kind: string): ArtifactCategoryId {
  return KIND_CATEGORY[kind]?.category ?? "other";
}

export function categoryInfo(id: ArtifactCategoryId): ArtifactCategory {
  return BY_ID.get(id) ?? (BY_ID.get("other") as ArtifactCategory);
}

export function kindIcon(kind: string): IconName {
  return KIND_CATEGORY[kind]?.icon ?? "package";
}

/**
 * Kinds that belong to `category`. With `available` (the run's kinds) the
 * result is limited to those — and includes unknown kinds for 기타.
 */
export function kindsForCategory(category: string, available?: readonly string[]): string[] {
  if (available) return available.filter((kind) => categoryOf(kind) === category);
  return Object.keys(KIND_CATEGORY).filter((kind) => KIND_CATEGORY[kind]?.category === category);
}

export interface CategoryGroup<T> {
  category: ArtifactCategory;
  total: number;
  items: T[];
}

/** Group kind entries by category in display order; empty categories are dropped. */
export function groupByCategory<T>(
  entries: readonly T[],
  kindOf: (entry: T) => string,
  countOf: (entry: T) => number,
): Array<CategoryGroup<T>> {
  const buckets = new Map<ArtifactCategoryId, T[]>();
  for (const entry of entries) {
    const id = categoryOf(kindOf(entry));
    const list = buckets.get(id) ?? [];
    list.push(entry);
    buckets.set(id, list);
  }
  return ARTIFACT_CATEGORIES.flatMap((category) => {
    const items = buckets.get(category.id);
    if (!items?.length) return [];
    return [{ category, items, total: items.reduce((sum, entry) => sum + countOf(entry), 0) }];
  });
}
