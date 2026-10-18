import type { CollectionId } from "../../../contracts/collection";
import type { CollectionDef, ColumnSpec, GridPreset } from "../types";
import { analysisCollection } from "./analysis";
import { artifactsCollection } from "./artifacts";
import { withAxiom } from "./axiom";
import { docsCollection } from "./docs";
import { filesCollection } from "./files";
import { indicatorsCollection } from "./indicators";
import { intakeCollection } from "./intake";
import { outputsCollection } from "./outputs";
import { reviewCollection } from "./review";
import { searchCollection } from "./search";
import { timelineCollection } from "./timeline";

const BASE_COLLECTIONS: Record<CollectionId, CollectionDef> = {
  intake: intakeCollection,
  search: searchCollection,
  files: filesCollection,
  docs: docsCollection,
  artifacts: artifactsCollection,
  timeline: timelineCollection,
  indicators: indicatorsCollection,
  review: reviewCollection,
  outputs: outputsCollection,
  analysis: analysisCollection,
  // The 처리 stage is a page (runs + analysis cards), not a grid: no rows, like 접수.
  process: { ...intakeCollection, id: "process", label: "처리" },
  // 통합 보기 is its own pane (features/derived/DerivedPane), not the DataGrid: no rows here.
  derived: { ...intakeCollection, id: "derived", label: "통합 보기" },
  // 레지스트리 탐색기 is its own pane (features/explorers/RegistryExplorer), not the DataGrid.
  registry: { ...intakeCollection, id: "registry", label: "레지스트리 탐색기" },
};

/** Every collection also carries the AXIOM preset (two-line title + tag/status chip column). */
export const COLLECTIONS = Object.fromEntries(
  Object.entries(BASE_COLLECTIONS).map(([id, def]) => [id, withAxiom(def)]),
) as Record<CollectionId, CollectionDef>;

export function collectionDef(id: CollectionId): CollectionDef {
  return COLLECTIONS[id];
}

/**
 * The column that can never be hidden: 항목 (`title`) when the layout has one, else the first
 * column. Locking by position hid 항목 behind 시각 once 시각 led the generic layout (review B2-6).
 */
export function lockedColumnId(columns: readonly ColumnSpec[]): string | undefined {
  return columns.find((c) => c.id === "title")?.id ?? columns[0]?.id;
}

export function presetColumnIds(columns: ColumnSpec[], preset: GridPreset): string[] {
  return columns.filter((c) => c.presets.includes(preset)).map((c) => c.id);
}
