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
};

/** Every collection also carries the AXIOM preset (two-line title + tag/status chip column). */
export const COLLECTIONS = Object.fromEntries(
  Object.entries(BASE_COLLECTIONS).map(([id, def]) => [id, withAxiom(def)]),
) as Record<CollectionId, CollectionDef>;

export function collectionDef(id: CollectionId): CollectionDef {
  return COLLECTIONS[id];
}

export function presetColumnIds(columns: ColumnSpec[], preset: GridPreset): string[] {
  return columns.filter((c) => c.presets.includes(preset)).map((c) => c.id);
}
