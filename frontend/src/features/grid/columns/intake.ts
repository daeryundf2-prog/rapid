import type { CollectionDef } from "../types";
import { col, makeRef, makeRow } from "./common";

/** "접수" is the run summary page (S1/S4), not a row collection; the grid shows nothing. */
export const intakeCollection: CollectionDef = {
  id: "intake",
  label: "접수",
  source: "whole",
  fetch: async () => ({ rows: [], total: 0, offset: 0, backend: "none", truncated: false, elapsedMs: 0 }),
  mapRow: (_raw, index) => makeRow(makeRef("intake", `intake:${index}`), { title: "" }),
  columns: [col.title()],
};
