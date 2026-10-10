/**
 * RowRef — how a grid row is addressed in URLs, review marks and the viewer.
 *
 * Rows are never addressed by array index (pages shift); they are addressed by
 * the locator the backend already emits: an artifact_id / records_path+row
 * index for artifacts, a candidate index for files, an event index for
 * timeline, a document id for docs, and the case-db row id once persisted.
 */

import type { CollectionId } from "./collection";

export interface RowRef {
  collection: CollectionId;
  /** Artifact kind for artifacts rows. */
  kind?: string;
  /**
   * Backend locator, verbatim from the API (e.g. "/candidates/894",
   * "/events/278261", "artifacts_eventlog:row:12345", "doc:17").
   */
  locator: string;
  /** Case-db primary key when the row has been persisted (review marks). */
  caseDbId?: number;
}

/** Serialise for the `row=` URL query parameter (and back). */
export function encodeRowRef(ref: RowRef): string {
  return encodeURIComponent(
    [ref.collection, ref.kind ?? "", ref.locator, ref.caseDbId ?? ""].join("|"),
  );
}

export function decodeRowRef(value: string | null): RowRef | null {
  if (!value) return null;
  const [collection, kind, locator, caseDbId] = decodeURIComponent(value).split("|");
  if (!collection || !locator) return null;
  return {
    collection: collection as CollectionId,
    kind: kind || undefined,
    locator,
    caseDbId: caseDbId ? Number(caseDbId) : undefined,
  };
}
