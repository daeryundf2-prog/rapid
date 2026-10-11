import { fetchTimelinePage } from "../../../api/collections";
import type { CollectionDef } from "../types";
import { col, makeRef, makeRow, str, strOrNull } from "./common";

export const timelineCollection: CollectionDef = {
  id: "timeline",
  label: "타임라인",
  source: "paged",
  fetch: (runId, query, signal) => fetchTimelinePage(runId, query.offset, query.limit, signal),
  mapRow: (raw, index) =>
    makeRow(
      makeRef("timeline", `/events/${index}`),
      {
        title: strOrNull(raw.summary) ?? strOrNull(raw.event_type) ?? `이벤트 ${index + 1}`,
        sourcePath: strOrNull(raw.path),
        timestamp: strOrNull(raw.timestamp),
        artifactType: strOrNull(raw.event_type),
        provider: strOrNull(raw.source),
      },
      { source: str(raw.source), eventType: str(raw.event_type), inputFile: str(raw.input_file) },
    ),
  columns: [
    col.timestamp(190, ["analysis", "compact", "source"]),
    col.field("source", "출처", 90, ["analysis", "compact", "source"], (r) => r.provider),
    col.field("eventType", "이벤트", 160, ["analysis", "compact"], (r) => r.artifactType),
    col.title("요약", 380),
    col.review(),
    col.path(420),
  ],
};
