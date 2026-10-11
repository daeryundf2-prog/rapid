import { fetchFilesPage } from "../../../api/collections";
import type { CollectionDef } from "../types";
import {
  baseName,
  col,
  fieldStr,
  formatBytes,
  isRecord,
  joinList,
  makeRef,
  makeRow,
  recoveryFields,
  sha256Of,
  str,
  strOrNull,
} from "./common";

export const filesCollection: CollectionDef = {
  id: "files",
  label: "파일",
  source: "paged",
  fetch: (runId, query, signal) => fetchFilesPage(runId, query.offset, query.limit, signal),
  mapRow: (raw, index) => {
    const path = strOrNull(raw.path);
    const recovery = isRecord(raw.recovery) ? raw.recovery : {};
    const hashes = isRecord(raw.hashes) ? raw.hashes : {};
    return makeRow(
      makeRef("files", `/candidates/${index}`),
      {
        title: strOrNull(raw.name) ?? (baseName(path) || `파일 ${index + 1}`),
        sourcePath: path,
        timestamp: strOrNull(raw.modified_at),
        artifactType: strOrNull(raw.extension),
        sha256: sha256Of(raw.sha256, hashes.sha256),
      },
      {
        extension: str(raw.extension),
        size: typeof raw.size === "number" ? raw.size : null,
        categories: joinList(raw.categories),
        recovery: str(recovery.candidate_kind),
        knownGood: str(raw.known_good_status),
        ...recoveryFields(raw.recovery),
      },
    );
  },
  columns: [
    col.title("이름", 260),
    col.review(),
    col.field("extension", "확장자", 80, ["analysis", "compact"], (r) => fieldStr(r, "extension")),
    col.field("size", "크기", 90, ["analysis", "compact"], (r) => (r.fields.size as number | null) ?? null, {
      align: "right",
      format: (r) => formatBytes(r.fields.size),
    }),
    col.timestamp(170),
    col.field("categories", "분류", 160, ["analysis"], (r) => fieldStr(r, "categories")),
    col.field("recovery", "복구 유형", 100, ["source"], (r) => fieldStr(r, "recovery")),
    col.path(420),
    col.sha256(),
  ],
};
