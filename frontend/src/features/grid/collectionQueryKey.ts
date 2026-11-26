import { type CollectionQuery, recordFieldsKey } from "../../contracts/collection";
import { collectionDef } from "./columns";
import { serverPathFilter } from "./gridUtils";

/** The sort the server applies: artifacts of exactly one kind, one analysis job's rows, or the timeline. */
export function serverSortOf(query: CollectionQuery): CollectionQuery["sort"] {
  if (!query.sort) return undefined;
  if (query.ref.id === "artifacts" && query.ref.kind) return query.sort;
  if (query.ref.id === "analysis" && query.ref.analysisId) return query.sort;
  if (query.ref.id === "timeline") return query.sort;
  return undefined;
}

/** react-query key of a collection listing; its pages append `"page", <n>`. */
export function collectionQueryKey(runId: string | null, query: CollectionQuery, pageSize: number) {
  // A whole collection is one response and a search is its own request: both depend on these.
  const ownRequest = collectionDef(query.ref.id).source === "whole" || query.ref.id === "search";
  return [
    "collection",
    runId,
    query.ref.id,
    query.ref.kind ?? "",
    (query.ref.id === "artifacts" && !query.ref.kind) || query.ref.id === "files" || query.ref.id === "docs"
      ? (query.ref.category ?? "")
      : "",
    ownRequest ? (query.search ?? null) : null,
    ownRequest ? (query.extension ?? null) : null,
    query.ref.id === "analysis" ? (query.ref.analysisId ?? "") : "",
    // 파일 시스템 탐색기 folder / special node (files only): another folder is another listing.
    query.ref.id === "files" && (query.ref.dir !== undefined || query.ref.special)
      ? `${query.ref.dir ?? ""}|${query.ref.recursive ? "r" : "d"}|${query.ref.special ?? ""}`
      : "",
    query.ref.id === "artifacts" || query.ref.id === "analysis"
      ? query.pathContains?.trim() || serverPathFilter(query.text) || ""
      : "",
    query.ref.id === "artifacts" ? (query.artifactTypes ?? []).join(",") : "",
    serverSortOf(query) ? `${query.sort?.key}:${query.sort?.order}` : "",
    pageSize,
    // 특이사항 server filters (viewer-families §3.1); empty for every other listing.
    query.flags?.length || query.flagGrade ? `${query.flagGrade ?? ""}|${(query.flags ?? []).join(",")}` : "",
    // Exact record-field filters (`browser=` / `service=`), artifacts only.
    query.ref.id === "artifacts" ? recordFieldsKey(query.fields) : "",
    // Event-log channel / channel-group server filters (R3 O2), artifacts only: two 채널별 nodes
    // of the same kind must not share a cache entry.
    query.ref.id === "artifacts" && (query.channels?.length || query.channelGroups?.length)
      ? `${[...(query.channels ?? [])].sort().join("|")}#${[...(query.channelGroups ?? [])].sort().join("|")}`
      : "",
    // Analysis rows `details` server filters (R3 §3.3).
    query.ref.id === "analysis" && query.detailFilters ? JSON.stringify(query.detailFilters) : "",
    // Row conditions (r4 §2.3: time, 요일·시간대, 부분 결과, 콘텐츠 유형, 위치), artifacts · files · timeline.
    query.rowConditions ? JSON.stringify(query.rowConditions) : "",
  ] as const;
}
