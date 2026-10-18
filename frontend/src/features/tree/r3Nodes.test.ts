/**
 * R3 O3 (plan r3-os-depth §3.3, Q-R3-5 / Q-R3-6): 파일시스템 › 타임스탬프 불일치 / $LogFile 트랜잭션 and the
 * per-family "복구됨(카빙)" nodes — server `details` filters, counts from the job summary, empty reasons.
 */
import { describe, expect, it } from "vitest";
import { type AnalysisState, analysisRowsUrl } from "../../api/analyses";
import type { RunTree } from "../../api/runs";
import { applyFiltersToQuery, EMPTY_FILTERS, partitionFilters } from "../filters/filterModel";
import {
  CARVE_NEVER_RAN,
  DOMAINS,
  type DomainNodeDef,
  flattenDomainNodes,
  NTFS_META_NEVER_RAN,
  targetKey,
} from "./domains";
import { analysisSubCount, domainNodeCount, domainRoute, emptyNodeReason, UNKNOWN_COUNT } from "./model";

function node(domain: string, id: string): DomainNodeDef {
  const found = flattenDomainNodes(DOMAINS.find((d) => d.id === domain)?.nodes ?? []).find(
    (n) => n.id === id,
  );
  if (!found) throw new Error(`${domain}/${id} missing`);
  return found;
}

function job(
  kind: string,
  summary: Record<string, unknown>,
  status: AnalysisState["status"] = "completed",
): AnalysisState {
  return {
    analysis_id: `${kind}-1`,
    kind,
    status,
    options: {},
    created_at: "2026-10-18T00:00:00Z",
    progress: { done: 1, total: 1, unit: "", message: "", percent: 100 },
    row_count: 500,
    summary,
  };
}

describe("파일시스템 › 타임스탬프 불일치 / $LogFile 트랜잭션", () => {
  const mismatch = node("filesystem", "fs-timestamp-mismatch");
  const mismatchDeleted = node("filesystem", "fs-timestamp-mismatch-deleted");
  const logfile = node("filesystem", "fs-logfile");
  const mft = node("filesystem", "fs-mft");

  it("are ntfs-meta views filtered on details.source by the server, selected apart from MFT/USN", () => {
    expect(mismatch.label).toBe("타임스탬프 불일치");
    expect(mismatch.target).toMatchObject({ collection: "analysis", analysis: "ntfs-meta" });
    // Default: in-use MFT records only (most real mismatch rows are deleted records).
    expect(domainRoute(mismatch.target).cf).toEqual([
      { col: "f:source", op: ":", value: "timestamp-mismatch" },
      { col: "f:in_use", op: ":", value: "true" },
    ]);
    expect(domainRoute(mismatchDeleted.target).cf).toEqual([
      { col: "f:source", op: ":", value: "timestamp-mismatch" },
      { col: "f:in_use", op: ":", value: "false" },
    ]);
    expect(mismatchDeleted.label).toBe("타임스탬프 불일치(삭제된 레코드)");
    expect(mismatchDeleted.detail).toBe(true);
    expect(domainRoute(mismatch.target).cols).toContain("details.reason");
    expect(
      new Set([
        targetKey(mismatch.target),
        targetKey(mismatchDeleted.target),
        targetKey(logfile.target),
        targetKey(mft.target),
      ]).size,
    ).toBe(4);
    // A route carrying the same server filter selects the node (EvidenceTree compares route keys).
    expect(targetKey({ ...domainRoute(mismatch.target) })).toBe(targetKey(mismatch.target));
    expect(mismatch.note).toContain("ntfs.si_before_fn");
  });

  it("send in_use with source to the rows API (server filter, nothing left on the loaded rows)", () => {
    const columns = domainRoute(mismatch.target).cf ?? [];
    const plan = partitionFilters({ id: "analysis", kind: "ntfs-meta" }, { ...EMPTY_FILTERS, columns });
    expect(plan.server.details).toEqual({ source: ["timestamp-mismatch"], in_use: ["true"] });
    expect(plan.clientColumns).toEqual([]);
    const query = applyFiltersToQuery(
      { ref: { id: "analysis", kind: "ntfs-meta", analysisId: "n1" }, offset: 0, limit: 100 },
      { ...EMPTY_FILTERS, columns },
    );
    const url = analysisRowsUrl("r1", "n1", { offset: 0, limit: 100, detailFilters: query.detailFilters });
    expect(url).toContain("source=timestamp-mismatch");
    expect(url).toContain("in_use=true");
  });

  it("count the job summary's source_counts / source_in_use_counts, not the whole row count", () => {
    const analyses = [
      job("ntfs-meta", {
        source_counts: { mft: 480, "timestamp-mismatch": 3, "logfile-transaction": 17 },
        source_in_use_counts: { "timestamp-mismatch:in-use": 1, "timestamp-mismatch:deleted": 2 },
      }),
    ];
    expect(domainNodeCount(mismatch.target, { analyses }).count).toBe(1);
    expect(domainNodeCount(mismatchDeleted.target, { analyses }).count).toBe(2);
    expect(domainNodeCount(logfile.target, { analyses }).count).toBe(17);
    expect(domainNodeCount(mft.target, { analyses }).count).toBe(500);
    const none = domainNodeCount(mismatch.target, {
      analyses: [job("ntfs-meta", { source_counts: { mft: 500 }, source_in_use_counts: {} })],
    });
    expect(none.count).toBe(0);
    expect(emptyNodeReason(none)).toBe("이 런에는 해당 데이터가 없습니다");
  });

  it("never ran: hidden with the ntfs-meta reason; an older job without source counts shows —", () => {
    const never = domainNodeCount(mismatch.target, { analyses: [] });
    expect(never.neverRan).toBe(true);
    expect(emptyNodeReason(never)).toBe(NTFS_META_NEVER_RAN);
    expect(domainNodeCount(mismatch.target, { analyses: [job("ntfs-meta", {})] }).count).toBe(UNKNOWN_COUNT);
  });

  it("falls back to the /tree brief while the job list is unknown", () => {
    const tree: RunTree = {
      run_id: "r1",
      root: {},
      nodes: [
        {
          id: "analyses",
          label: "분석 작업",
          count: 1,
          children: [
            {
              id: "analysis:ntfs-meta",
              label: "NTFS 메타(MFT/USN)",
              count: 500,
              state: { status: "completed" },
              latest_completed: {
                analysis_id: "a",
                row_count: 500,
                source_counts: { "timestamp-mismatch": 9 },
                source_in_use_counts: { "timestamp-mismatch:in-use": 4, "timestamp-mismatch:deleted": 5 },
              },
            },
          ],
        },
      ],
    };
    expect(domainNodeCount(mismatch.target, { tree }).count).toBe(4);
    expect(domainNodeCount(mismatchDeleted.target, { tree }).count).toBe(5);
  });
});

describe("복구됨(카빙) family nodes", () => {
  const carveJob = job("carve", {
    kind_counts: { wav: 1, mp3: 2, m4a: 0, mp4: 4, jpeg: 5, docx: 1, eml: 2, pe: 3, evtx: 1 },
  });

  it("each family node sends its signature kinds and recovery_method=carved", () => {
    const audio = node("media", "media-audio-carved");
    expect(audio.label).toBe("오디오 복구됨(카빙)");
    expect(domainRoute(audio.target).cf).toEqual([
      { col: "f:signature_kind", op: ":", value: "wav,mp3,m4a" },
      { col: "f:recovery_method", op: ":", value: "carved" },
    ]);
    const plan = partitionFilters(
      { id: "analysis", kind: "carve" },
      { ...EMPTY_FILTERS, columns: domainRoute(audio.target).cf ?? [] },
    );
    expect(plan.server.details).toEqual({
      signature_kind: ["wav", "mp3", "m4a"],
      recovery_method: ["carved"],
    });
    expect(plan.clientColumns).toEqual([]);
    const query = applyFiltersToQuery(
      { ref: { id: "analysis", kind: "carve", analysisId: "c1" }, offset: 0, limit: 100 },
      { ...EMPTY_FILTERS, columns: domainRoute(audio.target).cf ?? [] },
    );
    const url = analysisRowsUrl("r1", "c1", { offset: 0, limit: 100, detailFilters: query.detailFilters });
    expect(url).toContain("signature_kind=wav&signature_kind=mp3&signature_kind=m4a");
    expect(url).toContain("recovery_method=carved");
  });

  it("other collections keep f:source as a loaded-rows filter", () => {
    const plan = partitionFilters(
      { id: "artifacts", kind: "eventlog" },
      {
        ...EMPTY_FILTERS,
        columns: [{ col: "f:source", op: ":", value: "x" }],
      },
    );
    expect(plan.server.details).toBeUndefined();
    expect(plan.clientColumns).toHaveLength(1);
  });

  it("count the carve job's kind_counts per family", () => {
    const analyses = [carveJob];
    const count = (domain: string, id: string) =>
      domainNodeCount(node(domain, id).target, { analyses }).count;
    expect(count("media", "media-audio-carved")).toBe(3);
    expect(count("media", "media-video-carved")).toBe(4);
    expect(count("media", "media-images-carved")).toBe(5);
    expect(count("media", "media-documents-carved")).toBe(1);
    expect(count("messaging", "msg-eml-carved")).toBe(2);
    expect(count("execution", "exec-carved")).toBe(3);
    expect(count("eventlog", "evt-carved")).toBe(1);
    expect(count("filesystem", "fs-carved")).toBe(19);
    const never = domainNodeCount(node("media", "media-audio-carved").target, { analyses: [] });
    expect(emptyNodeReason(never)).toBe(CARVE_NEVER_RAN);
  });

  it("analysisSubCount sums the listed keys (all when none)", () => {
    expect(analysisSubCount({ field: "kind_counts", keys: ["a"] }, { kind_counts: { a: 2, b: 3 } }, 9)).toBe(
      2,
    );
    expect(analysisSubCount({ field: "kind_counts", keys: [] }, { kind_counts: { a: 2, b: 3 } }, 9)).toBe(5);
    expect(analysisSubCount({ field: "kind_counts", keys: [] }, undefined, undefined)).toBeUndefined();
  });
});
