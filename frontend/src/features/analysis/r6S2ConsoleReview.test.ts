/**
 * R6 S2 console review (plan r6-followups-2026-10-19 §7): url-carve E01 media offsets, url-carve /
 * ntfs-meta summary notes, the ntfs-meta volume row, empty-node reasons of a $Boot-only job, keyed
 * meta value labels and the antivirus 조치 reading.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AnalysisState } from "../../api/analyses";
import { avAction, deriveColumn } from "../derived/derivedFields";
import { hiddenFilterLabel } from "../filters/filterModel";
import { FALLBACK_CATALOG, setCatalog } from "../flags/catalog";
import {
  analysisCollection,
  analysisFamily,
  isContainerMediaOffset,
  MEDIA_OFFSET_NOTE,
} from "../grid/columns/analysis";
import { buildViewerTarget } from "../grid/gridCommands";
import { DOMAINS, flattenDomainNodes } from "../tree/domains";
import {
  analysisEmptyReason,
  BOOT_ONLY_NATIVE_REASON,
  domainNodeCount,
  emptyNodeReason,
} from "../tree/model";
import { metaLabel, metaValueLabel } from "../viewer/views/metaLabels";
import { summaryNotes } from "./kinds";

function job(kind: string, summary: Record<string, unknown>, rowCount = 3): AnalysisState {
  return {
    analysis_id: `${kind}-1`,
    kind,
    status: "completed",
    options: {},
    created_at: "2026-10-19T00:00:00Z",
    progress: { done: 1, total: 1, unit: "", message: "", percent: 100 },
    row_count: rowCount,
    summary,
    error: null,
  } as AnalysisState;
}

function node(domain: string, id: string) {
  const found = flattenDomainNodes(DOMAINS.find((d) => d.id === domain)?.nodes ?? []).find(
    (n) => n.id === id,
  );
  if (!found) throw new Error(`${domain}/${id} missing`);
  return found;
}

const mapUrl = (path: string, details: Record<string, unknown>) =>
  analysisCollection.mapRow(
    { path, artifact_type: "carved-url-candidate", _index: 0, details: { source_path: path, ...details } },
    0,
    { ref: { id: "analysis", kind: "url-carve", analysisId: "u" } },
  );

describe("#1 url-carve image-unallocated hits in a container image", () => {
  const hit = {
    url: "https://example.com/",
    encoding: "ascii",
    offset: 1_048_576,
    cluster: 200,
    partition_start_sector: 2048,
  };

  it("never opens the E01 at the media offset; the offset stays metadata with the note", () => {
    const row = mapUrl("D:/case/disk.E01", { ...hit, source_kind: "image-unallocated" });
    expect(row.fields.highlight).toBeUndefined();
    expect(row.fields.viewerMode).toBeUndefined();
    expect(row.fields.sourceOffset).toBeUndefined();
    const details = row.fields.details as Record<string, unknown>;
    expect(details).toMatchObject({ offset: 1_048_576, cluster: 200, partition_start_sector: 2048 });
    expect(details.offset_basis_note).toBe(MEDIA_OFFSET_NOTE);
    expect(MEDIA_OFFSET_NOTE).toBe("E01 미디어 오프셋 — 파일 위치가 아님");
    expect(buildViewerTarget("run", row).highlight).toBeUndefined();
    expect(metaLabel("offset_basis_note")).toBe("오프셋 기준");
    expect(metaLabel("cluster")).toBe("클러스터 번호(NTFS)");
    expect(metaLabel("partition_start_sector")).toBe("파티션 시작 섹터");
  });

  it("raw / dd images still open at the offset (the media offset is the file offset)", () => {
    const row = mapUrl("D:/case/disk.dd", { ...hit, source_kind: "image-unallocated" });
    expect(row.fields.highlight).toEqual({ offset: 1_048_576, length: hit.url.length });
    expect(row.fields.viewerMode).toBe("hex");
  });

  it("decides by the server flag first, else the extension (split / Ex01 = container)", () => {
    const d = (extra: Record<string, unknown>) => ({ source_kind: "image-unallocated", ...extra });
    expect(isContainerMediaOffset(d({ image_media_kind: "raw" }), "D:/case/disk.E01")).toBe(false);
    expect(isContainerMediaOffset(d({ image_format: "ewf" }), "D:/case/disk.raw")).toBe(true);
    for (const name of ["disk.Ex01", "disk.001", "disk.E01"]) {
      expect(isContainerMediaOffset(d({}), `D:/case/${name}`)).toBe(true);
    }
    for (const name of ["disk.dd", "disk.RAW", "disk.img", "disk.bin"]) {
      expect(isContainerMediaOffset(d({}), `D:/case/${name}`)).toBe(false);
    }
    // file sources (pagefile …) are never media offsets
    expect(isContainerMediaOffset({ source_kind: "pagefile" }, "C:/pagefile.sys")).toBe(false);
  });
});

describe("#2 url-carve summary notes", () => {
  it("says the image source failed (with the error), was truncated, or hit the candidate cap", () => {
    const notes = summaryNotes(
      job("url-carve", {
        image_unallocated_status: "failed",
        image_unallocated_error: "이미지 미할당 영역을 읽지 못했습니다: NTFS 아님",
      }),
    );
    expect(notes).toContain("이미지 미할당 영역 실패: 이미지 미할당 영역을 읽지 못했습니다: NTFS 아님");
    const truncated = summaryNotes(
      job("url-carve", {
        image_unallocated_status: "scanned",
        image_unallocated_truncated: true,
        image_unallocated_scanned_bytes: 4 * 1024 ** 3,
        image_unallocated_bytes: 10 * 1024 ** 3,
        candidate_cap_reached: true,
        candidate_count: 50_000,
      }),
    );
    expect(truncated).toContain("이미지 미할당 영역 일부만 스캔: 4 GiB / 10 GiB (스캔 상한·구간 상한)");
    expect(truncated.some((note) => note.startsWith("URL 후보 상한 도달(50,000건)"))).toBe(true);
    expect(summaryNotes(job("url-carve", { image_unallocated_status: "scanned" }))).toEqual([]);
  });
});

describe("#3 ntfs-meta $Boot-only (no Sleuth Kit)", () => {
  const bootOnly = job(
    "ntfs-meta",
    {
      extraction_status: "boot-only-native",
      skipped: ["mft", "usn_journal", "logfile"].map((target) => ({
        target,
        reason: "Sleuth Kit(icat)이 없어 추출하지 않았습니다",
      })),
      source_counts: { "volume-information": 1 },
      source_in_use_counts: {},
      volume_information_status: "parsed",
    },
    1,
  );

  it("adds a summary note with the install hint", () => {
    expect(summaryNotes(bootOnly).join(" ")).toContain(
      "Sleuth Kit이 없어 $Boot만 읽음 — $MFT·USN·$LogFile 미추출",
    );
  });

  it("explains the empty MFT/USN, mismatch and $LogFile nodes; the volume node has its row", () => {
    for (const id of ["fs-mft", "fs-timestamp-mismatch", "fs-logfile"]) {
      const state = domainNodeCount(node("filesystem", id).target, { analyses: [bootOnly] });
      expect(state.count).toBe(0);
      expect(emptyNodeReason(state)).toBe(BOOT_ONLY_NATIVE_REASON);
    }
    const volume = domainNodeCount(node("filesystem", "fs-volume-info-analysis").target, {
      analyses: [bootOnly],
    });
    expect(volume.count).toBe(1);
  });

  it("uses summary.skipped when only one target was skipped", () => {
    const partial = job("ntfs-meta", {
      extraction_status: "partial",
      skipped: [{ target: "usn_journal", reason: "$UsnJrnl:$J 없음" }],
      source_counts: { mft: 10 },
    });
    const usnOnly = {
      ...node("filesystem", "fs-mft").target,
      cf: [{ col: "f:source", op: ":" as const, value: "usn" }],
    };
    expect(analysisEmptyReason(usnOnly, partial)).toBe("USN 저널($UsnJrnl:$J) 추출 안 됨 — $UsnJrnl:$J 없음");
  });
});

describe("#4 ntfs-meta volume-information row", () => {
  beforeEach(() => setCatalog(FALLBACK_CATALOG, "server"));
  afterEach(() => setCatalog(null));

  it("has a tree node, a catalogue family, a title and a filter chip", () => {
    const target = node("filesystem", "fs-volume-info-analysis").target;
    expect(target.cf).toEqual([{ col: "f:source", op: ":", value: "volume-information" }]);
    expect(analysisFamily("ntfs-meta", target.cf)?.id).toBe("ntfs-volume-information");
    const row = analysisCollection.mapRow(
      {
        path: "C:/run/analyses/n/ntfs/$Boot",
        artifact_type: "ntfs-volume-information",
        _index: 7,
        details: {
          source: "volume-information",
          volume_serial_display: "5E6F-7788",
          volume_label: "증거볼륨",
        },
      },
      7,
      { ref: { id: "analysis", kind: "ntfs-meta", analysisId: "n" } },
    );
    expect(row.title).toBe("NTFS 볼륨 정보 · VSN 5E6F-7788 · 증거볼륨");
    expect(hiddenFilterLabel({ col: "f:source", op: ":", value: "volume-information" })).toBe(
      "출처 NTFS 볼륨 정보",
    );
  });
});

describe("#6 keyed meta value labels and the antivirus 조치", () => {
  it("reads adb backup codes only under their key", () => {
    expect(metaValueLabel("db", "backup_domain")).toBe("데이터베이스(databases)");
    expect(metaValueLabel("db")).toBeNull();
    expect(metaValueLabel("size", "inner_extract_skipped_reason")).toBe("항목 크기 상한 초과");
    expect(metaValueLabel("cap", "inner_extract_skipped")).toBe("상한 도달");
    expect(metaValueLabel("name-collision")).toBe("이름 충돌");
    expect(metaValueLabel("adb-backup-extracted")).toBe("ADB 백업에서 해제한 사본을 해석");
    expect(metaValueLabel("error", "parse_outcome")).toBe("해석 오류");
    expect(metaLabel("inner_path")).toBe("해제 사본(증거 아님)");
    expect(metaLabel("container_backup_path")).toBe("원본 ADB 백업(.ab)");
    expect(metaLabel("parse_error")).toBe("해석 오류 사유");
  });

  it("labels a raw AhnLab DB 조치 value that matched no action word", () => {
    expect(avAction({ action: "quarantined", action_label: "격리" })).toEqual({
      value: "격리",
      detail: "quarantined",
    });
    expect(avAction({ action: "", action_label: "7" })).toEqual({
      value: "7 (DB 원본 값·조치 분류 안 됨)",
      detail: "DB 원본 값·조치 분류 안 됨",
    });
    expect(deriveColumn("av_action", {}, "av-detection-log")).toBeNull();
  });

  it("names the presence node neutrally (AhnLab in the note)", () => {
    const presence = node("anti-forensics", "af-av-presence");
    expect(presence.label).toBe("백신 제품 흔적");
    expect(presence.note).toContain("AhnLab");
  });
});
