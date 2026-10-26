import { describe, expect, it } from "vitest";
import { isRawToken, metaLabel, metaValueLabel, sectionLabels, viewerLimitationKo } from "./metaLabels";

describe("meta key labels (visual-polish S5)", () => {
  it("labels provenance and verification keys in Korean", () => {
    expect(metaLabel("source_path")).toBe("원본 경로");
    expect(metaLabel("source_index")).toBe("원본 순번");
    expect(metaLabel("source_hashes")).toBe("컨테이너 파일 해시");
    expect(metaLabel("confidence")).toBe("신뢰도");
    expect(metaLabel("risk_flags")).toBe("위험 표시");
    expect(metaLabel("core_accuracy_gates")).toBe("핵심 정확도 게이트");
    expect(metaLabel("commercial_gap_ids")).toBe("상용 대비 격차 ID");
    expect(metaLabel("commercial_uplift_evidence")).toBe("상용 수준 보강 근거");
    expect(metaLabel("cloud_validation_matrix")).toBe("클라우드 검증 매트릭스");
    expect(metaLabel("artifact_record_contract")).toBe("아티팩트 레코드 계약");
  });

  it("labels parser manifest families from prefix + suffix, with _hash", () => {
    expect(metaLabel("m365_export_report_grade_validation_plan")).toBe("M365 내보내기 보고서 등급 검증 계획");
    expect(metaLabel("m365_export_report_grade_validation_plan_hash")).toBe(
      "M365 내보내기 보고서 등급 검증 계획 해시",
    );
    expect(metaLabel("m365_export_parser_manifest")).toBe("M365 내보내기 파서 매니페스트");
    expect(metaLabel("mobile_schema_compatibility_matrix")).toBe("모바일 스키마 호환 매트릭스");
    expect(metaLabel("prefetch_analyst_review_profile")).toBe("프리페치 분석관 검토 프로필");
    expect(metaLabel("chat_app_gap_ids")).toBe("채팅 앱 격차 ID");
  });

  it("returns null for keys without a label (they go under 원시 필드)", () => {
    expect(metaLabel("volume_label")).toBeNull();
    expect(metaLabel("browser_validation_checks")).toBeNull();
    expect(metaLabel("zz_unknown_manifest")).toBeNull();
  });
});

describe("meta value readings (visual-polish B2 #5)", () => {
  it("reads booleans and enum tokens in Korean", () => {
    expect(metaValueLabel(false)).toBe("아니요");
    expect(metaValueLabel(true)).toBe("예");
    expect(metaValueLabel("false")).toBe("아니요");
    expect(metaValueLabel("validation-required")).toBe("검증 필요");
    expect(metaValueLabel("shellbags-validation-required")).toBe("검증 필요");
    expect(metaValueLabel("native-ese-catalog-decoding-required")).toBe("해석 필요");
    expect(metaValueLabel("critical")).toBe("심각");
  });

  it("leaves unknown values alone (raw tokens are shown in mono)", () => {
    expect(metaValueLabel("microsoft-365")).toBeNull();
    expect(metaValueLabel("C:/Users/x")).toBeNull();
    expect(metaValueLabel(42)).toBeNull();
    expect(isRawToken("microsoft-365")).toBe(true);
    expect(isRawToken("cloud_family")).toBe(true);
    expect(isRawToken("Hello world")).toBe(false);
  });

  it("labels the keys nested groups use", () => {
    for (const key of ["status", "cloud_family", "service", "blockers", "severity", "passed"]) {
      expect(metaLabel(key), key).not.toBeNull();
    }
  });
});

describe("sectionLabels (review B2-8)", () => {
  it("numbers labels two keys of one section share — never the raw key (R7 L3)", () => {
    const labels = sectionLabels(["timestamp", "time", "user", "user_name", "channel", "zz_raw"]);
    expect(labels.get("timestamp")).toBe("시각");
    expect(labels.get("time")).toBe("시각 (2)");
    expect(labels.get("user")).toBe("사용자");
    expect(labels.get("user_name")).toBe("사용자 (2)");
    expect(labels.get("channel")).toBe("채널");
    expect(labels.get("zz_raw")).toBeNull();
  });
});

describe("viewerLimitationKo (R7 L3)", () => {
  it("reads the source viewer's English limitation notes in Korean", () => {
    expect(
      viewerLimitationKo("Preview is read-only and may be capped to keep large cases responsive."),
    ).toMatch(/^미리보기는 읽기 전용/);
    expect(viewerLimitationKo("Inline text snippets are capped near 200000 characters.")).toBe(
      "본문 미리보기는 약 200,000자까지만 표시합니다.",
    );
    expect(viewerLimitationKo("Something new.")).toBe("Something new.");
  });
});

/**
 * Every value the collectors / case DB / QC write into `reportability` and `evidence_strength`
 * (R-10). Enumerated by grepping the field names in rapidtriage/ (string literals and keyword
 * arguments, conditional branches included); a new value needs a Korean reading here and in
 * META_KEYED_VALUE_LABELS.
 */
const REPORTABILITY_VALUES = [
  "bounded-delete-lifecycle-candidate",
  "bounded-mft-cache-usn-path-candidate",
  "bounded-mft-cache-usn-review-preview",
  "bounded-mft-path-cache-quality-profile",
  "bounded-parent-cache-usn-name-path-candidate",
  "bounded-rename-pair-candidate",
  "bounded-scan-path-candidate",
  "bounded-usn-path-reliability-assessment",
  "bounded-usn-state-replay-preview",
  "bounded-usn-state-replay-transition",
  "bounded-usn-timeline-review-candidate",
  "candidate-destlist-entry-citation",
  "candidate-review-only",
  "commercial-blocked",
  "excluded-from-execution-evidence",
  "excluded-from-recent-file-evidence",
  "internally-covered",
  "inventory-only",
  "inventory-triage",
  "metadata-only",
  "native-pure-python-decompression",
  "normal-scca-path",
  "not-commercial-grade-until-real-case-diff-and-signoff",
  "not-reportable",
  "reportable",
  "review",
  "review-only",
  "review-only-string-offset-candidate",
  "review-pivot",
  "reviewed-report-candidate",
  "reviewed-reportable",
  "source-context-candidate",
  "triage",
  "triage-cache-entry-candidate",
  "triage-embedded-media-candidate",
  "triage-pivot",
  "triage-preview-candidate",
  "triage-timeline-candidate",
  "usn-state-replay-validation-gate",
  "validation-diff-attachment-inventory",
];
const EVIDENCE_STRENGTH_VALUES = [
  "account-lifecycle-registry-export",
  "amcache-native-string-pivot",
  "application-fault-report",
  "application-resource-usage-database-presence",
  "application-resource-usage-indicator",
  "application-resource-usage-string-pivot",
  "context",
  "evtx-chunk-header",
  "evtx-record-candidate",
  "evtx-slack-copy",
  "execution-indicator",
  "exported-group-membership-hint",
  "external-tool-index-row",
  "indexed-document-match",
  "indicator-pivot",
  "jumplist-destination-candidate",
  "kakaotalk-application-database-presence",
  "kakaotalk-cross-source-presence-candidate",
  "kakaotalk-deviceinfo-context-preserved",
  "kakaotalk-macos-database-presence-and-openability",
  "kakaotalk-user-id-context-preserved",
  "local-rule-ioc-hit",
  "mounted-device-registry-key",
  "native-hive-deviceinfo-string-presence-candidate",
  "native-hive-deviceinfo-values-preserved",
  "ntfs-mft-native-attribute-metadata",
  "ntfs-usn-native-record",
  "package-integrity-finding",
  "partial-event-record",
  "persistence-configuration",
  "prefetch-file-reference",
  "program-presence-not-proof-of-execution",
  "program-presence-or-execution",
  "program-presence-or-execution-candidate",
  "recent-execution-indicator-candidate",
  "registry-deleted-cell-candidate",
  "registry-deleted-key-candidate",
  "registry-deleted-value-candidate",
  "registry-export-key",
  "registry-hive-header",
  "registry-hive-string-candidate",
  "remote-access-destination",
  "sam-hive-group-key-candidate",
  "sam-hive-key-candidate",
  "search-index-database-presence",
  "search-index-string-pivot",
  "security-policy-sensitive-location",
  "security-privilege-assignment",
  "snapshot-file-delta",
  "srum-native-row-string-candidate",
  "srum-row-indicator-candidate",
  "srum-table-presence-candidate",
  "strong",
  "system-service-configuration",
  "triage",
  "user-execution-indicator",
  "user-execution-indicator-candidate",
  "vsc-snapshot-file-copy",
  "weak",
  "windows-search-correlated-native-string-candidate",
  "windows-search-page-local-string-correlation",
  "windows-search-table-presence-candidate",
];

describe("provenance enumerations in Korean (R-10)", () => {
  it.each([
    ["reportability", REPORTABILITY_VALUES],
    ["evidence_strength", EVIDENCE_STRENGTH_VALUES],
  ] as const)("every %s value has a Korean reading", (key, values) => {
    const missing = values.filter((value) => !/[가-힣]/.test(metaValueLabel(value, key) ?? ""));
    expect(missing).toEqual([]);
  });

  it("reads the values the 출처 section showed raw", () => {
    expect(metaValueLabel("review", "reportability")).toBe("검토 필요");
    expect(metaValueLabel("program-presence-not-proof-of-execution", "evidence_strength")).toBe(
      "프로그램 존재(실행 증명 아님)",
    );
    expect(metaValueLabel("review", "source_reference.reportability")).toBe("검토 필요");
  });
});
