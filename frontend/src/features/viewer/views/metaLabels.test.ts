import { describe, expect, it } from "vitest";
import { metaLabel } from "./metaLabels";

describe("meta key labels (visual-polish S5)", () => {
  it("labels provenance and verification keys in Korean", () => {
    expect(metaLabel("source_path")).toBe("원본 경로");
    expect(metaLabel("source_index")).toBe("원본 순번");
    expect(metaLabel("source_hashes")).toBe("원본 해시");
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
