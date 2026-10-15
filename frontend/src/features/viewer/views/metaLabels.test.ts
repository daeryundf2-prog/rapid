import { describe, expect, it } from "vitest";
import { isRawToken, metaLabel, metaValueLabel, sectionLabels } from "./metaLabels";

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
  it("spells out the raw key when two keys of one section share a label", () => {
    const labels = sectionLabels(["timestamp", "time", "user", "user_name", "channel", "zz_raw"]);
    expect(labels.get("timestamp")).toBe("시각 (timestamp)");
    expect(labels.get("time")).toBe("시각 (time)");
    expect(labels.get("user")).toBe("사용자 (user)");
    expect(labels.get("user_name")).toBe("사용자 (user_name)");
    expect(labels.get("channel")).toBe("채널");
    expect(labels.get("zz_raw")).toBeNull();
  });
});
