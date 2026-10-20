import { describe, expect, it } from "vitest";

import { ANALYSIS_FIELDS, buildAnalysisOptions, defaultForm, validateAnalysisForm } from "./analysisForm";

describe("R6 S2 url-carve image-unallocated source", () => {
  it("offers the source without making it a default", () => {
    const sources = ANALYSIS_FIELDS["url-carve"].find((field) => field.key === "sources");
    expect(sources && "choices" in sources ? sources.choices.map((choice) => choice.id) : []).toContain(
      "image-unallocated",
    );
    const form = defaultForm("url-carve");
    expect(form.sources).toEqual(["pagefile", "unallocated"]);
    expect(buildAnalysisOptions("url-carve", form)).not.toHaveProperty("image_path");
  });

  it("sends image_path and partition_start_sector with image-unallocated", () => {
    const form = {
      ...defaultForm("url-carve"),
      sources: ["image-unallocated"],
      image_path: "D:\\case\\disk.E01",
      partition_start_sector: "2048",
    };
    expect(validateAnalysisForm("url-carve", form)).toEqual({});
    expect(buildAnalysisOptions("url-carve", form)).toMatchObject({
      sources: ["image-unallocated"],
      image_path: "D:\\case\\disk.E01",
      partition_start_sector: 2048,
    });
  });

  it("rejects image options without the image source, in Korean", () => {
    const form = { ...defaultForm("url-carve"), image_path: "D:\\case\\disk.E01" };
    expect(validateAnalysisForm("url-carve", form).image_path).toMatch(/이미지 미할당 영역/);
    // console review #7: the message sits on the field that holds the value.
    const sector = { ...defaultForm("url-carve"), partition_start_sector: "63" };
    const errors = validateAnalysisForm("url-carve", sector);
    expect(errors.partition_start_sector).toMatch(/^파티션 시작 섹터: .*고를 때만/);
    expect(errors.image_path).toBeUndefined();
  });
});
