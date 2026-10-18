/**
 * R5 L3 (plan r5-residual §3 L3): 통합 보기 › 지도 URL 위치 후보 (map view), 웹·브라우저 › GA 쿠키 /
 * P2P·토렌트 / URL 카빙 후보, 모바일 › adb 백업 — node mapping, kinds, analysis node, type labels.
 */
import { describe, expect, it } from "vitest";
import { ANALYSIS_KINDS } from "../../api/analyses";
import {
  ANALYSIS_FIELDS,
  buildAnalysisOptions,
  defaultForm,
  validateAnalysisForm,
} from "../analysis/analysisForm";
import { analysisNode, KIND_LABEL } from "../analysis/kinds";
import { artifactTypeLabel } from "../filters/typeLabels";
import { ANALYSIS_COLUMNS, ANALYSIS_KIND_FAMILIES } from "../grid/columns/analysis";
import { viewDisabledReason } from "../views/availability";
import { categoryOf } from "./categories";
import { DOMAINS, type DomainNodeDef, flattenDomainNodes } from "./domains";

function node(domain: string, id: string): DomainNodeDef {
  const found = flattenDomainNodes(DOMAINS.find((d) => d.id === domain)?.nodes ?? []).find(
    (n) => n.id === id,
  );
  if (!found) throw new Error(`${domain}/${id} missing`);
  return found;
}

describe("R5 L3 nodes", () => {
  it("map-URL location candidates live in 통합 보기 and open in the map view", () => {
    const locations = node("derived", "derived-location-urls");
    expect(locations.target).toMatchObject({
      collection: "artifacts",
      kind: "browser",
      types: ["location-url-candidate"],
    });
    expect(viewDisabledReason("map", { id: "artifacts", kind: "browser" })).toBeUndefined();
    expect(node("web", "web-location-urls").crossRef).toBe(true);
    expect(artifactTypeLabel("location-url-candidate")).toBe("지도 URL 위치 후보");
  });

  it("P2P group maps every p2p row type once; errors are detail rows", () => {
    const group = node("web", "web-p2p");
    const types = (group.children ?? []).flatMap((child) => child.target.types ?? []);
    expect(types.sort()).toEqual(
      [
        "p2p-client-config",
        "p2p-parse-error",
        "p2p-search-term",
        "p2p-shared-file",
        "p2p-torrent",
        "p2p-transfer",
      ].sort(),
    );
    expect(node("web", "web-p2p-errors").detail).toBe(true);
    expect(categoryOf("p2p")).toBe("web");
    expect(artifactTypeLabel("p2p-transfer")).toBe("전송 기록");
  });

  it("GA cookies, adb backup and carved URL nodes", () => {
    expect(node("web", "web-analytics-cookies").target.types).toEqual(["browser-analytics-cookie"]);
    expect(node("mobile", "mobile-adb-backup").target).toMatchObject({ kind: "mobile-export" });
    expect(artifactTypeLabel("android-backup-member")).toBe("adb 백업 항목");
    const carved = node("web", "web-carved-urls");
    expect(carved.target).toMatchObject({ collection: "analysis", analysis: "url-carve" });
    expect(artifactTypeLabel("carved-url-candidate")).toBe("URL 카빙 후보");
  });

  it("url-carve analysis kind: node, form defaults mirror the backend, columns and family", () => {
    expect(ANALYSIS_KINDS).toContain("url-carve");
    expect(analysisNode("url-carve")?.kinds).toEqual(["url-carve"]);
    expect(KIND_LABEL["url-carve"]).toBe("URL 카빙");
    const form = defaultForm("url-carve");
    expect(validateAnalysisForm("url-carve", form)).toEqual({});
    expect(buildAnalysisOptions("url-carve", form)).toEqual({
      sources: ["pagefile", "unallocated"],
      max_scan_bytes: 4096 * 1024 * 1024,
      max_candidates: 50000,
      ascii_urls: true,
      utf16_urls: true,
    });
    expect(validateAnalysisForm("url-carve", { ...form, sources: [] }).sources).toMatch(/1개 이상/);
    expect(ANALYSIS_FIELDS["url-carve"].map((field) => field.key)).toContain("sources");
    expect(ANALYSIS_COLUMNS["url-carve"]?.[0]?.keys).toEqual(["url"]);
    expect(ANALYSIS_KIND_FAMILIES["url-carve"]).toBe("carved-url-candidate");
  });
});
