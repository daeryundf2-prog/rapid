import { describe, expect, it } from "vitest";
import { DEFAULT_SEARCH_OPTIONS } from "./keywordPacks";
import { type QuestionPack, searchFromQuestion } from "./questionPacks";

const pack = (over: Partial<QuestionPack> = {}): QuestionPack => ({
  id: "exfil-cloud-upload",
  question: "클라우드에 자료를 올린 기록이 있나?",
  category: "유출",
  keyword_packs: ["exfiltration"],
  keywords: ["업로드"],
  expanded_keywords: ["mega.nz", "dropbox", "업로드"],
  collections: ["artifacts", "timeline", "search"],
  artifact_kinds: ["cloud-sync"],
  event_ids: [],
  extensions: [".zip", "7z"],
  references: ["MITRE ATT&CK T1567"],
  note: "동기화 폴더는 업로드와 구분되지 않는다.",
  source_ref: "builtin",
  ...over,
});

describe("searchFromQuestion", () => {
  it("uses the server-expanded keywords as the search terms", () => {
    expect(searchFromQuestion(pack()).keywords).toEqual(["mega.nz", "dropbox", "업로드"]);
  });

  it("maps collections to search sources and drops the ones that are not a scope", () => {
    expect(searchFromQuestion(pack()).options.sources).toEqual(["artifacts", "timeline"]);
    expect(searchFromQuestion(pack({ collections: ["docs", "files"] })).options.sources).toEqual([
      "documents",
      "files",
    ]);
    // derived / registry have no search scope of their own: the search stays unscoped.
    expect(searchFromQuestion(pack({ collections: ["derived", "registry"] })).options.sources).toEqual([]);
  });

  it("carries the keyword packs and normalises extensions to the search's bare form", () => {
    const { options } = searchFromQuestion(pack());
    expect(options.keywordPacks).toEqual(["exfiltration"]);
    expect(options.extensions).toEqual(["zip", "7z"]);
  });

  it("leaves every other option alone when merged over the defaults", () => {
    const merged = { ...DEFAULT_SEARCH_OPTIONS, ...searchFromQuestion(pack()).options };
    expect(merged.mode).toBe(DEFAULT_SEARCH_OPTIONS.mode);
    expect(merged.limit).toBe(DEFAULT_SEARCH_OPTIONS.limit);
    expect(merged.ocr).toBe(DEFAULT_SEARCH_OPTIONS.ocr);
  });
});
