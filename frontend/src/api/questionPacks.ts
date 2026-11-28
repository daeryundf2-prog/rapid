import { api } from "./client";
import type { SearchOptions } from "./keywordPacks";

/**
 * 질문 팩: 수사관이 묻는 말 한 줄에 그 질문을 확인할 검색 조건을 묶어 둔 것
 * (`GET /api/question-packs`, 서버의 core/question_packs.py).
 */
export interface QuestionPack {
  id: string;
  question: string;
  category: string;
  keyword_packs: string[];
  keywords: string[];
  expanded_keywords: string[];
  collections: string[];
  artifact_kinds: string[];
  event_ids: string[];
  extensions: string[];
  references: string[];
  note: string;
  /** "builtin" 또는 이 질문이 온 사용자 파일 경로. */
  source_ref: string;
}

export interface QuestionPackCatalog {
  packs: QuestionPack[];
  categories: string[];
  /** 결과가 없다고 그 행위가 없었다는 뜻은 아니라는 등, 화면에 함께 보일 한계. */
  limits: string[];
}

export async function listQuestionPacks(): Promise<QuestionPackCatalog> {
  const payload = await api<Partial<QuestionPackCatalog>>("/api/question-packs");
  return {
    packs: Array.isArray(payload.packs) ? payload.packs : [],
    categories: Array.isArray(payload.categories) ? payload.categories : [],
    limits: Array.isArray(payload.limits) ? payload.limits : [],
  };
}

/** 질문의 컬렉션 이름 → 통합 검색의 범위 이름 (search·derived·registry 는 범위를 좁히지 않는다). */
const SOURCE_OF_COLLECTION: Record<string, string> = {
  docs: "documents",
  files: "files",
  artifacts: "artifacts",
  timeline: "timeline",
  indicators: "indicators",
};

/** 고른 질문이 만드는 검색: 검색어와 바꿀 옵션만 돌려준다(실행은 호출한 쪽에서). */
export function searchFromQuestion(pack: QuestionPack): {
  keywords: string[];
  options: Partial<SearchOptions>;
} {
  const sources = pack.collections.flatMap((name) => SOURCE_OF_COLLECTION[name] ?? []);
  return {
    keywords: [...pack.expanded_keywords],
    options: {
      keywordPacks: [...pack.keyword_packs],
      sources: [...new Set(sources)],
      extensions: pack.extensions.map((value) => value.replace(/^\./, "")),
    },
  };
}
