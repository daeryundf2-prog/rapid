// Shared case-tag fixtures of the review tests (review.test.tsx, tagAuthor.test.tsx).

import type { CaseTag } from "../../api/reviewTools";

export function tag(partial: Partial<CaseTag> & { id: number; name: string }): CaseTag {
  return {
    case_id: "run-r1",
    kind: "user",
    color_token: "tag-5",
    shortcut: null,
    description: "",
    created_by: "분석 담당 A",
    created_at: "2026-10-17T00:00:00+00:00",
    updated_at: "2026-10-17T00:00:00+00:00",
    deleted_at: null,
    deleted_by: null,
    count: 0,
    ...partial,
  };
}

export const SYSTEM: CaseTag[] = [
  tag({ id: 1, name: "북마크", kind: "system", color_token: "tag-3" }),
  ...[1, 2, 3, 4, 5].map((n) => tag({ id: n + 1, name: `우선순위 ${n}`, kind: "system", shortcut: n })),
];

export function caseRoutes(tags: CaseTag[], extra: Record<string, unknown> = {}) {
  return {
    "GET /api/runs/r1/review-counts": { run_id: "r1", case_id: "run-r1", exists: true, by_status: {} },
    "GET /api/cases/run-r1/tags": { case_id: "run-r1", exists: true, tags },
    "POST /api/runs/r1/case-db/ensure": { database: "D:/out/rapidtriage-case.db", case_id: "run-r1" },
    ...extra,
  };
}
