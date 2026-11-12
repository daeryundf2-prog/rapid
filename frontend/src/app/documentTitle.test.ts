// Browser tab title (r8 T-169): `{화면} · {사건 표시명} — RapidTriage`, `(n%)` while processing,
// `(!)` for failed / partial runs; titles differ across screens × cases.

import { cleanup, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { RunWithProgress } from "../api/runsProgress";
import { useCaseLinks } from "../features/case/caseLink";
import type { Route } from "../router";
import { documentTitle, runPercent, screenName, statusPrefix, useDocumentTitle } from "./documentTitle";

const runA: RunWithProgress = {
  run_id: "run-a-0001",
  status: "completed",
  request: { root: "D:/ev/laptop.E01" },
};
const runB: RunWithProgress = {
  run_id: "run-b-0002",
  status: "completed",
  request: { root: "D:/ev/phone.E01" },
};

const SCREENS: Array<Omit<Route, "runId">> = [
  { collection: "intake" },
  { collection: "process" },
  { collection: "files" },
  { collection: "docs" },
  { collection: "artifacts" },
  { collection: "timeline" },
  { collection: "indicators" },
  { collection: "search" },
  { collection: "analysis" },
  { collection: "derived" },
  { collection: "registry" },
  { collection: "review" },
  { collection: "artifacts", inReview: true },
  { collection: "outputs" },
];

afterEach(() => {
  cleanup();
  useCaseLinks.setState({ byRun: {}, loading: {} });
});

describe("documentTitle (T-169)", () => {
  it("is {화면} · {사건 표시명} — RapidTriage and differs across every screen × 2 cases", () => {
    const titles = SCREENS.flatMap((screen) => [
      documentTitle({ route: { ...screen, runId: runA.run_id }, run: runA, caseNumber: "2026-고단-1234" }),
      documentTitle({ route: { ...screen, runId: runB.run_id }, run: runB }),
    ]);
    expect(SCREENS.length).toBeGreaterThanOrEqual(11);
    expect(new Set(titles).size).toBe(titles.length);
    expect(titles[0]).toBe("접수 · 2026-고단-1234 — RapidTriage");
    expect(titles[1]).toBe("접수 · phone.E01 — RapidTriage");
    for (const title of titles) expect(title).toMatch(/^[^·]+ · .+ — RapidTriage$/);
  });

  it("names each stage and explore view in Korean", () => {
    expect(screenName({ runId: "r", collection: "files" })).toBe("파일/미디어");
    expect(screenName({ runId: "r", collection: "review" })).toBe("검토");
    expect(screenName({ runId: "r", collection: "artifacts", inReview: true })).toBe("특이사항");
    expect(screenName({ runId: "r", collection: "outputs" })).toBe("보고");
    expect(screenName({ runId: null, collection: null })).toBe("사건 선택");
    expect(documentTitle({ route: { runId: null, collection: null } })).toBe("사건 선택 — RapidTriage");
  });

  it("prefixes (n%) while processing and (!) for failed or partial runs", () => {
    const running: RunWithProgress = {
      ...runA,
      status: "running",
      progress: { completed_count: 3, total_count: 8 },
    };
    expect(runPercent(running)).toBe(37);
    expect(documentTitle({ route: { runId: runA.run_id, collection: "process" }, run: running })).toBe(
      "(37%) 처리 · laptop.E01 — RapidTriage",
    );
    const planOnly: RunWithProgress = {
      ...runA,
      status: "running",
      progress: { plan_counts: { tasks: 4, completed: 1, failed: 1 } },
    };
    expect(statusPrefix(planOnly)).toBe("(50%)");
    expect(statusPrefix({ ...runA, status: "queued" })).toBe("(0%)");
    expect(statusPrefix({ ...runA, status: "failed" })).toBe("(!)");
    expect(statusPrefix({ ...runA, status: "interrupted" })).toBe("(!)");
    expect(
      statusPrefix({ ...runA, status: "completed", progress: { plan_counts: { tasks: 4, partial: 1 } } }),
    ).toBe("(!)");
    expect(statusPrefix(runA)).toBe("");
    expect(
      documentTitle({
        route: { runId: runA.run_id, collection: "intake" },
        run: { ...runA, status: "failed" },
      }),
    ).toBe("(!) 접수 · laptop.E01 — RapidTriage");
  });

  it("the hook writes document.title and follows the case link", () => {
    const route: Route = { runId: runA.run_id, collection: "timeline" };
    const { rerender } = renderHook(({ r }) => useDocumentTitle(r, [runA, runB]), {
      initialProps: { r: route },
    });
    expect(document.title).toBe("타임라인 · laptop.E01 — RapidTriage");
    useCaseLinks.getState().setLink(runA.run_id, {
      caseId: "case-1",
      caseNumber: "2026-고단-1234",
      evidenceCitationId: "",
      evidenceNumber: "",
      examiner: "",
    });
    rerender({ r: route });
    expect(document.title).toBe("타임라인 · 2026-고단-1234 — RapidTriage");
    rerender({ r: { runId: runB.run_id, collection: "review" } });
    expect(document.title).toBe("검토 · phone.E01 — RapidTriage");
  });
});
