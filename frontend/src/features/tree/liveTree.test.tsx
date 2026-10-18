// Live tree (R4 V1 U-P2-4): while a run has no summary, `/tree` lists only finished providers;
// unfinished kinds are dimmed, not openable, with the server reason, never hidden as empty; a
// banner says what is shown.

import { cleanup, configure, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { RunTree } from "../../api/runs";
import { mockFetch, renderWithQuery } from "../case/testUtils";
import { EvidenceTree } from "./EvidenceTree";
import { LIVE_BANNER_FALLBACK, liveBannerText } from "./LiveRunBanner";
import { buildTreeModel, filterEmptyNodes, type TreeModelNode } from "./model";

configure({ asyncUtilTimeout: 5000 });

const LIVE_MESSAGE = "런 진행 중 · 완료된 그룹만 표시 · 검색/타임라인은 마무리 후";

const tree: RunTree = {
  run_id: "r1",
  root: {},
  live: {
    run_status: "running",
    partial: true,
    available_kinds: ["windows-system"],
    pending_kinds: ["eventlog"],
    message: LIVE_MESSAGE,
  },
  nodes: [
    {
      id: "artifacts:eventlog",
      label: "EVTX",
      count: 0,
      collection: "artifacts",
      kind: "eventlog",
      state: "running",
      disabled: true,
      reason: "처리 중 (그룹 이벤트 로그)",
    },
    {
      id: "artifacts:windows-system",
      label: "Windows 시스템",
      count: 9,
      collection: "artifacts",
      kind: "windows-system",
      state: "partial",
      artifact_type_counts: { "web-server-log": 5, "wer-report": 4 },
    },
  ],
};

function flatten(nodes: TreeModelNode[]): TreeModelNode[] {
  return nodes.flatMap((node) => [node, ...flatten(node.children ?? [])]);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("live tree model", () => {
  it("dims unfinished kinds with the server reason and keeps finished kinds openable", () => {
    const model = buildTreeModel({ tree });
    const all = flatten(model);
    const eventlog = all.filter((node) => node.target?.kind === "eventlog");
    expect(eventlog.length).toBeGreaterThan(0);
    for (const node of eventlog) {
      expect(node.disabledReason).toBe("처리 중 (그룹 이벤트 로그)");
      expect(node.dimmed).toBe(true);
      expect(node.marker).toBe("처리 중");
      expect(node.hiddenReason).toBeUndefined();
    }
    // Not hidden by the "결과 없는 계열" filter: the examiner sees what is still coming.
    const shown = flatten(filterEmptyNodes(model, false).nodes);
    expect(shown.some((node) => node.target?.kind === "eventlog")).toBe(true);
    const system = all.find((node) => node.target?.kind === "windows-system" && !node.target.types?.length);
    expect(system?.disabledReason).toBeUndefined();
    expect(system?.count).toBe(9);
    expect(system?.marker).toBe("일부 완료");
  });

  it("banner text falls back by run state", () => {
    expect(liveBannerText({ message: LIVE_MESSAGE })).toBe(LIVE_MESSAGE);
    expect(liveBannerText({ run_status: "running" })).toBe(LIVE_BANNER_FALLBACK);
    expect(liveBannerText({ run_status: "interrupted" })).toContain("런 중단됨");
    expect(liveBannerText({ run_status: "canceled" })).toContain("런 취소됨");
  });
});

describe("EvidenceTree on a running run", () => {
  it("shows the live banner and refuses to open a pending kind with its reason", async () => {
    mockFetch({
      "GET /api/runs": { runs: [{ run_id: "r1", status: "running" }] },
      "GET /api/runs/r1/summary": new Response(
        JSON.stringify({ detail: "런 마무리 후 사용할 수 있습니다" }),
        {
          status: 409,
        },
      ),
      "GET /api/runs/r1/tree": tree,
    });
    renderWithQuery(<EvidenceTree runId="r1" />);
    const banner = await screen.findByTestId("live-run-banner");
    expect(banner.textContent).toContain(LIVE_MESSAGE);
    expect(banner.textContent).toContain("열람 가능 1 · 대기 1");
    fireEvent.change(screen.getByRole("searchbox", { name: "트리 검색" }), { target: { value: "EVTX" } });
    const pending = await screen.findAllByRole("treeitem", { name: /\(처리 중\)/ });
    const item = pending[0] as HTMLElement;
    expect(item.getAttribute("aria-disabled")).toBe("true");
    expect(item.className).toContain("is-dimmed");
    fireEvent.click(item);
    await waitFor(() => expect(screen.getByText("처리 중 (그룹 이벤트 로그)")).toBeTruthy());
    expect(window.location.hash).not.toContain("eventlog");
  });
});
