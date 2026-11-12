/**
 * The timeline 이벤트 section shows result-folder paths as in-evidence paths (IS-128, T-172;
 * re-verify @91fe6e9: a LNK event row printed `…\_e01\fs\…` twice outside 기술 정보).
 */
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { GridRow } from "../../../contracts/collection";
import type { ViewerTarget } from "../../../contracts/viewer";
import { MetaView } from "./MetaView";

afterEach(cleanup);

const STAGE = "D:\\out\\run1\\_e01\\fs\\Users\\u\\Recent\\A.lnk";

function timelineRow(): GridRow {
  return {
    rowKey: "timeline:/events/7",
    ref: { collection: "timeline", locator: "/events/7" },
    title: "바로 가기",
    sourcePath: STAGE,
    timestamp: "2024-03-01T10:00:00+00:00",
    artifactType: "lnk-file",
    provider: null,
    sha256: null,
    reviewStatus: null,
    tags: [],
    fields: {
      targetFull: STAGE,
      sourceArtifactType: "lnk-file",
      details: {},
      groupSources: [
        { artifactType: "lnk-file", path: STAGE, recordIndex: 0 },
        { artifactType: "jumplist-entry", path: "D:\\out\\run1\\_e01\\fs\\$OrphanFiles\\x.lnk", recordIndex: null },
      ],
    },
  } as GridRow;
}

describe("timeline event section paths", () => {
  it("shows no result-folder string and reads recovery folders as unknown", () => {
    const target = {
      runId: "run-1",
      ref: { collection: "timeline", locator: "/events/7" },
      sourcePath: STAGE,
    } as ViewerTarget;
    render(
      <MetaView
        target={target}
        preview={null}
        metadata={null}
        metadataError={null}
        hashBusy={false}
        row={timelineRow()}
        sessionMarks={[]}
        onComputeHash={() => {}}
      />,
    );
    const section = screen.getByTestId("timeline-event-section");
    expect(section.textContent).not.toMatch(/_e01|D:\\out/);
    expect(section.textContent).toContain("\\Users\\u\\Recent\\A.lnk");
    expect(section.textContent).toContain("원래 위치 알 수 없음");
  });
});
