import { describe, expect, it } from "vitest";
import type { GridRow } from "../../../contracts/collection";
import { timestampKindLabel } from "../../../utils/timeKinds";
import { artifactTypeLabel } from "../../filters/typeLabels";
import {
  EVENTLOG_CATEGORY_LABELS,
  eventTypeLabel,
  timelineEventLabel,
  timelineSummaryText,
} from "./timeline";

describe("타임라인 이벤트 column reads event types in Korean (#77 남은 것)", () => {
  it("names a files event by its time kind", () => {
    expect(eventTypeLabel("file-created")).toBe(`파일 · ${timestampKindLabel("created")}`);
  });

  it("names an event-log event by its category, an unnamed category stays the id", () => {
    const evtx = artifactTypeLabel("eventlog-event") ?? "이벤트 로그";
    expect(eventTypeLabel("eventlog-logon-success")).toBe(
      `${evtx} · ${EVENTLOG_CATEGORY_LABELS["logon-success"]}`,
    );
    expect(eventTypeLabel("eventlog-never-heard-of")).toBe("eventlog-never-heard-of");
  });

  it("splits an artifact id into the longest named type and its time kind without a source type", () => {
    // amcache-entry is a helper row no tree node names alone (UNLISTED_TYPE_LABELS).
    expect(eventTypeLabel("artifact-amcache-entry-last-written")).toBe(
      `Amcache 항목 · ${timestampKindLabel("last-written")}`,
    );
    expect(eventTypeLabel("artifact-kakaotalk-memory-dump-skipped-observed")).toBe(
      `카카오톡 메모리 덤프(건너뜀) · ${timestampKindLabel("observed")}`,
    );
  });

  it("uses the row's source artifact type when it has one", () => {
    expect(eventTypeLabel("artifact-bam-entry-run", "bam-entry")).toBe(
      `BAM 실행 기록 · ${timestampKindLabel("run")}`,
    );
    expect(eventTypeLabel("something-else", "bam-entry")).toBe("BAM 실행 기록");
    const row = {
      artifactType: "artifact-srum-app-usage-recorded",
      fields: { sourceArtifactType: "srum-app-usage" },
    } as unknown as GridRow;
    expect(timelineEventLabel(row)).toBe(`SRUM 앱 사용량 · ${timestampKindLabel("recorded")}`);
  });

  it("요약 drops the builder's English artifact lead-in, other summaries stay", () => {
    expect(timelineSummaryText("Artifact event: browser-history https://bank.example.test/")).toBe(
      "https://bank.example.test/",
    );
    expect(timelineSummaryText("Artifact event: browser-history ")).toBe("Artifact event: browser-history ");
    expect(timelineSummaryText("AI usage: ChatGPT")).toBe("AI usage: ChatGPT");
  });

  it("keeps an unknown id and an empty one as they are", () => {
    expect(eventTypeLabel("")).toBe("");
    expect(eventTypeLabel("artifact-unheard-of-thing")).toBe("artifact-unheard-of-thing");
  });
});
