/**
 * R3 console fix #7: tree-node server filters without a grid column (이벤트 로그 채널 그룹, ntfs-meta
 * 출처 / 사용 중, 카빙 서명 종류 / 복구 방법) show as removable Korean chips; removing one writes the
 * route (the grid refetches from it).
 */
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { ColumnFilter } from "../../contracts/collection";
import { parseHash } from "../../router";
import { useAppStore } from "../../state/store";
import { FilterBar } from "./FilterBar";
import {
  activeChips,
  CHANNEL_GROUP_FILTER_COLUMN,
  EMPTY_FILTERS,
  type FilterState,
  hiddenFilterLabel,
  removeChip,
} from "./filterModel";
import { useFilterStore } from "./filterStore";

const HASH = "#/case/r1/analysis/ntfs-meta";

const columns: ColumnFilter[] = [
  { col: CHANNEL_GROUP_FILTER_COLUMN, op: ":", value: "security|firewall" },
  { col: "f:source", op: ":", value: "timestamp-mismatch" },
  { col: "f:in_use", op: ":", value: "false" },
  { col: "f:signature_kind", op: ":", value: "wav,mp3" },
  { col: "f:recovery_method", op: ":", value: "carved" },
  // A visible column's own header filter is not a chip (the filter row shows it).
  { col: "d:reason", op: ":", value: "생성" },
];

beforeEach(() => {
  window.location.hash = HASH;
  useAppStore.setState({ route: parseHash(HASH) });
  useFilterStore.setState({ filters: EMPTY_FILTERS, report: null });
});
afterEach(() => {
  cleanup();
  window.location.hash = "";
});

describe("hidden server filter chips", () => {
  it("label every hidden filter in Korean", () => {
    const filters: FilterState = { ...EMPTY_FILTERS, columns };
    expect(activeChips(filters, (s) => s).map((chip) => chip.label)).toEqual([
      "채널 보안, 방화벽(이벤트 채널)",
      "출처 타임스탬프 불일치",
      "삭제된 레코드",
      "서명 종류 WAV 오디오, MP3 오디오",
      "복구 방법 카빙",
    ]);
    // The run's /tree labels win over the bundled ones.
    expect(
      hiddenFilterLabel(columns[0] as ColumnFilter, { channelGroupLabels: { security: "보안 로그" } }),
    ).toBe("채널 보안 로그, 방화벽(이벤트 채널)");
    expect(hiddenFilterLabel({ col: "f:in_use", op: ":", value: "true" })).toBe("사용 중인 레코드");
    expect(hiddenFilterLabel({ col: "f:source", op: ":", value: "mft,usn" })).toBe("출처 MFT·USN 저널");
  });

  it("removing one drops only that filter", () => {
    const filters: FilterState = { ...EMPTY_FILTERS, columns };
    const chip = activeChips(filters, (s) => s).find((c) => c.label === "삭제된 레코드");
    if (!chip) throw new Error("chip missing");
    const next = removeChip(filters, chip);
    expect(next.columns.map((f) => f.col)).toEqual([
      CHANNEL_GROUP_FILTER_COLUMN,
      "f:source",
      "f:signature_kind",
      "f:recovery_method",
      "d:reason",
    ]);
  });

  it("FilterBar shows the chip and removing it rewrites the route", () => {
    act(() =>
      useFilterStore.getState().setFilters({
        ...EMPTY_FILTERS,
        columns: [
          { col: "f:source", op: ":", value: "timestamp-mismatch" },
          { col: "f:in_use", op: ":", value: "true" },
        ],
      }),
    );
    expect(useAppStore.getState().route.cf).toHaveLength(2);
    render(<FilterBar filterRef={{ current: null }} query="" onQuery={() => {}} onReturnToGrid={() => {}} />);
    fireEvent.click(screen.getByRole("button", { name: /사용 중인 레코드 조건 제거/ }));
    expect(useAppStore.getState().route.cf).toEqual([
      { col: "f:source", op: ":", value: "timestamp-mismatch" },
    ]);
    expect(window.location.hash).not.toContain("in_use");
  });
});
