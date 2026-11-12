// Tag manager author field and tag history (T-144): the 작성자 field never shows web-ui, and the
// history never reads 태그 없음 → 없음 for an unchanged tag set.
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetCommandRegistry } from "../../commands/registry";
import { resetAppStore } from "../../state/store";
import { mockFetch, renderWithQuery } from "../case/testUtils";
import { resetCaseDbHandles } from "../grid/reviewActions";
import { changedLabel, tagsChanged } from "./NotePanel";
import { resetRowSources } from "./rowSource";
import { TagManagerDialog } from "./TagManagerDialog";
import { resetTagKeyFlights } from "./tagKeys";
import { resetCaseTagStore } from "./tagStore";
import { caseRoutes, SYSTEM, tag } from "./tagTestData";
import { reloadViewPrefs } from "./viewPrefs";

const announceMock = vi.hoisted(() => vi.fn());
vi.mock("../../a11y", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../a11y")>()),
  announce: announceMock,
}));

beforeEach(() => {
  resetCommandRegistry();
  resetCaseTagStore();
  resetCaseDbHandles();
  resetRowSources();
  resetTagKeyFlights();
  resetAppStore({ route: { runId: null, collection: null } });
  announceMock.mockReset();
  window.localStorage.clear();
  reloadViewPrefs();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("tag manager author field and tag history (T-144)", () => {
  it("the 작성자 field never shows web-ui: empty value, placeholder 담당자 이름, legacy web-ui author hidden", async () => {
    mockFetch(caseRoutes([...SYSTEM, tag({ id: 9, name: "옛 태그", created_by: "web-ui" })]));
    renderWithQuery(<TagManagerDialog runId="r1" onClose={vi.fn()} />);
    const dialog = await screen.findByRole("dialog", { name: "태그 관리" });
    await waitFor(() => expect(within(dialog).getAllByTestId("tag-row")).toHaveLength(7));
    const field = within(dialog).getByLabelText("작성자 (태그·메모에 기록)") as HTMLInputElement;
    expect(field.value).toBe("");
    expect(field.placeholder).toBe("담당자 이름");
    expect(dialog.textContent).not.toContain("web-ui");
    // A typed name is kept for the next tag / memo.
    fireEvent.change(field, { target: { value: " 김 수사관 " } });
    fireEvent.blur(field);
    expect(window.localStorage.getItem("rapidtriage.reviewer")).toContain("김 수사관");
  });

  it("history never reads 태그 없음 → 없음 when the tag set did not change", () => {
    const entry = {
      changed_fields: ["note", "tags"],
      tags_before: [] as string[],
      tags_after: [] as string[],
    } as unknown as Parameters<typeof tagsChanged>[0];
    expect(tagsChanged(entry)).toBe(false);
    expect(changedLabel(entry)).toBe("메모");
    const same = { ...entry, tags_before: ["b", "a"], tags_after: ["a", "b"] };
    expect(tagsChanged(same)).toBe(false);
    const real = { ...entry, tags_before: [], tags_after: ["북마크"] };
    expect(tagsChanged(real)).toBe(true);
    expect(changedLabel(real)).toBe("메모, 태그");
  });
});
