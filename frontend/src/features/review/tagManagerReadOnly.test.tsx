// T-348 (verify WB-10): on a read-only result the tag manager's write buttons stay visible,
// disabled with the read-only sentence.
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readOnlySentence, SERVER_READ_ONLY, useReadOnlyStore } from "../../shell/readOnly";
import { mockFetch, renderWithQuery } from "../case/testUtils";
import { resetCaseDbHandles } from "../grid/reviewActions";
import { TagManagerDialog } from "./TagManagerDialog";
import { resetCaseTagStore } from "./tagStore";
import { caseRoutes, SYSTEM, tag } from "./tagTestData";

beforeEach(() => {
  resetCaseTagStore();
  resetCaseDbHandles();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("tag manager on a read-only result", () => {
  it("read-only: 편집 · 삭제 · 새 태그 are disabled with the read-only sentence (T-348)", async () => {
    mockFetch(caseRoutes([...SYSTEM, tag({ id: 9, name: "하 태그", count: 2 })]));
    useReadOnlyStore.setState({ serverReadOnly: true });
    try {
      renderWithQuery(<TagManagerDialog runId="r1" onClose={() => undefined} />);
      const dialog = await screen.findByRole("dialog", { name: "태그 관리" });
      await waitFor(() => expect(within(dialog).getAllByTestId("tag-row")).toHaveLength(7));
      const sentence = readOnlySentence(SERVER_READ_ONLY);
      for (const name of ["하 태그 태그 편집", "하 태그 태그 삭제", "북마크 태그 편집", "북마크 태그 삭제"]) {
        const button = within(dialog).getByRole("button", { name });
        expect(button.getAttribute("aria-disabled")).toBe("true");
        expect(button.getAttribute("title")).toBe(sentence);
      }
      const create = within(dialog).getByTestId("tag-new");
      expect(create.getAttribute("aria-disabled")).toBe("true");
      expect(create.getAttribute("title")).toBe(sentence);
      fireEvent.click(create);
      fireEvent.click(within(dialog).getByRole("button", { name: "하 태그 태그 편집" }));
      expect(within(dialog).queryByRole("form")).toBeNull();
    } finally {
      useReadOnlyStore.setState({ serverReadOnly: false });
    }
  });
});
