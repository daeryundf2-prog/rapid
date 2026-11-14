// T-348: read-only band + disabled writes. The band reads `readonly_reason` of the run dashboard
// and `read_only` of /api/health; write commands and write buttons carry the same sentence, and a
// 409 RUN_READ_ONLY never reads as a generic failure.

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { normalizeDashboard } from "../api/dashboard";
import { ApiError } from "../api/errors";
import { disabledReasonOf, getCommand, registerCommand, resetCommandRegistry } from "../commands/registry";
import { useToastStore } from "../components/toastStore";
import { ReasonButton } from "../features/case/ReasonButton";
import { notifyWriteFailed } from "../features/case/WriteConfirm";
import { resetAppStore } from "../state/store";
import { ReadOnlyBanner } from "./ReadOnlyBanner";
import {
  commandWriteScope,
  OUTPUT_INSIDE_EVIDENCE,
  readOnlyErrorSentence,
  readOnlySentence,
  SERVER_READ_ONLY,
  useReadOnlyStore,
  useWriteBlock,
  type WriteScope,
  writeBlockReason,
} from "./readOnly";

const RUN = "run-ro";
const CTX = {
  runId: RUN,
  collection: null,
  selectedRowKeys: [],
  focusedRowKey: null,
  viewerHasTarget: true,
  runIsActive: false,
};

function client(reason: string | null, serverReadOnly = false): QueryClient {
  const queries = new QueryClient({
    defaultOptions: { queries: { staleTime: Number.POSITIVE_INFINITY, retry: false } },
  });
  queries.setQueryData(["server-read-only"], serverReadOnly);
  queries.setQueryData(
    ["run-dashboard", RUN],
    normalizeDashboard(RUN, { run_id: RUN, readonly_reason: reason }),
  );
  return queries;
}

/** The registered command's disabled reason (the registry wraps write commands). */
function reasonOf(id: string): string | undefined {
  const command = getCommand(id);
  if (!command) throw new Error(`not registered: ${id}`);
  return disabledReasonOf(command, CTX);
}

function renderBanner(queries: QueryClient) {
  return render(
    <QueryClientProvider client={queries}>
      <ReadOnlyBanner />
    </QueryClientProvider>,
  );
}

function WriteButton({ scope }: { scope: WriteScope }) {
  const block = useWriteBlock(scope);
  return <ReasonButton reason={block}>저장</ReasonButton>;
}

beforeEach(() => {
  resetAppStore({ route: { runId: RUN, collection: null } });
  useReadOnlyStore.setState({ runId: null, runReason: null, serverReadOnly: false });
  useToastStore.getState().clear();
  resetCommandRegistry();
});

afterEach(() => {
  cleanup();
  resetCommandRegistry();
});

describe("ReadOnlyBanner", () => {
  it("shows one band with the run's reason", () => {
    renderBanner(client(OUTPUT_INSIDE_EVIDENCE));
    const bands = screen.getAllByTestId("readonly-band");
    expect(bands).toHaveLength(1);
    expect(bands[0]?.textContent).toBe(readOnlySentence(OUTPUT_INSIDE_EVIDENCE));
    expect(bands[0]?.textContent).toContain("결과 폴더가 증거 안에");
    expect(writeBlockReason("run")).toBe(readOnlySentence(OUTPUT_INSIDE_EVIDENCE));
    // A read-only result does not block writes elsewhere (cases, new results).
    expect(writeBlockReason("server")).toBeUndefined();
  });

  it("shows the server reason on a read-only server, even before a run is open", () => {
    resetAppStore({ route: { runId: null, collection: null } });
    renderBanner(client(null, true));
    expect(screen.getByTestId("readonly-band").dataset.reason).toBe(SERVER_READ_ONLY);
    expect(writeBlockReason("server")).toBe(readOnlySentence(SERVER_READ_ONLY));
  });

  it("shows nothing for a writable run", () => {
    renderBanner(client(null));
    expect(screen.queryByTestId("readonly-band")).toBeNull();
    expect(writeBlockReason("run")).toBeUndefined();
  });

  it("renders without a QueryClient (bare shell)", () => {
    render(<ReadOnlyBanner />);
    expect(screen.queryByTestId("readonly-band")).toBeNull();
  });
});

describe("write controls", () => {
  it("disables a write button with the reason as tooltip", () => {
    renderBanner(client(OUTPUT_INSIDE_EVIDENCE));
    render(<WriteButton scope="run" />);
    const button = screen.getByRole("button", { name: "저장" });
    expect(button.getAttribute("aria-disabled")).toBe("true");
    expect(button.getAttribute("title")).toBe(readOnlySentence(OUTPUT_INSIDE_EVIDENCE));
  });

  it("gates the four write kinds: marks, memos, exports, index builds", () => {
    const ids = [
      "review.mark.relevant",
      "grid.batch.excluded",
      "grid.row.tag",
      "review.priority.1",
      "viewer.mark.bookmark",
      "export.case-report",
      "export.open",
      "analysis.run.search-index",
      "derived.rebuild",
      "search.save",
    ];
    for (const id of ids) {
      registerCommand({ id, label: id, group: "review", run: () => undefined });
      expect(commandWriteScope(id)).toBe("run");
    }
    registerCommand({ id: "export.report", label: "보고서", group: "export", run: () => undefined });
    registerCommand({ id: "case.edit", label: "사건 정보 편집", group: "case", run: () => undefined });
    expect(commandWriteScope("export.report")).toBeNull(); // navigates to 보고 only

    for (const id of ids) expect(reasonOf(id)).toBeUndefined();
    act(() => useReadOnlyStore.getState().setRun(RUN, OUTPUT_INSIDE_EVIDENCE));
    const sentence = readOnlySentence(OUTPUT_INSIDE_EVIDENCE);
    for (const id of ids) expect(reasonOf(id)).toBe(sentence);
    expect(reasonOf("export.report")).toBeUndefined();
    expect(reasonOf("case.edit")).toBeUndefined();
    act(() => useReadOnlyStore.getState().setServerReadOnly(true));
    expect(reasonOf("case.edit")).toBe(readOnlySentence(SERVER_READ_ONLY));
  });

  it("keeps a command's own reason when the result is writable", () => {
    registerCommand({
      id: "review.mark.excluded",
      label: "제외",
      group: "review",
      disabledReason: () => "행을 고르세요",
      run: () => undefined,
    });
    expect(reasonOf("review.mark.excluded")).toBe("행을 고르세요");
  });
});

describe("409 RUN_READ_ONLY", () => {
  const refused = new ApiError(
    "서버 문장",
    409,
    { code: "RUN_READ_ONLY", readonly_reason: SERVER_READ_ONLY },
    {
      code: "RUN_READ_ONLY",
    },
  );

  it("maps to the band's sentence", () => {
    expect(readOnlyErrorSentence(refused)).toBe(readOnlySentence(SERVER_READ_ONLY));
    expect(readOnlyErrorSentence(new ApiError("x", 409, null, { code: "CONFLICT" }))).toBeNull();
    expect(readOnlyErrorSentence(new Error("x"))).toBeNull();
  });

  it("is shown as information, not as a failed write", () => {
    notifyWriteFailed("보고서 내보내기", refused);
    const toasts = useToastStore.getState().toasts;
    expect(toasts).toHaveLength(1);
    expect(toasts[0]?.tone).toBe("info");
    expect(toasts[0]?.text).toBe(readOnlySentence(SERVER_READ_ONLY));
    expect(toasts[0]?.text).not.toContain("실패");
  });
});
