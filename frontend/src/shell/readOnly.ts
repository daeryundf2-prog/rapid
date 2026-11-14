/**
 * Read-only results (R8 T-348, decision D37 / T-112). The server says why nothing may be written:
 *
 * - `GET /api/runs/{id}/dashboard` → `readonly_reason` of the open run: "OUTPUT_INSIDE_EVIDENCE"
 *   (a result folder inside its evidence, opened read-only) or "SERVER_READ_ONLY";
 * - `GET /api/health` → `read_only` (`rapidtriage web --read-only`: nothing is written anywhere).
 *
 * `ReadOnlyBanner` reads both and keeps this module's store current; every write control asks
 * `useWriteBlock(scope)` (React) or `writeBlockReason(scope)` (commands) and stays visible but inert
 * with the same sentence as its tooltip, so a read-only result never answers a click with a 409
 * toast. A 409 `RUN_READ_ONLY` that still arrives is shown with that sentence too
 * (`readOnlyErrorSentence`), never as a generic failure.
 *
 * Scopes: "run" — writes into the open result (marks, tags, notes, exports, analyses, index);
 * blocked by a read-only run or server. "server" — writes elsewhere (cases, new results, imports);
 * blocked by a read-only server only.
 */

import { create } from "zustand";
import { ApiError } from "../api/errors";

export type WriteScope = "run" | "server";

export const OUTPUT_INSIDE_EVIDENCE = "OUTPUT_INSIDE_EVIDENCE";
export const SERVER_READ_ONLY = "SERVER_READ_ONLY";
/** T-360 (archived case) — the band already knows its sentence. */
export const ARCHIVED_CASE = "ARCHIVED_CASE";

const SENTENCES: Readonly<Record<string, string>> = {
  [OUTPUT_INSIDE_EVIDENCE]: "읽기 전용 결과 — 결과 폴더가 증거 안에 있어 이 결과에는 아무것도 쓰지 않습니다",
  [SERVER_READ_ONLY]: "읽기 전용 서버 — 서버를 읽기 전용으로 실행해 쓰기 동작을 모두 껐습니다",
  [ARCHIVED_CASE]: "보관된 사건 — 보관을 풀어야 고칠 수 있습니다",
};
const FALLBACK_SENTENCE = "읽기 전용 결과 — 이 결과에는 쓰지 않습니다";

/** The one Korean sentence of a read-only reason (band text and every disabled control's tooltip). */
export function readOnlySentence(reason: string): string {
  return SENTENCES[reason] ?? FALLBACK_SENTENCE;
}

interface ReadOnlyState {
  /** The open run and its own reason (null: writable or not known yet). */
  runId: string | null;
  runReason: string | null;
  serverReadOnly: boolean;
  setRun: (runId: string | null, reason: string | null) => void;
  setServerReadOnly: (readOnly: boolean) => void;
}

export const useReadOnlyStore = create<ReadOnlyState>((set, get) => ({
  runId: null,
  runReason: null,
  serverReadOnly: false,
  setRun: (runId, reason) => {
    const current = get();
    if (current.runId !== runId || current.runReason !== reason) set({ runId, runReason: reason });
  },
  setServerReadOnly: (readOnly) => {
    if (get().serverReadOnly !== readOnly) set({ serverReadOnly: readOnly });
  },
}));

/** The reason code that blocks a write of `scope` now, else null. */
export function readOnlyReasonOf(
  state: Pick<ReadOnlyState, "runReason" | "serverReadOnly">,
  scope: WriteScope = "run",
): string | null {
  if (state.serverReadOnly) return SERVER_READ_ONLY;
  return scope === "run" ? state.runReason : null;
}

/** Tooltip / disabled reason of a write control of `scope` (undefined: it may write). */
export function writeBlockReason(scope: WriteScope = "run"): string | undefined {
  const reason = readOnlyReasonOf(useReadOnlyStore.getState(), scope);
  return reason ? readOnlySentence(reason) : undefined;
}

/** React view of `writeBlockReason`: re-renders when the run or the server turns read-only. */
export function useWriteBlock(scope: WriteScope = "run"): string | undefined {
  const reason = useReadOnlyStore((s) => readOnlyReasonOf(s, scope));
  return reason ? readOnlySentence(reason) : undefined;
}

/** The band's reason: the run's own, else the server's (null: no band). */
export function useReadOnlyReason(): string | null {
  return useReadOnlyStore((s) => readOnlyReasonOf(s, "run"));
}

// --- commands -----------------------------------------------------------------------------------

/**
 * Commands that write into the open result. Opening a dialog that only shows (태그 관리, 메모 패널)
 * stays enabled; its own save buttons ask `useWriteBlock`.
 */
const RUN_WRITE_COMMANDS: readonly RegExp[] = [
  /^review\.(mark\.|priority\.|tagKey\.)/,
  /^review\.undo$/,
  /^review\.tags\.propagate/,
  /^viewer\.(mark\.|note$)/,
  /^grid\.batch\./,
  /^grid\.row\.(relevant|needs-review|excluded|include-in-report|bookmark|tag)$/,
  /^grid\.ocrSelected$/,
  /^analysis\.(run|snapshot)\./,
  /^derived\.rebuild$/,
  /^search\.save$/,
  /^export\.(open|case-report|reviewer-bundle|submission-manifest|validation-package)$/,
  /^case\.retry$/,
  /^run\.resume$/,
];
/** Commands that write outside the open result (blocked on a read-only server only). */
const SERVER_WRITE_COMMANDS: readonly RegExp[] = [
  /^case\.(create|link|edit|evidence\.add|run\.add|run\.new|run|import|sample|delete|cancel)$/,
  /^run\.plan\./,
  /^analysis\.cancel$/,
];

/** The write scope of a command id, or null when it writes nothing. */
export function commandWriteScope(id: string): WriteScope | null {
  if (RUN_WRITE_COMMANDS.some((pattern) => pattern.test(id))) return "run";
  if (SERVER_WRITE_COMMANDS.some((pattern) => pattern.test(id))) return "server";
  return null;
}

/** Disabled reason of a command because the result / server is read-only (undefined: not blocked). */
export function commandReadOnlyReason(id: string): string | undefined {
  const scope = commandWriteScope(id);
  return scope ? writeBlockReason(scope) : undefined;
}

// --- 409 RUN_READ_ONLY ------------------------------------------------------------------------

/** The read-only sentence of a refused write (409 `RUN_READ_ONLY`), else null. */
export function readOnlyErrorSentence(error: unknown): string | null {
  if (!(error instanceof ApiError) || error.code !== "RUN_READ_ONLY") return null;
  const detail = error.detail;
  const reason =
    detail &&
    typeof detail === "object" &&
    typeof (detail as { readonly_reason?: unknown }).readonly_reason === "string"
      ? (detail as { readonly_reason: string }).readonly_reason
      : "";
  return readOnlySentence(reason);
}
