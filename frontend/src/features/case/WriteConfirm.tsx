/**
 * Write confirmation (r7 L4, console review D8 "쓰기 동작에는 항상 확인·피드백"): every action that
 * writes on the analyst's machine — 샘플 실행, 검증 패키지 내보내기, 통합 보기 다시 만들기, 그룹
 * 건너뛰기 — first says WHAT is written WHERE and waits for an explicit 확인. Nothing is sent before
 * it. `confirmWrite()` is callable from commands (non-React code); `WriteConfirmHost` (mounted once
 * by the shell) renders the dialog. After the write, `notifyWritten()` shows the completion toast
 * with the path and an 열기 link.
 */

import { useEffect, useRef } from "react";
import { create } from "zustand";
import { announce } from "../../a11y";
import { getRun } from "../../api/runs";
import { pushToast, type ToastAction } from "../../components/toastStore";
import "../../components/toast.css";
import { Modal } from "./Modal";

export interface WriteTarget {
  /** What is written ("검증 패키지(JSON)·감사 기록"). */
  what: string;
  /** Where ("D:\…\run\rapidforensic-run-validation-package.json"). */
  where: string;
}

export interface WriteConfirmRequest {
  title: string;
  writes: WriteTarget[];
  /** Extra sentence under the list (e.g. "원본 증거는 바꾸지 않습니다."). */
  note?: string;
  confirmLabel: string;
}

interface WriteConfirmState {
  pending: (WriteConfirmRequest & { resolve: (ok: boolean) => void }) | null;
  open: (request: WriteConfirmRequest) => Promise<boolean>;
  settle: (ok: boolean) => void;
}

export const useWriteConfirm = create<WriteConfirmState>((set, get) => ({
  pending: null,
  open: (request) =>
    new Promise<boolean>((resolve) => {
      // A second request replaces (and declines) one still open: never two write dialogs.
      get().pending?.resolve(false);
      set({ pending: { ...request, resolve } });
    }),
  settle: (ok) => {
    const pending = get().pending;
    set({ pending: null });
    pending?.resolve(ok);
  },
}));

/** Ask before a write; resolves true only on the dialog's confirm button. */
export function confirmWrite(request: WriteConfirmRequest): Promise<boolean> {
  return useWriteConfirm.getState().open(request);
}

/** Completion toast of a write: what was written, the path, and 열기 when there is a read-only link. */
export function notifyWritten(text: string, path: string | null | undefined, action?: ToastAction): void {
  announce(path ? `${text} ${path}` : text);
  pushToast(text, "ok", { ...(path ? { detail: path } : {}), ...(action ? { action } : {}) });
}

/** Failure toast of a write (Korean; the server's own message when it sent one). */
export function notifyWriteFailed(what: string, error: unknown): void {
  const reason = error instanceof Error && error.message ? error.message : "알 수 없는 오류";
  announce(`${what} 실패: ${reason}`, { politeness: "assertive" });
  pushToast(`${what} 실패: ${reason}`, "error");
}

/** Placeholder of the run folder until it is known (never a guessed path). */
export const RUN_FOLDER_UNKNOWN = "이 런의 출력 폴더";

const outputDirs = new Map<string, Promise<string | null>>();

/** The run's output folder (`summary.output_dir`), once per run; null when the server has none. */
export function runOutputDir(runId: string): Promise<string | null> {
  let hit = outputDirs.get(runId);
  if (!hit) {
    hit = getRun(runId).then(
      (run) => (typeof run.summary?.output_dir === "string" && run.summary.output_dir) || null,
      () => {
        outputDirs.delete(runId);
        return null;
      },
    );
    outputDirs.set(runId, hit);
  }
  return hit;
}

/** `<folder>\<name>` with the folder's own separator. */
export function joinRunPath(folder: string | null, name: string): string {
  if (!folder) return `${RUN_FOLDER_UNKNOWN}\\${name}`;
  const sep = folder.includes("\\") ? "\\" : "/";
  return `${folder.replace(/[\\/]+$/, "")}${sep}${name}`;
}

/** The one write-confirmation dialog of the console. */
export function WriteConfirmHost() {
  const pending = useWriteConfirm((s) => s.pending);
  const settle = useWriteConfirm((s) => s.settle);
  const okRef = useRef<HTMLButtonElement>(null);
  // Cancel is the safe default focus: Enter on an unread dialog must not write.
  const cancelRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (pending) cancelRef.current?.focus();
  }, [pending]);
  if (!pending) return null;
  return (
    <Modal
      title={pending.title}
      onClose={() => settle(false)}
      footer={
        <>
          <button
            ref={cancelRef}
            type="button"
            className="button roomy"
            data-testid="write-confirm-cancel"
            onClick={() => settle(false)}
          >
            취소
          </button>
          <button
            ref={okRef}
            type="button"
            className="button primary roomy"
            data-testid="write-confirm-ok"
            onClick={() => settle(true)}
          >
            {pending.confirmLabel}
          </button>
        </>
      }
    >
      <div data-testid="write-confirm">
        <p className="case-help">다음 파일을 씁니다. 확인을 누르기 전에는 아무것도 쓰지 않습니다.</p>
        <ul className="write-confirm-list">
          {pending.writes.map((item) => (
            <li key={`${item.what}|${item.where}`}>
              <strong>{item.what}</strong>
              <div className="write-confirm-where" data-testid="write-confirm-where">
                {item.where}
              </div>
            </li>
          ))}
        </ul>
        {pending.note ? <p className="case-reason">{pending.note}</p> : null}
      </div>
    </Modal>
  );
}
