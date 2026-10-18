import type { ReactNode } from "react";
import { normalizeRunStatus } from "../api/runs";
import { chipToneOf, ToneChip } from "./ToneChip";

export type BadgeTone = "ok" | "warn" | "danger" | "info" | "muted";

/** Run, plan group and plan task states (R4 V1); `canceled` reads as `cancelled`. */
const STATUS_TONE: Record<string, BadgeTone> = {
  completed: "ok",
  running: "info",
  queued: "muted",
  failed: "danger",
  cancelled: "warn",
  partial: "warn",
  interrupted: "warn",
  skipped: "muted",
};

const STATUS_LABEL: Record<string, string> = {
  completed: "완료",
  running: "실행 중",
  queued: "대기",
  failed: "실패",
  cancelled: "취소됨",
  partial: "일부 완료",
  interrupted: "중단됨",
  skipped: "건너뜀",
};

export function statusTone(status: string): BadgeTone {
  return STATUS_TONE[normalizeRunStatus(status)] ?? "muted";
}

export function statusLabel(status: string): string {
  return STATUS_LABEL[normalizeRunStatus(status)] ?? status;
}

export function Badge({ tone, children }: { tone: BadgeTone; children: ReactNode }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

/** A run's state as the shared dot + text chip (review #24), the same one tables and cards use. */
export function StatusBadge({ status, title }: { status: string; title?: string }) {
  const normalized = normalizeRunStatus(status) || status;
  return (
    <ToneChip tone={chipToneOf(normalized)} title={title}>
      {statusLabel(status)}
    </ToneChip>
  );
}
