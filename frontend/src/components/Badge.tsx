import type { ReactNode } from "react";

export type BadgeTone = "ok" | "warn" | "danger" | "info" | "muted";

const STATUS_TONE: Record<string, BadgeTone> = {
  completed: "ok",
  running: "info",
  queued: "muted",
  failed: "danger",
  cancelled: "warn",
};

const STATUS_LABEL: Record<string, string> = {
  completed: "완료",
  running: "실행 중",
  queued: "대기",
  failed: "실패",
  cancelled: "취소됨",
};

export function statusTone(status: string): BadgeTone {
  return STATUS_TONE[status] ?? "muted";
}

export function statusLabel(status: string): string {
  return STATUS_LABEL[status] ?? status;
}

export function Badge({ tone, children }: { tone: BadgeTone; children: ReactNode }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  return <Badge tone={statusTone(status)}>{statusLabel(status)}</Badge>;
}
