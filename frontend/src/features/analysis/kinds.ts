/**
 * Analysis workbench catalogue (plan analysis-workbench-p1 §2 U-P1-1, §3.2).
 *
 * Analysis nodes (처리 cards `#/case/{run}/process/{node}`, results `#/case/{run}/explore/analysis/{node}`) and the API
 * job kinds they run. One node may run several kinds (볼륨 섀도우 = discover → compare →
 * extract). Jobs run from the 처리 stage cards; results open in the 탐색 domain tree
 * (console-ia §3). Web logs / web shells are domain nodes (침해사고), not jobs.
 */

import {
  type AnalysisKind,
  type AnalysisState,
  type AnalysisStatus,
  isAnalysisActive,
} from "../../api/analyses";
import type { IconName } from "../../icons";

export type AnalysisNodeId = "carve" | "vsc" | "ntfs-meta" | "ocr-batch" | "memory-import" | "cross-case";

export interface AnalysisNodeDef {
  id: AnalysisNodeId;
  label: string;
  /** One sentence under the pane title. */
  description: string;
  /** API kinds this node runs (empty: link node). */
  kinds: AnalysisKind[];
}

export const ANALYSIS_NODES: readonly AnalysisNodeDef[] = [
  {
    id: "carve",
    label: "카빙",
    description: "런의 파일에서 알려진 파일 서명(JPEG·PNG·PDF·ZIP 등)을 찾아 위치와 해시를 기록합니다.",
    kinds: ["carve"],
  },
  {
    id: "vsc",
    label: "볼륨 섀도우",
    description: "볼륨 섀도우 복사본을 찾고(탐색), 현재 파일과 비교하고(비교), 바뀐 파일을 꺼냅니다(추출).",
    kinds: ["vsc-discover", "vsc-compare", "vsc-extract"],
  },
  {
    id: "ntfs-meta",
    label: "NTFS 메타(MFT/USN)",
    description: "$MFT와 USN 저널을 읽어 생성·접근·MFT 수정 시각과 MFT 엔트리 번호를 파일 목록에 채웁니다.",
    kinds: ["ntfs-meta"],
  },
  {
    id: "ocr-batch",
    label: "OCR 일괄",
    description: "이미지에서 글자를 한꺼번에 읽습니다. 결과는 뷰어의 이미지 OCR 모드가 그대로 재사용합니다.",
    kinds: ["ocr-batch"],
  },
  {
    id: "memory-import",
    label: "메모리",
    description: "Volatility 출력 폴더를 가져와 메모리 분석 레코드로 보여 줍니다.",
    kinds: ["memory-import"],
  },
  {
    id: "cross-case",
    label: "교차 케이스",
    description: "여러 케이스에 함께 나타난 지표(해시·도메인·IP 등)를 찾습니다.",
    kinds: ["cross-case"],
  },
];

export function isAnalysisNodeId(value: unknown): value is AnalysisNodeId {
  return typeof value === "string" && ANALYSIS_NODES.some((node) => node.id === value);
}

export function analysisNode(id: string | undefined): AnalysisNodeDef | undefined {
  return ANALYSIS_NODES.find((node) => node.id === id);
}

/** The node an API kind belongs to (vsc-* → vsc). */
export function nodeOfKind(kind: string): AnalysisNodeDef | undefined {
  return ANALYSIS_NODES.find((node) => (node.kinds as string[]).includes(kind));
}

/** Korean names of the API kinds (history, progress chip, announcements). */
export const KIND_LABEL: Record<AnalysisKind, string> = {
  carve: "카빙",
  "vsc-discover": "볼륨 섀도우 탐색",
  "vsc-compare": "볼륨 섀도우 비교",
  "vsc-extract": "볼륨 섀도우 추출",
  "ntfs-meta": "NTFS 메타 분석",
  "ocr-batch": "OCR 일괄",
  "memory-import": "메모리 분석 가져오기",
  "cross-case": "교차 케이스 상관 분석",
};

export function kindLabel(kind: string): string {
  return (KIND_LABEL as Record<string, string>)[kind] ?? kind;
}

/** Dialog notes: expected scope and cautions ("예상 범위·주의"). */
export const KIND_CAUTION: Record<AnalysisKind, string> = {
  carve:
    "소스 파일마다 최대 스캔 바이트까지 읽습니다. 파일이 많으면 수 분 이상 걸릴 수 있고, 추출을 켜면 런 출력 폴더에 파일을 씁니다.",
  "vsc-discover":
    "런 루트 아래 폴더를 최대 깊이까지 훑어 스냅샷처럼 보이는 폴더를 찾습니다. 파일 내용은 읽지 않습니다.",
  "vsc-compare":
    "선택한 스냅샷과 현재 파일 인덱스를 비교합니다. 해시를 켜면 파일 내용을 모두 읽으므로 오래 걸립니다.",
  "vsc-extract":
    "비교 결과 중 선택한 상태의 파일을 런 출력 폴더로 복사합니다. 허용 루트 밖으로는 쓸 수 없습니다.",
  "ntfs-meta":
    "Sleuth Kit으로 $MFT(와 선택 시 USN 저널 전체)를 추출해 파싱합니다. 큰 볼륨은 수십 분 걸릴 수 있습니다. 증거 이미지는 읽기만 합니다.",
  "ocr-batch":
    "이미지 1장마다 OCR을 실행합니다. 이미지가 많으면 오래 걸립니다. 실패한 이미지는 사유와 함께 남습니다.",
  "memory-import": "지정한 Volatility 출력 폴더의 JSON을 읽기만 합니다. 폴더는 허용 루트 아래여야 합니다.",
  "cross-case": "선택한 케이스들의 지표를 쌍마다 비교합니다. 케이스가 많으면 쌍의 수만큼 늘어납니다.",
};

export const STATUS_LABEL: Record<AnalysisStatus, string> = {
  queued: "대기 중",
  running: "실행 중",
  completed: "완료",
  failed: "실패",
  cancelled: "취소됨",
};

/** Tree state glyph: 미실행 / 실행 중 / 완료 / 실패 (cancelled reads as 취소됨, failure glyph). */
export function nodeStateIcon(status: AnalysisStatus | null): IconName {
  if (status === null) return "info";
  if (status === "queued" || status === "running") return "spinner";
  if (status === "completed") return "check";
  return "error";
}

export function nodeStateLabel(status: AnalysisStatus | null): string {
  return status === null ? "미실행" : STATUS_LABEL[status];
}

/** Newest job of a node (the list is newest first, §3.1). */
export function latestForNode(
  analyses: readonly AnalysisState[] | undefined,
  node: AnalysisNodeDef,
): AnalysisState | undefined {
  return analyses?.find((a) => (node.kinds as string[]).includes(a.kind));
}

/** The job a node opens on: the routed `id=`, else the newest completed, else the newest. */
export function selectedForNode(
  analyses: readonly AnalysisState[] | undefined,
  node: AnalysisNodeDef,
  routedId: string | undefined,
): AnalysisState | undefined {
  const mine = (analyses ?? []).filter((a) => (node.kinds as string[]).includes(a.kind));
  if (routedId) {
    const hit = mine.find((a) => a.analysis_id === routedId);
    if (hit) return hit;
  }
  return mine.find((a) => a.status === "completed") ?? mine[0];
}

/** "42% · 소스 파일 12/30 · 메시지" for the progress chip and the history row. */
export function progressText(state: AnalysisState): string {
  const p = state.progress;
  const parts: string[] = [];
  if (typeof p.percent === "number") parts.push(`${Math.round(p.percent)}%`);
  if (p.total !== null && p.total > 0) parts.push(`${p.unit ? `${p.unit} ` : ""}${p.done}/${p.total}`);
  else if (p.done > 0) parts.push(`${p.unit ? `${p.unit} ` : ""}${p.done}`);
  if (p.message) parts.push(p.message);
  return parts.join(" · ");
}

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

/**
 * OCR batch outcome: `summary.succeeded_count` / `failed_count` (newer servers) or
 * `summary.status_counts` {ok, empty, failed} (analysis_kinds.run_ocr_batch). Null for other
 * kinds or when the summary has neither.
 */
export function ocrOutcome(job: AnalysisState): { succeeded: number; failed: number } | null {
  if (job.kind !== "ocr-batch") return null;
  const summary = job.summary ?? {};
  const failed = count(summary.failed_count);
  const succeeded = count(summary.succeeded_count);
  if (failed !== null || succeeded !== null) return { succeeded: succeeded ?? 0, failed: failed ?? 0 };
  const statuses = summary.status_counts;
  if (!statuses || typeof statuses !== "object") return null;
  const s = statuses as Record<string, unknown>;
  return { succeeded: (count(s.ok) ?? 0) + (count(s.empty) ?? 0), failed: count(s.failed) ?? 0 };
}

/** A cancelled / failed job that still wrote result rows (shown as a partial result). */
export function isPartialResult(job: AnalysisState): boolean {
  return (job.status === "cancelled" || job.status === "failed") && job.row_count > 0;
}

/** A completed batch in which every item failed (OCR without a working engine). */
export function isAllFailed(job: AnalysisState): boolean {
  const outcome = ocrOutcome(job);
  return job.status === "completed" && outcome !== null && outcome.failed > 0 && outcome.succeeded === 0;
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

/**
 * Extra facts of a finished job worth one line on its card / pane: OCR success/failure
 * counts and engine error, a truncated volume-shadow comparison with its reason, the
 * failure text of a failed job.
 */
export function summaryNotes(job: AnalysisState): string[] {
  const notes: string[] = [];
  const summary = job.summary ?? {};
  const outcome = ocrOutcome(job);
  // A job that failed outright with no rows (engine missing) has no per-image counts:
  // "성공 0 · 실패 0 · 실패 사유 …" contradicts itself, so only the reason is shown.
  const engineFailure = job.status === "failed" && job.row_count === 0;
  if (outcome && !isAnalysisActive(job) && !engineFailure) {
    notes.push(
      `성공 ${outcome.succeeded.toLocaleString("ko-KR")} · 실패 ${outcome.failed.toLocaleString("ko-KR")}`,
    );
  }
  const engine = text(summary.engine_error) || text(summary.engine_error_detail);
  if (engine && job.status !== "failed") notes.push(`OCR 엔진: ${engine}`);
  const rejected = count(summary.rejected_count);
  if (job.kind === "carve" && rejected) {
    notes.push(`검증 실패로 뺀 후보 ${rejected.toLocaleString("ko-KR")}건`);
  }
  const truncatedReason = text(summary.truncated_reason) || text(summary.truncation_reason);
  if (summary.truncated === true || truncatedReason) {
    notes.push(`일부만 처리: ${truncatedReason || "상한에 도달해 일부만 처리했습니다"}`);
  }
  if (summary.selection_truncated === true && !truncatedReason) {
    notes.push("일부만 처리: 비교 결과 중 상한까지만 골랐습니다");
  }
  if (job.kind === "ntfs-meta" && summary.source === "mft") {
    notes.push("입력: 추출한 $MFT 파일(USN 저널 없음)");
  }
  if (job.status === "failed" && job.error) notes.push(`실패 사유: ${job.error}`);
  return notes;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (typeof seconds !== "number" || !Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}초`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m < 60) return `${m}분 ${s}초`;
  return `${Math.floor(m / 60)}시간 ${m % 60}분`;
}
