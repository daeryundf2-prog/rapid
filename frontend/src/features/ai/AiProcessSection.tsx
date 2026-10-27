/**
 * 처리 › AI 사용 기록 (R7 단계 3.5 갈래 D, plan §3.5): how this run collected AI usage — the plan
 * group `ai`'s state and time, the rows it wrote (and parse errors), and the collection scope
 * (메시지 본문 포함·마스킹 / 메타만, 대형 DB 해시) the run was started with. The options are chosen
 * in the run dialog (처리 그룹 › AI 사용 기록 수집 범위) for the next run.
 */

import { useQuery } from "@tanstack/react-query";
import type { RunPlan } from "../../api/runPlan";
import { getRunTree } from "../../api/runs";
import { StatusBadge } from "../../components/Badge";
import { serializeRoute } from "../../router";
import { collectorOptionsText } from "../case/runSummary";
import { aiRowCount, aiTypeCount } from "./useAiUsage";

const n = (value: number) => value.toLocaleString("ko-KR");

/** Collection scope of a run request (the defaults when the run sent no AI options). */
export function aiScopeText(request: Record<string, unknown> | null | undefined): string {
  const options = request?.collector_options;
  if (options && typeof options === "object" && "ai-agent" in (options as Record<string, unknown>)) {
    return collectorOptionsText({ "ai-agent": (options as Record<string, unknown>)["ai-agent"] });
  }
  return "기본값 — 메시지 본문 포함(마스킹) · 대형 DB 해시 안 함";
}

function durationText(ms: number | null | undefined): string {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return "—";
  if (ms < 1000) return `${n(ms)} ms`;
  return `${(ms / 1000).toLocaleString("ko-KR", { maximumFractionDigits: 1 })} 초`;
}

export function AiProcessSection({
  runId,
  plan,
  request,
}: {
  runId: string;
  plan: RunPlan | undefined;
  request: Record<string, unknown> | null | undefined;
}) {
  const tree = useQuery({
    queryKey: ["run-tree", runId],
    queryFn: () => getRunTree(runId),
    retry: false,
  });
  const group = plan?.groups.find((item) => item.id === "ai");
  const skipped = (plan?.options?.skip_groups ?? []).includes("ai");
  const rows = aiRowCount(tree.data);
  const errors = aiTypeCount(tree.data, "ai-agent-parse-error") ?? 0;
  return (
    <section className="stage-section process-ai" aria-labelledby="process-ai-title" data-testid="process-ai">
      <h3 id="process-ai-title">AI 사용 기록</h3>
      <dl className="stage-dl">
        <dt>상태</dt>
        <dd data-testid="process-ai-status">
          {group ? <StatusBadge status={String(group.status)} /> : skipped ? "건너뜀" : "계획 기록 없음"}
          {group?.duration_ms ? (
            <span className="process-run-note"> · {durationText(group.duration_ms)}</span>
          ) : null}
        </dd>
        <dt>수집 범위</dt>
        <dd data-testid="process-ai-scope">{aiScopeText(request)}</dd>
        <dt>행</dt>
        <dd data-testid="process-ai-rows">
          {rows === undefined ? (
            "—"
          ) : rows === 0 ? (
            "0건 — 이 증거에서 AI 도구 흔적을 찾지 못했습니다(서버 측 기록은 별도로 확인해야 합니다)"
          ) : (
            <a
              href={serializeRoute({
                runId,
                collection: "artifacts",
                kind: "ai-agent",
                types: ["ai-agent-session"],
              })}
            >
              {`${n(rows)}건`}
            </a>
          )}
          {errors ? <span className="process-run-note is-warn"> · 읽기 오류 {n(errors)}건</span> : null}
        </dd>
      </dl>
      <p className="analysis-desc">
        다음 런의 수집 범위(메시지 본문 포함 여부, 대형 AI 데이터베이스 해시)는 런 시작 대화상자의 처리 그룹
        아래에서 고릅니다. 자격 증명 파일의 값은 어떤 설정에서도 수집하지 않습니다.
      </p>
    </section>
  );
}
