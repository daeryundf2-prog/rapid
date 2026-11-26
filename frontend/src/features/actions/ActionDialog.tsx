/**
 * 선택 항목 분석 / 관련 항목 표시 (fe-audit A6, D2). One dialog over the action API v1:
 * it profiles the selection (POST …/actions/select) and marks every row of it in one call
 * (POST …/actions/mark, actor human). The request it sends is shown under "AI에게 맡기기", so
 * an examiner can hand the same instruction to an agent word for word.
 */

import { useQuery } from "@tanstack/react-query";
import { useId, useState } from "react";
import { announce } from "../../a11y";
import { pushToast } from "../../components/toastStore";
import type { GridRow } from "../../contracts/collection";
import { useAppStore } from "../../state/store";
import { Modal } from "../case/Modal";
import { notifyReviewApplied } from "../grid/reviewActions";
import { currentReviewer } from "../review/author";
import { toIsoBounds } from "../views/timelineRange";
import {
  type ActionSelection,
  type MarkRequest,
  markRows,
  type Relation,
  relatedSelection,
  relationReason,
  rowsSelection,
  type SelectionProfile,
  selectRows,
} from "./actionApi";
import { STATUS_CHOICES, type StatusChoice, summarize } from "./summary";
import "./actions.css";

export type ActionDialogTarget =
  | { mode: "analyze"; runId: string; rows: GridRow[] }
  | { mode: "related"; runId: string; row: GridRow };

const RELATIONS: { id: Relation; label: string }[] = [
  { id: "time_window", label: "같은 시간대" },
  { id: "same_path", label: "같은 경로" },
  { id: "same_name", label: "같은 파일 이름" },
];

export function ActionDialog({ target, onClose }: { target: ActionDialogTarget; onClose: () => void }) {
  const [relation, setRelation] = useState<Relation>("time_window");
  const [minutes, setMinutes] = useState(5);
  const [status, setStatus] = useState<StatusChoice>("needs-review");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const baseId = useId();
  const selection: ActionSelection | null =
    target.mode === "analyze"
      ? rowsSelection(target.rows)
      : relatedSelection(target.row, relation, Math.max(1, minutes) * 60);
  const profile = useQuery({
    queryKey: ["actions.select", target.runId, selection],
    queryFn: ({ signal }) =>
      selection ? selectRows(target.runId, selection, 3, signal) : Promise.resolve(null),
    enabled: selection !== null,
    retry: false,
  });
  const data: SelectionProfile | null | undefined = profile.data;
  const request: MarkRequest | null = selection
    ? { selection, mark: { status }, dry_run: false, actor: { kind: "human", name: currentReviewer() } }
    : null;
  const agentRequest = request
    ? { ...request, dry_run: true, actor: { kind: "agent", name: "<에이전트 이름>" } }
    : null;
  const count = data?.total ?? 0;
  const applyReason = !selection
    ? target.mode === "related"
      ? relationReason(target.row, relation)
      : "표시할 수 있는 행이 없습니다"
    : profile.isPending
      ? "건수를 세는 중입니다"
      : profile.error
        ? "선택을 분석하지 못했습니다"
        : count === 0
          ? "해당하는 행이 없습니다"
          : data?.over_limit
            ? `한 번에 ${data.limit.toLocaleString("ko-KR")}건까지 표시할 수 있습니다. 범위를 좁히세요`
            : busy
              ? "표시하는 중입니다"
              : undefined;
  const statusLabel = STATUS_CHOICES.find((choice) => choice.id === status)?.label ?? status;

  const apply = async () => {
    if (!request || applyReason) return;
    setBusy(true);
    setError(null);
    try {
      const result = await markRows(target.runId, request);
      notifyReviewApplied(target.runId);
      const message = `${(result.updated_count ?? count).toLocaleString("ko-KR")}건을 '${statusLabel}'(으)로 표시했습니다`;
      announce(message);
      pushToast(message, "ok");
      onClose();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
    } finally {
      setBusy(false);
    }
  };

  const showInTimeline = () => {
    const range = data?.time_range;
    if (!range) return;
    const { from, to } = toIsoBounds({ fromMs: Date.parse(range.first), toMs: Date.parse(range.last) });
    useAppStore.getState().navigate({ runId: target.runId, collection: "timeline", from, to });
    onClose();
  };

  return (
    <Modal
      title={target.mode === "analyze" ? "선택 항목 분석" : "관련 항목 표시"}
      wide
      onClose={onClose}
      footer={
        <>
          <button type="button" className="button roomy" onClick={onClose}>
            취소
          </button>
          <button
            type="button"
            className="button roomy primary"
            aria-disabled={applyReason ? true : undefined}
            title={applyReason}
            onClick={() => void apply()}
          >
            {count ? `${count.toLocaleString("ko-KR")}건 표시` : "표시"}
          </button>
        </>
      }
    >
      <div className="action-dialog">
        {target.mode === "related" ? (
          <>
            <p className="action-anchor">
              기준 행 <strong title={target.row.title}>{target.row.title}</strong>
            </p>
            <fieldset className="action-relations">
              <legend>무엇과 관련된 행인가</legend>
              {RELATIONS.map((choice) => (
                <label key={choice.id} className="action-relation">
                  <input
                    type="radio"
                    name={`${baseId}-relation`}
                    checked={relation === choice.id}
                    onChange={() => setRelation(choice.id)}
                  />
                  {choice.label}
                  {choice.id === "time_window" ? (
                    <span className="action-minutes">
                      ±
                      <input
                        type="number"
                        min={1}
                        max={1440}
                        aria-label="앞뒤 분"
                        value={minutes}
                        onChange={(event) => setMinutes(Number(event.target.value) || 1)}
                      />
                      분
                    </span>
                  ) : null}
                </label>
              ))}
            </fieldset>
          </>
        ) : null}

        <section className="action-profile" aria-live="polite" aria-busy={profile.isFetching}>
          {selection === null ? (
            <p className="action-note">{applyReason}</p>
          ) : profile.error ? (
            <p className="action-error" role="alert">
              {profile.error instanceof Error ? profile.error.message : String(profile.error)}
            </p>
          ) : data ? (
            <ProfileView profile={data} />
          ) : (
            <p className="action-note">건수를 세는 중…</p>
          )}
        </section>

        <div className="action-mark">
          <label>
            표시
            <select
              value={status}
              onChange={(event) =>
                setStatus(STATUS_CHOICES.find((choice) => choice.id === event.target.value)?.id ?? status)
              }
            >
              {STATUS_CHOICES.map((choice) => (
                <option key={choice.id} value={choice.id}>
                  {choice.label}
                </option>
              ))}
            </select>
          </label>
          {data?.time_range ? (
            <button type="button" className="button ghost" onClick={showInTimeline}>
              타임라인에서 이 구간 보기
            </button>
          ) : null}
        </div>
        {error ? (
          <p className="action-error" role="alert">
            {error}
          </p>
        ) : null}

        {agentRequest ? (
          <details className="action-agent">
            <summary>AI에게 맡기기: 같은 요청</summary>
            <p className="action-note">
              에이전트는 이 본문을 <code>POST /api/runs/{target.runId}/actions/mark</code>로 보냅니다. 먼저
              미리보기(dry_run)로 건수를 확인한 뒤 적용합니다. 자세한 내용은 docs/ai-action-api.md.
            </p>
            <pre>{JSON.stringify(agentRequest, null, 2)}</pre>
          </details>
        ) : null}
      </div>
    </Modal>
  );
}

function ProfileView({ profile }: { profile: SelectionProfile }) {
  const lines = summarize(profile);
  return (
    <dl className="action-facts">
      {lines.map((line) => (
        <div key={line.label}>
          <dt>{line.label}</dt>
          <dd>{line.value}</dd>
        </div>
      ))}
    </dl>
  );
}
