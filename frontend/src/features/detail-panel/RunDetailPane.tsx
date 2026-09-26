import { useQuery } from "@tanstack/react-query";
import { ApiError } from "../../api/client";
import { getRunSummary, type ItemRow } from "../../api/runs";
import { StatusBadge } from "../../components/Badge";
import { useUiStore } from "../../state/ui";

/** Provenance fields shown in the fixed tracking block per plan 6-4. */
const PROVENANCE_KEYS: Array<[string, string]> = [
  ["path", "원본 경로"],
  ["input_file", "입력 파일"],
  ["source", "출처"],
  ["sha256", "SHA256"],
  ["md5", "MD5"],
  ["artifact_type", "아티팩트 유형"],
  ["event_type", "이벤트 유형"],
];

function fieldText(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function ItemDetail({ item }: { item: ItemRow }) {
  const provider = item.provider as Record<string, unknown> | undefined;
  const details = item.details as Record<string, unknown> | undefined;
  const provenance: Array<[string, string]> = [];
  for (const [key, label] of PROVENANCE_KEYS) {
    const value = fieldText(item[key]);
    if (value) provenance.push([label, value]);
  }
  if (provider?.name) provenance.push(["파서", fieldText(provider.name)]);
  if (details?.sha256) provenance.push(["SHA256", fieldText(details.sha256)]);
  if (item.supported === false)
    provenance.push(["제한사항", "이 항목은 파서 미지원 원본에서 수집되었습니다."]);

  const remaining = Object.entries(item).filter(
    ([key]) =>
      !key.startsWith("_") &&
      !["provider", "details", "artifact_record"].includes(key) &&
      !PROVENANCE_KEYS.some(([k]) => k === key),
  );

  return (
    <div className="pane-body">
      <div className="provenance-block" data-testid="provenance-block">
        {provenance.length === 0 ? (
          <p className="pane-empty">추적성 정보가 없습니다.</p>
        ) : (
          <dl className="detail-grid">
            {provenance.map(([label, value]) => (
              <div key={label} className="detail-row">
                <dt>{label}</dt>
                <dd className="mono break-all" title={value}>
                  {value}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </div>
      {remaining.length > 0 && (
        <dl className="detail-grid">
          {remaining.slice(0, 12).map(([key, value]) => (
            <div key={key} className="detail-row">
              <dt>{key}</dt>
              <dd className="break-all">{fieldText(value) || "-"}</dd>
            </div>
          ))}
        </dl>
      )}
    </div>
  );
}

export function RunDetailPane() {
  const selectedRunId = useUiStore((s) => s.selectedRunId);
  const selectedItem = useUiStore((s) => s.selectedItem);
  const summaryQuery = useQuery({
    queryKey: ["run-summary", selectedRunId],
    queryFn: () => getRunSummary(selectedRunId as string),
    enabled: Boolean(selectedRunId),
  });

  if (!selectedRunId) {
    return (
      <div className="pane" data-testid="detail-pane">
        <div className="pane-title">
          <span>상세</span>
        </div>
        <p className="pane-empty">왼쪽 또는 표에서 케이스를 선택하면 요약 정보가 표시됩니다.</p>
      </div>
    );
  }

  if (selectedItem) {
    return (
      <div className="pane" data-testid="detail-pane">
        <div className="pane-title">
          <span>상세</span>
          <span className="badge muted">항목</span>
        </div>
        <ItemDetail item={selectedItem} />
      </div>
    );
  }

  if (summaryQuery.isPending) {
    return (
      <div className="pane" data-testid="detail-pane">
        <div className="pane-title">
          <span>상세</span>
        </div>
        <p className="pane-empty">요약을 불러오는 중…</p>
      </div>
    );
  }

  if (summaryQuery.isError) {
    const error = summaryQuery.error;
    const message = error instanceof ApiError ? error.message : String(error);
    return (
      <div className="pane" data-testid="detail-pane">
        <div className="pane-title">
          <span>상세</span>
        </div>
        <div className="error-banner">요약을 불러오지 못했습니다: {message}</div>
      </div>
    );
  }

  const payload = summaryQuery.data;
  const counts = payload.summary?.counts;

  return (
    <div className="pane" data-testid="detail-pane">
      <div className="pane-title">
        <span>상세</span>
        <StatusBadge status="completed" />
      </div>
      <div className="pane-body">
        {counts && (
          <div className="count-chips" data-testid="canonical-counts">
            <CountChip label="검증 이슈" value={counts.validation_issues} />
            <CountChip label="산출물" value={counts.outputs} />
            <CountChip label="아티팩트" value={counts.artifacts} />
            <CountChip label="문서" value={counts.docs} />
            <CountChip label="파일" value={counts.files} />
            <CountChip label="타임라인" value={counts.timeline_events} />
            <CountChip label="선별물" value={counts.review_items} />
            <CountChip label="지표" value={counts.indicators} />
          </div>
        )}
        <dl className="detail-grid">
          <dt>실행 ID</dt>
          <dd className="mono">{selectedRunId}</dd>
          <dt>모드</dt>
          <dd>{payload.mode || "-"}</dd>
          <dt>입력 경로</dt>
          <dd className="mono">{payload.root || "-"}</dd>
          <dt>출력 폴더</dt>
          <dd className="mono">{payload.output_dir || "-"}</dd>
        </dl>
      </div>
    </div>
  );
}

function CountChip({ label, value }: { label: string; value: number }) {
  return (
    <div className="count-chip">
      <b>{value.toLocaleString("ko-KR")}</b>
      <span>{label}</span>
    </div>
  );
}
