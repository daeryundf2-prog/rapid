import { useQuery } from "@tanstack/react-query";
import { getDoctor } from "../../api/runs";
import { ErrorText } from "./ErrorText";
import { Modal } from "./Modal";

const STATUS_LABEL: Record<string, string> = { ok: "정상", warn: "주의", error: "오류" };
const STATUS_BADGE: Record<string, string> = { ok: "ok", warn: "warn", error: "danger" };

export function DoctorDialog({ onClose }: { onClose: () => void }) {
  const doctor = useQuery({ queryKey: ["doctor"], queryFn: getDoctor, retry: false, staleTime: 0 });

  return (
    <Modal title="환경 점검" onClose={onClose} wide>
      {doctor.isPending && <p aria-busy="true">점검 중…</p>}
      {doctor.isError && (
        <ErrorText>
          점검하지 못했습니다: {doctor.error instanceof Error ? doctor.error.message : "알 수 없는 오류"}
        </ErrorText>
      )}
      {doctor.data && (
        <>
          <p>
            전체 {STATUS_LABEL[doctor.data.status] ?? doctor.data.status}: 정상 {doctor.data.summary.ok} ·
            주의 {doctor.data.summary.warn} · 오류 {doctor.data.summary.error}
          </p>
          <ul className="case-check-list" aria-label="점검 항목">
            {doctor.data.checks.map((check) => (
              <li key={check.name}>
                <span className={`badge ${STATUS_BADGE[check.status] ?? "muted"}`}>
                  {STATUS_LABEL[check.status] ?? check.status}
                </span>{" "}
                <strong>{check.name}</strong> — {check.summary}
                {check.remediation && <div className="case-reason">조치: {check.remediation}</div>}
              </li>
            ))}
          </ul>
        </>
      )}
      <div className="case-actions">
        <button type="button" className="button" onClick={() => void doctor.refetch()}>
          다시 점검
        </button>
        <button type="button" className="button primary" onClick={onClose}>
          닫기
        </button>
      </div>
    </Modal>
  );
}
