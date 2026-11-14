import { useQuery } from "@tanstack/react-query";
import { type DoctorCheck, getDoctor } from "../../api/runs";
import { ErrorText } from "./ErrorText";
import { Modal } from "./Modal";

const STATUS_LABEL: Record<string, string> = { ok: "정상", warn: "주의", error: "오류" };
const STATUS_BADGE: Record<string, string> = { ok: "ok", warn: "warn", error: "danger" };

/** A check as the server sends it: `message_key` names the wording (core/doctor.py, R7 L3). */
type Check = DoctorCheck & { message_key?: string };

const text = (value: unknown) =>
  typeof value === "string" || typeof value === "number" ? String(value) : "";
const list = (value: unknown) =>
  Array.isArray(value) ? value.filter((item) => typeof item === "string").join(", ") : "";

/** Korean name of a check (`name`; `python-package:<name>` names the package). */
export function doctorCheckName(name: string): string {
  if (name.startsWith("python-package:")) return `Python 패키지 ${name.slice("python-package:".length)}`;
  const names: Record<string, string> = {
    "python-version": "Python 버전",
    "web-static-assets": "웹 화면 파일",
    "app-data-dir": "앱 데이터 폴더",
    "tool:tesseract": "OCR 도구(Tesseract)",
    "tools:e01": "E01 직접 추출 도구",
    "tools:email-pst": "PST/OST 메일 도구",
    "web-port": "웹 포트",
  };
  return names[name] ?? "기타 점검";
}

/**
 * Korean summary and remediation of a check by its `message_key` (C-G16), the details as the
 * parameters. An older server without keys (or an unknown key) keeps its own text.
 */
export function doctorMessage(check: Check): { summary: string; remediation: string | null } {
  const d = check.details ?? {};
  const keyed: Record<string, [string, string | null]> = {
    "python-version.supported": [`Python ${text(d.current)} — 지원되는 버전입니다.`, null],
    "python-version.too-old": [
      `Python ${text(d.current)} — 너무 오래된 버전입니다(최소 ${text(d.minimum)}).`,
      `Python ${text(d.minimum)} 이상을 설치하세요.`,
    ],
    "python-package.importable": ["설치되어 있습니다.", null],
    "python-package.missing": [
      "설치되어 있지 않습니다.",
      d.extra
        ? `추가 구성 요소 '${text(d.extra)}'를 함께 설치하세요.`
        : `${text(d.package)} 패키지를 설치하세요.`,
    ],
    "web-static-assets.present": ["웹 화면 파일이 있습니다.", null],
    "web-static-assets.incomplete": [
      `웹 화면 파일이 일부 없습니다: ${list(d.missing)}`,
      "프로그램을 다시 설치하거나 웹 화면 파일을 포함해 배포본을 다시 만드세요.",
    ],
    "app-data-dir.writable": ["앱 데이터 폴더에 쓸 수 있습니다.", null],
    "app-data-dir.probe-skipped": ["앱 데이터 폴더 경로를 확인했습니다(쓰기 시험은 건너뜀).", null],
    "app-data-dir.not-writable": [
      "앱 데이터 폴더에 쓸 수 없습니다.",
      "쓸 수 있는 케이스·앱 데이터 폴더를 고르거나 파일 시스템 권한을 고치세요.",
    ],
    "tesseract.available": ["Tesseract를 OCR에 쓸 수 있습니다.", null],
    "tesseract.missing": [
      "Tesseract가 없어 OCR을 쓸 수 없습니다.",
      "Tesseract OCR을 설치하고 PATH에 두세요. Windows에서는 언어 데이터(tessdata) 파일도 확인하세요.",
    ],
    "e01-tools.available": ["E01 직접 추출 도구가 모두 있습니다.", null],
    "e01-tools.incomplete": [
      `E01 직접 추출 도구 일부가 없습니다: ${list(d.missing)}`,
      "EWF를 지원하는 Sleuth Kit(Windows 빌드는 E01을 직접 읽음) 또는 ewfmount용 libewf를 설치하세요. WSL2를 쓰거나 마운트·추출한 폴더를 스캔해도 됩니다.",
    ],
    "email-pst.available": [
      `${list(d.available)} 있음 — 런에서는 외부 메일 도구 사용을 켰을 때만 씁니다.`,
      null,
    ],
    "email-pst.missing": [
      "PST/OST 도구(pffexport·readpst)가 없어 Outlook 메일함은 컨테이너 목록만 만듭니다.",
      "libpff(pffexport) 또는 libpst(readpst)를 설치해 PATH에 두고 외부 메일 도구 사용을 켜고 런을 실행하면 PST/OST를 메일·일정·연락처·첨부 행으로 변환합니다.",
    ],
    "web-port.available": [`웹 포트 ${text(d.host)}:${text(d.port)}를 쓸 수 있습니다.`, null],
    "web-port.busy": [
      `웹 포트 ${text(d.host)}:${text(d.port)}를 다른 프로그램이 쓰고 있습니다.`,
      "이 포트를 쓰는 프로그램을 끝내거나 다른 포트로 웹 화면을 시작하세요.",
    ],
  };
  const hit = check.message_key ? keyed[check.message_key] : undefined;
  if (hit) return { summary: hit[0], remediation: check.remediation ? hit[1] : null };
  return { summary: check.summary, remediation: check.remediation ?? null };
}

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
            {doctor.data.checks.map((check: Check) => {
              const message = doctorMessage(check);
              return (
                <li
                  key={check.name}
                  title={[check.name, check.summary, check.remediation].filter(Boolean).join("\n")}
                >
                  <span className={`badge ${STATUS_BADGE[check.status] ?? "muted"}`}>
                    {STATUS_LABEL[check.status] ?? check.status}
                  </span>{" "}
                  <strong>{doctorCheckName(check.name)}</strong> — {message.summary}
                  {message.remediation && <div className="case-reason">조치: {message.remediation}</div>}
                </li>
              );
            })}
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
