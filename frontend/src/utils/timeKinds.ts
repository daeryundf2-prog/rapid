/**
 * Korean names of timestamp kinds (`timestamp_kind` / `timestamp_label` / timeline labels —
 * core/timeline.py TIMELINE_FIELD_MAP). Shared by the timeline grid, the record view's time
 * chips and the citation.
 */

export const TIMESTAMP_KIND_LABELS: Readonly<Record<string, string>> = {
  created: "생성",
  modified: "수정",
  accessed: "접근",
  changed: "변경",
  "mft-modified": "MFT 변경",
  event: "이벤트",
  run: "실행",
  "last-run": "마지막 실행",
  "last-written": "키 마지막 기록",
  last_written: "키 마지막 기록",
  "last-visited": "마지막 방문",
  visited: "방문",
  visit: "방문",
  installed: "설치",
  registered: "등록",
  "first-connected": "최초 연결",
  "last-connected": "마지막 연결",
  "last-arrival": "마지막 연결",
  "last-removal": "마지막 분리",
  "first-install": "최초 설치",
  "download-start": "다운로드 시작",
  "download-end": "다운로드 완료",
  taken: "촬영",
  "archive-entry-modified": "압축 항목 수정",
  "last-logon": "마지막 로그온",
  "password-last-set": "암호 마지막 변경",
  "last-failed-logon": "마지막 로그온 실패",
  "account-expires": "계정 만료",
  "target-created": "대상 생성",
  "target-modified": "대상 수정",
  "target-accessed": "대상 접근",
  "last-used": "마지막 사용",
  "last-updated": "마지막 갱신",
  expires: "만료",
  "event-time": "이벤트",
  upload: "업로드",
  started: "시작",
  ended: "종료",
  "logon-start": "로그온 시작",
  "logon-end": "로그오프",
  "last-modified": "마지막 수정",
  "last-accessed": "마지막 접근",
  "key-last-written": "키 마지막 기록",
};

/**
 * Korean label of a time kind. Numbered run times ("run-3", Prefetch's 8 slots) read
 * "실행 3회차"; other numbered kinds "<label> N"; unknown kinds are returned as written.
 */
export function timestampKindLabel(kind: string): string {
  if (!kind) return "";
  const direct = TIMESTAMP_KIND_LABELS[kind] ?? TIMESTAMP_KIND_LABELS[kind.replace(/_/g, "-")];
  if (direct) return direct;
  const numbered = /^(.*)-(\d+)$/.exec(kind);
  if (numbered?.[1] && TIMESTAMP_KIND_LABELS[numbered[1]]) {
    return numbered[1] === "run"
      ? `실행 ${numbered[2]}회차`
      : `${TIMESTAMP_KIND_LABELS[numbered[1]]} ${numbered[2]}`;
  }
  return kind;
}
