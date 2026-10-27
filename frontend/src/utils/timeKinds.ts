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
  // R3 O1: Office MRU open time, PCA (Program Compatibility Assistant) event time.
  "last-opened": "마지막 열기",
  "pca-event": "PCA 이벤트",
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
  observed: "관측",
  // Filesystem / registry / system (core/timeline.py TIMELINE_FIELD_MAP).
  "si-created": "SI 생성",
  "si-modified": "SI 수정",
  "si-mft-modified": "SI MFT 변경",
  "si-accessed": "SI 접근",
  "fn-created": "FN 생성",
  "fn-modified": "FN 수정",
  "fn-accessed": "FN 접근",
  "fn-mft-modified": "FN MFT 변경",
  "file-modified": "파일 수정",
  // Timeline/grid readability C4 / C8: kinds of a real Windows run that read raw before.
  "file-last-modified": "파일 수정(실행 아님)",
  "last-written-mru-head": "키 마지막 기록(MRU 첫 항목)",
  "last-execution": "마지막 실행",
  "last-access": "마지막 접근",
  "exif-datetime-original": "EXIF 촬영",
  "typed-url-time": "주소 직접 입력",
  "mp4-mvhd-creation": "MP4 생성 기록",
  shutdown: "시스템 종료",
  "volume-created": "볼륨 생성",
  "usn-change": "USN 변경",
  "hive-last-written": "하이브 마지막 기록",
  "last-written-recovered": "키 마지막 기록(복구)",
  "item-created": "항목 생성",
  "item-modified": "항목 수정",
  "item-accessed": "항목 접근",
  "destlist-last-modified": "점프 목록 마지막 수정",
  "indexed-created": "색인 생성",
  "indexed-modified": "색인 수정",
  "indexed-accessed": "색인 접근",
  "srum-record": "SRUM 기록",
  "os-installed": "OS 설치",
  "account-created": "계정 생성",
  "password-set": "암호 설정",
  logon: "로그온",
  logoff: "로그오프",
  deleted: "삭제",
  disabled: "사용 안 함 설정",
  crash: "크래시",
  "process-created": "프로세스 생성",
  notification: "알림",
  "note-created": "메모 생성",
  "note-updated": "메모 수정",
  "gps-fix": "GPS 측위",
  // Browser (R2 browser depth, cache, WebCache).
  "download-started": "다운로드 시작",
  "download-ended": "다운로드 완료",
  "search-url-last-visited": "검색 URL 마지막 방문",
  "ai-usage-visited": "AI 서비스 방문",
  "bookmark-added": "북마크 추가",
  added: "추가",
  navigated: "이동",
  "profile-created": "프로필 생성",
  "profile-last-active": "프로필 마지막 활동",
  "cookie-created": "쿠키 생성",
  "cookie-accessed": "쿠키 접근",
  "login-created": "로그인 정보 생성",
  "login-used": "로그인 정보 사용",
  "cache-request": "캐시 요청",
  "cache-response": "캐시 응답",
  "cache-created": "캐시 생성",
  "cache-last-used": "캐시 마지막 사용",
  "cache-stored": "캐시 저장",
  // Messenger / e-mail (R2 communication).
  sent: "발신",
  received: "수신",
  message: "메시지",
  edited: "편집",
  server: "서버 수신",
  start: "시작",
  end: "종료",
  // KakaoTalk shared picture: the time is read from the file name (local time, zone unknown).
  saved: "저장(파일 이름)",
  // Cloud sync (cloud_sync.py: f"cloud-{operation}" over OPERATION_LABELS, plus item times).
  "cloud-upload": "클라우드 업로드",
  "cloud-download": "클라우드 다운로드",
  "cloud-delete": "클라우드 삭제",
  "cloud-rename": "클라우드 이름 변경",
  "cloud-share": "클라우드 공유",
  "cloud-modified": "클라우드 수정",
  "cloud-viewed": "클라우드 열람",
  "cloud-shared-with-me": "나와 공유됨",
  // DriveFS local copy times (timeline.py cloud-sync-file).
  "sync-local-created": "로컬 사본 생성",
  "local-created": "로컬 사본 생성",
  "local-accessed": "로컬 사본 접근",
  "sync-local-accessed": "로컬 사본 접근",
  // R5 L3: Google Analytics cookies, P2P (torrent / eMule), adb backup members.
  "ga-current-visit": "GA 현재 방문",
  "ga-previous-visit": "GA 이전 방문",
  "ga-first-visit": "GA 첫 방문",
  "ga-campaign-set": "GA 유입 기록",
  "torrent-created": "토렌트 작성",
  "transfer-added": "전송 추가",
  "transfer-completed": "전송 완료",
  "part-file-date": "임시 파일 날짜",
  "last-shared": "마지막 공유",
  "file-date": "파일 날짜",
  "member-modified": "백업 항목 수정",
  "last-seen-complete": "완전 소스 마지막 확인",
  // Timeline canonical forms (core/timeline.py canonical_label strips the type noun:
  // p2p-transfer "transfer-completed" -> "completed", phone-link-photo "photo-synced" -> "synced",
  // cloud-sync-event "cloud-delete" -> "delete").
  completed: "완료",
  synced: "동기화",
  download: "다운로드",
  delete: "삭제",
  rename: "이름 변경·이동",
  share: "공유",
  // R5 L3 Phone Link (phone_link.py row timestamp_kind).
  "call-start": "통화 시작",
  "photo-taken": "사진 촬영",
  "photo-synced": "사진 동기화",
  // R7 AI 사용 (갈래 B rows, core/timeline.py ai block): account switch, retention cleanup marker,
  // AI-attributed commit, execution-trace match of an AI tool.
  switched: "계정 전환",
  cleanup: "보존 정리",
  committed: "AI 기여 커밋",
  executed: "실행",
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
