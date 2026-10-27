# R7 — 의뢰 브리프: FTop 의뢰 내용 → 구조화된 의도 → 검토 계획 (2026-10-26)

근거: 사용자 요청(2026-10-26, "사건관리 시스템(FTop)의 사건명·의뢰내용을 보고, 컴퓨터·맥북·리눅스 포렌식에서 의뢰인이 어떤 관점으로 요청했는지, 어떤 자료가 필요한지, 어떤 검토 형태가 필요한지 RapidTriage가 정리해 적용"), `docs/plans/r6-followups-2026-10-19.md` §0(공통 절차), `docs/console-glossary.md` §"접수 대시보드 (r7 검사관 우선 재설계)", `docs/rapidtriage-known-limitations.md` 37–38행(macOS·Linux 기준선), `## 정책 제외`. 브랜치 `feat/r6-ux`(`93dbcc7`) 위에 `feat/r7-request-brief`로 만든다.

**이름 결정(제안)**: 작업명 "의뢰 중심 사건 컨텍스트" 대신 **"의뢰 브리프"**(영문 식별자 `request_brief`). 사용자에게 보이는 명칭 한 가지로 통일한다(용어집 추가: 의뢰 브리프 = "의뢰 내용을 읽어 사건 유형·대상·기간·산출물로 정리하고 검토 계획으로 바꾼 접수 카드"; 금지 동의어: 사건 컨텍스트, 인텐트, 의뢰 분석). 하위 명칭: **의뢰 원문**(FTop에서 가져온 글), **의뢰 해석**(구조화 결과, 검사관이 고침), **검토 계획**(체크리스트), **필요 자료**(의뢰인에게 요청할 것), **플레이북**(사건 유형별 틀).

## 0. 공통 절차·제약

- 절차는 R6 §0과 같다: 이상 상태 → 갭 → 설계(갈래·파일 소유 분리) → QA 시나리오 표 → **Opus 구현**(워크트리 병렬) → **Sonnet 워커**(테스트·측정) → 적대적 리뷰(백/프런트) → 수정 → 게이트 → PR → "머지해라". 게이트 목록은 R6 §0 그대로(unittest·ruff·vulture·compileall·check-doc-refs·OpenAPI 스냅샷·frontend typecheck/test/lint/contrast/e2e·`git diff --check`).
- 정책(변경 없음): 로컬 우선, 백엔드 표준 라이브러리(+이미 있는 PyYAML), **제품이 자격 증명을 다루지 않는다**(FTop 비밀번호·세션 쿠키를 저장·입력·전달하지 않음), 외부 호출 없음(LLM 포함), 원격 수집 없음, 한국어 UI. FTop는 대외비 사내 시스템이므로 **FTop 화면·데이터는 Git에 넣지 않는다**(테스트 픽스처는 검사관이 가명화한 1건만, §7).
- **검사관 확인 원칙**: 해석기가 만든 것은 전부 "초안"이고, 검사관이 "확인"을 누르기 전에는 런·검색·보고서 어디에도 적용되지 않는다. 자동 적용 없음.
- 의뢰 원문에는 의뢰인·피의자 실명, 전화번호, 계좌, 주민번호가 들어올 수 있다. 저장은 케이스 DB(로컬) 안에만, 내보내기·보고서·로그에는 **가린 값**으로만 나간다(§4.1.4).
- 공유 파일(`frontend/src/features/tree/domains.ts`, `docs/console-glossary.md`, `known-limitations.md`, `api_openapi_snapshot.json`)은 갈래별 블록 **추가만**, 코디네이터가 병합.

---

## 1. 목표·이상 상태

**이상 상태**: 검사관이 FTop에서 사건을 열고 의뢰 내용을 RapidTriage에 넘기면(붙여넣기 한 번), 케이스 만들기 1단계가 사건번호·사건명·의뢰처·검사관으로 채워지고, 접수 대시보드에 "의뢰 브리프" 카드가 뜬다. 카드에는 ① 사건 유형(예: 유출 + 노무), ② 대상 플랫폼(Windows 노트북 1, macOS 1), ③ 이름이 나온 사람·계정·장치, ④ 사건 시간대, ⑤ 요청 산출물(USB 연결 이력·클라우드 업로드·메신저)이 신뢰도와 함께 적혀 있고, 검사관이 틀린 곳을 고쳐 "확인"을 누르면 다음이 한 번에 준비된다:

- 런 추천: 모드(`seizure`), 건너뛸 그룹, 추가로 돌릴 분석(ntfs-meta·carve·url-carve), 키워드 팩, 사건 시간대(규칙 `usb.new_device` 등이 쓰는 값).
- 검토 계획: 순서 있는 체크리스트(트리 노드·통합 보기·규칙 계열·자동 생성된 저장 검색·분석 결과)로, 검토 단계에서 항목을 열어 보고 완료 표시를 하면 카드의 진행률이 오른다.
- 필요 자료: 사건 유형별로 의뢰인에게 요청할 것(OneDrive 관리자 로그, 메일 서버 로그, 출입 기록, 서면 동의)을 "요청함/받음/해당 없음"으로 관리.
- 보고서: "의뢰 내용 → 수행 범위 → 결과" 절이 미리 들어가고, 요청 산출물마다 결과 행(리뷰 표시 항목)이 매핑된다.
- 플랫폼 정직성: 맥북·리눅스에서 RapidTriage가 **못 보는 것**(Unified Log, FSEvents, iMessage, journald 등)이 카드에 "현재 미지원 — 수동 검토 또는 외부 도구"로 명시된다.
- 학습: 같은 유형의 과거 사건(로컬 케이스 DB)이 썼던 플레이북·체크리스트가 추천되고, 검사관이 플레이북을 UI에서 고치면 다음 사건에 반영된다.

**목표 밖**(이번 라운드 아님): FTop 쓰기(상태 갱신·결과 업로드), LLM 호출, FTop 자동 로그인, 모바일 기기 직접 추출, 새 파서.

---

## 2. 사용자 시나리오

### S1. 퇴사 예정 직원의 자료 유출 의심 — Windows 노트북 1대 + 업무용 맥북 1대
1. 검사관이 FTop 사건 페이지에서 본문을 복사해 RapidTriage "케이스 만들기 → 의뢰 가져오기"에 붙여넣는다(또는 북마클릿으로 클립보드에 JSON을 담는다). 사건번호 `2026-10-0123`, 사건명 "○○전자 영업비밀 유출 의심", 의뢰처 "○○전자 법무팀", 접수일, 대상 기기 "회사 지급 노트북(Windows 11) 1대, MacBook Pro 1대", 기한 "11/15 중간보고"가 채워진다.
2. 해석기(규칙 기반)가 원문 "퇴사 통보 후 2주간 설계 도면을 USB·개인 메일·구글드라이브로 반출했는지, 삭제한 파일 복구 가능 여부"에서 **유형 유출(0.92)+삭제 복구(0.61)**, 플랫폼 Windows·macOS, 대상 "홍○○(퇴사자)·개인 Gmail 계정·USB", 시간대 "2026-09-15 ~ 2026-10-01"(퇴사 통보일 기준, 원문 근거 표시), 산출물 "USB 연결 이력·클라우드 업로드·웹메일 첨부·삭제 파일 복구·인쇄"를 초안으로 낸다.
3. 검사관이 시간대 시작을 "2026-09-01"로 고치고, 산출물에 "출력(인쇄) 기록"을 유지한 채 "확인".
4. 적용 결과: Windows 증거에 런 `seizure`(건너뛰기: `memory`·`p2p`), 분석 `ntfs-meta`·`url-carve`·`carve(documents)` 대기열, 키워드 팩 `exfiltration`+사건 키워드(도면 파일명·프로젝트명) 저장 검색 3개, 사건 시간대가 규칙 파라미터로 전달. macOS 증거에는 `seizure`가 그대로 돌되 카드에 "macOS에서 지원: 사용자 프로필·브라우저 기록/다운로드·격리(다운로드 출처)·TCC·LaunchAgent·카카오톡 macOS·APFS 스냅샷 힌트. **미지원: USB 연결 이력(kernel log), FSEvents, Unified Log, Mail.app, iMessage, Time Machine** → 수동 검토 항목으로 체크리스트에 남김".
5. 검토 계획(순서): ① 장치 식별자(통합 보기) → USB 규칙 계열(`usb.new_device`·`usb.mass_storage_activity`·`usb.cross_match`) → ② 접근 경로(통합 보기)+바로 가기·ShellBag(설계 폴더) → ③ 클라우드(`cloud-sync`·웹 업로드 흔적) → ④ 웹메일 첨부(브라우저 업로드 패턴·메일) → ⑤ 저장 검색 "도면·프로젝트명" → ⑥ 삭제 파일 후보(`recovery` 표·carve) → ⑦ 인쇄 이벤트(이벤트 로그 PrintService) → ⑧ macOS 수동 항목. 각 항목을 열면 해당 화면으로 가고, 완료 표시가 카드에 반영된다.
6. 필요 자료: "Google Workspace/Drive 관리자 감사 로그(의뢰처 보유)", "사내 메일 서버 송신 로그", "USB 지급 대장", "퇴사자 서약서·정보보호 서약서 사본", "피조사자 동의서 또는 회사 소유 기기 확인서". 상태 관리.
7. 보고서: "2. 분석 대상 및 범위" 앞에 "의뢰 내용"(가린 원문 요약 + 해석 표)이 들어가고, "4. 주요 검토 결과"가 산출물별(USB/클라우드/웹메일/삭제 복구/인쇄)로 나뉘어 리뷰 표시 항목이 매핑된다. 결과 없는 산출물은 "확인된 흔적 없음(부재 ≠ 미발생)"으로 남는다.

### S2. 웹 서버 침해 — Ubuntu 서버 디스크 이미지 + 관리자 Windows PC
- 원문 "홈페이지 변조, 관리자 계정 탈취 의심, 랜섬 노트 발견, 침입 경로와 피해 범위, 재발 방지 자료" → 유형 **해킹·침해(0.95)**, 플랫폼 Linux·Windows, 대상 "관리자 계정 `admin`·웹 서버 IP·변조 시각", 산출물 "침입 경로·실행 흔적·지속성·계정 탈취·유출 여부".
- 적용: Linux 증거에 `hacking`(지원: 사용자·셸 기록·SSH 인증키/known_hosts·auth 로그·auditd·dpkg·cron·systemd·Docker 설정; **미지원: journald 바이너리 로그·RPM(RHEL 계열)·XFS 메타·웹서버 액세스 로그 전용 파서(파일 검색으로만)**), Windows PC에 `hacking`+키워드 팩 `windows-ir`·`execution`·`credentials`. 체크리스트는 Linux 계정→auth 로그 실패/성공 로그인→SSH 키→cron/systemd 지속성→셸 기록 의심 명령→패키지 변경 시각 순, Windows는 실행 흔적→원격 접속(RDP)→이벤트 로그 보안 채널 순. 필요 자료: "방화벽·WAF 로그", "웹 서버 액세스 로그 원본(로테이션 포함)", "클라우드 콘솔 감사 로그", "백업 이미지(변조 전)".

### S3. 명예훼손·협박 메시지 — 아이폰 백업이 든 Windows PC 1대
- 원문 "카카오톡·인스타 DM으로 협박, 삭제된 대화 복구, 발신자 특정" → 유형 **명예훼손·협박(0.9)**, 플랫폼 iOS(백업)·Windows, 산출물 "메신저 대화·삭제 복구·발신자 식별".
- 적용: `recovery` 모드(메신저·모바일 추출물·카카오톡 Windows 포함) + 분석 `carve`. 카드가 정직하게 적는다: "iOS 백업은 PC에 있는 `sms.db`(iMessage/SMS)·카카오톡 Windows 대화·브라우저만 본다. **인스타그램 DM·암호화된 iOS 백업·카카오톡 iOS 내부 DB는 미지원** → 필요 자료에 '모바일 전문 도구 추출물 또는 플랫폼 사업자 자료 요청(수사기관 경유)'을 자동 추가". 검토 계획: 사람 식별자(통합 보기) → 메신저 계열 규칙 → 저장 검색(협박 어휘 팩 — 새 키워드 팩 `threat-ko`) → 삭제 후보.

---

## 3. 현재 상태(근거)

| 영역 | 근거 | 갭 |
|---|---|---|
| 케이스 정보 | `rapidtriage/core/case_db/intake.py` `CASE_FIELDS = (case_number, name, case_type, examiner, requester, organization, description, status)`; `routes_cases.py` 라벨 사건 번호/사건명/사건 유형/검사관/의뢰처; 위저드 3단계(`wizardModel.ts` `WIZARD_STEPS = ["사건 정보","증거 추가","처리 옵션"]`) | **의뢰 내용 본문·요청 산출물·대상 기기·기한·접수일 필드 없음**. `case_type`은 자유 문자열 |
| 런 프로필 | `core/run/profiles.py` 4모드(seizure/fraud/hacking/recovery), `keywords` 튜플은 영문 8개, kind 목록은 `constants.py` 3묶음(GENERAL 14·WINDOWS 14·CROSS_PLATFORM `linux-system`·`macos-system`) | 모드 선택 외의 조정 수단은 `RunRequest.skip_groups/skip_tasks`·`known_good_*`·`extract` 뿐. "사건 시간대"를 런에 넣는 입력이 없음(규칙 `usb.new_device`는 "사건 시간대를 지정해야 동작") |
| 규칙 카탈로그 | `core/triage_rules/catalog/*.yaml` 20파일, 규칙 156개(`rules:` 항목 합계), `family`·`label_ko`·`rationale_ko`·`grade`·`params` | 규칙을 사건 유형과 잇는 메타데이터 없음 |
| 키워드 팩 | `core/keyword_packs.py` 6팩(credentials 9·execution 10·network 10·browser-ai 10·windows-ir 11·exfiltration 10), 영문 | 한국어 법포렌식 어휘 팩 없음 |
| 저장 검색·리뷰·태그 | `database.save_search(case_id, name, keywords, sources…)`, `/api/case-db/saved-searches`, `review_tools.py`(태그·리뷰 표시, `_audit` → `audit_event`) | 검토 "할 일" 개념 없음(리뷰 상태 4종만, 용어집 62행 — 새 상태 추가 금지) |
| 대시보드 | `CaseDashboard.tsx` 12열 밴드 9카드(처리 상태·증거·범주·처리 경고·사건 정보·키워드·시작할 곳·노트·산출물), `cards.tsx` `StartCard` 3개 고정 링크 | "시작할 곳"이 사건과 무관한 고정 안내 |
| 보고서 | `core/case_report.py` 절 1–9(사건 정보·분석 대상 및 범위·절차·주요 검토 결과·해시·제외·결론·첨부·부록), `CaseReportRequest.scope/conclusion` 자유 문자열 | 의뢰 내용 절 없음, 산출물별 결과 매핑 없음 |
| macOS | `artifacts/macos.py`(`macos-system-v3`): 사용자 프로필, Chrome/Edge/Brave/Firefox/Safari 기록·다운로드, 격리 이벤트, TCC, LaunchAgent, 네이티브 인벤토리(Unified Log·Spotlight·FSEvents 파일 존재·문자열만), APFS 스냅샷 힌트; `kakaotalk_macos.py` | known-limitations 37행: "full native Unified Log, Spotlight, FSEvents, APFS 의미 해석은 계획" |
| Linux | `artifacts/linux.py`(`linux-system-v2`): 사용자·셸 기록·SSH·auth 로그·auditd·dpkg·Docker·cron·systemd | 38행: journald 바이너리·RPM·XFS·컨테이너 심층 미지원. Linux 데스크톱 브라우저(`~/.config/google-chrome`, `~/.mozilla`) 수집 여부 **코드로 미확인** → 갈래 B가 확인해 표에 적는다 |
| 감사 추적 | `audit_event`(citation_id·actor·action·target_type·target_id·params_json), `case_note_history` append-only 트리거 패턴 | 그대로 재사용 |

---

## 4. 설계

### 4.1 의뢰 원문 가져오기(FTop 연결)

#### 4.1.1 접수 방식 순위(결정 요청, §7-1)

| 순위 | 방식 | 인증 | 장점 | 단점 | 결정 |
|---|---|---|---|---|---|
| 1 | **붙여넣기**: 검사관이 FTop 사건 페이지 본문(Ctrl+A·복사) 또는 `/cases/export` HTML을 저장해 업로드 | 없음(검사관의 브라우저 세션만) | 구현 단순·정책 충돌 없음·FTop 변경에 둔감 | 한 사건씩 수동 | **기본(갈래 A)** |
| 2 | **북마클릿 → 클립보드**: FTop 페이지에서 북마클릿을 누르면 DOM에서 필드를 뽑아 JSON을 클립보드에 넣는다(네트워크 전송 없음). RapidTriage 붙여넣기 칸이 JSON을 인식 | 없음 | 선택·정리 과정 생략, CORS·토큰 불필요(로컬 API로 POST하지 않음) | FTop DOM이 바뀌면 북마클릿 갱신 | **기본에 포함(갈래 A, 작은 추가)** |
| 3 | 북마클릿 → 로컬 API POST(`http://127.0.0.1:<port>/api/intake/ftop`) | 없음이지만 FTop 출처에서 로컬로 교차 출처 요청 → CORS 허용 목록·CSRF 방지 토큰 필요 | 클릭 한 번 | 로컬 API를 외부 출처에 여는 셈(정책 위험), 토큰 관리 | **보류** |
| 4 | Playwright가 검사관 Chrome 프로필로 FTop를 읽음 | 검사관 세션 재사용(명시 동의) | 월별 일괄 | Playwright는 제품 의존성 밖, 세션 재사용은 "제품이 자격 증명을 다루지 않음"과 경계, 매번 동의 UI 필요 | **제품 밖**: 필요하면 `scripts/ftop-export-playwright.py`(선택 의존성, 사용자 실행, 출력은 방식 1의 입력 파일) — 이번 범위 아님 |
| 5 | 세션 쿠키 붙여넣기 → 직접 HTTP | 쿠키를 제품이 쥠 | — | 정책 위반 | **거부** |

#### 4.1.2 어댑터 인터페이스(`rapidtriage/core/request_brief/adapters/`)

```python
@dataclass(frozen=True)
class RequestSource:
    kind: Literal["paste-text", "paste-html", "export-html", "bookmarklet-json", "manual"]
    text: str                    # 원문(최대 256 KiB; 초과는 400)
    captured_at: str             # ISO, 검사관 입력 시각
    origin_hint: str = ""        # 북마클릿이 넣는 FTop 경로(쿼리 없이, 예: /cases/123) — 호스트·토큰 금지

@dataclass(frozen=True)
class RequestFields:             # 정규화 결과(모두 문자열, 없으면 "")
    case_number: str; case_name: str; requester: str; requester_contact_masked: str
    received_at: str; case_type_raw: str; request_body: str; deliverables_raw: str
    examiner: str; devices_raw: str; due_at: str
    extra: dict[str, str]        # 매핑 안 된 라벨→값(검사관이 확인용)
    field_sources: dict[str, str]  # 필드별 근거(라벨 이름·행 번호)

class RequestAdapter(Protocol):
    adapter_id: str; version: int
    def sniff(self, source: RequestSource) -> float        # 0–1, 가장 높은 어댑터가 담당
    def parse(self, source: RequestSource) -> RequestFields
```

- `GenericLabelAdapter`(기본, 모든 소스): 한국어 라벨 사전(`adapters/labels.yaml`: `사건번호|사건 번호|접수번호` → case_number, `사건명|제목` → case_name, `의뢰처|의뢰인|의뢰기관|고객` → requester, `접수일|접수일자|의뢰일` → received_at, `사건유형|사건 종류|분류` → case_type_raw, `의뢰내용|의뢰 내용|요청사항|사건개요|개요` → request_body, `요청산출물|산출물|요청 결과물|납품` → deliverables_raw, `담당|담당자|검사관|분석관` → examiner, `대상|대상기기|증거물|기기` → devices_raw, `기한|납기|마감|보고기한` → due_at)로 "라벨: 값"·표의 라벨 셀/값 셀·`<dt>/<dd>`·`<th>/<td>`를 뽑는다. HTML은 `html.parser`(표준 라이브러리)로 텍스트화하고 `<script>`·`<style>`·속성은 버린다.
- `FtopAdapter(GenericLabelAdapter)`: `adapters/ftop.yaml`에 FTop 전용 라벨·표 구조(현재 **미확인** — §7-2에서 검사관이 가명화 표본 1건을 주면 채움). 확인 전까지는 Generic과 같고 `sniff`가 "FTop"·"디지털포렌식 센터 통합 관리" 문자열로 0.6을 준다. `/cases/export` HTML은 사건 목록(월별 표)이므로 **사건 선택 단계**가 필요: 표를 파싱해 사건번호·사건명 목록을 보여주고 검사관이 하나를 고른다(`ExportListAdapter`).
- 북마클릿(`rapidtriage/api/static/ftop-bookmarklet.js`, 빌드 산출 아님·순수 JS 1파일): 페이지의 라벨-값 쌍(`th/td`, `dt/dd`, `label+input`, `.form-group`)과 본문 `innerText`를 `{"rapidtriage_request":1,"fields":{...},"text":"...","origin_hint":"/cases/123"}`로 만들어 `navigator.clipboard.writeText`. 쿠키·URL 쿼리·localStorage는 읽지 않는다. 설치 안내 화면(설정 → 의뢰 가져오기)에 드래그 링크와 "FTop DOM이 바뀌면 붙여넣기 방식으로 돌아간다" 안내.

#### 4.1.3 데이터 모델(케이스 DB, `core/case_db/request_brief.py`, 추가만)

```sql
CREATE TABLE IF NOT EXISTS case_request (            -- 의뢰 원문(케이스당 여러 판, 최신이 current)
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL,
  version INTEGER NOT NULL, is_current INTEGER NOT NULL DEFAULT 1,
  source_kind TEXT NOT NULL, origin_hint TEXT NOT NULL DEFAULT '',
  adapter_id TEXT NOT NULL, adapter_version INTEGER NOT NULL,
  raw_text TEXT NOT NULL, raw_sha256 TEXT NOT NULL,
  fields_json TEXT NOT NULL,                         -- RequestFields
  captured_at TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (case_id) REFERENCES case_record(case_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS case_intent (             -- 의뢰 해석(초안→확인)
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, request_id INTEGER NOT NULL,
  version INTEGER NOT NULL, status TEXT NOT NULL,     -- draft | confirmed | superseded
  classifier_version TEXT NOT NULL, vocab_sha256 TEXT NOT NULL,
  auto_json TEXT NOT NULL,                           -- 해석기 출력(불변)
  intent_json TEXT NOT NULL,                         -- 검사관 수정본(확인 시 고정)
  playbook_id TEXT NOT NULL DEFAULT '', playbook_sha256 TEXT NOT NULL DEFAULT '',
  confirmed_at TEXT, confirmed_by TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS case_plan (               -- 검토 계획(확인된 intent 1개당 1개)
  id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, intent_id INTEGER NOT NULL UNIQUE,
  plan_json TEXT NOT NULL,                           -- run·checklist·materials·report 골격
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS case_plan_item (          -- 체크리스트·필요 자료 항목(진행 상태)
  id INTEGER PRIMARY KEY AUTOINCREMENT, plan_id INTEGER NOT NULL, case_id TEXT NOT NULL,
  item_id TEXT NOT NULL, group_kind TEXT NOT NULL,   -- checklist | material | report-section
  ordinal INTEGER NOT NULL, label TEXT NOT NULL, target_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'open',               -- checklist: open|done|not-applicable ; material: requested|received|not-applicable
  note TEXT NOT NULL DEFAULT '', done_at TEXT, done_by TEXT NOT NULL DEFAULT '',
  UNIQUE (plan_id, item_id));
```

- 이력: `case_request`·`case_intent`는 판(version)을 새로 만들고 이전 판을 `superseded`로 둔다(UPDATE는 `is_current`·`status`만). 모든 쓰기는 `audit_event`에 `target_type ∈ {case_request, case_intent, case_plan, case_plan_item}`로 남긴다(`review_tools._audit`와 같은 꼴, `params_json`에는 **가린 diff**만).
- `intent_json` 구조:

```json
{"categories":[{"id":"leak","confidence":0.92,"evidence":[{"term":"반출","offset":112}]}],
 "platforms":[{"id":"windows","confidence":0.9,"evidence":[...]},{"id":"macos","confidence":0.8}],
 "subjects":[{"kind":"person","value":"홍○○","role":"피조사자","masked":"홍**"},
             {"kind":"account","value":"xxx@gmail.com","role":"개인 메일","masked":"x**@gmail.com"},
             {"kind":"device","value":"USB","role":"반출 매체"}],
 "time_window":{"from":"2026-09-15","to":"2026-10-01","basis":"퇴사 통보일 2주 전후(원문 87행)","confidence":0.7},
 "deliverables":[{"id":"usb-history"},{"id":"cloud-upload"},{"id":"webmail-attachment"},{"id":"deleted-recovery"},{"id":"print"}],
 "devices":[{"os":"windows","kind":"laptop","count":1,"note":"회사 지급"},{"os":"macos","kind":"laptop","count":1}],
 "examiner_edits":[{"path":"time_window.from","from":"2026-09-15","to":"2026-09-01","at":"..."}]}
```

#### 4.1.4 개인정보 가리기(`core/request_brief/redaction.py`, 표준 라이브러리 정규식)
- 패턴: 주민등록번호(`\d{6}-[1-4]\d{6}`), 휴대전화(`01[016789]-?\d{3,4}-?\d{4}`), 일반 전화, 이메일(사용자 이름 첫 글자만), 계좌번호(은행명 뒤 10–14자리), 카드번호(Luhn), 차량번호, 2–4자 한글 이름 뒤 호칭(`씨|님|과장|부장|대표|피의자|의뢰인`) → `홍**`. 기존 `artifacts/url_redaction.py`·통합 보기 자격 증명 가림 규칙과 표기(`***`·길이 보존)를 맞춘다.
- 적용 지점: `GET …/request`의 `raw_text_masked`(기본) vs `raw_text`(`?reveal=1`, 감사 이벤트 기록), 보고서·내보내기·리뷰어 번들·로그는 **항상 가린 값**. 케이스 DB 파일 자체는 로컬이므로 원문 보존(기존 메모와 동일 수준).
- `subjects[].value`(실명·계정)는 저장 검색 키워드로 쓰이므로 원문 보존이 필요하다. 저장 검색 이름은 `의뢰: 피조사자(홍**)`처럼 가린 이름을 쓴다.

### 4.2 의뢰 해석기(`core/request_brief/classifier.py` + `vocab/*.yaml`)

- 입력: `RequestFields.request_body + deliverables_raw + devices_raw + case_type_raw + case_name`. 전처리: NFC 정규화·소문자(영문)·공백 축약·문장 분리(`.`·`。`·줄바꿈·`며|고|,` 는 분리하지 않음). 형태소 분석 없음 — 어휘 표의 **어간·변형을 패턴에 직접 나열**한다(`유출(했|한|된|하였|여부)?`).
- 점수: 범주마다 `patterns[].weight` 합을 시그모이드로 0–1에 넣고, `negations`(예: "해킹은 아니고") 안의 일치는 0.3배, `case_type_raw`가 플레이북 `aliases`와 맞으면 +0.3. 임계 0.35 이상을 후보로 내되 최상위 1개는 항상 포함. 각 일치는 `evidence[]`에 용어·오프셋으로 남겨 카드가 밑줄을 긋는다.
- 시간대: 절대 날짜(`2026. 9. 15`, `9월 15일`, `26.09.15`), 상대 표현(`퇴사 통보 후 2주`, `최근 3개월`, `사건 당일`)은 `received_at` 또는 원문 속 기준일로 풀고 `basis`에 근거 문장을 적는다. 풀 수 없으면 `null` + "검사관 입력 필요".
- 대상: 한글 이름+호칭, 이메일, 전화번호, 계정 ID(`@`·`id:`), 기기명(`노트북|데스크톱|서버|맥북|MacBook|아이폰|갤럭시|NAS|USB|외장`), IP/호스트. `role`은 주변 10자 안의 역할어(`피의자|피조사자|퇴사자|직원|의뢰인|관리자|피해자|상대방`).
- 산출물 ID 사전(deliverables.yaml): `timeline, deleted-recovery, logon-history, messenger, email, webmail-attachment, usb-history, print, cloud-upload, web-history, file-access, execution, persistence, intrusion-path, account-takeover, media-review, location, device-identification, data-wipe-check, contract-doc-authenticity`(각각 `label_ko`, 매핑 §4.3).
- **로컬 모델 훅**(이번 범위 밖, 인터페이스만): `IntentSuggester` Protocol `suggest(fields) -> IntentDraft | None`; 기본 구현은 규칙 해석기. 설정 `request_brief.suggester = "rules"`만 허용하고 다른 값은 거부(외부 호출 금지가 코드로 보장). 나중에 로컬 모델을 붙이더라도 결과는 같은 `auto_json`에 들어가고 검사관 확인을 거친다.

#### 4.2.1 어휘 YAML 스키마(`rapidtriage/core/request_brief/vocab/categories.yaml`)

```yaml
version: 1
categories:
- id: leak
  label_ko: 유출(영업비밀·개인정보·내부자료)
  aliases: [자료 유출, 기술 유출, 영업비밀, 정보 유출, 반출]      # FTop 사건유형 문자열 대조
  default_playbook: pb-leak-employee
  patterns:                                                  # 정규식(NFC·대소문자 무시), weight 1–3
  - {re: '영업\s*비밀|기술\s*유출|산업\s*기술', weight: 3}
  - {re: '(자료|파일|문서|도면|소스\s*코드|고객\s*(정보|명단|DB))\s*(를|을)?\s*(유출|반출|외부\s*전송|빼돌)', weight: 3}
  - {re: 'USB|외장\s*(하드|디스크)|이동식\s*(저장|디스크)', weight: 1}
  - {re: '(개인|외부)\s*(메일|이메일|지메일|gmail|네이버\s*메일)', weight: 2}
  - {re: '(구글\s*드라이브|google\s*drive|원드라이브|onedrive|드롭박스|dropbox|네이버\s*(클라우드|mybox)|icloud)', weight: 2}
  - {re: '퇴사|이직|경쟁사|전직', weight: 2}
  - {re: '(출력|인쇄|프린트)\s*(기록|이력|여부)', weight: 1}
  - {re: '(카톡|카카오톡|텔레그램|메신저)\s*(으로|로)?\s*(전송|보냄|보낸|공유)', weight: 1}
  - {re: '부정경쟁방지|산업기술보호법|비밀유지\s*(서약|계약)|NDA', weight: 2}
  - {re: '(접근|열람)\s*(권한|이력)\s*(이|을)?\s*(없|초과|벗어)', weight: 1}
  - {re: '화면\s*캡처|스크린\s*샷|촬영해서', weight: 1}
  negations: ['유출\s*(은|는)\s*아니']
- id: embezzlement
  label_ko: 횡령·배임·부정(회계·거래)
  aliases: [횡령, 배임, 부정, 회계 부정, 자금]
  default_playbook: pb-fraud-finance
  patterns:
  - {re: '횡령|배임|업무상\s*(횡령|배임)', weight: 3}
  - {re: '(자금|회사\s*돈|공금|법인\s*카드)\s*(을|를)?\s*(유용|빼|사적|무단)', weight: 3}
  - {re: '(허위|가공|이중)\s*(세금)?계산서|가짜\s*(영수증|견적)', weight: 3}
  - {re: '(장부|회계|전표|원장|ERP)\s*(조작|수정|삭제|변조)', weight: 3}
  - {re: '(이체|송금|입금|출금)\s*(내역|기록|이력)', weight: 2}
  - {re: '(거래처|협력사|납품)\s*(와|과)?\s*(리베이트|뒷돈|킥백|유착)', weight: 2}
  - {re: '(계좌|통장|카드)\s*(번호|내역|명세)', weight: 1}
  - {re: '엑셀|xlsx|회계\s*프로그램|더존|세무', weight: 1}
  - {re: '(급여|인건비|경비)\s*(부풀|과다|허위)', weight: 2}
  - {re: '(계약서|견적서|발주서)\s*(위조|변조|작성\s*시점|진위)', weight: 2}
  - {re: '문서\s*(작성|수정)\s*(시각|일시|시점)|메타데이터', weight: 1}
- id: intrusion
  label_ko: 해킹·침해(침입·악성코드·계정 탈취)
  aliases: [해킹, 침해, 침해사고, 랜섬웨어, 악성코드, 계정 탈취]
  default_playbook: pb-intrusion
  patterns:
  - {re: '해킹|침입|침해\s*(사고)?|crack', weight: 3}
  - {re: '랜섬|ransom|암호화\s*(되었|됐|되어)|복호화\s*요구', weight: 3}
  - {re: '악성\s*코드|멀웨어|malware|트로이|백도어|웹\s*셸|webshell', weight: 3}
  - {re: '(계정|비밀번호|패스워드|자격\s*증명)\s*(탈취|도용|유출|변경)', weight: 3}
  - {re: '(홈페이지|웹\s*사이트|서버)\s*(변조|다운|장애|접속\s*불가)', weight: 2}
  - {re: '(원격|RDP|VPN|SSH)\s*(접속|로그인)\s*(이력|기록|시도)', weight: 2}
  - {re: '피싱|스미싱|스피어|이메일\s*첨부\s*(실행|열람)', weight: 2}
  - {re: '침입\s*경로|최초\s*감염|초기\s*침투|lateral|내부\s*확산', weight: 2}
  - {re: '(방화벽|IDS|IPS|WAF|EDR|백신)\s*(로그|탐지|경보)', weight: 1}
  - {re: '코인|암호화폐|지갑|wallet', weight: 1}
  - {re: '개인정보\s*(유출|침해)\s*(신고|통지)|KISA|개보위', weight: 1}
- id: recovery
  label_ko: 삭제 복구(파일·메시지·사진)
  aliases: [복구, 삭제 복구, 데이터 복구]
  default_playbook: pb-recovery
  patterns:
  - {re: '(삭제|지운|지워진|날린|포맷)\s*(파일|자료|사진|문서|메시지|대화|영상)', weight: 3}
  - {re: '복구\s*(가능|여부|요청|바람|해\s*주)', weight: 3}
  - {re: '휴지통|recycle|trash|비운', weight: 2}
  - {re: '포맷|초기화|공장\s*초기화|재설치', weight: 2}
  - {re: '(고의|의도적)\s*(삭제|파기|인멸)|증거\s*인멸', weight: 3}
  - {re: '(삭제|파기)\s*(시점|시각|일시|순서)', weight: 2}
  - {re: '카빙|carving|미할당', weight: 1}
  - {re: '(백업|스냅샷|타임머신|time\s*machine|볼륨\s*섀도)', weight: 1}
  - {re: '(완전|영구)\s*삭제|와이핑|wip(e|ing)|ccleaner|bleachbit', weight: 2}
  - {re: '(SSD|TRIM)', weight: 1}
  - {re: '(사진|영상|음성)\s*(복원|되살)', weight: 2}
- id: illicit-media
  label_ko: 음란물·불법촬영·아동 성착취물
  aliases: [불법촬영, 음란물, 성착취물, 카메라등이용촬영]
  default_playbook: pb-illicit-media
  patterns:
  - {re: '불법\s*촬영|몰래\s*카메라|몰카|카메라등이용촬영', weight: 3}
  - {re: '음란|성\s*착취|아동\s*성|청소년\s*성보호법|성폭력처벌법', weight: 3}
  - {re: '(사진|영상|동영상)\s*(유포|전송|소지|저장|촬영)', weight: 2}
  - {re: '딥페이크|합성\s*(사진|영상)|deepfake|AI\s*생성', weight: 3}
  - {re: '(텔레그램|디스코드|토렌트|웹하드|P2P)', weight: 1}
  - {re: '(피해자|상대방)\s*(동의|허락)\s*없이', weight: 2}
  - {re: '(촬영|생성)\s*(일시|시각|기기|장소)|EXIF|GPS', weight: 2}
  - {re: '(스마트폰|휴대폰|갤러리|카메라\s*롤|iCloud\s*사진)', weight: 1}
  - {re: '(썸네일|캐시|미리보기)\s*(복구|추출)', weight: 1}
  - {re: '유사\s*(이미지|사진)|같은\s*(사진|영상)\s*(인지|여부)|해시\s*비교', weight: 2}
  - {re: '(협박|유포\s*협박|돈\s*요구)', weight: 1}
- id: defamation-threat
  label_ko: 명예훼손·모욕·협박·스토킹(메시지·게시글)
  aliases: [명예훼손, 모욕, 협박, 스토킹, 사이버 명예훼손]
  default_playbook: pb-message-dispute
  patterns:
  - {re: '명예\s*훼손|모욕|비방|허위\s*사실', weight: 3}
  - {re: '협박|공갈|스토킹|괴롭힘|지속적\s*(연락|접근)', weight: 3}
  - {re: '(카톡|카카오톡|문자|SMS|DM|디엠|인스타|텔레그램|라인|메신저)\s*(대화|메시지|내용|내역)', weight: 2}
  - {re: '(게시글|댓글|커뮤니티|블라인드|에브리타임|디시|네이트판|SNS)', weight: 2}
  - {re: '(작성자|발신자|게시자|계정\s*주인)\s*(특정|확인|추적|식별)', weight: 3}
  - {re: '(대화|메시지)\s*(원본|진위|위변조|조작|캡처\s*진위)', weight: 3}
  - {re: '(삭제된|지운)\s*(대화|메시지|채팅)', weight: 2}
  - {re: '(통화|녹음)\s*(파일|내역|기록)', weight: 1}
  - {re: '(차단|탈퇴|닉네임|프로필)\s*(변경|이력)', weight: 1}
  - {re: '정보통신망법|성폭력처벌법\s*제1[34]조|스토킹처벌법', weight: 2}
  - {re: '(단톡|단체\s*(채팅|방)|오픈\s*채팅)', weight: 1}
- id: labor
  label_ko: 노무·근태·업무 태만·징계
  aliases: [근태, 노무, 징계, 업무 태만, 겸업]
  default_playbook: pb-labor
  patterns:
  - {re: '근태|출퇴근|재택\s*(근무)?\s*(중|시)|근무\s*시간|초과\s*근무|야근\s*(수당|허위)', weight: 3}
  - {re: '(업무|근무)\s*(태만|해태|불성실)|딴짓|게임|유튜브|주식|사적\s*(사용|이용)', weight: 3}
  - {re: '겸업|겸직|부업|경쟁\s*업체\s*(근무|운영)', weight: 3}
  - {re: '징계|해고\s*(사유|정당성)|인사\s*위원회|감사', weight: 2}
  - {re: '(로그온|로그인|잠금\s*해제|화면\s*보호기|절전)\s*(시각|이력|기록)', weight: 2}
  - {re: '(PC|컴퓨터|노트북)\s*(사용|켠|끈)\s*(시간|시각|기록)', weight: 2}
  - {re: '(원격|RDP|VPN)\s*(접속)\s*(시간|이력)', weight: 1}
  - {re: '(이메일|메일)\s*(송수신|발송)\s*(시각|시간대)', weight: 1}
  - {re: '(직장\s*내|사내)\s*(괴롭힘|성희롱)', weight: 2}
  - {re: '(회사|사내)\s*(자산|장비)\s*(반납|회수)\s*(후|전)', weight: 1}
  - {re: '(출장|외근|근무지)\s*(허위|사실\s*확인)', weight: 2}
- id: other
  label_ko: 기타(일반 검토)
  aliases: [기타, 일반]
  default_playbook: pb-general
  patterns:
  - {re: '(전반적|일반적)\s*(검토|분석|조사)', weight: 1}
  - {re: '(사용|이용)\s*(내역|이력)\s*(전체|전반)', weight: 1}
  - {re: '타임라인|시간\s*순|경위', weight: 1}
  - {re: '(문서|계약서|파일)\s*(진위|작성\s*시점|원본\s*여부)', weight: 1}
  - {re: '(이혼|상속|유언|가사)', weight: 1}
  - {re: '(교통|사고|블랙박스|차량)', weight: 1}
  - {re: '(학교|학폭|학생)', weight: 1}
  - {re: '(의료|진료\s*기록|EMR)', weight: 1}
  - {re: '(저작권|표절|불법\s*복제|라이선스)', weight: 1}
  - {re: '(선거|정치|후원금)', weight: 1}
```

같은 파일 구조로 `platforms.yaml`(windows: `윈도우|Windows|PC|데스크톱|노트북(?!.*맥)|NTFS|.exe`; macos: `맥북|MacBook|iMac|macOS|애플\s*(노트북|컴퓨터)|APFS`; linux: `리눅스|Linux|Ubuntu|CentOS|Rocky|서버(?!.*윈도우)|NAS|시놀로지|Synology|도커|Docker|쿠버`; android: `안드로이드|갤럭시|Galaxy|삼성\s*폰|adb`; ios: `아이폰|iPhone|iPad|iOS|iCloud\s*백업|iTunes\s*백업`; cloud: `클라우드|구글\s*드라이브|원드라이브|드롭박스|M365|Google\s*Workspace|AWS|Azure|GCP`), `deliverables.yaml`(산출물 20종 × 패턴 ≥ 5), `subjects.yaml`(역할어·기기명), `time.yaml`(날짜·상대 표현). 어휘 파일은 `scripts/check-request-vocab.py`로 정규식 컴파일·중복·ReDoS(중첩 수량자) 검사(게이트 추가).

#### 4.2.2 확인 단계(검사관 편집)
- 카드·위저드의 "의뢰 해석" 편집기: 범주 칩(추가·제거·주범주 지정), 플랫폼·기기 표, 대상 표(역할 드롭다운, 가림 미리보기), 시간대 두 칸 + 근거 문장, 산출물 체크 목록. 모든 칸 옆에 신뢰도(높음 ≥ 0.75 / 보통 / 낮음 < 0.5)와 근거 용어(원문 밑줄). "확인" 전에는 저장만 되고 적용되지 않는다. 수정 내용은 `examiner_edits`로 남아 **플레이북 개선 근거**가 된다(§4.4).

### 4.3 적용(의도 → 런·검토 계획·필요 자료·보고서)

#### 4.3.1 런 추천(`core/request_brief/planner.py`, 플레이북 `run` 블록)

| 범주 | 모드 | 건너뛰기(`skip_groups`) | 추가 분석(대기열) | 키워드 팩 | 비고 |
|---|---|---|---|---|---|
| leak | seizure | memory, p2p(산출물에 P2P 없을 때) | ntfs-meta, url-carve(pagefile), carve(documents·archives) | exfiltration + `leak-ko`(신규) | 사건 시간대 → USB·대량 열람 규칙 파라미터 |
| embezzlement | fraud | memory, p2p, media | ntfs-meta(문서 시각 불일치) | `finance-ko`(신규) | 문서 메타데이터·작성 시각 중심 |
| intrusion | hacking | — | ntfs-meta, url-carve, memory-volatility(덤프 있을 때) | windows-ir, execution, credentials, network | Linux: `linux-system` 포함 |
| recovery | recovery | — | carve(전체), ntfs-meta, url-carve | — | 삭제 후보·휴지통 |
| illicit-media | seizure | p2p 유지, memory | carve(images·video), 미디어 유사도 | `media-ko`(신규) | 통합 보기 지도(EXIF GPS) |
| defamation-threat | recovery | execution, prefetch | carve(sqlite) | `threat-ko`(신규) | 메신저·브라우저·모바일 추출물 |
| labor | seizure | p2p, media | — | — | 이벤트 로그 로그온·OS 계정·실행·RDP |
| other | seizure | — | — | — | 플레이북 없음 → 기본 체크리스트 |

- 런 요청은 기존 `RunRequest` 필드만 쓴다(`mode`·`skip_groups`·`known_good_*`·`extract`). **새 런 옵션 `event_window`(from/to)**를 하나 추가해 규칙 엔진 파라미터(`usb.new_device` 등 "사건 시간대" 규칙)에 전달한다 — 이것이 이번 라운드의 유일한 런 파이프라인 변경(갈래 B, `core/run` 1곳 + 규칙 엔진 파라미터 주입 1곳, OpenAPI 스냅샷 갱신). 복수 범주는 주범주 모드 + 부범주 분석·팩의 합집합.
- 적용 결과는 위저드 3단계 "처리 옵션"의 **기본값 prefill**이지 강제가 아니다(검사관이 바꾸면 `processing_snapshot`에 바뀐 값이 남는다).

#### 4.3.2 플랫폼 커버리지 표(카드·known-limitations에 그대로 게시; 코드 근거)

| 검토 항목 | Windows | macOS | Linux | 모바일(PC 내 추출물) |
|---|---|---|---|---|
| 사용자 계정·프로필 | 있음 `windows-os-account`(SAM·프로필) | 있음 `macos-user-profile` | 있음 `linux-user-profile` | — |
| 로그온·세션 이력 | 있음 이벤트 로그 보안 채널·RDP(`windows-remote-access`) | **없음**(Unified Log 미해석; `macos-native-*` 문자열 인벤토리만) | 있음 `linux-auth-log-event`·`linux-auditd-event` | — |
| 실행 흔적 | 있음 Prefetch·Amcache·PCA·SRUM·ShimCache | 부분: LaunchAgent·격리 이벤트(다운로드 실행 출처) | 있음 셸 기록·cron·systemd | — |
| 파일 접근·열람 | 있음 LNK·ShellBag·Jump List·Office 최근 | **없음**(FSEvents·Spotlight 미해석, `.sfl2` 최근 항목 미구현) | **없음**(`recently-used.xbel` 미구현) | — |
| 브라우저 | 있음 Chromium 계열·Firefox·IE/Edge 레거시·캐시·업로드 패턴 | 있음 Chrome/Edge/Brave/Firefox/Safari 기록·다운로드(`macos-browser-history-downloads`) — 업로드 패턴·캐시 **없음** | **미확인**(`~/.config/google-chrome`·`~/.mozilla` 수집 여부 코드 확인 → 갈래 B 결과로 표 갱신) | 브라우저 행 미지원(known-limitations 226행) |
| USB·외부 장치 | 있음 레지스트리·setupapi·이벤트 로그·VSN↔LNK 교차 | **없음**(`/var/log/system.log`·Unified Log 미해석) | **없음**(kernel/udev 로그 미해석) | — |
| 클라우드 동기화 | 있음 `cloud-sync`(OneDrive·Dropbox·GoogleDrive DB)·`cloud-export` | **미확인**(경로가 `Library/Application Support/...`인지 확인) | 없음 | — |
| 메일 | 있음 PST/OST·EML·Outlook·Windows 메일·Thunderbird(`email-clients`) | **없음**(Mail.app `.emlx` 미지원) | Thunderbird 경로 **미확인** | — |
| 메신저 | 있음 카카오톡 Windows·Telegram·Discord·Slack·Viber 등 `windows-messenger` | 있음 카카오톡 macOS(`kakaotalk-macos`), **iMessage `chat.db` 없음** | 없음 | iOS 백업 `sms.db`(`mobile-message`), adb 백업 내부 DB(R6 S2) — **암호화 백업·카카오톡 iOS 미지원** |
| 삭제 복구 | 있음 휴지통·`$MFT` 삭제 항목·카빙·미할당 URL(R6 S2) | 부분: `.Trash`·파일 카빙(폴더 입력), APFS 스냅샷 **힌트만** | 부분: 파일 카빙, journald 없음 | 부분 |
| 안티포렌식 | 있음 `antiforensics` 계열(와이퍼·시간 조작·로그 삭제) | 없음 | 부분(셸 기록 삭제 흔적만) | — |
| 인쇄 | 있음 이벤트 로그 PrintService·스풀 | 없음 | 없음(CUPS 로그 미구현) | — |
| 위치 | 있음 지도 URL 위치 후보·EXIF | EXIF만 | EXIF만 | EXIF |

"없음/미확인" 칸은 체크리스트에 **수동 검토 항목**(외부 도구·현장 확인)으로 들어간다. 이 표는 `core/request_brief/coverage.yaml`로 두고 카드와 known-limitations가 같은 파일을 읽는다(문서 drift 방지, `scripts/check-doc-refs.py`에 검사 추가).

#### 4.3.3 검토 계획(체크리스트) 항목 종류(`target_json`)

| kind | target 예 | 열면 |
|---|---|---|
| `tree-node` | `{"node":"devices"}`·`{"node":"artifacts","kind":"windows-remote-access"}` | 트리 노드로 이동(`domains.ts` 기존 id: `derived`·`os`·`execution`·`filesystem`·`registry`·`eventlog`·`web`·`messaging`·`cloud`·`media`·`mobile`·`devices`·`anti-forensics`·`incident`·`memory`·`location`) |
| `derived` | `{"table":"devices"}` (people·devices·paths·attachments·credentials·urls·location-urls) | 통합 보기 표 |
| `rule-family` | `{"family":"usb","rule_ids":["usb.new_device","usb.mass_storage_activity"]}` | 플래그 필터가 걸린 아티팩트 그리드 |
| `saved-search` | `{"saved_search_id":12}` | 검색 결과(확인 시 자동 생성: 대상 이름·계정·키워드 팩; 이름 `의뢰: …`) |
| `analysis` | `{"kind":"carve","options":{...}}` | 분석 대기열에 넣기 버튼(검사관이 실행) |
| `manual` | `{"note":"macOS USB 연결 이력은 미지원: Unified Log를 외부 도구로"}` | 메모만, 완료/해당 없음 |
| `condition` | `{"from":"2026-09-01","to":"2026-10-01"}` | 타임라인에 사건 시간대 조건 적용 |

완료 표시는 `case_plan_item.status`로, 리뷰 상태 4종과 **별개**다(용어집 규칙 준수). 항목에서 리뷰 표시(관련 있음·보고서 포함)를 하면 `done_at`이 자동으로 채워지는 것이 아니라 "표시 n건" 힌트만 보인다(검사관이 완료를 결정).

#### 4.3.4 필요 자료(플레이북 `materials` 블록, 범주별 기본)

| 범주 | 기본 요청 목록 |
|---|---|
| leak | 클라우드 관리자 감사 로그(Google Workspace/M365/Dropbox), 메일 서버 송신·첨부 로그, USB 지급 대장·MDM 정책, 출입·근태 기록, 정보보호 서약서·NDA, 기기 소유·동의 확인서, 유출 의심 자료 목록(파일명·해시) |
| embezzlement | 회계 시스템 사용자 로그·전표 이력, 은행 거래 내역, 법인카드 명세, 결재 시스템 로그, 계약서 원본·사본, 관련자 조직도·권한표 |
| intrusion | 방화벽·VPN·WAF·EDR 로그, 웹 서버 액세스 로그(로테이션 포함), 클라우드 콘솔 감사 로그, 네트워크 구성도·자산 목록, 사고 인지 시각·조치 내역, 랜섬 노트·연락 이력, 변조 전 백업 |
| recovery | 삭제 추정 시점·파일 목록, 백업·스냅샷 존재 여부, 기기 사용 중단 시점(덮어쓰기 위험 고지), 사용자 계정 비밀번호는 **요청하지 않음**(정책) |
| illicit-media | 피해자 진술·촬영 추정 일시·장소, 유포 경로 캡처, 플랫폼 신고 접수 번호, 영장·동의서 범위(열람 제한 고지), 반출 금지·열람자 기록 절차 |
| defamation-threat | 캡처 원본(기기 그대로), 상대방 계정 ID·전화번호, 플랫폼 보존 요청 사실, 통화 녹음 원본, 사건 발생 시간대 |
| labor | 근무 규정·재택 근무 정책, 출퇴근·VPN·출입 기록, 회사 기기 사용 정책(사적 사용 금지 여부), 노동조합·징계 절차 자료, 모니터링 동의 범위 |
| 공통 | 증거 봉인·인수인계서, 기기 사양(OS 버전·암호화 여부·BitLocker/FileVault 키 — **키는 의뢰처가 직접 해제해 제공, 제품에 입력하지 않음**), 분석 범위 승인서 |

#### 4.3.5 보고서 골격(`core/case_report.py` 추가만)
- 새 절 "1-1. 의뢰 내용"(사건 정보 아래): 의뢰처·접수일·기한, 가린 원문 요약(검사관이 카드에서 쓴 "의뢰 요약" 2–5줄 또는 원문 첫 500자 가린 값), 의뢰 해석 표(유형·플랫폼·시간대·산출물).
- "2. 분석 대상 및 범위"에 플랫폼 커버리지 요약(지원/미지원)이 자동 삽입되고 `scope` 자유 문자열은 뒤에 붙는다.
- "4. 주요 검토 결과"가 산출물별 소절로 나뉘고(`report-section` 항목), 각 소절에는 그 체크리스트 항목에서 "보고서 포함" 표시된 행이 들어간다. 행이 0이면 "확인된 흔적 없음(부재 ≠ 미발생; 미지원 항목은 외부 검토 필요)".
- `CaseReportRequest`에 `plan_id: int | None` 추가(없으면 기존 보고서 그대로).

### 4.4 플레이북 라이브러리(`core/request_brief/playbooks/*.yaml` + 작업 공간 덮어쓰기)

```yaml
id: pb-leak-employee
version: 3
label_ko: 임직원 자료 유출(퇴사·이직)
categories: [leak]                      # 매칭 범주
platform_notes: {macos: "USB·파일 접근 이력 미지원 → 수동", linux: "…"}
run: {mode: seizure, skip_groups: [memory, p2p], analyses: [ntfs-meta, url-carve, carve:documents], keyword_packs: [exfiltration, leak-ko]}
checklist:
- {id: devices, label_ko: 장치 식별자·USB 연결, kind: derived, target: {table: devices}, then: {kind: rule-family, target: {family: usb}}}
- {id: paths, label_ko: 설계·영업 폴더 접근 경로, kind: derived, target: {table: paths}, keywords_from: [subjects.file, deliverables]}
- {id: cloud, label_ko: 클라우드 동기화·웹 업로드, kind: tree-node, target: {node: cloud}}
- {id: webmail, label_ko: 웹메일 첨부·개인 메일, kind: rule-family, target: {family: browser, rule_ids: [browser.upload_*]}}
- {id: search-subjects, label_ko: 대상 이름·계정 검색, kind: saved-search, from: subjects}
- {id: deleted, label_ko: 삭제 파일 후보, kind: tree-node, target: {node: filesystem, view: recovery}, when: {deliverable: deleted-recovery}}
- {id: print, label_ko: 인쇄 기록, kind: tree-node, target: {node: eventlog, channel: other, filter: PrintService}, when: {deliverable: print}}
- {id: window, label_ko: 사건 시간대 타임라인, kind: condition, from: time_window}
materials: [cloud-admin-audit, mail-server-log, usb-ledger, nda, device-consent]
report_sections: [usb-history, cloud-upload, webmail-attachment, deleted-recovery, print]
```

- 시드(이번 라운드): `pb-leak-employee`, `pb-fraud-finance`, `pb-intrusion`(Windows·Linux 분기), `pb-recovery`, `pb-illicit-media`, `pb-message-dispute`, `pb-labor`, `pb-general`. 범주 복수면 주범주 플레이북 + 부범주 체크리스트를 뒤에 합친다(중복 id 제거).
- 편집: UI "플레이북" 대화상자(설정 메뉴)에서 체크리스트·필요 자료·건너뛰기 목록을 고치면 작업 공간 `rapidtriage-playbooks/<id>.yaml`(케이스 DB 옆)에 덮어쓰기 판이 저장된다(원본 리포 YAML은 불변, `playbook_sha256`로 어느 판을 썼는지 `case_intent`에 남음). 스키마 검증 실패 시 저장 거부(한국어 사유).
- 학습(로컬만): 확인 시 `examiner_edits`와 체크리스트 완료 패턴(어떤 항목이 "해당 없음"으로 자주 닫히는지, 어떤 저장 검색이 추가됐는지)을 `playbook_feedback` 표에 집계하고, 플레이북 대화상자가 "최근 5건에서 검사관이 항상 추가한 항목: … 플레이북에 넣기" 제안을 낸다. 자동 변경 없음. 과거 사건 추천은 `case_intent`의 범주·플랫폼이 같은 케이스 목록(사건명·가린 대상·사용 플레이북 판)을 카드 하단에 "비슷한 사건 n건"으로 보여준다.

### 4.5 API(모두 로컬 FastAPI, OpenAPI 스냅샷 갱신)

| 메서드·경로 | 본문/응답 | 비고 |
|---|---|---|
| `POST /api/request-brief/parse` | `{source_kind, text, origin_hint?}` → `{adapter, fields, intent_draft, warnings}` | 무상태 미리보기(위저드 1단계용, DB 저장 없음) |
| `POST /api/cases/{case_id}/request` | 같은 본문 → `case_request` 새 판 + `case_intent(draft)` | 감사 `request.import` |
| `GET /api/cases/{case_id}/request?reveal=0` | `{request(masked), intent(current), plan?, similar_cases[]}` | `reveal=1`은 원문, 감사 `request.reveal` |
| `PATCH /api/cases/{case_id}/request/intent` | `{intent_json}` → draft 갱신 | 감사 `intent.edit`(가린 diff) |
| `POST /api/cases/{case_id}/request/intent/confirm` | `{playbook_id?}` → `intent(confirmed)` + `plan` 생성 + 저장 검색 생성 + 런 prefill | 감사 `intent.confirm`·`plan.create`·`search.save` |
| `GET /api/cases/{case_id}/plan` | `{run_prefill, checklist[], materials[], report_sections[], progress{done,total}}` | 대시보드 카드·검토 단계 |
| `PATCH /api/cases/{case_id}/plan/items/{item_id}` | `{status, note}` | 감사 `plan.item` |
| `GET /api/playbooks`, `GET /api/playbooks/{id}`, `PUT /api/playbooks/{id}`, `DELETE /api/playbooks/{id}/override` | YAML 본문(문자열)과 검증 결과 | 작업 공간 덮어쓰기만 수정 |
| `GET /api/request-brief/coverage` | §4.3.2 표 | 카드·문서 |
| `GET /api/request-brief/bookmarklet` | JS 텍스트 + 설치 안내 | 정적 |

제한: 원문 256 KiB, 저장 검색 자동 생성 최대 10개/확인, 체크리스트 60항목, 플레이북 YAML 64 KiB. 모든 오류는 한국어 메시지(`CaseDatabaseError` 패턴).

### 4.6 UI(갈래 C)

위저드 1단계 "사건 정보" 상단:

```
┌ 1단계 · 사건 정보 ───────────────────────────────────────────────┐
│ [의뢰 가져오기 ▾]  FTop 화면 복사 붙여넣기 · 내보내기 HTML 열기 · 북마클릿 안내 │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ (붙여넣기 칸 — 원문/JSON/HTML 자동 인식)                        │ │
│ └──────────────────────────────────────────────────────────────┘ │
│ 인식: FTop 어댑터(라벨 9/10)  ⚠ '기한' 찾지 못함 → 아래에서 입력        │
│ 사건 번호 [2026-10-0123]  사건명 [○○전자 영업비밀 유출 의심]           │
│ 의뢰처 [○○전자 법무팀]   검사관 [김영규]   접수일 [2026-10-20]  기한 [ ] │
│ 사건 유형(FTop) [기술유출]  → 의뢰 해석 초안: 유출(높음) · 삭제 복구(보통) │
│ 의뢰 원문(가림)  ▸ 펼치기                                              │
└──────────────────────────────────────────────────────────────────┘
```

접수 대시보드: "시작할 곳"(8+4 밴드 마지막 4열)을 **"의뢰 브리프" 카드로 교체**(의뢰가 없으면 기존 3링크 + "의뢰 가져오기" 버튼으로 퇴화):

```
┌ 의뢰 브리프  유출 · 삭제 복구     확인됨 10-20 김영규   진행 3/8 ━━━━━━░░░░ ┐
│ 대상 Windows 노트북 1 · macOS 1   시간대 2026-09-01 ~ 10-01   [해석 고치기]    │
│ 산출물  USB ✓  클라우드 ✓  웹메일 ✓  삭제 복구 ·  인쇄 ·                     │
│ 검토 계획                                                                   │
│  ☑ 1 장치 식별자·USB 연결            통합 보기 → USB 규칙 3건 표시          │
│  ☑ 2 설계 폴더 접근 경로              접근 경로                              │
│  ☑ 3 클라우드 동기화·웹 업로드        클라우드                               │
│  ☐ 4 웹메일 첨부·개인 메일            브라우저 업로드 규칙        [열기]      │
│  ☐ 5 대상 이름·계정 검색(저장 검색 3)                           [열기]      │
│  ☐ 6 삭제 파일 후보                   복구 보기 · carve 대기     [실행]      │
│  ☐ 7 인쇄 기록                        이벤트 로그 PrintService   [열기]      │
│  ⚠ 8 macOS: USB·파일 접근 이력 미지원  수동 검토                 [해당 없음] │
│ 필요 자료 2/5 받음  ▸   비슷한 사건 2건 ▸   보고서 골격 5절 ▸                │
└─────────────────────────────────────────────────────────────────────────────┘
```

검토 단계(`ReviewReportStage.tsx`) 왼쪽에 같은 체크리스트가 "검토 계획" 패널로 들어가고, 보고서 대화상자(`ReportDialog.tsx`)에 "의뢰 브리프 절 포함(plan #n)" 토글. 설정 메뉴에 "플레이북" 대화상자(YAML 편집기 + 검증 결과 + "원본으로 되돌리기"). 접근성: 체크리스트는 `role=list`, 완료 토글은 `aria-pressed`, 신뢰도는 색만이 아니라 글자(높음/보통/낮음).

---

## 5. 갈래(파일 소유 분리, 4 워크트리 병렬)

#### 갈래 A — 가져오기·저장·가리기(백엔드)
소유: `core/request_brief/__init__.py`·`adapters/{base,generic_label,ftop,export_list}.py`·`adapters/labels.yaml`·`adapters/ftop.yaml`·`redaction.py`, `core/case_db/request_brief.py`(스키마·CRUD·감사), `api/app/routes_request_brief.py`(parse·request·intent PATCH·reveal·bookmarklet), `api/static/ftop-bookmarklet.js`, `tests/test_r7_request_adapters.py`·`tests/test_r7_request_db.py`·`tests/test_r7_redaction.py`, 픽스처 `tests/fixtures/request_brief/`(합성·가명 텍스트/HTML만).
- 의존: 없음(해석기는 갈래 B 함수를 호출하되 인터페이스 `classify(fields) -> IntentDraft`만 합의; B 미완이면 스텁).

#### 갈래 B — 해석기·플레이북·플래너(백엔드)
소유: `core/request_brief/classifier.py`·`vocab/*.yaml`·`planner.py`·`playbooks/*.yaml`·`playbook_store.py`·`coverage.yaml`·`coverage.py`, `core/keyword_packs.py`(한국어 팩 4개 추가만), `core/run/`의 `event_window` 옵션 + 규칙 엔진 파라미터 주입(파일 2곳, 최소 diff), `api/app/routes_request_brief.py`의 confirm·plan·playbooks·coverage 핸들러(A와 같은 파일을 피하려고 `routes_request_plan.py`로 분리), `scripts/check-request-vocab.py`, `tests/test_r7_classifier.py`·`tests/test_r7_planner.py`·`tests/test_r7_playbooks.py`·`tests/test_r7_event_window.py`.
- 추가 조사 의무: Linux 브라우저·Thunderbird, macOS cloud-sync 경로 수집 여부를 코드로 확인해 `coverage.yaml`과 known-limitations에 적는다(구현은 하지 않음).

#### 갈래 C — 프런트(위저드·카드·검토 패널·플레이북 대화상자)
소유: `frontend/src/features/case/RequestImportField.tsx`(신규)·`IntentEditor.tsx`(신규)·`wizardModel.ts`(필드 추가)·`CaseWizard.tsx`(1단계 삽입)·`RunOptionsFields.tsx`(prefill 수신), `frontend/src/features/dashboard/requestBriefCard.tsx`(신규)·`CaseDashboard.tsx`(start 카드 교체 분기)·`useDashboardData.ts`(plan fetch), `frontend/src/features/stages/ReviewPlanPanel.tsx`(신규)·`ReviewReportStage.tsx`(패널 삽입), `frontend/src/features/case/ReportDialog.tsx`(토글), `frontend/src/features/playbooks/`(신규 디렉터리), `frontend/src/api/requestBrief.ts`(신규), CSS는 각 feature css에 블록 추가, 테스트 `requestBrief.test.tsx`·`requestBriefCard.test.tsx`·`reviewPlan.test.tsx`·e2e `e2e/request-brief.spec.ts`.
- 백엔드 미완 시 `msw` 스텁으로 개발(응답 스키마는 §4.5 고정).

#### 갈래 D — 보고서·검색 연결·문서
소유: `core/case_report.py`(절 추가)·`api/app/models.py` `CaseReportRequest.plan_id`·`routes_reports.py`(plan 로드), `core/case_db/database.py` 저장 검색 자동 생성 헬퍼(`save_search` 재사용, 이름 규칙), `docs/console-glossary.md`(의뢰 브리프 절)·`docs/rapidtriage-known-limitations.md` `## R7`·`docs/request-brief-ftop-setup.md`(신규: 북마클릿 설치·붙여넣기 절차·가명화 표본 만드는 법)·`scripts/check-doc-refs.py`(coverage.yaml 대조)·OpenAPI 스냅샷 갱신, `tests/test_r7_report_sections.py`.

---

## 6. QA 시나리오

| # | 시나리오 | 기준 |
|---|---|---|
| Q-R7-1 | 붙여넣기 3형식(텍스트·HTML·북마클릿 JSON)에서 라벨 10개 추출 | 합성 픽스처 3종에서 필드 10/10, `field_sources` 근거 있음, 누락 라벨은 `extra`·경고 |
| Q-R7-2 | `/cases/export` 목록 HTML | 사건 n건 목록 → 선택 → 필드 채움; 쿼리 문자열·쿠키·`<script>` 내용이 저장값 어디에도 없음 |
| Q-R7-3 | 원문 상한·오염 입력 | 256 KiB 초과 400, 깨진 HTML·제어 문자·NFD 한글 → 파싱 성공 또는 한국어 오류, 서버 생존 |
| Q-R7-4 | 가리기 | 주민번호·휴대전화·이메일·계좌·이름+호칭 10종 픽스처가 `raw_text_masked`·보고서·리뷰어 번들·로그에 원문으로 안 나옴; `reveal=1`만 원문, 감사 이벤트 1건 |
| Q-R7-5 | 해석기 정확도 | 가명 의뢰문 코퍼스 ≥ 40건(검사관 작성, `tests/fixtures/request_brief/corpus.yaml`, 범주별 ≥ 5)에서 주범주 정확도 ≥ 85%, 플랫폼 재현율 ≥ 90%, 시간대 추출 ≥ 70%(절대 날짜 100%); 부정문("해킹은 아님") 억제 검증 |
| Q-R7-6 | 결정론·오프라인 | 같은 입력 → 같은 `auto_json`(sha256 일치), 테스트 중 소켓 열림 0(기존 "외부 요청 금지" 테스트 패턴), `suggester != rules` 거부 |
| Q-R7-7 | 확인 전 비적용 | draft 상태에서 저장 검색·plan·런 prefill 생성 0; confirm 후에만 생성, 감사 이벤트 체인 유효 |
| Q-R7-8 | 플래너 매핑 | 범주 8종 × 플랫폼 조합에서 모드·skip_groups·분석·팩이 표 §4.3.1과 일치, 복수 범주 합집합·중복 없음, 미지원 칸이 `manual` 항목으로 들어감(coverage.yaml 대조) |
| Q-R7-9 | `event_window` | 런 요청에 from/to → `usb.new_device`가 시간대 안 장치만 플래그(합성 레지스트리·setupapi), 없으면 기존 동작 그대로(회귀 0), OpenAPI 스냅샷 diff 첨부 |
| Q-R7-10 | 플레이북 | 리포 YAML 8개 스키마 통과; 덮어쓰기 저장·검증 실패 거부·되돌리기; `playbook_sha256`가 intent에 기록; YAML 64 KiB 상한·`!!python` 태그 거부(safe_load) |
| Q-R7-11 | 체크리스트·진행 | 항목 상태 전이(open→done→open, not-applicable), 진행률 계산, 저장 검색 항목 열기 → 검색 화면, 조건 항목 → 타임라인 from/to 적용(프런트 테스트) |
| Q-R7-12 | 대시보드 | 의뢰 없음 → 기존 시작할 곳 + 가져오기 버튼; 있음 → 카드; 좁은 창(<1100 px) 단일 열; 명암비·키보드 조작(e2e) |
| Q-R7-13 | 위저드 prefill | 붙여넣기 → 1단계 필드 채움 → 3단계 처리 옵션이 플래너 값으로 기본 설정, 검사관 변경값이 `processing_snapshot`에 남음 |
| Q-R7-14 | 보고서 | `plan_id` 있는 보고서에 "1-1. 의뢰 내용"·산출물별 4절 소절, 0건 소절 문구, 가린 값만; `plan_id` 없으면 기존 보고서 바이트 동일 |
| Q-R7-15 | 비슷한 사건·피드백 | 케이스 3건(유출 2·침해 1) 후 유출 케이스 카드에 "비슷한 사건 2건"; `examiner_edits` 집계 제안이 자동 반영되지 않음 |
| Q-R7-16 | 실데이터 | `D:\rapid-qa\bsh-subset` 케이스에 가명 유출 의뢰문 적용 → `seizure`+`event_window` 런(Antigravity 위임) → 체크리스트 8항목 모두 열림·저장 검색 결과 존재·보고서 생성; 기존 kind 행 수 변화 0(`scripts/compare-runs.py`) |
| Q-R7-17 | 게이트·비밀 | §0 게이트 전체, `tests/fixtures/request_brief/`에 실제 FTop 문자열·실명·실제 사건번호 없음(검사관 확인 서명을 PR에 기록), `git status`에 FTop 캡처 없음 |

---

## 7. 사용자 조치·승인

1. **FTop 접수 방식 결정**: 권고 = 붙여넣기 + 북마클릿(클립보드). Playwright 스크립트는 제품 밖 후속(원하면 별도 승인). 로컬 API POST 북마클릿은 보류.
2. **FTop 가명화 표본 1건**: 검사관이 FTop 사건 페이지 1건과 `/cases/export` 1건을 저장한 뒤 실명·사건번호·연락처를 치환해 `tests/fixtures/request_brief/ftop-sample-*.html`로 제공(또는 제공 불가 시 Generic 어댑터만 검증하고 FtopAdapter는 "미확인"으로 둠). 북마클릿은 제공받은 DOM으로 셀렉터를 확정한다.
3. **의뢰문 코퍼스 ≥ 40건**: 과거 사건을 **가명·변형**한 문장(실제 문장 복사 금지). 범주별 5건 이상. 없으면 에이전트가 합성 코퍼스를 쓰되 정확도 수치는 "합성 기준"으로 표기.
4. **플레이북 시드 검토**: §4.3.4 필요 자료·§4.4 체크리스트 초안을 검사관이 한 번 읽고 사무실 관행에 맞게 수정(PR 전).
5. **동의·고지 문구**: 카드의 "미지원" 문구와 필요 자료의 법적 항목(동의서·영장 범위)은 법률 검토 담당이 확인.
6. 실데이터 QA(Q-R7-16) Antigravity 위임 승인.

---

## 8. 완료 기준·규모

- Q-R7-1~17 충족, 적대적 리뷰(백/프런트) 미해결 0, known-limitations `## R7`(FTop 어댑터 확인 상태, 해석기 한계, 커버리지 표 링크, 가리기 범위), 용어집 "의뢰 브리프" 절, `docs/request-brief-ftop-setup.md`.
- 규모: **대**. 백엔드 신규 모듈 ~10(어댑터 3·가리기·해석기·플래너·플레이북 저장소·커버리지·케이스 DB·라우트 2) ≈ 2,800줄 + YAML(어휘 5·플레이북 8·커버리지 1), 런 변경 2곳(소), 보고서 1모듈(소); 프런트 신규 컴포넌트 7 + 기존 6 수정 ≈ 2,000줄; 테스트 백 8파일·프런트 4 + e2e 1. 갈래 A·B·C·D 파일 겹침 없음(라우트를 두 파일로 나눔). 예상: Opus 4갈래 병렬 2–3일, QA·리뷰 1–2일, PR 1개(`feat/r7-request-brief`), 커밋은 갈래별 분리.

---

## 9. 위험

| 위험 | 대응 |
|---|---|
| 의뢰 원문의 개인정보(실명·연락처·계좌)가 보고서·번들·로그로 샘 | §4.1.4 가리기를 출력 경로 전부에 적용하고 Q-R7-4로 고정; `reveal`은 감사 기록; 픽스처는 가명만 |
| 해석기가 틀린 유형·시간대를 "그럴듯하게" 제시(과신) | 신뢰도 등급·근거 용어 밑줄·확인 필수; 임계 아래는 "낮음" 표시; 코퍼스 정확도 공개(Q-R7-5) |
| 매핑 환각: 플레이북이 존재하지 않는 노드·규칙·표를 가리킴 | 플래너가 `domains.ts` id·카탈로그 규칙 id·통합 보기 표 id를 **빌드 시 생성된 목록**(`scripts/gen-flag-catalog` 패턴)과 대조, 테스트가 모든 플레이북 target을 해석 |
| 과자동화: 확인 없이 런·검색이 생기거나 검사관 판단이 체크리스트로 대체됨 | draft/confirmed 분리(Q-R7-7), 체크리스트는 리뷰 상태와 별개, 보고서는 리뷰 표시 행만 사용 |
| macOS·Linux 커버리지 과장 | `coverage.yaml` 단일 출처 + 갈래 B 코드 확인 의무 + known-limitations 동기화 검사 |
| FTop DOM 변경·대외비 | 어댑터는 YAML 라벨 사전만 바꾸면 되게; FTop 자료는 Git 밖; 북마클릿 실패 시 붙여넣기로 퇴화 |
| 정규식 ReDoS·YAML 안전 | `check-request-vocab.py`(중첩 수량자 금지·길이 상한), `safe_load`만, 입력 상한 |
| 케이스 DB 스키마 마이그레이션 | 추가만(`apply_intake_schema` 패턴), 구 DB 열기 회귀 테스트 |
| 범위 팽창(FTop 쓰기·LLM·모바일) | §1 목표 밖 명시; 후속 후보로만 기록 |

---

## 10. 결정 요청 요약(사용자)

1. 이름 "의뢰 브리프" 채택 여부.
2. FTop 접수 방식: 붙여넣기 + 클립보드 북마클릿(권고) / 로컬 POST 북마클릿 / Playwright 스크립트(제품 밖).
3. 가명화 FTop 표본·의뢰문 코퍼스 제공 여부(없으면 합성 기준으로 진행).
4. 런 옵션 `event_window` 추가(런 파이프라인 소규모 변경) 승인.
5. "시작할 곳" 카드를 의뢰 브리프 카드로 교체(의뢰 없으면 기존 유지) 승인.
6. 플레이북 시드 8종과 필요 자료 목록의 사무실 관행 검토.

## 결과 기록
(구현 후 채움)
