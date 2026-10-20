# R6 단계 1(b) — 일회용 VM 실앱 표본 생성 실행서 (2026-10-19)

근거: `docs/plans/r6-followups-2026-10-19.md` §1.4(경로 b)·§1.5(수용 기준)·§1.7(사용자 조치), `docs/validation/r6-sample-validation-2026-10-19.md`(표본 보관 규칙·known-answer 스키마·`scripts/sample-check.py` 사용법).
사용자 승인: U2 "VM 생성·앱 설치"(2026-10-19). **다운로드는 아직 승인되지 않았다** — §1 표의 각 항목은 파일명·출처·크기를 확인한 사용자 승인 후에만 받는다.

이 문서는 **준비 문서**다. 엔지니어링 측정용 표본을 만드는 절차이며 릴리스 증거가 아니다. 표본·known-answer·비밀번호·해시 값은 Git에 넣지 않는다.

---

## 0. 한눈에 보기

| 항목 | 값 |
|---|---|
| 호스트 | VMware Workstation 17.5.2 (`C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe`), 기존 VM 없음, Windows ISO 없음, D: 여유 약 2.2 TB |
| VM 위치(제안) | `D:\rapid-qa\vm\rt-sample-w11\` (Git 밖) |
| 호스트 → VM 입력 폴더 | `D:\rapid-qa\vm-inbox\` (VMware 공유 폴더, **읽기 전용**으로 연결) |
| VM → 호스트 반출 폴더 | `D:\rapid-qa\samples\_vm-export\` (공유 폴더, 반출할 때만 켬) |
| 최종 표본 위치 | `D:\rapid-qa\samples\<parser>\vm01\` + `D:\rapid-qa\samples\<parser>\vm01-known-answer.json` |
| VM 사용자 이름 | `rtuser` (실명·회사명 금지), 로컬 계정 |
| 스냅샷 | `clean-os` → `apps-installed` (→ 선택 `samples-made`) |
| 네트워크 | NAT. 앱 설치가 끝나면 **가상 NIC 연결 해제**(eMule·qBittorrent 단계는 오프라인) |
| 우선순위 | ① EGG/ALZ ② 팟플레이어 ③ 곰플레이어 → ④ KMPlayer·VLC ⑤ eMule·qBittorrent ⑥ PSD ⑦ (선택) V3 Lite+EICAR |

---

## 1. 다운로드 목록 (사용자 승인 대상)

모두 **공식 배포 페이지**에서만 받는다. 크기는 2026-10 기준 대략값이며 공식 페이지 표기를 승인 시 다시 확인한다. 설치 파일은 VM 안에서 받거나(권장: 호스트에 실행 파일이 남지 않음), 호스트에서 받는 경우 `D:\rapid-qa\vm-inbox\installers\`(새 빈 폴더)에만 둔다. 호스트에서 실행하지 않는다.

| # | 항목 | 공식 출처 | 대략 크기 | 라이선스·약관 메모 | 필수/선택 |
|---|---|---|---|---|---|
| D1 | Windows 11 Enterprise 평가판 ISO (한국어 또는 영어, x64) | Microsoft Evaluation Center — https://www.microsoft.com/ko-kr/evalcenter/download-windows-11-enterprise | 약 5–6.5 GB | 90일 평가판, 평가·테스트 용도. 다운로드 전 **등록 양식(이름·이메일 등) 입력은 사용자만** 한다 | 필수 |
| D2 | 알집(ALZip) 설치 파일 | ESTsoft 알툴즈 — https://www.altools.co.kr (알집 다운로드 페이지) | 약 40–80 MB | **개인 무료, 기업·기관 사용은 유료 라이선스**. 법무법인 업무 PC가 아닌 일회용 VM 테스트라도 약관상 "기업 사용"에 해당하는지 **사용자가 확인**. 설치 중 제휴 프로그램 체크 해제 | 필수 |
| D3 | 팟플레이어(PotPlayer) 64비트 | 카카오 — https://tv.kakao.com/guide/potplayer | 약 30–50 MB | 무료(카카오 배포 약관). 설치 중 추가 제품 체크 해제 | 필수 |
| D4 | 곰플레이어(GOM Player) | 곰앤컴퍼니(구 그래텍) — https://www.gomlab.com (GOM Player 페이지) | 약 30–60 MB | 무료판 약관 확인(개인 무료, 업무 사용 조건은 약관 기준). 광고·제휴 설치 체크 해제 | 필수 |
| D5 | KMPlayer (64X 또는 표준) | 판도라TV KMPlayer — https://www.kmplayer.com | 약 40–80 MB | 무료(광고 포함). 제휴 설치 체크 해제 | 필수 |
| D6 | VLC media player 64비트 | VideoLAN — https://www.videolan.org/vlc/ | 약 40 MB | GPLv2 | 필수 |
| D7 | eMule 0.50a (공식) | eMule Project — https://www.emule-project.com (Downloads) | 약 5 MB | GPLv2. **네트워크 연결 없이** 사용(§4.6). 커뮤니티 0.70b(github.com/irwir/eMule Releases, 파서 주석이 참조하는 소스)는 공식 0.50a로 0xE1 등이 재현되지 않을 때만 별도 승인 후 | 필수 |
| D8 | qBittorrent 64비트 | qBittorrent — https://www.qbittorrent.org/download | 약 30–40 MB | GPLv2. **자체 제작 가짜 토렌트만** 추가(§4.7) | 필수 |
| D9 | GIMP 2.10/3.x **또는** Krita 5.x (PSD 저장용, 하나만) | https://www.gimp.org/downloads/ / https://krita.org/ko/download/ | GIMP 약 300 MB / Krita 약 130 MB | GPL. Photoshop XMP 이력은 만들어지지 않음(헤더·해상도·색 모드만 검증) | 필수(하나) |
| D10 | AhnLab V3 Lite | 안랩 — https://www.ahnlab.com (V3 Lite 다운로드 페이지) | 설치 파일 약 2–5 MB + 설치 중 엔진 약 100–300 MB | **개인 무료, 기업 사용 금지**(안랩 약관). 사용자가 약관상 가능할 때만. 설치 중 업데이트에 네트워크 필요 | 선택 |
| D11 | EICAR 표준 시험 파일 | EICAR — https://www.eicar.org/download-anti-malware-testfile/ | 68 바이트(`eicar.com`) | 악성 코드가 아닌 업계 표준 시험 문자열. **VM 안에서만** 받는다(호스트 백신 반응 방지). 호스트로 반출하지 않는다 | 선택(D10과 함께) |
| D12 | (선택) 공개 도메인 영상 URL 1개 — 플레이어 "URL 재생" 항목용 | Wikimedia Commons 공개 도메인 영상(예: commons.wikimedia.org의 "Public domain" 분류 중 하나, 사용자가 고름) | 재생 중 스트리밍 수 MB, 파일 저장 없음 | 공개 도메인. 대안: 연결되지 않는 시험 URL `http://media.invalid/rt-sample/stream01.mp4`(네트워크 불필요, 기록만 남는지 확인용) | 선택 |

다운로드가 **필요 없는** 것: VMware Tools(Workstation 17.5.2에 포함된 설치 이미지를 "VM > Install VMware Tools"로 사용; 번들이 없다고 나오면 그때 별도 승인), 가짜 콘텐츠(호스트에서 Claude가 생성, §2.2), 리눅스 배포판 토렌트(자체 제작 가짜 토렌트로 대체 — 받지 않는다).

---

## 2. 역할 분담

원칙: **비밀번호·계정·약관 동의·설치 프롬프트·VMware 조작은 사용자**, **자격 증명이 필요 없는 준비·검증은 Claude**. Claude는 VMware(`vmrun` 포함)를 조작하지 않고, VM 안 GUI도 조작하지 않는다(가장 단순하고 안전한 분담).

### 2.1 사용자가 직접 하는 일

| 단계 | 내용 |
|---|---|
| U-a | §1 다운로드 승인, Evaluation Center 등록 양식 입력, ISO 다운로드 |
| U-b | VMware에서 새 VM 생성(§3), vTPM용 VM 암호화 비밀번호 설정(Workstation이 TPM 추가 시 요구 — 비밀번호는 사용자만 입력·보관) |
| U-c | Windows 설치·OOBE: 로컬 계정 `rtuser` 생성과 비밀번호 입력, 개인정보 옵션 모두 "끔"(§7) |
| U-d | VMware Tools 설치, 공유 폴더 2개 연결(§3.2), 스냅샷 생성 |
| U-e | 각 앱 설치(약관 동의, 제휴 프로그램 체크 해제), 알집 압축 시 테스트용 압축 비밀번호 입력 |
| U-f | §4 시나리오 GUI 조작(재생·중지·압축·eMule/qBittorrent 조작), Claude가 준비한 `vm-collect.ps1` 실행 |
| U-g | 작업 후 VM 삭제(§3.4) |

### 2.2 Claude가 하는 일(자격 증명 없음, 호스트 `D:\rapid-qa\` 안에서만)

| 단계 | 내용 | 결과 위치 |
|---|---|---|
| C-1 | 가짜 콘텐츠 생성(표준 라이브러리 스크립트, 스크립트는 scratchpad에 둠): 한국어·ASCII 이름의 텍스트, PNG(zlib로 직접 작성), 압축률 높은 2 MB 텍스트(LZMA 블록용), 12 MB 의사난수 파일(분할용), 3분 길이 무압축 AVI 3개(96×72 RGB24, 2 fps, 각 약 7.5 MB, 프레임마다 숫자 막대 — 재생 위치 눈으로 확인 가능) | `D:\rapid-qa\vm-inbox\content\` |
| C-2 | eMule용: 공유할 가짜 파일 2개 + 그 ed2k 링크(MD4 직접 계산), 소스가 없는 가짜 ed2k 링크 3개(작은 파일 1, 4 GiB 초과 크기 1 — 0xE2 유도, 한국어 이름 1) | `D:\rapid-qa\vm-inbox\emule\` |
| C-3 | qBittorrent용: 가짜 콘텐츠의 `.torrent` 2개(표준 라이브러리 bencode, 트래커 `http://tracker.invalid/announce`, info-hash 미리 계산) | `D:\rapid-qa\vm-inbox\torrent\` |
| C-4 | VM 안에서 사용자가 실행할 PowerShell 2개: `vm-manifest.ps1`(복사된 원본의 이름·크기·`LastWriteTimeUtc`·SHA-256을 JSON으로), `vm-collect.ps1`(§5 경로를 반출 폴더로 복사, `reg save HKCU`, `reg export`) | `D:\rapid-qa\vm-inbox\scripts\` |
| C-5 | known-answer 초안 작성(C-1~C-3에서 아는 값 + VM 매니페스트 + 사용자가 적은 재생 위치) | `D:\rapid-qa\samples\<parser>\vm01-known-answer.json` |
| C-6 | 반출 폴더 → 파서별 폴더 정리(복사만, 원본 반출본은 그대로), `sample-check.py` 실행, 곰 `--probe-hash`, 팟·KM `reg export` 전후 diff | `D:\rapid-qa\samples\`, `D:\rapid-qa\derived\r6-vm-*` |
| C-7 | `docs/validation/r6-sample-validation-2026-10-19.md` §5.2·§5.3에 **행 수·일치 여부·불일치 필드 이름·확정 사실(문장)만** 기록 | Git(값 없음) |

Claude가 하지 않는 일: 비밀번호·계정 입력, 약관 동의, CAPTCHA, VMware/`vmrun` 조작, VM 안 프로그램 실행, 설치 파일·EICAR를 호스트에서 열거나 실행, 호스트 사용자 프로필(`C:\Users\HP`) 접근.

---

## 3. VM 설정

### 3.1 하드웨어(새 VM 마법사 "Typical" → 이후 수정)

| 항목 | 값 | 이유 |
|---|---|---|
| 게스트 OS | Windows 11 x64 | |
| 펌웨어 | UEFI + Secure Boot | Windows 11 요구 |
| TPM | 가상 TPM 추가(Workstation이 "TPM에 필요한 파일만 암호화"를 요구 — 사용자 비밀번호) | 설치 요구사항 우회(레지스트리 LabConfig 등)는 쓰지 않는다 |
| CPU / RAM | 4 vCPU / 8 GB | |
| 디스크 | 80 GB, 단일 파일 아님(분할)·사전 할당 안 함 | 실제 사용 약 30–40 GB |
| (선택) 두 번째 디스크 | 2 GB → VM 안에서 `E:`로 포맷, 영상 1개를 `E:\` 아래에서 재생 | `drive_letter` 필드 검증 |
| 네트워크 | NAT | 설치·ISO 활성화용. 앱 설치 후 "Connected" 해제 |
| USB·사운드·프린터·카메라 | 제거 | 호스트 장치 노출 차단 |
| 드래그 앤 드롭·클립보드 공유 | **끔**(VM Settings > Options > Guest Isolation) | 호스트 클립보드 PII 유입 방지 |
| 3D 가속 | 끔 | 무압축 AVI 재생에 불필요 |

### 3.2 공유 폴더(VM Settings > Options > Shared Folders)

| 이름 | 호스트 경로 | 속성 | 켜는 시점 |
|---|---|---|---|
| `inbox` | `D:\rapid-qa\vm-inbox` | **Read-only** | 콘텐츠·스크립트 복사할 때 |
| `export` | `D:\rapid-qa\samples\_vm-export` | 쓰기 가능 | `vm-collect.ps1` 실행할 때만, 끝나면 끔 |

- VM 안에서는 `\\vmware-host\Shared Folders\inbox\...`로 보인다. **재생·압축은 반드시 VM 로컬 경로로 복사한 사본으로** 한다(공유 폴더 경로가 MRU에 남으면 known-answer가 복잡해짐).
- 그 밖의 호스트 폴더는 공유하지 않는다.

### 3.3 스냅샷

| 이름 | 시점 | 비고 |
|---|---|---|
| `clean-os` | OOBE 완료 + Windows 업데이트 1회(선택) + VMware Tools + 공유 폴더 설정 직후, 앱 설치 전 | 시나리오 재시작 지점 |
| `apps-installed` | §1 필수 앱 설치 + 각 앱 첫 실행·종료 + `vm-collect.ps1 -Baseline`(설치 직후 레지스트리 기준 덤프) 후, 표본 조작 전 | 팟·곰·KM 값 이름 diff의 "전" |
| (선택) `samples-made` | §4 완료, 반출 전 | 반출 실패 시 재시도용. 반출 확인 후 삭제 |

### 3.4 폐기 절차(작업 완료 후, 사용자)

1. Claude가 §5 검증을 끝내고 "재수집 불필요"를 확인한 뒤 진행한다.
2. VM 종료 → 공유 폴더 2개 제거 → VM > Manage > **Delete from Disk** → `D:\rapid-qa\vm\rt-sample-w11\` 폴더가 남지 않았는지 확인(vTPM 암호화 파일 포함).
3. ISO(`D:\rapid-qa\vm-inbox\installers\` 포함)는 재사용 계획이 없으면 휴지통으로. **휴지통 비우기·영구 삭제는 사용자 판단**.
4. `D:\rapid-qa\samples\_vm-export\`는 파서별 폴더로 정리된 뒤에도 원본 반출본으로 보존(재검증용). 크기·보존 기간은 사용자 결정.
5. 평가판 Windows의 Microsoft 등록 정보는 VM 삭제와 무관하므로 별도 조치 없음.

---

## 4. 표본 생성 시나리오(VM 안, 사용자 조작)

공통: `inbox\content`를 VM `C:\Users\rtuser\Documents\rt-src\`로 복사 → `vm-manifest.ps1 -Root C:\Users\rtuser\Documents\rt-src`로 매니페스트를 `export\manifest-src.json`에 저장(이름·크기·수정 시각·SHA-256 = known-answer 기준값). 각 단계에서 **실제로 고른 메뉴 표기·옵션·재생 위치**를 `export\notes.txt`(VM 메모장)에 적는다 — known-answer의 근거다.

### 4.1 알집 EGG / ALZ (최우선)

원본: `rt-src\archive\` = `가짜문서01.txt`, `readme_ascii.txt`, `샘플이미지.png`, `image_ascii.png`, `하위폴더\메모 02.txt`, `big_text_2mb.txt`(LZMA·다중 블록), `random_12mb.bin`(분할).

출력 폴더 `C:\Users\rtuser\Documents\rt-egg\`에 아래 파일을 만든다(알집 "압축하기 → 상세 설정"; UI 표기는 버전마다 다르므로 **표기 그대로 notes.txt에 기록**):

| 파일 | 형식·옵션 | 기대(파서 필드) |
|---|---|---|
| `01-store.egg` | EGG, 압축 안 함(저장) | `compression_methods=["store"]`, `sha256` 있음 |
| `02-deflate.egg` | EGG, 일반/빠른 압축(Deflate) | `["deflate"]`, `sha256` 있음 |
| `03-bzip2.egg` | EGG, bzip2(메뉴에 있을 때) | `["bzip2"]`, `sha256` 있음 |
| `04-lzma.egg` | EGG, LZMA(고압축 계열) — `big_text_2mb.txt` 포함 | `["lzma"]`, `sha256` 있음, `crc_ok=true` → `_lzma_block` 추정 확정 |
| `05-azo.egg` | EGG, AZO | `["azo"]`, `extract_note="list-only-method:azo"` |
| `06-solid.egg` | EGG, 솔리드 압축 켬(방식은 Deflate) | `archive_solid=true`, `sha256` 빈 값 |
| `07-zip20.egg` | EGG, 암호(ZIP 2.0 호환) | `encryption_method="zip-2.0"`, `extract_note="encrypted-not-extracted"` |
| `08-aes256.egg` | EGG, 암호 AES-256 | `encryption_method="aes-256"` |
| `09-lea.egg` | EGG, 암호 LEA(128/256 중 메뉴에 있는 것) | `lea-128` 또는 `lea-256` |
| `10-namecrypt.egg` | EGG, 암호 + "파일 이름도 암호화"(메뉴에 있을 때) | `name_encrypted=true`, 이름 빈 값 |
| `11-split.egg` (+ 이어지는 볼륨) | EGG, 분할 5 MB, `random_12mb.bin` 포함 | `archive_split=true`; 볼륨 파일별 결과는 그대로 기록(첫 볼륨 외 `egg-open-failed`/`*-partial`이면 사실로 기록) |
| `12-utf8-names.egg` / `13-cp949-names.egg` | 파일 이름 저장 방식(UTF-8 / 한국어 코드 페이지) 옵션이 있으면 둘 다 | `name_encoding` 값 확인, 한국어 이름 일치 |
| `20-basic.alz` | ALZ 형식(알집이 ALZ 생성을 지원할 때만) | ALZ 이름(cp949)·크기·DOS 시각·방식 |

- 압축 비밀번호는 사용자가 입력한다. 이 VM 밖에서 쓰지 않는 버리는 문자열로 하고 Git·문서에 적지 않는다(파서는 해독하지 않으므로 known-answer에도 불필요).
- 알집 최신판에 ALZ 생성 메뉴가 없으면 ALZ는 "미검증 유지"로 둔다(구버전 비공식 배포본은 받지 않는다).
- 알집이 압축 후 원본을 지우거나 이동하는 옵션은 끈다.

### 4.2 공통 — 영상 준비

`inbox\content\video\`의 3개(C-1에서 생성: `가짜영상01.avi`, `clip02.avi`, `테스트 영상 03.avi`)를 `C:\Users\rtuser\Videos\rt\`로 복사(선택 디스크가 있으면 `clip02.avi`는 `E:\rt\clip02.avi`). 각 플레이어마다 아래를 한다:

1. 플레이어 실행 → 파일 3개를 **순서대로** 열어 재생. 1번은 끝까지(3분 또는 빨리 감기 후 끝까지), 2번은 **약 1분 30초에서 정지 후 플레이어 종료**, 3번은 약 40초에서 종료. 화면의 재생 시각을 notes.txt에 초 단위로 적는다(위치 단위 ms/s 확정용).
2. URL 1개 열기(§1 D12 — 공개 도메인 URL 또는 `http://media.invalid/rt-sample/stream01.mp4`). 실패해도 그대로 둔다.
3. 플레이어를 정상 종료(창 닫기)해 설정이 기록되게 한다.
4. 플레이어마다 이 순서를 지켜 MRU 순서 known-answer를 만든다: 최신 = URL, 그다음 3번, 2번, 1번.

### 4.3 팟플레이어

- §4.2 수행. 재생목록 창에서 3개를 담은 목록을 **재생목록 저장**으로 기본 폴더(`%APPDATA%\PotPlayerMini64\Playlist\`)에 `rt-list.dpl`로 저장.
- (선택) 환경설정에 설정 저장 위치(레지스트리/ini) 항목이 있으면 ini로 바꾼 뒤 2번 영상을 다시 재생·종료 → `%APPDATA%\PotPlayerMini64\PotPlayerMini64.ini` 생성 확인. 바꾼 사실을 notes.txt에 적는다.
- 수집: `vm-collect.ps1 -Player potplayer` → `reg export HKCU\Software\DAUM ...\reg\potplayer-after.reg`, `%APPDATA%\PotPlayer*\` 전체(ini·Playlist).

### 4.4 곰플레이어

- §4.2 수행(재생 시각 기록 필수 — `_RECENTMEDIAPOS###` 단위 확정용).
- 수집: `reg export HKCU\Software\GRETECH ...\reg\gom-after.reg`. 곰은 경로 대신 32자리 식별자를 남기므로 **재생한 VM 경로 문자열을 notes.txt에 정확히** 적는다(대소문자·공백 포함, 예: `C:\Users\rtuser\Videos\rt\가짜영상01.avi`).

### 4.5 KMPlayer · VLC

- KMPlayer: §4.2 수행 → `reg export HKCU\Software\KMPlayer`, `HKCU\Software\PandoraTV`(있으면). `%APPDATA%\KMPlayer\`가 있으면 함께.
- VLC: 환경설정 "재생 계속하기"는 기본값(묻기) 유지. §4.2 수행(VLC는 짧은 영상의 위치를 저장하지 않을 수 있어 3분 길이로 만든다) → `%APPDATA%\vlc\vlc-qt-interface.ini`(`[RecentsMRU] list=`·`times=`)와 `vlcrc`.

### 4.6 eMule (오프라인)

설치 시 "사용자별 설정" 기본값을 쓰고, **가상 NIC를 끊은 상태**로 진행한다. 서버·Kad에 연결하지 않는다(첫 실행 마법사의 "시작 시 자동 연결"은 끔).

1. 첫 실행 → 마법사에서 닉네임 `rt-sample`(실명 금지), 자동 연결 끔.
2. 공유: `inbox\emule\share\`의 가짜 파일 2개를 eMule 받은 파일 폴더(`Incoming`, 기본 `%USERPROFILE%\Downloads\eMule\Incoming`)로 복사 → 공유 목록에서 해시 계산 완료 확인 → `known.met` 생성 대상.
3. 다운로드 추가: `inbox\emule\ed2k-links.txt`의 가짜 링크 3개를 "검색 > ed2k 링크 붙여넣기"(또는 해당 입력란)로 추가 → 소스가 없으므로 실제 전송은 일어나지 않는다. 각 항목을 **일시 중지**. 설정에서 "파일 전체 크기 미리 할당"은 끈다(4 GiB 초과 가짜 링크가 디스크를 차지하지 않게).
4. 검색어: 검색 창에 `rt-sample-검색어-01`, `ubuntu`, `public domain test` 순으로 입력·검색 시도(오프라인이라 결과 없음). 오프라인에서 `AC_SearchStrings.dat`가 생기지 않으면 그 사실을 기록하고 "검색어 = 미검증 유지"로 둔다 — 이를 위해 네트워크를 연결하지 않는다.
5. eMule 정상 종료(설정·met 기록).
6. 수집: `preferences.ini`의 `TempDir`·`IncomingDir` 확인 → `config\`(`known.met`, `AC_SearchStrings.dat`, `preferences.ini`, `clients.met` 등)와 Temp 폴더의 `*.part.met`만(**`*.part` 본체는 복사하지 않음**). 기본 위치 후보: `%LOCALAPPDATA%\eMule\config\`, `%LOCALAPPDATA%\eMule\Temp\`(설치 시 "프로그램 폴더" 방식을 골랐으면 `C:\Program Files (x86)\eMule\config\`·`Temp\`).
- `part.met` 버전: 일반 링크 → 0xE0, 4 GiB 초과 → 0xE2 기대. 0xE1(분할 형식)은 공식 0.50a에서 새로 만들어지지 않을 수 있다 → 생기지 않으면 "0xE1은 소스 기반 확인(계획 §1.4)만" 기록.

### 4.7 qBittorrent (오프라인)

1. NIC 끊은 상태로 실행 → 법적 고지 동의(사용자) → 설정 > BitTorrent에서 DHT·PeX·LSD 끄기.
2. `inbox\torrent\`의 가짜 토렌트 2개를 "토렌트 파일 추가"로 연다 → 추가 대화 상자에서 **"토렌트 시작" 체크 해제**, 저장 경로 `C:\Users\rtuser\Downloads\rt-bt\`(2번째는 `...\rt-bt2\`로 바꿔 저장 경로 필드 구분).
3. 하나는 그대로 둔 채, 다른 하나는 선택 후 "재개 → 즉시 일시 중지"(상태 값 차이). 트래커가 `.invalid`라 통신은 실패한다.
4. qBittorrent 종료(종료 시 `fastresume` 기록).
5. 수집: `%LOCALAPPDATA%\qBittorrent\BT_backup\`(`*.fastresume`, `*.torrent`) 전체. 추가 시각은 notes.txt에 분 단위로.
- 리눅스 배포판 실제 토렌트는 쓰지 않는다(필요해지면 별도 승인·추가 즉시 정지·다운로드 완료 금지).

### 4.8 PSD (GIMP 또는 Krita)

- `inbox\content\샘플이미지.png`를 열어 레이어 1개 추가(텍스트 "RT SAMPLE") → `C:\Users\rtuser\Pictures\rt\rt-gimp.psd`(Krita면 `rt-krita.psd`)로 내보내기, 같은 그림을 2배 크기로 하나 더(`rt-gimp-2x.psd`).
- 기록: 폭·높이·색 모드(RGB)·채널 수·비트 깊이. XMP 이력은 Photoshop만 만들므로 "XMP 이력 = 미검증 유지".

### 4.9 (선택) V3 Lite + EICAR

사용자가 V3 Lite 약관상 사용 가능하다고 확인한 경우만.

1. NIC 연결 → V3 Lite 설치·엔진 업데이트 → `apps-installed` 이후의 별도 스냅샷 `v3-installed` 권장.
2. VM 브라우저로 eicar.org에서 `eicar.com`을 VM 안에 받음 → 실시간 검사 탐지·치료/격리 확인 → 정밀 검사 1회.
3. 수집: `C:\Program Files\AhnLab\`·`C:\Program Files (x86)\AhnLab\`·`C:\ProgramData\AhnLab\`·`%LOCALAPPDATA%\AhnLab`·`%APPDATA%\AhnLab`에서 **격리 폴더(이름에 quarantine/vault/격리 포함) 내용은 제외**하고 복사, 격리 폴더는 `vm-collect.ps1`이 파일 수·크기만 `ahnlab-quarantine-counts.json`으로 남긴다. 파서도 격리 내용은 열지 않는다(`av_ahnlab.py`). V3 화면의 탐지 기록(시각·위협명·경로)을 notes.txt에 옮겨 적는다.
4. EICAR 원본·격리본은 VM 밖으로 내보내지 않는다(호스트 백신 반응 방지). VM 폐기로 함께 삭제.

### 4.10 (선택) Windows 메일

Windows 11의 기존 "메일" 앱은 2024년 말 지원이 끝나 새 평가판 VM에 설치할 수 없고, 계정 로그인도 필요하다(Claude 불가). **이번 VM에서는 생략, "미검증 유지"**. 필요하면 사용자 제공 표본(경로 a)으로.

---

## 5. 수집 체크리스트

### 5.1 `vm-collect.ps1`이 만드는 반출 구조

반출 루트 `\\vmware-host\Shared Folders\export\vm01\` (호스트 `D:\rapid-qa\samples\_vm-export\vm01\`). 프로필 아래는 파서가 기대하는 증거 트리 모양(`Users\<이름>\NTUSER.DAT`, `Users\<이름>\AppData\...`, `ProgramData\...`)을 그대로 따른다(`iter_windows_user_homes`는 `<root>\Users\*`를 본다).

| 게스트 원본 | 반출 경로(vm01 기준) | 최종 위치(호스트, Claude가 복사) | `--parser` |
|---|---|---|---|
| `reg save HKCU <tmp>\NTUSER.DAT /y` (regf 하이브 — 파서는 `.reg`가 아니라 하이브를 읽음) | `Users\rtuser\NTUSER.DAT` | `samples\media-player\vm01\Users\rtuser\NTUSER.DAT` | media-player |
| `%APPDATA%\PotPlayer*\` (ini, `Playlist\*.dpl`) | `Users\rtuser\AppData\Roaming\PotPlayerMini64\...` | `samples\media-player\vm01\Users\rtuser\AppData\Roaming\...` | media-player |
| `%APPDATA%\vlc\vlc-qt-interface.ini`, `vlcrc` | `Users\rtuser\AppData\Roaming\vlc\` | 같은 구조 | media-player |
| `%APPDATA%\KMPlayer\`(있으면) | `Users\rtuser\AppData\Roaming\KMPlayer\` | 같은 구조 | media-player |
| `reg export` `HKCU\Software\DAUM`, `GRETECH`, `KMPlayer`, `PandoraTV` (기준·이후 2벌) | `reg\<player>-baseline.reg`, `reg\<player>-after.reg` | `samples\media-player\vm01-reg\` (**파서 입력 폴더 밖**, diff 전용) | — |
| 재생한 AVI 3개(VM 사본) | `media\` | `samples\media-player\vm01-media\` (`--candidate-file`용, 입력 폴더 밖) | — |
| `Documents\rt-egg\*.egg`, `*.alz` | `egg\`, `alz\` | `samples\egg\vm01\`, `samples\alz\vm01\` | egg / alz |
| eMule `config\`(known.met, AC_SearchStrings.dat, preferences.ini), Temp `*.part.met` | `Users\rtuser\AppData\Local\eMule\config\`, `...\Temp\` | `samples\p2p\vm01\Users\rtuser\AppData\Local\eMule\...` | p2p |
| `%LOCALAPPDATA%\qBittorrent\BT_backup\` | `Users\rtuser\AppData\Local\qBittorrent\BT_backup\` | `samples\p2p\vm01\...`(같은 구조, 경로에 `/qbittorrent/`가 있어야 클라이언트 판별) | p2p |
| `Pictures\rt\*.psd` | `psd\` | `samples\media-image\vm01\` | media-image |
| (선택) AhnLab 폴더(격리 내용 제외) | `Program Files\AhnLab\`, `ProgramData\AhnLab\`, `Users\rtuser\AppData\...\AhnLab\` | `samples\windows-system\vm01\...` | windows-system |
| `manifest-src.json`, `notes.txt` | 루트 | `samples\_vm-export\vm01\`(원본 보존) | — |

### 5.2 known-answer 항목(계획 §1.5) — Claude 작성

| 파서 | `expect[].match` | `expect[].fields` | `counts` |
|---|---|---|---|
| egg | `artifact_type=egg-entry`, `archive_file`, `name` | `uncompressed_size`, `compression_methods`, `encrypted`, `encryption_method`, `name_encrypted`, `last_modified`(매니페스트 UTC), `sha256`(저장·Deflate·bzip2·LZMA 비암호·비솔리드만), `extract_note`(AZO·암호·솔리드), `archive_solid`, `archive_split` | `egg-entry` 개수, `egg-archive` 개수 |
| alz | `artifact_type=alz-entry`, `name` | `uncompressed_size`, `last_modified`(DOS 2초 단위), `compression_methods` | `alz-entry` |
| media-player | `player_id`(vlc·potplayer·gom·kmplayer), `media_path` 또는 `media_url`; 곰은 `entry_kind=file-hash`, `mru_order` | `drive_letter`, `mru_order`, `resume_position_seconds`/`resume_position_raw`(notes.txt 시각과 비교해 단위 판정) | 플레이어별 행 수(경로 3 + URL 1) |
| p2p | `client`(emule·qbittorrent), `file_name`/`name`/`term` | eMule: `file_size`, `ed2k_hash`(C-2 계산값), `part_met_version`, `downloaded`; qBittorrent: `info_hash`(C-3 계산값), `save_path`, `added_at`(분 단위 확인), `state`; 검색어: `term`, `list_position` | `p2p-shared-file` 2, `p2p-transfer` 3+2, `p2p-search-term` 3(생성된 경우), `p2p-client-config` 1 |
| media-image | PSD 파일 경로 | 폭·높이·색 모드·채널·깊이(필드 이름은 첫 `--show-values` 실행으로 확정 후 고정) | PSD 행 수 |
| windows-system(선택) | `av_product=ahnlab-v3` | 제품 폴더 행, 로그 후보 행 수, 탐지 행의 위협명(EICAR 계열) | `av-product-presence`·`av-detection-log` 행 수 |

팟·KM의 값 이름은 known-answer로 쓰지 않고 `reg export` 전후 diff로 먼저 확정한다(diff에서 새로 생긴 값 중 재생 경로·위치를 담은 값 이름 → `media_players.py`의 `verification` 갱신 여부는 단계 1 갈래 C에서 판단).

### 5.3 실행 명령(호스트, Claude)

```powershell
python scripts\sample-check.py --parser egg   --input D:\rapid-qa\samples\egg\vm01   --expect D:\rapid-qa\samples\egg\vm01-known-answer.json --json --output D:\rapid-qa\derived\r6-vm-egg.json
python scripts\sample-check.py --parser alz   --input D:\rapid-qa\samples\alz\vm01   --expect D:\rapid-qa\samples\alz\vm01-known-answer.json --json --output D:\rapid-qa\derived\r6-vm-alz.json
python scripts\sample-check.py --parser media-player --input D:\rapid-qa\samples\media-player\vm01 --expect D:\rapid-qa\samples\media-player\vm01-known-answer.json --json --output D:\rapid-qa\derived\r6-vm-media.json
python scripts\sample-check.py --parser p2p   --input D:\rapid-qa\samples\p2p\vm01   --expect D:\rapid-qa\samples\p2p\vm01-known-answer.json --json --output D:\rapid-qa\derived\r6-vm-p2p.json
python scripts\sample-check.py --parser media-image --input D:\rapid-qa\samples\media-image\vm01 --expect D:\rapid-qa\samples\media-image\vm01-known-answer.json --json --output D:\rapid-qa\derived\r6-vm-psd.json
# 선택
python scripts\sample-check.py --parser windows-system --input D:\rapid-qa\samples\windows-system\vm01 --expect D:\rapid-qa\samples\windows-system\vm01-known-answer.json --json --output D:\rapid-qa\derived\r6-vm-ahnlab.json
```

곰플레이어 식별자 탐색 — `_RECENTMEDIANAME###` 값마다(값은 `gom-after.reg` 또는 media-player 결과의 `media_hash`), notes.txt의 VM 경로 3개와 VM 사본 3개를 모두 후보로:

```powershell
python scripts\sample-check.py --probe-hash <32자리값> `
    --candidate-path "C:\Users\rtuser\Videos\rt\가짜영상01.avi" `
    --candidate-path "E:\rt\clip02.avi" `
    --candidate-path "C:\Users\rtuser\Videos\rt\테스트 영상 03.avi" `
    --candidate-file D:\rapid-qa\samples\media-player\vm01-media\가짜영상01.avi `
    --candidate-file D:\rapid-qa\samples\media-player\vm01-media\clip02.avi `
    --candidate-file "D:\rapid-qa\samples\media-player\vm01-media\테스트 영상 03.avi" `
    --json --output D:\rapid-qa\derived\r6-vm-gom-probe-01.json
```

- 일치 없음 → `--head-bytes`로 다른 길이(예: 16384, 262144)를 추가해 한 번 더. 그래도 없으면 "확인 불가"로 기록(계획 §1.5 허용).
- 값 출력(`--show-values`)은 화면 확인용, 결과 파일·값은 Git에 넣지 않는다.

### 5.4 체크리스트

- [ ] `manifest-src.json`·`notes.txt` 반출됨
- [ ] EGG 12개 내외 + (가능하면) ALZ 1개, 분할 볼륨 전부
- [ ] `NTUSER.DAT`가 regf 하이브(첫 4바이트 `regf`)
- [ ] `reg` baseline/after 4쌍(DAUM·GRETECH·KMPlayer·PandoraTV, 없는 키는 없음으로 기록)
- [ ] PotPlayer ini/dpl, VLC ini, (KMPlayer 폴더)
- [ ] eMule `known.met`·`*.part.met`(본체 `.part` 제외)·`preferences.ini`·(`AC_SearchStrings.dat`)
- [ ] qBittorrent `BT_backup`
- [ ] PSD 2개
- [ ] (선택) AhnLab 폴더(격리 내용 제외) + 격리 개수 JSON
- [ ] `git status --short`에 `D:\rapid-qa` 관련 변경 없음(저장소 밖이므로 원래 없어야 함), 검증 문서에는 값 없이 결과만

---

## 6. 소요 시간·순서

| 순서 | 작업 | 담당 | 예상 |
|---|---|---|---|
| 0 | 다운로드 승인, Claude 가짜 콘텐츠·스크립트·토렌트·ed2k 준비(C-1~C-4) | 사용자 승인 / Claude | 10분 / 30분(병행) |
| 1 | ISO 다운로드 | 사용자 | 20–60분(회선) |
| 2 | VM 생성·Windows 설치·OOBE·Tools·공유 폴더 → `clean-os` | 사용자 | 40–60분 |
| 3 | 알집·팟플레이어·곰플레이어 설치·첫 실행 → baseline 덤프 | 사용자 | 20분 |
| 4 | **EGG/ALZ 시나리오(§4.1)** | 사용자 | 30–40분 |
| 5 | **팟플레이어·곰플레이어(§4.3·4.4)** → 1차 반출 | 사용자 | 30분 |
| 6 | 1차 검증: egg·alz·media-player(팟·곰), 곰 `--probe-hash`, 팟 diff | Claude | 40–60분 |
| 7 | 나머지 앱 설치 → `apps-installed`(1차 반출 뒤 찍어도 됨; 그 경우 팟·곰 baseline은 3단계 덤프 사용) | 사용자 | 20분 |
| 8 | KMPlayer·VLC → eMule·qBittorrent(NIC 끊음) → PSD → (선택) V3+EICAR | 사용자 | 60–90분 |
| 9 | 2차 반출·검증, 결과 문서 기록 | 사용자 10분 / Claude 60분 | |
| 10 | VM 폐기 | 사용자 | 10분 |

합계: 사용자 손 작업 약 4–5시간(대기 포함), Claude 약 3시간. 1차 묶음(EGG·팟·곰)만으로도 가장 중요한 미확인 세부 3개(LZMA 블록, 팟 값 이름, 곰 해시)를 먼저 확정할 수 있다.

---

## 7. 개인정보·안전 체크

- [ ] VM 계정은 로컬 `rtuser`, Microsoft 계정·회사 계정 로그인 없음. OOBE 개인정보 옵션(위치·진단·맞춤형 광고·음성 인식·잉크) 모두 끔.
- [ ] VM에 사용자 실제 파일·사건 자료·이메일·브라우저 로그인 없음. 내용물은 Claude가 만든 가짜 콘텐츠와 공식 설치 파일뿐.
- [ ] 호스트 프로필(`C:\Users\HP`)·`D:\rapid-qa\bsh-subset`·`D:\devin\bsh-e01`은 공유하지 않고 표본으로 쓰지 않는다.
- [ ] 클립보드·드래그 앤 드롭 공유 끔, 공유 폴더는 inbox(읽기 전용)·export(반출 시에만) 2개뿐.
- [ ] 앱 설치 후 NIC 끊음. eMule은 서버·Kad 연결 없음, qBittorrent는 자체 제작 가짜 토렌트만·시작 안 함·DHT 끔. 저작권 콘텐츠 검색·다운로드 없음.
- [ ] 설치 시 제휴·광고 프로그램 체크 해제, 브라우저 시작 페이지 변경 거부.
- [ ] 라이선스: Windows 평가판(90일), 알집·곰·V3 Lite는 개인 무료/기업 조건을 사용자가 확인. 확인되지 않으면 해당 표본은 "미검증 유지".
- [ ] EICAR·격리 파일은 VM 밖으로 내보내지 않음. 호스트 백신 설정은 바꾸지 않음.
- [ ] 압축 비밀번호·vTPM 비밀번호·Windows 비밀번호는 사용자만 알고, Git·문서·known-answer에 적지 않음.
- [ ] 표본·known-answer·`--show-values`·`--probe-hash` 결과는 `D:\rapid-qa\` 아래에만, Git에는 행 수·판정·필드 이름·확정 사실만.
- [ ] 작업 후 VM 삭제(§3.4), 반출본 보존 여부는 사용자 결정.
