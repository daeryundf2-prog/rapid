# R6 단계 1 — 실표본 파서 검증 기록 (2026-10-19)

근거: `docs/plans/r6-followups-2026-10-19.md` §1.3 갈래 A·B, §1.5(수용 기준), §1.6(QA 시나리오 Q-S1-1~Q-S1-6).
이 문서는 **엔지니어링 측정 기록**이다. 릴리스 증거가 아니며, 결과표가 채워져도 Release Evidence 차단 사유는 그대로다.

## 1. 목적

1. 매트릭스(`docs/research/axiom-parity-matrix-2026-10-17.md`) Table A에서 "실샘플 미검증"으로 남은 15행과 국내 확장(EGG/ALZ, 팟플레이어, 곰플레이어, KMPlayer)을 **실제 앱이 만든 표본**으로 필드 단위 확인한다.
2. 미확인 세부(곰플레이어 `_RECENTMEDIANAME###` 식별자 해시, 팟플레이어·KMPlayer 값 이름, EGG LZMA 블록 배치)를 확정하거나 "확인 불가"로 명시한다.
3. 전체 재실행(`run --mode hacking`) 결과를 기준 런과 비교해 기존 kind의 행 수 회귀가 없음을 보인다(`scripts/compare-runs.py`).

도구:

| 도구 | 역할 | 테스트 |
|---|---|---|
| `scripts/compare-runs.py` | 기준 런 vs 새 런: kind·artifact_type 행 수, 새 kind, 단계 시간, 회귀 판정 | `tests/test_compare_runs.py` |
| `scripts/sample-check.py` | 공급자 하나를 표본 폴더에 직접 돌려 known-answer와 필드 대조, `--probe-hash`로 32자리 식별자 해시 탐색 | `tests/test_sample_check.py` |

두 도구 모두 표준 라이브러리 + 저장소 내부 모듈(`rapidtriage.core.*`, 외부 의존성 없음)만 쓰고, 입력을 읽기만 한다.

## 2. 표본 보관 규칙 (Git 밖)

- 표본과 known-answer는 `D:\rapid-qa\samples\<parser>\` 아래에만 둔다. 예: `D:\rapid-qa\samples\egg\lzma-01.egg`, `D:\rapid-qa\samples\egg\known-answer.json`.
- 런 출력·비교 보고서는 `D:\rapid-qa\derived\r6-*` 아래에 둔다(예: `D:\rapid-qa\derived\r6-s1-run`, `D:\rapid-qa\derived\r6-s1-compare.json`).
- **Git에 넣지 않는 것**: 표본 파일, known-answer 파일, `--show-values` 출력, 비교 보고서의 경로 꼬리(`path_tails`), 실제 경로·사용자 이름·URL·해시 값. 이 문서에는 행 수·일치 여부·불일치 필드 이름·확정된 사실(문장)만 적는다.
- 이 기계의 사용자 프로필(`C:\Users\HP`)은 표본으로 쓰지 않는다. 표본 확보 경로는 계획 §1.4의 세 가지(사용자 제공·일회용 VM·승인된 공개 코퍼스)뿐이다.
- 증거 폴더(`D:\rapid-qa\bsh-subset`, `D:\devin\bsh-e01`)는 읽기 전용이다.
- 테스트는 합성 표본만 쓰며 `D:\rapid-qa` 경로를 참조하지 않는다.

## 3. known-answer 스키마

```json
{
  "parser": "media-player",
  "expect": [
    {"match": {"artifact_type": "media-player-recent", "player_id": "vlc", "media_path": "E:\\가짜\\clip01.mp4"},
     "fields": {"drive_letter": "E", "resume_position_seconds": 0}}
  ],
  "counts": {"media-player-recent": 4}
}
```

- `parser`: `--parser`와 같아야 한다(다르면 입력 오류, 종료 코드 2).
- `expect[].match`: 행을 고르는 필드 조건(모두 같아야 함). 여러 행이 맞으면 `fields` 불일치가 가장 적은 행을 쓴다.
- `expect[].fields`: 그 행에서 기대하는 값. 필드 이름은 평탄화한 행 기준이다: `artifact_type`, `path`, `provider`와 `details`의 모든 키. 중첩 값은 점 표기(`details.a.b`, `a.0`).
- 값 비교: 같은 값, 숫자는 수치 비교, 그 밖의 스칼라는 문자열 비교. 목록·객체는 정확히 같아야 한다.
- `counts`: artifact_type별 기대 행 수(적은 유형만 검사).
- 파서별 행 모양: 공급자 파서는 `rapidtriage artifacts --kind <kind>`와 같은 행. `egg`/`alz`는 파일마다 `<fmt>-archive` 1행 + 항목마다 `<fmt>-entry` 행(`name`·`uncompressed_size`·`compressed_size`·`compression_methods`·`crc32`(ALZ)·`sha256`·`last_modified`·`encrypted`·`extract_note` 등, `archive_file`은 입력 기준 상대 경로), 열 수 없는 파일은 `<fmt>-open-failed`. `url-carve`는 입력 폴더의 모든 파일을 `core/url_carving.py` `scan_url_source`로 읽어 `carved-url-candidate` 행(`url`·`encoding`·`offset`·`host`·`source_file`).

파서 ID와 공급자 kind:

| `--parser` | 실행 대상 | 표본 하위 범위 |
|---|---|---|
| `media-player` | kind `media-player` | potplayer·gom·kmplayer·vlc |
| `egg` / `alz` | `core/egg_archive.py` `list_egg` / `list_alz` | 저장·Deflate·bzip2·LZMA·AZO·솔리드·암호·분할 |
| `p2p` | kind `p2p` | emule·qbittorrent·utorrent·frostwire |
| `windows-phone-link` | kind `windows-phone-link` | Your Phone / 휴대폰과 연결 |
| `windows-messenger` | kind `windows-messenger` | viber·facebook |
| `email-clients` | kind `email-clients` | windows-mail |
| `mobile-export` | kind `mobile-export` | adb 백업 |
| `url-carve` | `core/url_carving.py` | 페이지 파일·미할당 덤프 |
| `browser` | kind `browser` | 360·qq·yandex 루트 |
| `windows-system` | kind `windows-system` | mcafee·backstage |
| `media-image` | kind `media-image` | PSD |

## 4. 파서별 수용 기준 (계획 §1.5)

| 파서 | known-answer 항목 | 통과 기준 |
|---|---|---|
| EGG | 항목별 이름(cp949·UTF-8 혼합)·크기·압축 방식·CRC·수정 시각; LZMA·AZO·암호·솔리드·분할 각 1 | 목록 100% 일치, 비암호·비솔리드 저장/Deflate/bzip2/LZMA 항목 SHA-256 일치, AZO·암호·솔리드는 해제 생략 사유, 폭탄 상한 유지 |
| ALZ | 항목 이름·크기·DOS 시각 | 100% 일치 |
| 팟플레이어 | 재생 파일 경로 3·URL 1·마지막 위치·재생 순서 | 값 이름 확정 → `verification: confirmed`, 경로 4/4·위치 단위(ms/s) 확정, 설정 경로가 재생 기록으로 잡히지 않음 |
| 곰플레이어 | 재생 파일 경로·크기·해시 여러 종 | `_RECENTMEDIANAME###`이 후보 해시 중 하나와 일치(알고리즘 확정) 또는 "확인 불가" 명시; `_RECENTMEDIAPOS###` 단위 확정 |
| KMPlayer | 재생 파일 경로 | 값 이름 확정 또는 미확인 유지 |
| VLC | 목록·`times=` | 100% |
| eMule | known.met 파일명·크기·해시·전송량, part.met(3 버전) 이름·다운로드량, 검색어 목록 | 100%; 0xE1은 단계 2 구현 후 재검 |
| qBittorrent/µTorrent/FrostWire | 토렌트 이름·info-hash·추가 시각·저장 경로·상태 | 100% |
| adb 백업 | 패키지 수·구성원 수·SQLite 항목 수 | 100% |
| URL 카빙 | 기대 URL 목록 ≥ 20 | 재현율(`expectations.recall`) ≥ 90%, 오탐률(`rows_not_in_known_answer` / `row_count`, 기록·known-answer 밖 URL 비율) 측정값 기록(기준 없음) |
| Phone Link·Viber·Facebook·Windows 메일·McAfee·Backstage·360/QQ/Yandex·PSD | 표본이 있을 때만: 메시지 수·방향·시각 단위 / 탐지 줄 수·위협명 / 항목 수 / 프로필 경로 / XMP 필드 | 100% 또는 "미검증 유지" |

## 5. 결과 기록 (빈 표 — 표본 확보 후 채움)

### 5.1 전체 재실행 비교 (Q-S1-1~Q-S1-4)

| 항목 | 기준 런 | 새 런 | 판정 |
|---|---|---|---|
| 대상 커밋 / 런 ID | `run-subset10` (런 `b5fabbe09f18`, 2026-10-15) | `feat/r6-followups` `b65341b`, `D:\rapid-qa\derived\r6-s1-run` (2026-10-19, `--mode hacking --read-only`) | — |
| 종료 코드 · `parser_errors` | 0 · 0 | 0 · 0 (로그 6줄, 트레이스백 없음; PIL DecompressionBombWarning 1건) | 통과 |
| 기존 kind 회귀(`regression_kinds`) | — | 없음 (`compare-runs.py` PASS, 종료 코드 0) | 통과 |
| 이동(`move_kinds`)·허용 유형(`--allow-type`) | — | 이동 없음; 허용 `browser-analytics-cookie` 0 → 197 | 통과 |
| 새 유형(기존 kind 안) | — | browser-cache-entry 6,595 · kakaotalk-shared-picture 101 · kakaotalk-app-inventory 1 · execution-pca 642 · execution-feature-usage 335 · registry-office-mru 246 · registry-known-dll 36 · registry-install-state 15 · registry-network-share 12 · startup-item 12 · desktop-wallpaper 7 · registry-default-browser 2 · credential-store-presence 4 | R2–R5 추가분, 기존 유형 변화 0 |
| 새 kind 행 수·시간·오류 | — | cloud-sync 1행 1.19 s · email-clients 0행 1.36 s · media-player 5행 1.47 s · p2p 0행 0.66 s · windows-messenger 0행 2.96 s · windows-phone-link 0행 0.35 s · 오류 0 | 통과 |
| 새 kind 합계 시간(≤ 60 s) | — | 7.99 s | 통과 |
| 전체 소요(≤ 기준 × 1.2) | 2,526.7 s | 1,973.9 s (0.78×) | 통과 |
| 단계별 | — | artifacts 0.75× · docs 0.68× · files 0.59× · timeline 0.75× · indicators 0.78× · persist 0.85×; 새 단계 triage-flags 45.0 s · derived 39.0 s; **fingerprint 5.6 → 44.6 s** | 아래 주 1 |
| 타임라인 이벤트 · 파일 후보 · 지표 수 | 323,543 · 4,935 · 4,712 | 330,707 · 4,935 · 11,383 | 증가분은 새 유형(캐시 항목 URL 등)에서 옴 |

주 1 — fingerprint 단계: 비재개 런의 지문은 메타데이터만 보며(`build_run_input_fingerprint(hash_contents=False)`), 같은 서브셋에서 단독 측정 1.4 s, 단계 구간 프로파일 7.5 s였다. 시간 대부분은 런 공유 경로 캐시(`core/files.py` `_cached_evidence_paths`)의 **첫 증거 트리 순회**이며, 런 직후 콜드 디스크에서 44.6 s가 걸렸다. 같은 순회를 이후 단계가 재사용해 artifacts·docs·files가 빨라졌고 전체는 0.78×다. 코드 회귀가 아니라 비용이 앞 단계로 옮겨 간 것으로 판정한다(3단계 성능 작업에서 `pathlib.relative_to` 비용 1/2 이상 절감 여지 확인됨).

### 5.2 파서별 표본 검증 (Q-S1-6)

| 파서 | 표본 출처(경로 a/b/c) | 행 수 | 기대 일치 | 불일치 필드 이름 | 판정(통과 / 미검증 유지 / 수정 필요) |
|---|---|---|---|---|---|
| EGG | | | | | |
| ALZ | | | | | |
| 팟플레이어 | | | | | |
| 곰플레이어 | | | | | |
| KMPlayer | | | | | |
| VLC | | | | | |
| eMule | | | | | |
| qBittorrent/µTorrent/FrostWire | | | | | |
| adb 백업 | | | | | |
| URL 카빙(재현율·오탐률) | | | | | |
| Phone Link | | | | | |
| Viber | | | | | |
| Facebook Messenger | | | | | 미검증 유지(앱 종료) |
| Windows 메일 | | | | | |
| McAfee 로그 | | | | | |
| Office Backstage | | | | | |
| 360·QQ·Yandex 루트 | | | | | |
| Photoshop PSD | | | | | |

### 5.3 미확인 세부 확정

| 세부 | 방법 | 결과 |
|---|---|---|
| 곰 `_RECENTMEDIANAME###` 해시 | `sample-check.py --probe-hash` | |
| 곰 `_RECENTMEDIAPOS###` 단위 | VM 표본 재생 위치 대조 | |
| 팟플레이어 값 이름 | `reg export` 전후 diff | |
| KMPlayer 값 이름 | `reg export` 전후 diff | |
| EGG LZMA 블록 배치 | 실제 블록 바이트 vs `_lzma_block` 추정 | |

### 5.4 단계 2 실이미지 검증 (`$Boot`·미할당 카빙, 2026-10-19)

대상: D 드라이브에서 NTFS 볼륨 전체가 든 가장 작은 이미지 `IMG-A`(E01 파일 1.57 GB, 미디어 1 TB, NTFS 파티션 시작 섹터 2048). 사용자 지시("D드라이브에서 제일 작은 이미지")에 따라 읽기 전용으로 사용했다. 이름·경로·URL 내용은 기록하지 않는다. 원시 결과는 `D:\rapid-qa\derived\r6-s2-realimg\report.json`(Git 밖). 코드 `feat/r6-followups` `9f866e3`, Sleuth Kit 없음(pyewf 네이티브 경로).

| 항목 | 결과 | 교차 확인 | 판정 |
|---|---|---|---|
| `$Boot` 네이티브 추출(`dump_boot_sector`, 파티션 자동 탐지) | 0.24 s; 섹터 512 B, 클러스터 4,096 B, 총 섹터 1,953,519,615, MFT LCN 786,432, VSN `6224EA89`(64비트 `5A6225086224EA89`) | `dissect.ntfs`의 serial64·클러스터·MFT LCN·총 섹터 일치(E01 읽기는 같은 `EwfSectorReader`를 써서 NTFS 해석만 독립) | 통과 |
| `ntfs-meta`(Sleuth Kit 없음) | `extraction_status=boot-only-native`, `ntfs-volume-information` 1행, `source_counts.volume-information=1`, 요약 VSN·클러스터가 위와 같음, 0.27 s | — | 통과 |
| `$Bitmap` 네이티브 읽기 → 미할당 구간 | `$Bitmap` 30,523,744 B 0.108 s; 클러스터 244,189,951 중 미할당 244,156,705(99.99%), 구간 8개, 잘림 없음, 계산 0.059 s | `dissect.ntfs` `$Bitmap` 바이트 동일, 미할당 수 일치 | 통과 |
| 미할당 URL 카빙(기본 4 GiB 상한) | 4,294,967,296 B 스캔, `source_truncated=true`(미할당 약 1 TB), 114.4 s(37.5 MB/s), 후보 438(ASCII 289·UTF-16LE 149), 분류: 검색 3·소셜 1·미분류 434 | 64 MiB 상한 재실행: 정확히 67,108,864 B, 2.21 s, 후보 189 | 통과 |
| 취소 | 5 s 시점 취소 → 0.12 s 뒤 `AnalysisCancelled` | — | 통과 |
| raw 사본(같은 디스크 앞 2 GB) | `dump_boot_sector` 0.002 s, 시작 섹터 2048, VSN 동일 | — | 통과 |

관찰: 미할당 영역 대부분이 0으로 채워진 디스크에서도 E01 압축 해제 비용 때문에 37.5 MB/s에 그쳤다. 1 TB 전체를 훑으면 몇 시간이 걸리므로 4 GiB 기본 상한이 필요하다. 0으로만 된 청크를 건너뛰는 최적화는 단계 3(성능) 후보로 남긴다. LNK 볼륨 시리얼과의 대조는 이 이미지의 LNK를 추출하지 않아 하지 않았다(VSN 표기 `%08X`는 합성 테스트로 LNK와 같음을 확인).

## 6. 실행 방법

### 6.1 런 비교

```powershell
python -m rapidtriage run D:\rapid-qa\bsh-subset --mode hacking --output-dir D:\rapid-qa\derived\r6-s1-run --read-only
python scripts\compare-runs.py --baseline D:\rapid-qa\derived\run-subset10 --candidate D:\rapid-qa\derived\r6-s1-run `
    --allow-type browser-analytics-cookie --json --output D:\rapid-qa\derived\r6-s1-compare.json
```

- 종료 코드: 0 통과, 1 회귀, 2 입력 오류. `--fail-on-slow`를 주면 시간 표시(`timing_flags`)도 실패로 친다.
- artifact_type 판정: `unchanged`, `new-type`(기준에 없던 유형, 허용), `allowed`(`--allow-type`), `move`(허용 유형을 뺀 kind 합계가 같음 — 이벤트 채널 재분류 같은 이동), `regression`.
- kind 판정: 유형 회귀, 기준에 행이 있던 kind가 새 런에 없음, `parser_error_count` 증가, 스케줄러 상태가 완료가 아님 중 하나면 `regression`.
- 바뀐 유형마다 경로 꼬리(마지막 3개 경로 구성 요소)를 최대 5개 낸다. 행 내용은 내지 않는다. 경로 꼬리도 사건 정보이므로 보고서는 Git 밖에만 둔다(`--no-path-tails`로 끌 수 있음).
- 큰 JSONL은 바뀐 유형이 있는 kind만 한 줄씩 흘려 읽는다. 변화가 없으면 `artifacts/*.json` 머리만 읽는다.

### 6.2 표본 검증

```powershell
python scripts\sample-check.py --parser egg --input D:\rapid-qa\samples\egg --expect D:\rapid-qa\samples\egg\known-answer.json --json
python scripts\sample-check.py --parser media-player --input D:\rapid-qa\samples\media-player\vm01 --expect D:\rapid-qa\samples\media-player\vm01-known-answer.json
```

- 기본 출력은 행 수·artifact_type 수·기대 일치 수·**불일치 필드 이름**뿐이다. `--show-values`는 기대값·실제값을 함께 내므로 화면 확인용으로만 쓰고 결과를 Git에 넣지 않는다.
- 종료 코드: 0 모두 일치, 1 불일치·누락·개수 불일치, 2 입력 오류(경로 없음, known-answer 형식 오류, 파서 ID 불일치).

### 6.3 곰플레이어 식별자 해시 탐색

```powershell
python scripts\sample-check.py --probe-hash <레지스트리의 32자리 값> `
    --candidate-path "<VM에서 재생한 원래 경로>" --candidate-file D:\rapid-qa\samples\media-player\vm01\clip01.mp4 --json
```

- 경로 문자열: cp949·UTF-16LE·UTF-8 × 원래·소문자·대문자 × 원래·`\`·`/` 구분자 × 끝 NUL 유무.
- 파일: 내용 전체와 앞 N바이트(기본 512·4096·65536·1048576, `--head-bytes`로 바꿈), 파일 이름도 경로처럼 시도.
- 알고리즘: MD5(전체 일치), SHA-1·SHA-256(앞 32자리·뒤 32자리), CRC32(8자리 조각 위치).
- 일치는 `path[i]`/`file[i]` 번호와 변형·알고리즘·위치로만 보고한다(값은 `--show-values`일 때만).

## 7. 참고 — 계획 문서와 다른 점

- 계획 §1.2는 "`p2p` kind가 어느 모드에도 없다"고 적었지만, `rapidtriage/core/run/constants.py`의 `GENERAL_FORENSIC_ARTIFACT_KINDS`에는 R5 L3 커밋에서 이미 `"p2p"`가 들어가 있다(seizure·fraud·hacking 30 kind, recovery는 의도적으로 제외). 단계 1에서는 코드 변경 없이 단언 테스트만 추가했다(`tests/test_rapidtriage_run.py`, `tests/test_rapidtriage_run_plan.py`; Q-S1-4). 기준 런 `run-subset10`(2026-10-15)은 그 이전 24 kind 프로필이라 `p2p` 출력이 없고, 새 런에서는 `new_kinds`에 나타나야 한다.
