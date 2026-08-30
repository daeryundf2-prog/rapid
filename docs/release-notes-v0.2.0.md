# RapidTriage Release Notes

## Version

- Version: 0.2.0
- Release date: 2026-08-30
- Commit: 재개 기준선(restart baseline) 태그 `v0.2.0`

## Highlights

- Windows 실측 기준선 확보: 실제 Windows 11 호스트에서 전체 단위 테스트 스위트가
  녹색이 되도록 플랫폼 결함을 수정했습니다.
- `.gitattributes` 도입: 모든 파일의 바이트를 플랫폼 무관하게 보존(`-text`)하여
  known-answer fixture의 SHA-256이 체크아웃 플랫폼에 따라 달라지는 문제를
  근본 제거했습니다. Windows 셸 스크립트(`*.bat`, `*.cmd`, `*.ps1`)는 CRLF로
  체크아웃됩니다.
- 저장소 위생 정리: 실행 산출물(`qc-runs/` JSON 대량 증거, `ingest_out/`,
  `demo_test/`, `testdata/`)과 깨진 레거시 빌드 스크립트(`windows/build-windows.ps1`,
  고아가 된 `windows/entry/`)를 저장소에서 제거했습니다. QC 증거의 Markdown
  기록(`qc-runs/**/*.md`)은 보존됩니다.
- 배포 패키지 이름을 레거시 `dashcam-tools`에서 `rapidtriage`로 정리하고
  버전을 `0.2.0`으로 올렸습니다.
- Smoke 스크립트가 기본 토큰 인증 하드닝 이후 `/api` 401로 실패하던 문제를
  수정했습니다(Windows PowerShell + macOS/Linux sh 모두). 스크립트는 고정된
  smoke-only 토큰으로 서버를 구동하고 계약 요청에 헤더를 첨부합니다.

## Evidence And Parser Coverage

- Supported evidence inputs: 변경 없음 (README 지원 입력 범위 참조)
- New parsers: 없음 (본 릴리즈는 파서 로직 추가가 아닌 기준선 정비 릴리즈)
- Parser limitations: `docs/rapidtriage-known-limitations.md` 참조

## Validation

- Unit tests: Windows 11 Pro (build 26200) 실측 호스트에서
  `python -m unittest discover -s tests` → **790 tests, OK (skipped=2)**
  (정비 전 동일 호스트: 24 failures + 17 errors)
- Windows smoke: `scripts/windows/smoke-test-rapidtriage.ps1` PASS 8/8 checks
  (doctor/sample/search/benchmark/validation/evidence-guidance/web/
  workbench-smoke-contract) — 증거는 Git 밖 QC 저장소에 보관
- Compile check: `python -m compileall -q rapidtriage tests scripts`
- JS check: `node --check rapidtriage/web/static/app.js` 등 CI 참조
- Package build: `python scripts/build-release.py --output-dir release`
- Sample case: `rapidtriage sample --run --overwrite`
- Benchmark summary: `rapidtriage benchmark --output-dir ./release-benchmark --file-count 1000 --overwrite`

## Known Limitations

- 상용 포렌식 제품 대비 상용급 검증(실제 E01/Ex01 코퍼스, trusted-tool diff,
  독립 검증, 10TB 스트레스, 서명 설치파일/notarization)은 여전히 외부 증거로
  남아 있으며 `commercial_claim_allowed=false`입니다.
- 레지스트리 트랜잭션 리플레이, SAM F/V 전체 디코딩, ESE 카탈로그/페이지
  디코딩 등 네이티브 파서 깊이는 roadmap Phase 2~3에서 trusted diff와 함께
  승격됩니다.

## Security Notes

- Localhost/default binding: 변경 없음 (원격 바인딩 시 auth token 필수)
- Remote binding/auth: 변경 없음 (`X-RapidTriage-Token` 요구)

## Migration / Upgrade Notes

- 배포 패키지 이름이 `dashcam-tools` → `rapidtriage`로 변경되었습니다.
  기존 가상환경에서는 `pip uninstall dashcam-tools` 후 `pip install -e .`로
  재설치하세요. 모듈 `dashcam_tools`와 실행 명령 `dashcam-*`은 이번 버전에서도
  유지됩니다.
- 저장소 클론 시 EOL 변환이 발생하지 않습니다(`* -text`). 로컬 워크트리가
  CRLF인 기존 클론은 `git checkout-index -f -a`로 갱신해야 fixture 해시가
  일치합니다.
