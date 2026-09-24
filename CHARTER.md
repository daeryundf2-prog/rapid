# CHARTER — rapid

## Role
Evidence plane — 로컬 전용 디지털 트리아지 (Digital Triage Beta).

## Do
- 로컬 미디어/이미지 트리아지·복구 보조
- source locator + row hash 기반 재현 가능 산출물
- Tier 0 픽스처 엔지니어링 검증

## Don't
- commercial-grade 증거 주장 금지 — release evidence는 실물 E01/Windows 검증까지 보류
- import된 manifest의 경로를 권한으로 취급 금지 — `confine_path` 통과 전 사용 금지
- case 접근의 actor identity 검증 우회 금지

## Contracts
- Consumes: frametrace 산출물 (lazy-evidence-case-v1)
- Produces: 트리아지 결과, 복구 매니페스트
- Vendored: `contracts/` (lazy-contracts, hash-pinned)

## Claims allowed
`observed`, `heuristic`. 복구 정확도 주장은 trusted-diff 리시트가 있을 때만.
