# 질문 팩

수사관이 묻는 말 한 줄("유출 기록 있나?", "외부에서 접속한 기록 있나?")에, 그 질문을 확인할 때
보는 것들을 묶어 둔 카탈로그다. 키워드 팩이 단어 묶음이라면 질문 팩은 **질문 → 검색 조건**이다.

- 코드: `rapidtriage/core/question_packs.py` (검증·확장·해시), `rapidtriage/core/question_catalog.py` (내장 목록)
- API: `GET /api/question-packs`
- 콘솔: 검색 옵션 팝오버의 "질문으로 시작"에서 고르면 검색어·범위·확장자·키워드 팩이 한 번에 채워진다

## 한 건의 구조

```json
{
  "id": "exfil-cloud-upload",
  "question": "클라우드에 자료를 올린 기록이 있나?",
  "category": "유출",
  "keyword_packs": ["exfiltration", "network"],
  "keywords": ["업로드", "공유 링크"],
  "collections": ["artifacts", "timeline", "search"],
  "artifact_kinds": ["cloud-sync", "browser-history"],
  "event_ids": ["4624"],
  "extensions": ["zip"],
  "references": ["MITRE ATT&CK T1567 Exfiltration Over Web Service"],
  "note": "동기화 폴더는 업로드와 구분되지 않는다."
}
```

- `keyword_packs` 는 `keyword_packs.BUILTIN_KEYWORD_PACKS` 의 이름만 쓴다(credentials, execution,
  network, browser-ai, windows-ir, exfiltration). 없는 이름은 거부된다.
- `collections` 는 files·docs·artifacts·timeline·indicators·search·derived·registry 중에서만.
- 서버가 `expanded_keywords` 를 만들어 준다: 키워드 팩을 펼치고, 질문 자체 키워드와 이벤트 ID 를 더해
  대소문자 무시로 중복을 지운 목록이다. 콘솔은 이 값을 그대로 검색어로 쓴다.
- 각 건의 `pack_sha256` 와 카탈로그 전체의 `catalog_sha256` 가 함께 나간다. 보고서에 "어떤 질문으로
  무엇을 찾았는지" 남길 때 쓴다.

## 사건·기관에 맞게 늘리기

내장 카탈로그에 더해 두 곳을 읽는다.

1. 환경변수 `RAPIDTRIAGE_QUESTION_PACKS` — 파일이나 폴더. 여러 개면 경로 구분자(`:`, 윈도우는 `;`)로 잇는다.
2. `~/.rapidtriage/question-packs/*.json`

같은 `id` 를 쓰면 내장 항목을 **대체**하고, 새 `id` 면 추가된다. 어디서 왔는지는 각 건의 `source_ref`
에 남으므로, 화면과 보고서에서 내장과 사건용을 구분할 수 있다.

```bash
export RAPIDTRIAGE_QUESTION_PACKS=/cases/2026-123/question-packs.json
rapidtriage web
```

## 다른 도구의 키워드 목록 가져오기

Autopsy 키워드 리스트, 기관 표준 단어집처럼 **이름 → 단어 목록** 형태의 JSON 도 그대로 둘 수 있다.
질문 한 건으로 옮겨지고 분류는 `가져온 목록`, `references` 에 `imported:<파일이름>` 이 붙는다.

```json
{
  "유출 의심 단어": ["mega.nz", "대외비", "반출"],
  "금융 사건 단어": ["차명", "현금화", "환전"]
}
```

## 한계 (화면과 보고서에 같이 싣는다)

- 질문 팩은 조사 출발점이다. 결과가 없다고 해서 그 행위가 없었다는 뜻은 아니다.
- 키워드와 이벤트 ID 는 한국어·사내 용어·사건별 표현을 담지 못한다.
- 사건에 맞는 단어를 더해 쓰고, 쓴 팩 이름과 추가한 단어를 기록으로 남긴다.
