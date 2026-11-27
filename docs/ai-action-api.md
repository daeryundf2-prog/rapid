# 액션 API v1: 콘솔과 AI 에이전트가 함께 쓰는 선택·표시 경로

분석관이 콘솔에서 하는 "이 행 전후를 모두 검토 필요로 표시"와, AI 에이전트에게 맡기는 "A를 분석해라", "B와 관련된 것을 모두 체크/태그해라"는 같은 API를 탄다. 콘솔의 **관련 항목 표시** 대화상자와 **선택 항목 분석** 명령이 이 API를 호출한다.

- 인증: 다른 API와 같은 `X-RapidTriage-Token` 헤더.
- 카탈로그: `GET /api/actions` (버전, 액션 목록, 선택 형식). 에이전트는 이것부터 읽는다.
- 상한: 한 번에 표시할 수 있는 행은 10,000건. 넘으면 아무것도 바꾸지 않고 422로 이유를 돌려준다.
- 오류: 모두 한국어 `detail`.

## 선택(selection)

`selection`에는 아래 셋 중 **하나만** 넣는다.

| 형식 | 예 | 뜻 |
|---|---|---|
| `rows` | `{"rows": [{"collection": "timeline", "locator": "/events/12"}, {"collection": "artifacts", "kind": "browser", "locator": "/artifacts/3"}]}` | 화면에 보이는 행 그대로(로케이터는 콘솔 URL의 `row=` 값과 같다) |
| `timeline` | `{"timeline": {"from": "2026-04-18T14:00:00+09:00", "to": "2026-04-18T15:00:00+09:00", "contains": "invoice", "event_types": ["file-created"]}}` | 타임라인 시간 범위, 요약·경로·이벤트 유형의 문구, 이벤트 유형. 모두 생략하면 타임라인 전체 |
| `related` | `{"related": {"relation": "time_window", "anchor": {"collection": "timeline", "locator": "/events/12"}, "window_s": 300}}` | 기준 행과 관련된 타임라인 행 |

`related.relation`:

- `time_window`: 기준 시각 ±`window_s`초(기본 300초).
- `same_path`: 경로가 같은 행(대소문자·`/`와 `\` 무시).
- `same_name`: 파일 이름이 같은 행.

기준은 타임라인 행(`anchor`)이거나, 다른 화면의 행이면 그 행의 값(`at`: ISO 시각, `path`: 경로)을 직접 보낸다.

## 분석: `POST /api/runs/{run_id}/actions/select`

아무것도 바꾸지 않는다.

```bash
curl -s -H "X-RapidTriage-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{"selection": {"related": {"relation": "time_window", "anchor": {"collection": "timeline", "locator": "/events/12"}, "window_s": 600}}, "sample": 5}' \
  http://127.0.0.1:8765/api/runs/$RUN/actions/select
```

응답(요지):

```json
{
  "total": 18, "limit": 10000, "over_limit": false,
  "by_collection": {"timeline": 18},
  "time_range": {"first": "2026-04-18T14:01:07+00:00", "last": "2026-04-18T14:57:58+00:00"},
  "by_source": {"artifacts": 14, "files": 4},
  "by_event_type": {"file-created": 4, "process-execution": 2},
  "top_paths": [{"path": "...", "count": 3}],
  "sample": [{"locator": "/events/12", "timestamp": "...", "event_type": "...", "summary": "..."}]
}
```

## 체크·태그: `POST /api/runs/{run_id}/actions/mark`

```json
{
  "selection": {"related": {"relation": "same_name", "anchor": {"collection": "timeline", "locator": "/events/12"}}},
  "mark": {"status": "needs-review"},
  "dry_run": true,
  "actor": {"kind": "agent", "name": "triage-bot"}
}
```

- `dry_run`은 기본 `true`다. JSON 불리언만 받는다(`"false"`, `0` 같은 값은 422로 거절하고 아무것도 적용하지 않는다). 미리보기 응답은 분석 응답과 같은 건수·분포를 준다. 사람이 확인한 뒤 `false`로 다시 보내 적용한다.
- 미리보기도 적용과 같은 검사를 거친다. 적용 때 거절될 요청(`tag_ids`와 다른 표시를 섞은 경우, 런에 없는 행 로케이터, 케이스에 없는 태그 id, 빈 `tag_ids`/`add_tags`만 있는 표시)은 미리보기에서도 같은 상태 코드와 문구로 거절된다. 미리보기는 케이스 DB를 만들지 않는다. 케이스 DB가 아직 없으면 런 출력 행으로 로케이터를 확인한다.
- `mark`에는 `status`(`relevant` 관련 있음, `needs-review` 재검토, `excluded` 제외(보고서에서도 빠짐), `unreviewed` 미검토), `add_tags`(태그 이름 추가), `tag_ids`(케이스 태그 id), `include_in_report`, `note` 중 필요한 것을 넣는다. `tag_ids`는 다른 표시와 함께 보낼 수 없다(검토 일괄 표시와 같은 규칙).
- 적용은 런의 케이스 DB(`POST /api/case-db/review-batch`)를 그대로 쓴다. 케이스 DB가 아직 없으면 콘솔의 첫 표시처럼 만든다.
- `actor.kind = "agent"`이면 검토 이력의 작성자가 `agent:<name>`으로 남는다(이름이 비면 `agent:unnamed`). 사람(`human`)은 `name`, 없으면 서버의 `RAPIDTRIAGE_REVIEWER`, 그것도 없으면 `local-user`로 남는다. `actor`를 생략하면 이름 없는 사람이다. 행의 이전 작성자를 물려받지 않는다.
- 사람(`human`)의 `name`은 `agent:`로 시작할 수 없다(422). 사람의 표시가 에이전트 표시로 기록되지 않게 막는다.

적용 응답에는 `updated_count`와 `case_id`가 더해진다. 표시 이력은 `GET /api/runs/{run_id}/review-history?collection=timeline&locator=/events/12`로 본다.

## 위임 지시를 호출로 옮기는 법

| 지시 | 호출 |
|---|---|
| "4월 18일 14시대를 분석해라" | `select` + `timeline: {from, to}` |
| "이 이벤트 앞뒤 5분을 모두 검토 필요로 체크해라" | `mark` + `related: {relation: time_window, anchor, window_s: 300}` + `mark.status: needs-review`, 먼저 `dry_run: true` |
| "invoice_071.pdf와 관련된 것을 모두 태그해라" | `mark` + `related: {relation: same_name, path: "invoice_071.pdf"}` + `mark.add_tags: ["송금 정황"]` |
| "이 목록(로케이터 여러 개)을 보고서에 넣어라" | `mark` + `rows` + `mark.include_in_report: true` |

## 아직 없는 것

- 토큰 종류로 사람/에이전트를 구분하지 않는다. `actor.kind`는 요청이 밝히는 값이다(토큰 하나로 둘 다 쓸 수 있다).
- 묶음 단위 되돌리기가 없다. 되돌리려면 같은 선택으로 이전 상태를 다시 표시한다.
- `related`는 타임라인 행을 모은다. 같은 해시 전파는 기존 `propagate_by_hash`(파일 행)를 쓴다.
