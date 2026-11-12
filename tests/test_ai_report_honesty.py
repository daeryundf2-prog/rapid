"""R8 T-189: the "AI 사용" report section states only what the run's data supports (synthetic data)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rapidtriage.core.ai_report import (
    AI_SKIPPED_SIDECAR,
    BODIES_EXCLUDED_KO,
    ai_usage_gaps,
    ai_usage_section_lines,
    ai_usage_summary,
    period_text,
)


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _browser_payload(stamp: str = "2026-03-01T01:02:03Z") -> dict[str, object]:
    visit = {"ai_service": "ChatGPT", "url": "https://chat.example.test/c/1", "visit_count": 3, "last_visited_at": stamp}
    return {
        "command": "artifacts",
        "kind": "browser",
        "artifacts": [
            {"artifact_type": "browser-history-downloads", "details": {"history_count": 10}},
            {"artifact_type": "browser-ai-usage", "details": {"ai_usage_count": 2, "ai_usage": [visit, {**visit, "ai_service": "Claude", "visit_count": 1}]}},
        ],
    }


def _ai_row(artifact_type: str, **details: object) -> dict[str, object]:
    return {"artifact_type": artifact_type, "details": {"tool": "claude-code", "tool_label": "Claude Code", **details}}


def _ai_payload(*, bodies: object = None, rows: list[dict[str, object]] | None = None) -> dict[str, object]:
    payload: dict[str, object] = {"command": "artifacts", "kind": "ai-agent", "artifacts": rows or []}
    if bodies is not None:
        payload["collector_options"] = {"ai_bodies": bodies}
    return payload


def _section(output_dir: Path) -> str:
    return "\n".join(ai_usage_section_lines(ai_usage_summary(output_dir)))


class BrowserVisitTests(unittest.TestCase):
    def test_browser_visits_only_is_chatbot_visit_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            _write(out / "artifacts" / "rapidtriage-artifacts-browser.json", _browser_payload())
            summary = ai_usage_summary(out)
            self.assertFalse(summary["collected"])
            self.assertEqual(summary["browser_ai"]["urls"], 2)  # type: ignore[index]
            text = "\n".join(ai_usage_section_lines(summary))
            self.assertIn("챗봇: 있음(방문 기록)", text)
            self.assertIn("| 챗봇 | 있음(방문 기록) |", text)
            self.assertIn("ChatGPT(브라우저 방문)", text)
            self.assertIn("방문 기록만으로는 대화 내용·입력값을 알 수 없음", text)
            self.assertIn("(시간대: UTC)", text)
            self.assertNotIn("모든 분류를 '로컬 증거 없음'", text)
            self.assertEqual(text.count("| 없음 |"), 5)  # every other category stays "없음"
            gaps = ai_usage_gaps(summary)
            chatbot = next(row for row in gaps["categories"] if row["category"] == "chatbot")  # type: ignore[union-attr]
            self.assertTrue(chatbot["local_evidence"])
            self.assertEqual(chatbot["evidence"], ["visit"])

    def test_session_and_visit_evidence_combined(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            _write(out / "artifacts" / "rapidtriage-artifacts-browser.json", _browser_payload())
            _write(out / "artifacts" / "rapidtriage-artifacts-ai-agent.json", _ai_payload(rows=[_ai_row("ai-agent-session", started_at="2026-03-01T00:00:00+09:00")]))
            text = _section(out)
            self.assertIn("| 챗봇 | 있음(방문 기록) |", text)
            self.assertRegex(text, r"\| CLI 코딩 에이전트 \| 있음\(세션\)")
            self.assertIn("(시간대: UTC+09:00)", text)

    def test_no_evidence_keeps_all_categories_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            text = _section(Path(temp))
            self.assertEqual(text.count("| 없음 |"), 6)
            self.assertIn("모든 분류를 '로컬 증거 없음'", text)
            self.assertIn("해당 없음(AI 사용 기록 종류를 수집하지 않음)", text)


class CollectionLimitTests(unittest.TestCase):
    def test_budget_exhausted_unread_count_equals_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            rows = [
                _ai_row("ai-agent-session", messages_capped=True, messages_truncated=4, truncated=True, truncated_fields=["messages"], skipped_sidecar=AI_SKIPPED_SIDECAR),
                _ai_row("ai-agent-session", tool_calls_capped=True),
            ]
            _write(out / "artifacts" / "rapidtriage-artifacts-ai-agent.json", _ai_payload(bodies=True, rows=rows))
            entries = [{"adapter": "claude_code", "tool": "claude-code", "path": f"p{index}.jsonl", "size_bytes": 10} for index in range(7)]
            _write(out / "artifacts" / AI_SKIPPED_SIDECAR, {"command": "ai-agent-skipped", "skipped_count": len(entries), "entries": entries})
            summary = ai_usage_summary(out)
            self.assertEqual(summary["limits"]["skipped_files"], 7)  # type: ignore[index]
            text = "\n".join(ai_usage_section_lines(summary))
            line = next(item for item in text.splitlines() if item.startswith("- 수집 한계:"))
            self.assertIn("읽기 예산으로 미수집 파일 7개", line)
            self.assertIn("메시지 상한에 걸린 세션 1건", line)
            self.assertIn("도구 호출 상한에 걸린 세션 1건", line)
            self.assertIn("길이 상한으로 잘린 메시지 4건", line)

    def test_no_limits_stated_as_none(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            _write(out / "artifacts" / "rapidtriage-artifacts-ai-agent.json", _ai_payload(bodies=True, rows=[_ai_row("ai-agent-session")]))
            text = _section(out)
            self.assertIn("- 수집 한계: 확인된 한계 없음", text)
            self.assertIn("포함(비밀값 가림, 긴 메시지는 잘림)", text)


class BodiesScopeTests(unittest.TestCase):
    def test_metadata_only_run_states_what_was_collected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            rows = [
                _ai_row("ai-agent-session", title="작업 제목"),
                _ai_row("ai-agent-tool-call", tool_name="Bash", command="ls"),
                _ai_row("ai-instruction-file", head_text="# 지침"),
                _ai_row("ai-agent-message", text=""),
            ]
            _write(out / "artifacts" / "rapidtriage-artifacts-ai-agent.json", _ai_payload(bodies=False, rows=rows))
            text = _section(out)
            self.assertIn(f"AI 대화 본문 수집: {BODIES_EXCLUDED_KO}", text)
            self.assertIn("본문 제외(명령·제목·지침 머리는 수집됨)", text)
            self.assertIn("명령 1건 · 제목 1건 · 지침 머리 1건", text)
            self.assertNotIn("메타만", text)

    def test_unrecorded_option_is_not_claimed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)
            _write(out / "artifacts" / "rapidtriage-artifacts-ai-agent.json", _ai_payload(rows=[_ai_row("ai-agent-session")]))
            self.assertIn("실행 옵션 기록 없음", _section(out))


class PeriodZoneTests(unittest.TestCase):
    def test_zone_is_read_from_the_stamps(self) -> None:
        self.assertTrue(period_text("2026-01-01T00:00:00Z", "2026-01-02T00:00:00+00:00").endswith("(시간대: UTC)"))
        self.assertIn("UTC+09:00", period_text("2026-01-01T09:00:00+09:00", "2026-01-01T10:00:00+0900"))
        self.assertIn("표기 없음", period_text("2026-01-01 09:00:00", "2026-01-01 10:00:00"))
        self.assertIn("UTC / UTC-05:00", period_text("2026-01-01T00:00:00Z", "2026-01-01T00:00:00-05:00"))


if __name__ == "__main__":
    unittest.main()
