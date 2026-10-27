"""R7 AI lane C: indirect evidence (git trailers, execution traces), 통합 보기 AI tables, ai.* rules,
the "AI 사용" report section with its gap table, sub-agent families and step labels.

The pipeline class runs one full synthetic run (tests/fixtures/ai_agents/make_fixtures.py plus a
loose-object git repository, a tool call into OneDrive / a case evidence folder and an unknown
dot-folder) and checks every output against counts computed from the run's own ai-agent rows.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zlib
from collections import Counter
from pathlib import Path

from rapidtriage.artifacts.ai_agents.git_trailers import (
    ai_trailers,
    git_trailer_rows,
    scan_repository,
)
from rapidtriage.artifacts.ai_agents.run_indirect import append_ai_indirect_rows
from rapidtriage.core.ai_report import (
    AI_SECTION_HEADING,
    ai_usage_section_lines,
    ai_usage_summary,
)
from rapidtriage.core.artifact_profiles import iter_payload_records
from rapidtriage.core.case_report import (
    build_case_report_markdown,
    render_case_report_html,
)
from rapidtriage.core.run import run_triage_mode
from rapidtriage.core.run.steps import ai_step_notes
from rapidtriage.core.triage_rules import load_catalog
from rapidtriage.core.triage_rules.ai import ai_rule_params
from rapidtriage.core.triage_rules.base import FlagContext, RowView
from rapidtriage.core.triage_rules.engine import (
    TriageInputs,
    build_rules,
    run_triage_flags,
)
from tests.fixtures.ai_agents import make_fixtures as mf

AI_RULES = (
    "ai.credential_file_present",
    "ai.destructive_tool_call",
    "ai.evidence_path_in_tool_call",
    "ai.account_switch",
    "ai.personal_account_on_corporate",
    "ai.retention_cleanup_observed",
    "ai.unknown_tool_candidate",
    "ai.mcp_server_remote",
)
EVIDENCE_ROOT = "C:\\Case\\evidence"


# --- git fixture (loose objects, no git binary) -------------------------------------------------


def _write_object(git_dir: Path, kind: str, body: bytes) -> str:
    raw = f"{kind} {len(body)}".encode() + b"\0" + body
    sha = hashlib.sha1(raw).hexdigest()
    path = git_dir / "objects" / sha[:2] / sha[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(raw))
    return sha


def make_loose_repo(work: Path) -> tuple[Path, list[str]]:
    """``work/.git`` with 3 commits: a human co-author only, an AI co-author, a ``Generated with`` line."""
    git_dir = work / ".git"
    (git_dir / "refs" / "heads").mkdir(parents=True)
    tree = _write_object(git_dir, "tree", b"")
    messages = [
        "Initial import\n\nCo-authored-by: Bob Human <bob.human@corp.example>\n",
        "Add parser\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n",
        "Fix tests\n\nGenerated with [Claude Code](https://claude.com/claude-code)\n\nCo-authored-by: Bob Human <bob.human@corp.example>\n",
    ]
    shas: list[str] = []
    for index, message in enumerate(messages):
        stamp = 1791594000 + index * 3600
        head = f"tree {tree}\n" + (f"parent {shas[-1]}\n" if shas else "")
        head += f"author Dev <dev@corp.example> {stamp} +0900\ncommitter Dev <dev@corp.example> {stamp} +0900\n\n"
        shas.append(_write_object(git_dir, "commit", (head + message).encode()))
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git_dir / "refs" / "heads" / "main").write_text(shas[-1] + "\n", encoding="utf-8")
    log = git_dir / "logs" / "HEAD"
    log.parent.mkdir(parents=True)
    previous = "0" * 40
    lines = []
    for sha in shas:
        lines.append(f"{previous} {sha} Dev <dev@corp.example> 1791594000 +0900\tcommit: x\n")
        previous = sha
    log.write_text("".join(lines), encoding="utf-8")
    return git_dir, shas


class GitTrailerTests(unittest.TestCase):
    def test_trailer_detection_ignores_human_coauthors(self) -> None:
        self.assertEqual(ai_trailers("x\n\nCo-authored-by: Jane Doe <jane@example.com>\n"), [])
        found = ai_trailers("x\n\nCo-Authored-By: Cursor Agent <cursoragent@cursor.com>\nAgent-Logs-Url: https://app.devin.ai/sessions/abc\n")
        self.assertEqual([(item["kind"], item["tool"]) for item in found], [("co-authored-by", "cursor"), ("agent-logs-url", "devin")])
        self.assertEqual(found[1]["value"], "app.devin.ai")  # host only, never the session path

    def test_loose_repository_three_commits_two_ai(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            git_dir, shas = make_loose_repo(Path(temp) / "proj")
            scan, commits = scan_repository(git_dir)
            self.assertEqual(scan.commits_read, 3)
            self.assertEqual(scan.ai_commits, 2)
            self.assertEqual({item["commit"] for item in commits}, set(shas[1:]))
            rows = git_trailer_rows({"inventory": [{"path": str(git_dir / "HEAD")}, {"path": str(git_dir / "logs" / "HEAD")}]})
            attributions = [row for row in rows if row.artifact_type == "ai-code-attribution"]
            repos = [row for row in rows if row.payload.get("presence_kind") == "git-repo-scan"]
            self.assertEqual(len(attributions), 2)
            self.assertEqual({row.tool for row in attributions}, {"claude-code"})
            self.assertTrue(all(row.payload["source"] == "git-trailer" and row.timestamp_kind == "committed" for row in attributions))
            self.assertEqual(len(repos), 1)
            self.assertEqual((repos[0].payload["commits_read"], repos[0].payload["ai_commits"]), (3, 2))
            self.assertFalse(repos[0].payload["git_binary_used"])
            dumped = json.dumps([row.to_record().to_dict() for row in rows], ensure_ascii=False)
            self.assertNotIn("bob.human", dumped)  # human co-authors are never copied
            self.assertNotIn("dev@corp.example", dumped)

    def test_commit_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            git_dir, _ = make_loose_repo(Path(temp) / "proj")
            scan, _ = scan_repository(git_dir, max_commits=2)
            self.assertEqual(scan.commits_read, 2)
            self.assertTrue(scan.commits_capped)

    @unittest.skipIf(shutil.which("git") is None, "git binary only builds the packed fixture")
    def test_packed_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp) / "packed"
            work.mkdir()
            env = {**os.environ, "GIT_AUTHOR_NAME": "Dev", "GIT_AUTHOR_EMAIL": "dev@corp.example", "GIT_COMMITTER_NAME": "Dev", "GIT_COMMITTER_EMAIL": "dev@corp.example", "GIT_CONFIG_NOSYSTEM": "1", "HOME": temp}
            run = lambda *args: subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=work, env=env, check=True, capture_output=True)
            run("init", "-q")
            for message in ["one", "two\n\nCo-Authored-By: Claude <noreply@anthropic.com>", "three\n\nGenerated with Codex"]:
                run("commit", "-q", "--allow-empty", "--no-verify", "-m", message)
            run("repack", "-a", "-d", "-q")
            run("prune-packed")
            git_dir = work / ".git"
            self.assertTrue(list((git_dir / "objects" / "pack").glob("*.idx")))
            scan, commits = scan_repository(git_dir)
            self.assertEqual((scan.commits_read, scan.delta_commits_unread, scan.ai_commits), (3, 0, 2))
            self.assertEqual(sorted({trailer["tool"] for item in commits for trailer in item["trailers"]}), ["claude-code", "codex"])


# --- run hook ---------------------------------------------------------------------------------------


def _write_json(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class IndirectHookTests(unittest.TestCase):
    def test_execution_and_trailer_rows_are_appended_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifacts = root / "out" / "artifacts"
            git_dir, _ = make_loose_repo(root / "ev" / "proj")
            ai_row = {"provider": "ai-agents", "artifact_type": "ai-tool-presence", "path": "x", "supported": True, "details": {"parser": "ai-tool-presence", "tool": "cursor", "retention_auto_delete": True}}
            ai_path = _write_json(
                artifacts / "rapidtriage-artifacts-ai-agent.json",
                {"command": "artifacts", "kind": "ai-agent", "root": str(root / "ev"), "summary": {"artifact_count": 1, "artifact_type_counts": {"ai-tool-presence": 1}}, "artifacts": [ai_row]},
            )
            _write_json(
                artifacts / "rapidtriage-artifacts-windows-prefetch.json",
                {
                    "command": "artifacts",
                    "kind": "windows-prefetch",
                    "artifacts": [
                        {"artifact_type": "windows-prefetch-file", "path": "C:\\Windows\\Prefetch\\CLAUDE.EXE-1A2B3C4D.pf", "details": {"executable_name": "CLAUDE.EXE", "last_run_time": "2026-10-10T01:00:00Z"}},
                        {"artifact_type": "windows-prefetch-file", "path": "C:\\Windows\\Prefetch\\NOTEPAD.EXE-1.pf", "details": {"executable_name": "NOTEPAD.EXE"}},
                    ],
                },
            )
            payloads = {"ai-agent": json.loads(ai_path.read_text(encoding="utf-8"))}
            manifest = {"providers": [{"name": "ai-agents", "artifact_count": 1, "artifact_type_counts": {}}]}
            manifest_summary = {"providers": [{"name": "ai-agents", "artifact_count": 1}]}
            files = {"inventory": [{"path": str(git_dir / "HEAD")}]}
            for _ in range(2):  # a resumed run never doubles the rows
                block = append_ai_indirect_rows(
                    artifacts, payloads, {"ai-agent": ai_path}, files_payload=files,
                    manifest_payload=manifest, manifest_path=root / "out" / "manifest.json", manifest_summary=manifest_summary,
                )
                self.assertEqual(block["status"], "completed", block)
            rows = list(iter_payload_records(payloads["ai-agent"], payload_path=ai_path))
            types = Counter((row["artifact_type"], row["details"].get("parser")) for row in rows)
            # claude.exe matches two catalog tools (Claude desktop and Claude Code): one row each.
            self.assertEqual(types[("ai-tool-presence", "ai-tool-execution-match")], 2)
            self.assertEqual(types[("ai-code-attribution", "ai-git-trailers")], 2)
            self.assertEqual(types[("ai-tool-presence", "ai-git-trailers")], 1)
            self.assertEqual(len(rows), 6)
            self.assertEqual(payloads["ai-agent"]["summary"]["artifact_count"], 6)
            self.assertEqual(block["replaced_rows"], 5)
            # cursor (fixture row) + every execution-matched tool whose catalog retention auto-deletes
            auto_delete = {row["details"]["tool"] for row in rows if row["details"].get("retention_auto_delete") is True}
            self.assertIn("cursor", auto_delete)
            self.assertEqual(block["retention_rows"], len(auto_delete))
            self.assertEqual(manifest["providers"][0]["artifact_count"], 6)
            self.assertEqual(manifest_summary["providers"][0]["artifact_count"], 6)
            self.assertTrue((root / "out" / "manifest.json").is_file())
            on_disk = json.loads(ai_path.read_text(encoding="utf-8"))
            self.assertEqual(on_disk["summary"]["ai_indirect"]["git_trailer_commits"], 2)
            self.assertTrue(all("artifact_record" in row for row in rows if row["details"].get("parser") in {"ai-tool-execution-match", "ai-git-trailers"}))
            notes, level = ai_step_notes("ai-agent", payloads["ai-agent"]["summary"])
            self.assertEqual(level, "notice")
            self.assertTrue(any("AI 트레일러 커밋 2건" in note for note in notes))
            self.assertTrue(any(f"보존 기한 있는 AI 기록 {len(auto_delete)}건" in note for note in notes))

    def test_no_ai_kind_is_skipped(self) -> None:
        block = append_ai_indirect_rows(Path("."), {}, {}, files_payload=None)
        self.assertEqual(block["status"], "skipped")

    def test_failure_is_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            payloads = {"ai-agent": {"summary": {}, "records_path": str(Path(temp) / "missing.jsonl"), "artifacts": []}}
            block = append_ai_indirect_rows(Path(temp), payloads, {"ai-agent": Path(temp) / "rapidtriage-artifacts-ai-agent.json"}, files_payload=None)
        self.assertEqual(block["status"], "failed_isolated")
        notes, level = ai_step_notes("ai-agent", payloads["ai-agent"]["summary"])
        self.assertEqual(level, "warning")
        self.assertIn("추가 실패", notes[0])


# --- rule units ------------------------------------------------------------------------------------


def _rules() -> dict[str, object]:
    return {rule.rule_id: rule for rule in build_rules(load_catalog()) if rule.rule_id.startswith("ai.")}


def _view(artifact_type: str, details: dict, index: int = 0, kind: str = "ai-agent") -> RowView:
    return RowView(kind=kind, collection="artifacts", source_kind=kind, index=index, row={"artifact_type": artifact_type, "details": details})


class RuleUnitTests(unittest.TestCase):
    def test_catalog_has_every_rule_with_validation(self) -> None:
        catalog = load_catalog()
        for rule_id in AI_RULES:
            spec = catalog.specs[rule_id]
            self.assertIsNotNone(spec.validation, rule_id)
            self.assertTrue(spec.label_ko and spec.rationale_ko and spec.sources)
        self.assertEqual({rule_id: catalog.specs[rule_id].grade for rule_id in AI_RULES}["ai.destructive_tool_call"], "B")
        self.assertEqual(catalog.family_for("ai-agent-session", "ai-agent"), "ai-session")
        self.assertEqual(catalog.family_for("ai-agent-file-touch", "ai-agent"), "ai-file-touch")

    def test_evidence_path_removable_letter_and_sync_root(self) -> None:
        rule = build_rules(load_catalog(), {"ai.evidence_path_in_tool_call": {"evidence_roots": [EVIDENCE_ROOT]}})
        rule = next(item for item in rule if item.rule_id == "ai.evidence_path_in_tool_call")
        ctx = FlagContext()
        ctx.shared["removable_letters"] = {"e"}
        rule.prepare(ctx)
        cases = {
            0: "E:\\export\\a.docx",
            1: "D:\\Sync\\Box\\b.xlsx",
            2: "C:\\Users\\u1\\proj\\c.py",
            3: "c:\\case\\EVIDENCE\\img.e01",
            4: "/Volumes/USB/d.txt",
            5: "F:\\data\\e.txt",
        }
        for index, path in cases.items():
            rule.apply(_view("ai-agent-tool-call", {"target_path": path, "tool": "claude-code"}, index), ctx)
        rule.apply(_view("cloud-sync-account", {"sync_root": "D:\\Sync\\Box"}, 0, kind="cloud-sync"), ctx)
        flagged = {ref[1]: result.evidence["location"] for ref, result, _type in rule.finalize(ctx)}
        self.assertEqual(set(flagged), {0, 1, 3, 4})
        self.assertEqual(flagged[0], "이동식 드라이브(E:)")
        self.assertEqual(flagged[1], "클라우드 동기화 폴더")
        self.assertEqual(flagged[3], "사건 증거 폴더")

    def test_personal_account_needs_org_domain(self) -> None:
        row = _view("ai-account", {"email_domain": "gmail.example", "tool": "claude"})
        idle = _rules()["ai.personal_account_on_corporate"]
        idle.prepare(FlagContext())
        self.assertIsNone(idle.apply(row, FlagContext()))
        active = next(rule for rule in build_rules(load_catalog(), ai_rule_params({"ai-agent": {"org_email_domain": "@Corp.Example"}})) if rule.rule_id == "ai.personal_account_on_corporate")
        active.prepare(FlagContext())
        self.assertIsNotNone(active.apply(row, FlagContext()))
        self.assertIsNone(active.apply(_view("ai-account", {"email_domain": "mail.corp.example"}), FlagContext()))
        self.assertIsNone(ai_rule_params({"ai-agent": {"ai_bodies": True}}))

    def test_destructive_patterns(self) -> None:
        rule = _rules()["ai.destructive_tool_call"]
        rule.prepare(FlagContext())
        fires = ["rm -rf build", "Remove-Item -Recurse dist", "cmd /c del x.txt", "rmdir /s out", "format E: /q", "shred -u f", "rd /s /q x"]
        quiet = ["ls -la", "git status", "python format.py", "echo removed", "npm run lint"]
        for command in fires:
            self.assertIsNotNone(rule.apply(_view("ai-agent-tool-call", {"command": command}), FlagContext()), command)
        for command in quiet:
            self.assertIsNone(rule.apply(_view("ai-agent-tool-call", {"command": command}), FlagContext()), command)
        recorded = _view("ai-agent-tool-call", {"command": "custom", "destructive": True, "destructive_source": "tool-record"})
        guessed = _view("ai-agent-tool-call", {"command": "git reset --hard", "destructive": True, "destructive_source": "command-pattern"})
        self.assertIsNotNone(rule.apply(recorded, FlagContext()))
        self.assertIsNone(rule.apply(guessed, FlagContext()))


# --- full synthetic run ---------------------------------------------------------------------------------


def _extra_evidence(home: Path) -> None:
    """Additions to the lane B fixture: a session touching OneDrive / a case folder, an unknown
    dot-folder, and a git repository with AI trailers inside the project."""
    project = home / ".claude" / "projects" / "C--Users-u1-proj"
    mf._jsonl(
        project / "sess-X.jsonl",
        [
            mf._cc("user", "sess-X", "2026-10-16T01:00:00.000Z", "2.1.308", message={"role": "user", "content": "collect the files"}),
            mf._cc(
                "assistant", "sess-X", "2026-10-16T01:00:05.000Z", "2.1.308",
                message={"role": "assistant", "model": "claude-opus-4", "content": [
                    {"type": "tool_use", "id": "x1", "name": "Read", "input": {"file_path": "C:\\Users\\u1\\OneDrive\\Documents\\plan.docx"}},
                    {"type": "tool_use", "id": "x2", "name": "Bash", "input": {"command": "copy C:\\Case\\evidence\\a.txt C:\\Users\\u1\\proj\\b.txt"}},
                    {"type": "tool_use", "id": "x3", "name": "Read", "input": {"file_path": "C:\\Users\\u1\\proj\\ok.txt"}},
                ]},
            ),
        ],
    )
    mf._jsonl(home / ".weirdai" / "sessions" / "s1.jsonl", [{"role": "user", "text": "hi"}])
    make_loose_repo(home / "proj")


class PipelineTests(unittest.TestCase):
    temp: tempfile.TemporaryDirectory
    out: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        base = Path(cls.temp.name)
        evidence = base / "ev"
        home = mf.build_all(evidence)
        _extra_evidence(home)
        cls.out = base / "out"
        cls.summary = run_triage_mode(
            evidence,
            mode="seizure",
            output_dir=cls.out,
            read_only=True,
            overwrite=True,
            collector_options={"ai-agent": {"org_email_domain": "corp.example", "evidence_roots": [EVIDENCE_ROOT]}},
        )
        payload_path = cls.out / "artifacts" / "rapidtriage-artifacts-ai-agent.json"
        cls.ai_payload = json.loads(payload_path.read_text(encoding="utf-8"))
        cls.rows = list(iter_payload_records(cls.ai_payload, payload_path=payload_path))
        cls.derived = next((cls.out / "analyses").glob("run-derived-*"))
        cls.flags_dir = next((cls.out / "analyses").glob("run-triage-flags-*"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def _of(self, artifact_type: str) -> list[tuple[int, dict]]:
        return [(index, row["details"]) for index, row in enumerate(self.rows) if row["artifact_type"] == artifact_type]

    def _flags(self, flags_dir: Path | None = None) -> dict[str, list[tuple[int, dict]]]:
        out: dict[str, list[tuple[int, dict]]] = {}
        for line in (flags_dir or self.flags_dir).joinpath("flags.jsonl").read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            if record.get("kind") != "ai-agent":
                continue
            for flag in record["flags"]:
                out.setdefault(flag["id"], []).append((record["record_index"], flag))
        return out

    def _table(self, name: str) -> list[dict]:
        return [json.loads(line) for line in (self.derived / f"{name}.jsonl").read_text(encoding="utf-8").splitlines()]

    # derived ---------------------------------------------------------------------------------------

    def test_ai_usage_table(self) -> None:
        sessions = self._of("ai-agent-session")
        usage = self._table("ai_usage")
        self.assertEqual(sum(row["count"] for row in usage), len(sessions))
        summary = json.loads((self.derived / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["tables"]["ai_usage"]["occurrences"], len(sessions))
        self.assertEqual(summary["tables"]["ai_usage"]["rows"], len(usage))
        day = next(row for row in usage if row["normalized"] == "claude-code|u1|2026-10-10")
        # sess-A and its two sub-agents
        self.assertEqual((day["sessions"], day["subagent_sessions"], day["tool_calls"]), (3, 2, 7))
        self.assertEqual(day["account"], "u1")
        self.assertEqual(day["projects"], 1)
        expected = sum(int(details.get("tokens_in") or 0) for _i, details in sessions if details.get("tool") == "claude-code" and str(details.get("started_at", "")).startswith("2026-10-10"))
        self.assertEqual(day["tokens_in"], expected)
        for sample in day["samples"]:  # pivot -> the session rows themselves
            self.assertEqual(sample["kind"], "ai-agent")
            row = self.rows[sample["record_index"]]
            self.assertEqual(row["artifact_type"], "ai-agent-session")
            self.assertEqual(row["details"]["tool"], "claude-code")
        self.assertTrue((self.derived / "ai_usage.index.json").is_file())

    def test_ai_projects_table(self) -> None:
        projects = self._table("ai_projects")
        proj = next(row for row in projects if row["normalized"] == "c:/users/u1/proj")
        with_cwd = [d for _i, d in self._of("ai-agent-session") if str(d.get("cwd") or "").replace("\\", "/").casefold() == "c:/users/u1/proj"]
        self.assertEqual(proj["sessions"], len(with_cwd))
        self.assertIn("claude-code", proj["tools"])
        self.assertGreater(proj["file_touch_rows"], 0)
        self.assertIn("ai-file-touch", proj["families"])
        self.assertIsNotNone(proj["first_activity"])
        for sample in proj["samples"]:
            self.assertIn(self.rows[sample["record_index"]]["artifact_type"], {"ai-agent-session", "ai-agent-file-touch"})

    # rules -------------------------------------------------------------------------------------------

    def test_rules_fire_on_expected_rows_only(self) -> None:
        flags = self._flags()
        expected = {
            "ai.credential_file_present": {i for i, _d in self._of("ai-credential-presence")},
            "ai.account_switch": {i for i, _d in self._of("ai-account-switch")},
            "ai.retention_cleanup_observed": {i for i, _d in self._of("ai-retention-cleanup")},
            "ai.unknown_tool_candidate": {i for i, _d in self._of("unknown-ai-tool-candidate")},
            "ai.mcp_server_remote": {i for i, d in self._of("ai-mcp-server") if d.get("remote") is True},
            "ai.personal_account_on_corporate": {i for i, d in self._of("ai-account") if d.get("email_domain") and not str(d["email_domain"]).endswith("corp.example")},
        }
        for rule_id, indexes in expected.items():
            self.assertTrue(indexes, f"fixture has no input for {rule_id}")
            self.assertEqual({index for index, _flag in flags.get(rule_id, [])}, indexes, rule_id)
        self.assertEqual(len(expected["ai.unknown_tool_candidate"]), 1)
        self.assertEqual(len(expected["ai.retention_cleanup_observed"]), 1)

    def test_destructive_rule(self) -> None:
        flagged = {index: flag["evidence"] for index, flag in self._flags()["ai.destructive_tool_call"]}
        calls = dict(self._of("ai-agent-tool-call"))
        zcode = [i for i, d in calls.items() if d.get("destructive_source") == "tool-record" and d.get("destructive") is True]
        self.assertTrue(zcode)
        self.assertTrue(set(zcode) <= set(flagged))
        commands = {calls[i].get("command") for i in flagged}
        self.assertTrue(any("rm -rf" in str(c) for c in commands))
        self.assertTrue(any("Remove-Item" in str(c) for c in commands))
        for index, details in calls.items():
            if index not in flagged:
                self.assertNotRegex(str(details.get("command") or ""), r"(?i)(^|\s)(rm|del|rmdir|remove-item|shred)\s")

    def test_evidence_path_rule(self) -> None:
        flagged = {index: flag["evidence"] for index, flag in self._flags()["ai.evidence_path_in_tool_call"]}
        locations = Counter(evidence["location"] for evidence in flagged.values())
        # the Bash copy names the case folder in its command only: its read file touch is flagged
        self.assertEqual(locations["사건 증거 폴더"], 1)
        self.assertEqual(locations["클라우드 동기화 폴더(기본 이름)"], 2)  # the Read call (target_path) + its file touch
        paths = " ".join(str(evidence.get("path")) for evidence in flagged.values())
        self.assertNotIn("ok.txt", paths)
        self.assertNotIn("b.txt", paths)
        types = {self.rows[index]["artifact_type"] for index in flagged}
        self.assertEqual(types, {"ai-agent-tool-call", "ai-agent-file-touch"})

    def test_personal_account_rule_off_without_option(self) -> None:
        outputs = {path.name[len("rapidtriage-artifacts-"):-len(".json")]: path for path in (self.out / "artifacts").glob("rapidtriage-artifacts-*.json")}
        with tempfile.TemporaryDirectory() as temp:  # not the run stage: it would replace the run's own generation
            run_triage_flags(TriageInputs(output_dir=self.out, artifact_payloads=outputs, files_path=self.out / "rapidtriage-files.json"), Path(temp), source_label="test")
            flags = self._flags(Path(temp))
        self.assertNotIn("ai.personal_account_on_corporate", flags)
        # without the evidence_roots option only the cloud-folder hits remain
        self.assertEqual({flag["evidence"]["location"] for _i, flag in flags["ai.evidence_path_in_tool_call"]}, {"클라우드 동기화 폴더(기본 이름)"})
        self.assertEqual(Counter(index for index, _f in flags["ai.credential_file_present"]), Counter(index for index, _f in self._flags()["ai.credential_file_present"]))

    # indirect + families + steps ----------------------------------------------------------------------

    def test_git_trailers_in_run(self) -> None:
        attributions = [d for _i, d in self._of("ai-code-attribution") if d.get("source") == "git-trailer"]
        self.assertEqual(len(attributions), 2)
        self.assertEqual(self.ai_payload["summary"]["ai_indirect"]["git_repositories"], 1)
        manifest = json.loads((self.out / "rapidtriage-manifest.json").read_text(encoding="utf-8"))
        provider = next(row for row in manifest["providers"] if row["name"] == "ai-agents")
        self.assertEqual(provider["artifact_count"], len(self.rows))

    def test_subagent_families(self) -> None:
        edges = [json.loads(line) for line in (self.out / "rapidtriage-families.jsonl").read_text(encoding="utf-8").splitlines()]
        subagents = [edge for edge in edges if edge.get("relation") == "subagent"]
        sessions = self._of("ai-agent-session")
        ids = {(d.get("tool"), d.get("session_id")) for _i, d in sessions}
        expected = sum(1 for _i, d in sessions if d.get("parent_session_id") and (d.get("tool"), d.get("parent_session_id")) in ids)
        self.assertEqual(len(subagents), expected)
        self.assertGreaterEqual(expected, 6)
        self.assertTrue(all(edge["parent_type"] == edge["child_type"] == "ai-agent-session" for edge in subagents))

    def test_step_row_label(self) -> None:
        step = next(row for row in self.summary["steps"] if row.get("name") == "artifacts-ai-agent")
        self.assertEqual(step["label_ko"], "AI 사용 기록")
        self.assertTrue(any("AI 트레일러 커밋 2건" in message for message in step["warning_messages"]))
        self.assertTrue(any("보존 기한 있는 AI 기록" in message for message in step["warning_messages"]))

    # report -------------------------------------------------------------------------------------------

    def test_report_section_and_gap_table(self) -> None:
        markdown = build_case_report_markdown(
            run_summary={"output_dir": str(self.out), "mode": "seizure"},
            case_payload={},
            submission_manifest={},
            metadata={"ai_consent_basis": "동의서 2026-001"},
        )
        self.assertIn(AI_SECTION_HEADING, markdown)
        section = markdown[markdown.index(AI_SECTION_HEADING) : markdown.index("## 5.")]
        sessions = len(self._of("ai-agent-session"))
        self.assertIn(f"- 세션: {sessions}건", section)
        self.assertIn("| 도구 분류 | 로컬 증거 | 확인된 도구 | 필요한 서버 측 증거 |", section)
        self.assertIn("| 로컬 LLM | 없음 |", section)
        self.assertRegex(section, r"\| CLI 코딩 에이전트 \| 있음\([^|]*세션")
        self.assertIn("AI 트레일러 커밋 2건", section)
        self.assertIn("AI 54.5%", section)
        self.assertIn("동의서 2026-001", section)
        html = render_case_report_html(markdown)
        self.assertIn("<th>도구 분류</th>", html)
        self.assertEqual(html.count("<table>"), 1)
        for secret in mf.secret_values():
            self.assertNotIn(secret, markdown)
        off = build_case_report_markdown(run_summary={"output_dir": str(self.out)}, case_payload={}, submission_manifest={}, metadata={"sections": []})
        self.assertNotIn(AI_SECTION_HEADING, off)
        explicit = build_case_report_markdown(run_summary={"output_dir": str(self.out)}, case_payload={}, submission_manifest={}, metadata={"sections": ["ai-usage"]})
        self.assertIn(AI_SECTION_HEADING, explicit)

    def test_no_secrets_in_ai_tables_or_flags(self) -> None:
        tables = [(self.derived / f"{name}.jsonl").read_text(encoding="utf-8") for name in ("ai_usage", "ai_projects")]
        for secret in mf.secret_values():
            for text in tables:
                self.assertNotIn(secret, text)
        # claude-swap file names embed the account e-mail (lane A/B rows keep the evidence path as is);
        # key and token values must never reach a flag.
        flags = (self.flags_dir / "flags.jsonl").read_text(encoding="utf-8")
        for secret in mf.secret_values():
            if secret not in mf.EMAIL_LOCALS:
                self.assertNotIn(secret, flags)

    # API (lane D hand-off) -------------------------------------------------------------------------

    def test_api_gaps_tree_domain_and_facets(self) -> None:
        try:
            from fastapi.testclient import TestClient

            from rapidtriage.api.app import create_app
        except ImportError:  # pragma: no cover - API extras absent
            self.skipTest("fastapi not installed")
        from rapidtriage.core.jobs import RunJobStore

        store = RunJobStore()
        run_id = store.import_completed_run(self.out).run_id
        client = TestClient(create_app(store, auth_token="ai-c-token"), headers={"X-RapidTriage-Token": "ai-c-token"})
        gaps = client.get(f"/api/runs/{run_id}/ai-usage/gaps")
        self.assertEqual(gaps.status_code, 200, gaps.text)
        body = gaps.json()
        by_tool = {item["tool"]: item for item in body["tools"]}
        self.assertTrue(by_tool["claude-code"]["local_evidence"])
        self.assertIn("벤더 API·콘솔 사용 기록(키·계정별 사용량)", by_tool["claude-code"]["server_evidence_needed"])
        presence_only = [item for item in body["tools"] if not item["local_evidence"]]
        self.assertTrue(presence_only)  # e.g. Aider / Windsurf: path presence without sessions
        self.assertTrue(all(item["server_evidence_needed"] for item in presence_only))
        self.assertEqual([row["category"] for row in body["categories"]][-1], "local_llm")
        tree = client.get(f"/api/runs/{run_id}/tree").json()
        text = json.dumps(tree, ensure_ascii=False)
        self.assertIn("artifacts-group:ai", text)
        self.assertIn('"install_kind"', text)
        self.assertIn('"source"', text)

    def test_run_request_collector_options(self) -> None:
        from rapidtriage.api.app.models import RunCreateRequest
        from rapidtriage.api.app.routes_runs import run_request_from_body
        from rapidtriage.core.jobs import RunRequest

        body = RunCreateRequest(root="x", mode="seizure", collector_options={"ai-agent": {"ai_bodies": False, "ai_hash_dbs": True, "org_email_domain": "@Corp.Example", "evidence_roots": ["C:\\Case", " "]}})
        request = run_request_from_body(body)
        self.assertEqual(request.collector_options, {"ai-agent": {"ai_bodies": False, "ai_hash_dbs": True, "org_email_domain": "corp.example", "evidence_roots": ["C:\\Case"]}})
        self.assertEqual(RunRequest.from_dict(request.to_dict()).collector_options, request.collector_options)
        from fastapi import HTTPException

        for bad in ({"eventlog": {}}, {"ai-agent": {"ai_bodies": "yes"}}, {"ai-agent": {"unknown": 1}}, {"ai-agent": {"org_email_domain": "not a domain"}}):
            with self.assertRaises(HTTPException):
                run_request_from_body(RunCreateRequest(root="x", mode="seizure", collector_options=bad))
        self.assertIsNone(run_request_from_body(RunCreateRequest(root="x", mode="seizure")).collector_options)


class ZeroAiTests(unittest.TestCase):
    def test_report_without_ai_rows_keeps_gap_table(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            summary = ai_usage_summary(temp)
            self.assertFalse(summary["collected"])
            lines = ai_usage_section_lines(summary)
            text = "\n".join(lines)
            self.assertIn("포함되지 않았거나", text)
            self.assertEqual(text.count("| 없음 |"), 6)
            empty = Path(temp) / "artifacts"
            _write_json(empty / "rapidtriage-artifacts-ai-agent.json", {"command": "artifacts", "kind": "ai-agent", "summary": {"artifact_count": 0}, "artifacts": []})
            summary = ai_usage_summary(temp)
            self.assertTrue(summary["collected"])
            self.assertEqual((summary["rows"], summary["sessions"]), (0, 0))
            self.assertIn("- 세션: 0건", "\n".join(ai_usage_section_lines(summary)))


if __name__ == "__main__":
    unittest.main()
