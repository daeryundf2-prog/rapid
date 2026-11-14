"""Fixtures of ``rapidtriage.core.triage_rules.ai`` (see ``tests.triage_cases``)."""

from __future__ import annotations


def ai(artifact_type: str, **details: object) -> dict[str, object]:
    base: dict[str, object] = {"tool": "claude-code", "tool_label": "Claude Code", "session_id": "s1"}
    base.update(details)
    return {"kind": "ai-agent", "row": {"artifact_type": artifact_type, "path": r"C:\Users\u1\.claude\projects\p\s1.jsonl", "details": base}}


def call(command: str = "", target_path: str = "", **details: object) -> dict[str, object]:
    return ai("ai-agent-tool-call", tool_name="Bash", command=command, target_path=target_path, **details)


def removable_letter(letter: str) -> dict[str, object]:
    return {
        "kind": "windows-registry",
        "row": {"artifact_type": "windows-mounted-device", "details": {"drive_letter": f"{letter}:", "removable_usb": True}},
    }


CASES = {
    "ai.credential_file_present": {
        "positive": {"rows": [ai("ai-credential-presence", credential_kind="oauth-credentials", value_collected=False)], "flagged": [0]},
        "negative": {"rows": [ai("ai-instruction-file", instruction_kind="CLAUDE.md")], "flagged": []},
    },
    "ai.destructive_tool_call": {
        "positive": {
            "rows": [
                call("rm -rf C:\\Users\\u1\\proj\\build"),
                call("custom", destructive=True, destructive_source="tool-record"),
                call("ls -la"),
            ],
            "flagged": [0, 1],
        },
        "negative": {
            "rows": [call("git reset --hard", destructive=True, destructive_source="command-pattern"), call("python format.py")],
            "flagged": [],
        },
    },
    "ai.evidence_path_in_tool_call": {
        "positive": {
            "rows": [
                removable_letter("E"),
                call(target_path="E:\\export\\a.docx"),
                call(target_path="C:\\Users\\u1\\OneDrive\\plan.docx"),
                ai("ai-agent-file-touch", op="read", touched_path="C:\\Case\\evidence\\img.e01"),
                call(target_path="C:\\Users\\u1\\proj\\ok.txt"),
            ],
            "flagged": [1, 2, 3],
            "params": {"evidence_roots": ["C:\\Case\\evidence"]},
        },
        "negative": {
            "rows": [call(target_path="E:\\export\\a.docx"), ai("ai-agent-file-touch", op="read", touched_path="C:\\Case\\evidence\\img.e01")],
            "flagged": [],
        },
    },
    "ai.account_switch": {
        "positive": {"rows": [ai("ai-account-switch", tool="claude-swap", from_account="swap-1", tool_account_key="swap-2")], "flagged": [0]},
        "negative": {"rows": [ai("ai-account", tool="claude-swap", tool_account_key="swap-1")], "flagged": []},
    },
    "ai.personal_account_on_corporate": {
        "positive": {
            "rows": [ai("ai-account", email_domain="gmail.example"), ai("ai-account", email_domain="mail.corp.example")],
            "flagged": [0],
            "params": {"org_email_domain": "corp.example"},
        },
        # no organisation domain set: the rule never fires
        "negative": {"rows": [ai("ai-account", email_domain="gmail.example")], "flagged": []},
    },
    "ai.retention_cleanup_observed": {
        "positive": {"rows": [ai("ai-retention-cleanup", cleaned_at="2026-10-01T00:00:00Z")], "flagged": [0]},
        "negative": {"rows": [ai("ai-tool-presence", install_kind="path", retention_auto_delete=True)], "flagged": []},
    },
    "ai.unknown_tool_candidate": {
        "positive": {"rows": [ai("unknown-ai-tool-candidate", folder_name=".weirdai")], "flagged": [0]},
        "negative": {"rows": [ai("ai-tool-presence", install_kind="path")], "flagged": []},
    },
    "ai.mcp_server_remote": {
        "positive": {"rows": [ai("ai-mcp-server", server="remote", transport="http", remote=True), ai("ai-mcp-server", server="fs", transport="stdio", remote=False)], "flagged": [0]},
        "negative": {"rows": [ai("ai-mcp-server", server="fs", transport="stdio", remote=False)], "flagged": []},
    },
}
