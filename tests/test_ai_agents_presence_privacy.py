"""Lane A path identity masking and provider-level credential-row de-duplication (R7 AI privacy fix)."""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from rapidtriage.artifacts.ai_agents import AiAgentsProvider, load_adapters
from rapidtriage.artifacts.ai_agents.adapters.claude_swap import ClaudeSwapAdapter
from rapidtriage.artifacts.ai_agents.base import (
    AiRow,
    mask_identity_in_path,
    register_adapter,
    registered_adapters,
)
from rapidtriage.artifacts.ai_agents.presence import (
    dedupe_credential_rows,
    mask_row_identity,
)
from rapidtriage.artifacts.ai_agents.redact import mask_emails_in
from tests.fixtures.ai_agents.make_fixtures import build_all

_RAW_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_MASKED_RE = re.compile(r"^u-[0-9a-f]{8}@")
_LANE_A_TYPES = {"ai-tool-presence", "ai-credential-presence", "ai-model-file", "unknown-ai-tool-candidate"}


def _raw_emails(text: str) -> list[str]:
    return [token for token in _RAW_EMAIL_RE.findall(text) if not _MASKED_RE.match(token)]


def _ensure_adapters() -> None:
    load_adapters()
    if not any(adapter.name == "claude_swap" for adapter in registered_adapters()):
        register_adapter(ClaudeSwapAdapter)


class MaskIdentityInPathTests(unittest.TestCase):
    SAMPLES = (
        r"C:\Users\u1\.claude-swap-backup\credentials\.creds-1-alice.secret@corp.example.enc",
        "/Users/dana/.claude-swap-backup/configs/.claude-config-2-Bob.Private@Gmail.Example.json",
        "~/.zzagent/configs/acct-1-alice@example.com.json",
        "/home/x/a@b.io/inner/c.d+tag@sub.example.org/file.txt",
    )

    def test_same_output_as_claude_swap_scheme(self) -> None:
        for sample in self.SAMPLES:
            self.assertEqual(mask_identity_in_path(sample), mask_emails_in(sample), sample)
            self.assertEqual(mask_identity_in_path(Path(sample)), mask_emails_in(str(Path(sample))))

    def test_shape_and_no_raw_local_part(self) -> None:
        masked = mask_identity_in_path("/creds/.creds-1-alice.secret@corp.example.enc")
        self.assertRegex(masked, r"^/creds/u-[0-9a-f]{8}@corp\.example\.enc$")
        self.assertNotIn("alice", masked)
        for sample in self.SAMPLES:
            self.assertEqual(_raw_emails(mask_identity_in_path(sample)), [], sample)

    def test_idempotent_and_separator_bound(self) -> None:
        for sample in self.SAMPLES:
            once = mask_identity_in_path(sample)
            self.assertEqual(mask_identity_in_path(once), once)
            self.assertEqual(once.count("/") + once.count("\\"), sample.count("/") + sample.count("\\"))

    def test_plain_paths_unchanged(self) -> None:
        for plain in ("", "/home/u/.claude/.credentials.json", r"C:\Users\u\f1@v1", "~/node_modules/@scope/pkg"):
            self.assertEqual(mask_identity_in_path(plain), plain)

    def test_mask_row_identity_covers_payload_lists(self) -> None:
        row = AiRow(
            artifact_type="ai-tool-presence",
            tool="claude-swap",
            path="/h/.claude-swap-backup/configs/.c-1-a@x.example.json",
            payload={"matched_paths": ["~/configs/a@x.example.json"], "file_name": "a@x.example.gguf", "count": 3},
        )
        mask_row_identity(row)
        self.assertEqual(_raw_emails(json.dumps([row.path, row.payload])), [])
        self.assertEqual(row.payload["count"], 3)


class CredentialDedupeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _ensure_adapters()
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = build_all(Path(cls._tmp.name))
        # model file and lane A paths that embed an address
        model = cls.root / "Downloads" / "for-eve@corp.example" / "llama.Q4_K_M.gguf"
        model.parent.mkdir(parents=True)
        model.write_text("gguf", encoding="utf-8")
        provider = AiAgentsProvider(os_hint="windows")
        cls.raw = list(provider._all_rows(cls.root))
        cls.rows = list(provider.collect_rows(cls.root))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    @staticmethod
    def _key(row: AiRow) -> tuple[str, str, str]:
        return (row.user, mask_identity_in_path(row.path).replace("\\", "/").lower(), str(row.payload.get("key_name") or ""))

    def test_counts_before_and_after(self) -> None:
        before = [row for row in self.raw if row.artifact_type == "ai-credential-presence"]
        after = [row for row in self.rows if row.artifact_type == "ai-credential-presence"]
        distinct = {self._key(row) for row in before}
        self.assertGreater(len(before), len(distinct))  # both lanes report some files
        self.assertEqual(len(after), len(distinct))
        self.assertEqual(max(Counter(self._key(row) for row in after).values()), 1)  # no file twice
        # only credential rows are merged
        self.assertEqual(len(self.raw) - len(self.rows), len(before) - len(after))

    def test_merged_row_keeps_adapters_and_specific_kind(self) -> None:
        creds = [row for row in self.rows if row.artifact_type == "ai-credential-presence"]
        swap = [row for row in creds if row.path.endswith(".enc")]
        self.assertEqual(len(swap), 1)
        details = swap[0].payload
        self.assertEqual(details["adapters"], ["ai-tool-presence", "claude_swap"])
        self.assertEqual(details["credential_kind"], "encrypted-account-credential")
        self.assertIn("catalog-credential", details["credential_kinds"])
        self.assertEqual(details["merged_row_count"], 2)
        self.assertFalse(details["value_collected"])
        self.assertFalse(details["hash_collected"])
        self.assertEqual(swap[0].path, mask_identity_in_path(swap[0].path))
        self.assertNotIn("alice", swap[0].path)
        codex = next(row for row in creds if row.path.replace("\\", "/").endswith("/.codex/auth.json"))
        self.assertEqual(codex.payload["credential_kind"], "auth-token")
        self.assertEqual(codex.payload["adapters"], ["ai-tool-presence", "codex"])
        self.assertTrue(codex.timestamp)  # lane A's mtime fills the adapter row's empty timestamp

    def test_lane_a_rows_carry_no_raw_email(self) -> None:
        lane_a = [row for row in self.rows if row.artifact_type in _LANE_A_TYPES and "adapter" not in row.payload]
        self.assertTrue(any(row.artifact_type == "ai-model-file" and "u-" in row.path for row in lane_a))
        for row in lane_a:
            record = row.to_record().to_dict()
            self.assertEqual(_raw_emails(json.dumps(record, ensure_ascii=False)), [], row.artifact_type)
        for row in self.rows:
            if row.artifact_type == "ai-credential-presence":
                self.assertEqual(_raw_emails(row.path), [])

    def test_dedupe_passes_other_rows_through(self) -> None:
        rows = [
            AiRow(artifact_type="ai-tool-presence", tool="t", path="/a"),
            AiRow(artifact_type="ai-credential-presence", tool="t", user="u", path="/h/x/auth.json", payload={"credential_kind": "name-pattern"}),
            AiRow(artifact_type="ai-credential-presence", tool="t", user="u", path="/H/X/auth.json", payload={"adapter": "t_adapter", "credential_kind": "auth-file", "key_name": ""}),
            AiRow(artifact_type="ai-credential-presence", tool="t", user="u", path="/h/x/settings.json", payload={"adapter": "t_adapter", "credential_kind": "api-key", "key_name": "apiKey"}),
            AiRow(artifact_type="ai-credential-presence", tool="t", user="other", path="/h/x/auth.json", payload={"credential_kind": "name-pattern"}),
        ]
        out = list(dedupe_credential_rows(rows))
        self.assertEqual(out[0].artifact_type, "ai-tool-presence")
        creds = out[1:]
        self.assertEqual(len(creds), 3)
        self.assertEqual(creds[0].payload["credential_kind"], "auth-file")
        self.assertEqual(creds[0].payload["adapters"], ["ai-tool-presence", "t_adapter"])
        self.assertEqual(creds[1].payload["key_name"], "apiKey")
        self.assertEqual(creds[2].user, "other")


if __name__ == "__main__":
    unittest.main()
