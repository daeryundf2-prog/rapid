from __future__ import annotations

import os
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

from rapidtriage.artifacts import (
    all_providers,
    artifact_collectors,
    get_artifact_collector,
    plugin_search_dirs,
)
from rapidtriage.artifacts.generic import GenericDocumentArtifactProvider
from rapidtriage.core.artifacts import run_artifact_collection

VALID_PLUGIN = '''\
from pathlib import Path
from typing import Iterable

from rapidtriage.core.models import ArtifactRecord


class SampleVaultProvider:
    collector_kind = "sample-vault"
    name = "sample-vault"
    description = "test plugin provider"
    target_platform = "any"

    def supported(self) -> bool:
        return True

    def collect(self, root: Path) -> Iterable[ArtifactRecord]:
        yield ArtifactRecord(
            provider=self.name,
            artifact_type="sample-vault-row",
            path=str(root),
            supported=True,
            details={"parser": "sample-vault", "parser_version": "1"},
        )
'''

NO_CONTRACT_PLUGIN = '''\
class NotAProvider:
    pass
'''

BROKEN_PLUGIN = "this is not valid python !!!\n"

COLLIDING_PLUGIN = '''\
class CollidingProvider:
    collector_kind = "generic-documents"
    name = "colliding"
    description = "collides with a builtin kind"
    target_platform = "any"

    def supported(self):
        return True

    def collect(self, root):
        return iter(())
'''

CRASHING_PLUGIN = '''\
class CrashingProvider:
    collector_kind = "crashing-plugin"
    name = "crashing-plugin"
    description = "raises inside collect"
    target_platform = "any"

    def supported(self):
        return True

    def collect(self, root):
        raise RuntimeError("plugin exploded")
'''


class ProviderPluginDiscoveryTests(unittest.TestCase):
    def test_plugin_search_dirs_includes_env_dirs_and_default(self) -> None:
        with patch.dict(os.environ, {"RAPIDTRIAGE_PLUGIN_DIRS": os.pathsep.join(["/tmp/a", " /tmp/b ", ""])}):
            dirs = plugin_search_dirs()
        self.assertIn(Path("/tmp/a"), dirs)
        self.assertIn(Path("/tmp/b"), dirs)
        self.assertIn(Path.home() / ".rapidtriage" / "plugins", dirs)

    def test_valid_plugin_registers_and_collects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plugin_dir = Path(tmp_dir) / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "sample_vault_provider.py").write_text(VALID_PLUGIN, encoding="utf-8")
            with patch.dict(os.environ, {"RAPIDTRIAGE_PLUGIN_DIRS": str(plugin_dir)}):
                collectors = artifact_collectors()
                provider = get_artifact_collector("sample-vault")

        self.assertIn("sample-vault", collectors)
        self.assertEqual(provider.name, "sample-vault")

    def test_valid_plugin_appears_in_supported_kinds_listing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plugin_dir = Path(tmp_dir) / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "sample_vault_provider.py").write_text(VALID_PLUGIN, encoding="utf-8")
            with patch.dict(os.environ, {"RAPIDTRIAGE_PLUGIN_DIRS": str(plugin_dir)}):
                kinds = sorted(artifact_collectors())
                with self.assertRaises(KeyError) as raised:
                    get_artifact_collector("missing-kind")

        self.assertIn("sample-vault", kinds)
        self.assertIn("sample-vault", str(raised.exception))

    def test_plugin_collect_runs_through_collection_harness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plugin_dir = Path(tmp_dir) / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "sample_vault_provider.py").write_text(VALID_PLUGIN, encoding="utf-8")
            with patch.dict(os.environ, {"RAPIDTRIAGE_PLUGIN_DIRS": str(plugin_dir)}):
                payload = run_artifact_collection(Path(tmp_dir), kind="sample-vault")

        self.assertEqual(payload["kind"], "sample-vault")
        self.assertEqual(payload["summary"]["collection_status"], "completed")
        self.assertEqual(payload["summary"]["artifact_count"], 1)
        self.assertEqual(payload["artifacts"][0]["artifact_type"], "sample-vault-row")

    def test_import_error_plugin_is_skipped_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plugin_dir = Path(tmp_dir) / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "broken_provider.py").write_text(BROKEN_PLUGIN, encoding="utf-8")
            with patch.dict(os.environ, {"RAPIDTRIAGE_PLUGIN_DIRS": str(plugin_dir)}):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    collectors = artifact_collectors()

        self.assertTrue(any("import failed" in str(item.message) for item in caught))
        self.assertNotIn("broken", collectors)
        self.assertIn("generic-documents", collectors)

    def test_plugin_without_contract_is_skipped_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plugin_dir = Path(tmp_dir) / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "notaprovider_provider.py").write_text(NO_CONTRACT_PLUGIN, encoding="utf-8")
            with patch.dict(os.environ, {"RAPIDTRIAGE_PLUGIN_DIRS": str(plugin_dir)}):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    all_providers()

        self.assertTrue(any("provider contract" in str(item.message) for item in caught))

    def test_plugin_cannot_shadow_builtin_collector_kind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plugin_dir = Path(tmp_dir) / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "colliding_provider.py").write_text(COLLIDING_PLUGIN, encoding="utf-8")
            with patch.dict(os.environ, {"RAPIDTRIAGE_PLUGIN_DIRS": str(plugin_dir)}):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    collectors = artifact_collectors()
                provider = collectors["generic-documents"]

        self.assertTrue(any("already registered" in str(item.message) for item in caught))
        self.assertIsInstance(provider, GenericDocumentArtifactProvider)

    def test_crashing_plugin_collect_is_failed_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plugin_dir = Path(tmp_dir) / "plugins"
            plugin_dir.mkdir()
            (plugin_dir / "crashing_provider.py").write_text(CRASHING_PLUGIN, encoding="utf-8")
            with patch.dict(os.environ, {"RAPIDTRIAGE_PLUGIN_DIRS": str(plugin_dir)}):
                payload = run_artifact_collection(Path(tmp_dir), kind="crashing-plugin")

        self.assertEqual(payload["summary"]["collection_status"], "failed-isolated")
        self.assertEqual(payload["summary"]["parser_error_count"], 1)
        self.assertEqual(payload["parser_errors"][0]["error_type"], "RuntimeError")
        self.assertEqual(payload["artifacts"], [])


if __name__ == "__main__":
    unittest.main()
