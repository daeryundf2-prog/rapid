from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SIGN_SCRIPT = REPO_ROOT / "scripts" / "sign-release.py"
SBOM_SCRIPT = REPO_ROOT / "scripts" / "generate-sbom.py"
SIGNING_ENV = {"RAPIDTRIAGE_SIGNING_KEY": "test-signing-key"}
MANIFEST_NAME = "release-signature-manifest.json"


def _run(script: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged_env = dict(os.environ)
    merged_env.pop("RAPIDTRIAGE_SIGNING_KEY", None)
    if env:
        merged_env.update(env)
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        encoding="utf-8",
        text=True,
        env=merged_env,
    )


def _release_dir(tmp_dir: str) -> Path:
    release_dir = Path(tmp_dir) / "release"
    release_dir.mkdir()
    (release_dir / "rapidtriage-portable.zip").write_bytes(b"portable-payload")
    (release_dir / "SHA256SUMS").write_text("placeholder  SHA256SUMS\n", encoding="utf-8")
    return release_dir


class ReleaseSigningTests(unittest.TestCase):
    def test_manifest_lists_artifact_sha256s(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            release_dir = _release_dir(tmp_dir)
            result = _run(SIGN_SCRIPT, "--release-dir", str(release_dir))

            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((release_dir / MANIFEST_NAME).read_text(encoding="utf-8"))

        expected = hashlib.sha256(b"portable-payload").hexdigest()
        self.assertEqual(manifest["profile_version"], "release-signature-manifest-v1")
        self.assertEqual(manifest["files"]["rapidtriage-portable.zip"]["sha256"], expected)
        self.assertIn("SHA256SUMS", manifest["files"])
        self.assertNotIn(MANIFEST_NAME, manifest["files"])
        self.assertEqual(manifest["file_count"], 2)

    def test_unsigned_mode_writes_manifest_with_note(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            release_dir = _release_dir(tmp_dir)
            result = _run(SIGN_SCRIPT, "--release-dir", str(release_dir))

            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((release_dir / MANIFEST_NAME).read_text(encoding="utf-8"))

        self.assertFalse(manifest["signed"])
        self.assertIsNone(manifest["signature"])
        self.assertIn("RAPIDTRIAGE_SIGNING_KEY", manifest["note"])

    def test_signed_manifest_round_trip_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            release_dir = _release_dir(tmp_dir)
            signed = _run(SIGN_SCRIPT, "--release-dir", str(release_dir), env=SIGNING_ENV)
            self.assertEqual(signed.returncode, 0, signed.stderr)
            manifest = json.loads((release_dir / MANIFEST_NAME).read_text(encoding="utf-8"))

            self.assertTrue(manifest["signed"])
            signature = manifest["signature"]
            self.assertEqual(signature["algorithm"], "hmac-sha256")

            canonical = json.dumps(
                {"files": manifest["files"]}, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            expected_sig = hmac.new(b"test-signing-key", canonical, hashlib.sha256).hexdigest()
            self.assertEqual(signature["value"], expected_sig)

            verified = _run(SIGN_SCRIPT, "--release-dir", str(release_dir), "--verify", "--json", env=SIGNING_ENV)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            payload = json.loads(verified.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["signature_status"], "verified")

    def test_verify_detects_tampered_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            release_dir = _release_dir(tmp_dir)
            signed = _run(SIGN_SCRIPT, "--release-dir", str(release_dir), env=SIGNING_ENV)
            self.assertEqual(signed.returncode, 0, signed.stderr)
            (release_dir / "rapidtriage-portable.zip").write_bytes(b"tampered")

            verified = _run(SIGN_SCRIPT, "--release-dir", str(release_dir), "--verify", env=SIGNING_ENV)

        self.assertEqual(verified.returncode, 1)
        self.assertIn("Checksum mismatch", verified.stderr)

    def test_verify_rejects_wrong_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            release_dir = _release_dir(tmp_dir)
            signed = _run(SIGN_SCRIPT, "--release-dir", str(release_dir), env=SIGNING_ENV)
            self.assertEqual(signed.returncode, 0, signed.stderr)

            verified = _run(
                SIGN_SCRIPT,
                "--release-dir",
                str(release_dir),
                "--verify",
                env={"RAPIDTRIAGE_SIGNING_KEY": "wrong-key"},
            )

        self.assertEqual(verified.returncode, 1)
        self.assertIn("signature mismatch", verified.stderr.lower())

    def test_require_signed_fails_on_unsigned_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            release_dir = _release_dir(tmp_dir)
            unsigned = _run(SIGN_SCRIPT, "--release-dir", str(release_dir))
            self.assertEqual(unsigned.returncode, 0, unsigned.stderr)

            verified = _run(
                SIGN_SCRIPT, "--release-dir", str(release_dir), "--verify", "--require-signed"
            )
            self.assertEqual(verified.returncode, 1)

            verified_ok = _run(SIGN_SCRIPT, "--release-dir", str(release_dir), "--verify")
            self.assertEqual(verified_ok.returncode, 0, verified_ok.stderr)


class GenerateSbomTests(unittest.TestCase):
    def test_sbom_is_cycloneDX_shaped(self) -> None:
        result = _run(SBOM_SCRIPT, "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        sbom = json.loads(result.stdout)

        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertEqual(sbom["metadata"]["component"]["name"], "rapidtriage")
        self.assertTrue(sbom["serialNumber"].startswith("urn:uuid:"))
        components = sbom["components"]
        self.assertGreater(len(components), 0)
        for component in components:
            self.assertEqual(component["type"], "library")
            self.assertTrue(component["name"])
            self.assertTrue(component["version"])
            self.assertTrue(str(component["purl"]).startswith("pkg:pypi/"))
        names = {str(c["name"]).lower() for c in components}
        self.assertIn("pip", names)

    def test_sbom_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "sbom.cyclonedx.json"
            result = _run(SBOM_SCRIPT, "--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            sbom = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        depends_on = sbom["dependencies"][0]["dependsOn"]
        self.assertEqual(len(depends_on), len(sbom["components"]))


class BuildReleaseWiringTests(unittest.TestCase):
    def test_build_release_emits_sbom_and_signature_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "release"
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/build-release.py",
                    "--output-dir",
                    str(output_dir),
                    "--skip-build",
                ],
                cwd=REPO_ROOT,
                check=False,
                capture_output=True,
                encoding="utf-8",
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            sbom_path = output_dir / "sbom.cyclonedx.json"
            manifest_path = output_dir / MANIFEST_NAME
            self.assertTrue(sbom_path.is_file())
            self.assertTrue(manifest_path.is_file())

            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            checksums = (output_dir / "SHA256SUMS").read_text(encoding="utf-8")

        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertIn("sbom.cyclonedx.json", checksums)
        self.assertIn("SHA256SUMS", manifest["files"])
        self.assertNotIn(MANIFEST_NAME, manifest["files"])
        self.assertIn("signed", manifest)


if __name__ == "__main__":
    unittest.main()
