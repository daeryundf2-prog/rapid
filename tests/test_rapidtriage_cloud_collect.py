from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from rapidtriage.cli import build_parser, main


class RapidTriageCloudCollectTests(unittest.TestCase):
    def test_parser_exposes_cloud_collect_command(self) -> None:
        parser = build_parser()
        commands = parser._subparsers._group_actions[0].choices

        self.assertIn("cloud-collect", commands)
        self.assertIn("--bearer-token-env", commands["cloud-collect"].format_help())

    def test_cloud_collect_saves_redacted_response_manifest_and_importable_json(self) -> None:
        with cloud_test_server() as server:
            with tempfile.TemporaryDirectory() as tmp_dir:
                root = Path(tmp_dir)
                manifest = root / "cloud-api-manifest.json"
                output_dir = root / "cloud-api-raw"
                os.environ["RAPIDTRIAGE_TEST_TOKEN"] = "secret-token"
                try:
                    manifest.write_text(
                        json.dumps(
                            {
                                "requests": [
                                    {
                                        "name": "google-activity",
                                        "service": "google",
                                        "url": f"{server.url}/activity",
                                        "bearer_token_env": "RAPIDTRIAGE_TEST_TOKEN",
                                    }
                                ]
                            }
                        ),
                        encoding="utf-8",
                    )

                    exit_code = main(["cloud-collect", str(manifest), "--output-dir", str(output_dir)])
                finally:
                    os.environ.pop("RAPIDTRIAGE_TEST_TOKEN", None)

                self.assertEqual(exit_code, 0)
                payload_path = output_dir / "rapidtriage-cloud-collect.json"
                payload = json.loads(payload_path.read_text(encoding="utf-8"))
                self.assertEqual(payload["summary"]["collected_count"], 1)
                self.assertIn("#40", payload["cloud_api_report_grade_assessment"]["commercial_gap_ids"])
                self.assertEqual(payload["forensic_review"]["gap_id"], "#40")
                api_gate = payload["core_accuracy_gates"][0]
                self.assertEqual(api_gate["gap_id"], "#40")
                self.assertIn("manifest request validation", api_gate["satisfied_checks"])
                self.assertIn("credential redaction", api_gate["satisfied_checks"])
                self.assertIn("response hash/provenance", api_gate["satisfied_checks"])
                self.assertIn("pagination/backoff limitation warning", api_gate["satisfied_checks"])
                self.assertIn("provider OAuth/scope/legal warning", api_gate["satisfied_checks"])
                self.assertIn("#41", payload["credential_handling"]["commercial_gap_ids"])
                self.assertIn("#41", payload["credential_handling"]["credential_security_assessment"]["commercial_gap_ids"])
                self.assertEqual(payload["credential_handling"]["forensic_review"]["gap_id"], "#41")
                self.assertFalse(payload["cloud_api_native_capabilities"]["provider_specific_oauth_flow"])
                self.assertFalse(payload["credential_handling"]["tokens_written_to_output"])
                self.assertFalse(payload["credential_handling"]["secure_token_vault_integrated"])
                self.assertEqual(payload["credential_handling"]["scope_capture_status"], "not-captured")
                self.assertEqual(payload["credential_handling"]["credential_storage"], "environment-variable-only")
                self.assertEqual(payload["requests"][0]["request_headers"]["Authorization"], "<REDACTED>")
                self.assertEqual(payload["requests"][0]["credential_handling"]["sensitive_header_names"], ["Authorization"])
                self.assertTrue(payload["requests"][0]["credential_handling"]["sensitive_values_redacted"])
                self.assertFalse(payload["requests"][0]["credential_handling"]["tokens_written_to_output"])
                self.assertIn("#41", payload["requests"][0]["credential_handling"]["commercial_gap_ids"])
                self.assertFalse(payload["requests"][0]["credential_handling"]["secure_token_vault_integrated"])
                self.assertNotIn("secret-token", payload_path.read_text(encoding="utf-8"))
                response_path = Path(payload["requests"][0]["response_path"])
                self.assertTrue(response_path.exists())
                self.assertIn("response_sha256", payload["requests"][0])
                self.assertEqual(server.handler_class.last_authorization, "Bearer secret-token")

                cloud_output = root / "cloud-artifacts.json"
                self.assertEqual(
                    main(["artifacts", str(output_dir / "responses"), "--kind", "cloud-export", "--output", str(cloud_output)]),
                    0,
                )
                cloud_payload = json.loads(cloud_output.read_text(encoding="utf-8"))
                self.assertEqual(cloud_payload["summary"]["artifact_type_counts"]["cloud-activity"], 1)

    def test_cloud_collect_dry_run_does_not_call_endpoint(self) -> None:
        with cloud_test_server() as server:
            with tempfile.TemporaryDirectory() as tmp_dir:
                root = Path(tmp_dir)
                manifest = root / "manifest.json"
                output_dir = root / "dry"
                manifest.write_text(
                    json.dumps({"requests": [{"name": "dry", "url": f"{server.url}/activity"}]}),
                    encoding="utf-8",
                )

                exit_code = main(["cloud-collect", str(manifest), "--output-dir", str(output_dir), "--dry-run"])

                self.assertEqual(exit_code, 0)
                payload = json.loads((output_dir / "rapidtriage-cloud-collect.dry-run.json").read_text(encoding="utf-8"))
                self.assertTrue(payload["summary"]["dry_run"])
                self.assertEqual(payload["summary"]["validated_count"], 1)
                self.assertEqual(payload["summary"]["collected_count"], 0)
                self.assertIn("#40", payload["commercial_gap_ids"])
                self.assertIn("#41", payload["credential_handling"]["commercial_gap_ids"])
                self.assertTrue(payload["credential_handling"]["headers_redacted"])
                self.assertTrue(payload["requests"][0]["credential_handling"]["sensitive_values_redacted"])
                self.assertEqual(server.handler_class.request_count, 0)


class CloudApiHandler(BaseHTTPRequestHandler):
    request_count = 0
    last_authorization = ""

    def do_GET(self) -> None:
        type(self).request_count += 1
        type(self).last_authorization = self.headers.get("Authorization", "")
        payload = [
            {
                "time": "2026-04-26T01:02:03Z",
                "title": "Searched for cloud API collection",
                "products": ["Search"],
            }
        ]
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class CloudTestServer:
    def __enter__(self) -> "CloudTestServer":
        self.handler_class = type("PerTestCloudApiHandler", (CloudApiHandler,), {"request_count": 0, "last_authorization": ""})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler_class)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}"
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def cloud_test_server() -> CloudTestServer:
    return CloudTestServer()


if __name__ == "__main__":
    unittest.main()
