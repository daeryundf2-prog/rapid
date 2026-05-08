from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from rapidtriage.cli import build_parser, main
from rapidtriage.core.cloud_api import (
    build_cloud_api_trusted_diff,
    build_cloud_credential_trusted_diff,
    cloud_api_core_accuracy_gates,
    cloud_credential_core_accuracy_gates,
)


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
                                "provider": "google",
                                "account": "alice@example.com",
                                "scopes": ["https://www.googleapis.com/auth/userinfo.profile"],
                                "legal_authority": "unit-test-authority",
                                "requests": [
                                    {
                                        "name": "google-activity",
                                        "service": "google",
                                        "url": f"{server.url}/activity",
                                        "bearer_token_env": "RAPIDTRIAGE_TEST_TOKEN",
                                        "retry": {"max_attempts": 2, "backoff_seconds": 0},
                                        "pagination": {
                                            "mode": "next_link_field",
                                            "max_pages": 2,
                                            "next_link_field": "nextPageToken",
                                            "delta_token_field": "syncToken",
                                        },
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
                self.assertTrue(payload["summary"]["provider_scope_profile_present"])
                self.assertTrue(payload["summary"]["provider_scope_inventory_captured"])
                self.assertIn("#40", payload["cloud_api_report_grade_assessment"]["commercial_gap_ids"])
                self.assertEqual(payload["forensic_review"]["gap_id"], "#40")
                scope_profile = payload["cloud_api_provider_scope_profile"]
                self.assertEqual(scope_profile["profile_version"], "cloud-api-provider-scope-v1")
                self.assertEqual(scope_profile["provider"], "google")
                self.assertTrue(scope_profile["scope_inventory_captured"])
                self.assertTrue(scope_profile["legal_authority_record_present"])
                api_uplift = payload["commercial_uplift_evidence"]
                self.assertEqual(api_uplift["batch_id"], "commercial-uplift-036-040")
                self.assertEqual(api_uplift["item_numbers"], [40])
                self.assertIn("manifest-validated", api_uplift["passed_validation_matrix_ids"])
                self.assertIn("provider-oauth-scope-capture", api_uplift["failed_validation_matrix_ids"])
                self.assertEqual(
                    api_uplift["reportability_decision"]["decision"],
                    "do-not-report-cloud-api-collection-as-provider-complete",
                )
                self.assertEqual(
                    api_uplift["reportability_decision"]["allowed_use"],
                    "cloud-api-response-triage-pivot",
                )
                self.assertIn(
                    "provider-scope-inventory-not-captured",
                    api_uplift["reportability_decision"]["blockers"],
                )
                self.assertIn(
                    "cloud-api-provider-response-diff-required",
                    api_uplift["reportability_decision"]["blockers"],
                )
                functional_profile = payload["functional_priority_profile"]
                self.assertEqual(functional_profile["item_number"], 56)
                self.assertEqual(functional_profile["batch_id"], "commercial-uplift-056-060")
                self.assertTrue(functional_profile["implemented_controls"]["manifest_driven_https_requests"])
                self.assertTrue(functional_profile["implemented_controls"]["credential_redaction"])
                self.assertTrue(functional_profile["implemented_controls"]["cloud_api_acquisition_manifest_emitted"])
                self.assertIn("cloud-api-acquisition-manifest-emitted", functional_profile["passed_validation_check_ids"])
                acquisition_manifest = payload["cloud_api_acquisition_manifest"]
                self.assertEqual(acquisition_manifest["manifest_version"], "cloud-api-acquisition-manifest-v1")
                self.assertEqual(acquisition_manifest["item_number"], 56)
                self.assertEqual(acquisition_manifest["request_count"], 1)
                self.assertEqual(acquisition_manifest["collected_count"], 1)
                self.assertEqual(acquisition_manifest["credential_boundary"]["credential_storage"], "environment-variable-only")
                self.assertTrue(acquisition_manifest["credential_boundary"]["headers_redacted"])
                self.assertFalse(acquisition_manifest["credential_boundary"]["tokens_written_to_output"])
                self.assertEqual(acquisition_manifest["request_locators"][0]["service"], "google")
                self.assertEqual(len(acquisition_manifest["manifest_sha256"]), 64)
                self.assertEqual(
                    payload["summary"]["cloud_api_acquisition_manifest_hash"],
                    acquisition_manifest["manifest_sha256"],
                )
                self.assertEqual(
                    functional_profile["implemented_controls"]["cloud_api_acquisition_manifest_hash"],
                    acquisition_manifest["manifest_sha256"],
                )
                self.assertEqual(
                    payload["cloud_api_collection_strategy_profile"]["selected_track"],
                    "manifest-driven-bounded-api-collection",
                )
                self.assertEqual(payload["cloud_api_collection_strategy_profile"]["services"], ["google"])
                self.assertTrue(payload["cloud_api_collection_strategy_profile"]["request_retry_policy_declared"])
                self.assertTrue(payload["cloud_api_collection_strategy_profile"]["pagination_policy_declared"])
                self.assertTrue(
                    payload["cloud_api_collection_strategy_profile"]["provider_scope_profile"]["scope_inventory_captured"]
                )
                self.assertIn(
                    "provider-oauth-device-flow-not-implemented",
                    functional_profile["failed_validation_check_ids"],
                )
                self.assertTrue(functional_profile["implemented_controls"]["provider_scope_manifest_profile"])
                self.assertTrue(functional_profile["implemented_controls"]["provider_scope_inventory_captured"])
                api_gate = payload["core_accuracy_gates"][0]
                self.assertEqual(api_gate["gap_id"], "#40")
                self.assertIn("manifest request validation", api_gate["satisfied_checks"])
                self.assertIn("credential redaction", api_gate["satisfied_checks"])
                self.assertIn("credential strategy profile", api_gate["satisfied_checks"])
                self.assertIn("request acquisition profile", api_gate["satisfied_checks"])
                self.assertIn("response hash/provenance", api_gate["satisfied_checks"])
                self.assertIn("cloud API acquisition manifest", api_gate["satisfied_checks"])
                self.assertIn("pagination/backoff limitation warning", api_gate["satisfied_checks"])
                self.assertIn("provider OAuth/scope/legal warning", api_gate["satisfied_checks"])
                self.assertNotIn("trusted cloud API/provider response diff pass", api_gate["satisfied_checks"])
                self.assertIn("#41", payload["credential_handling"]["commercial_gap_ids"])
                self.assertIn("#41", payload["credential_handling"]["credential_security_assessment"]["commercial_gap_ids"])
                self.assertEqual(payload["credential_handling"]["forensic_review"]["gap_id"], "#41")
                credential_uplift = payload["credential_handling"]["commercial_uplift_evidence"]
                self.assertEqual(credential_uplift["item_numbers"], [41])
                self.assertIn("tokens_not_written", credential_uplift["passed_validation_check_ids"])
                self.assertIn("secure_token_vault", credential_uplift["failed_validation_check_ids"])
                self.assertIn("controlled_reveal_disabled", credential_uplift["passed_validation_check_ids"])
                self.assertIn(
                    "credential_authority_profile_present",
                    credential_uplift["passed_validation_check_ids"],
                )
                self.assertTrue(credential_uplift["large_data_controls"]["credential_authority_profile_present"])
                self.assertTrue(
                    credential_uplift["large_data_controls"][
                        "credential_authority_profile_linked_to_provider_scope"
                    ]
                )
                self.assertEqual(
                    credential_uplift["reportability_decision"]["decision"],
                    "do-not-report-cloud-credential-handling-as-enterprise-vaulted",
                )
                self.assertEqual(
                    credential_uplift["reportability_decision"]["allowed_use"],
                    "redacted-credential-handling-triage-pivot",
                )
                self.assertIn(
                    "check:secure_token_vault",
                    credential_uplift["reportability_decision"]["blockers"],
                )
                self.assertFalse(credential_uplift["reportability_decision"]["tokens_written_to_output"])
                credential_gate = payload["credential_handling"]["core_accuracy_gates"][0]
                self.assertEqual(credential_gate["gap_id"], "#41")
                self.assertIn("token value redaction", credential_gate["satisfied_checks"])
                self.assertIn("environment or vault storage boundary", credential_gate["satisfied_checks"])
                self.assertIn("credential strategy profile", credential_gate["satisfied_checks"])
                self.assertIn("scope and consent capture warning", credential_gate["satisfied_checks"])
                self.assertIn("rotation and revocation audit warning", credential_gate["satisfied_checks"])
                self.assertIn("legal authority warning", credential_gate["satisfied_checks"])
                self.assertNotIn("trusted credential authority/audit diff pass", credential_gate["satisfied_checks"])
                self.assertIn("credential authority profile", credential_gate["satisfied_checks"])
                self.assertIn("controlled reveal disabled by default", credential_gate["satisfied_checks"])
                self.assertFalse(payload["cloud_api_native_capabilities"]["provider_specific_oauth_flow"])
                self.assertFalse(payload["credential_handling"]["tokens_written_to_output"])
                self.assertFalse(payload["credential_handling"]["secure_token_vault_integrated"])
                self.assertFalse(payload["credential_handling"]["raw_secret_reveal_allowed"])
                self.assertEqual(payload["credential_handling"]["controlled_reveal_policy"], "disabled-by-default")
                self.assertEqual(payload["credential_handling"]["scope_capture_status"], "not-captured")
                self.assertEqual(payload["credential_handling"]["credential_storage"], "environment-variable-only")
                self.assertEqual(
                    payload["credential_handling"]["credential_strategy_profile"]["selected_track"],
                    "environment-token-redaction-with-external-authority-audit",
                )
                self.assertEqual(
                    credential_uplift["credential_strategy_profile"]["selected_track"],
                    "environment-token-redaction-with-external-authority-audit",
                )
                authority_profile = payload["credential_handling"]["credential_authority_profile"]
                self.assertEqual(authority_profile["profile_version"], "cloud-credential-authority-v1")
                self.assertEqual(authority_profile["provider"], "google")
                self.assertTrue(authority_profile["provider_scope_profile_linked"])
                self.assertTrue(authority_profile["scope_inventory_captured"])
                self.assertTrue(authority_profile["legal_authority_record_present"])
                self.assertEqual(authority_profile["controlled_reveal_policy"], "disabled-by-default")
                self.assertFalse(authority_profile["raw_secret_reveal_allowed"])
                self.assertFalse(authority_profile["tokens_written_to_output"])
                self.assertEqual(authority_profile["request_sensitive_header_names"], ["Authorization"])
                self.assertEqual(authority_profile["vault_integration_status"], "not-integrated")
                self.assertEqual(authority_profile["token_rotation_audit_status"], "not-captured")
                self.assertEqual(payload["requests"][0]["request_headers"]["Authorization"], "<REDACTED>")
                request_profile = payload["requests"][0]["request_acquisition_profile"]
                self.assertEqual(request_profile["profile_version"], "cloud-api-request-acquisition-v1")
                self.assertEqual(request_profile["retry_max_attempts"], 2)
                self.assertEqual(request_profile["pagination_mode"], "next_link_field")
                self.assertEqual(request_profile["pagination_execution_status"], "declared-not-executed")
                self.assertEqual(payload["requests"][0]["attempt_count"], 1)
                self.assertEqual(payload["requests"][0]["credential_handling"]["sensitive_header_names"], ["Authorization"])
                self.assertTrue(payload["requests"][0]["credential_handling"]["sensitive_values_redacted"])
                self.assertFalse(payload["requests"][0]["credential_handling"]["tokens_written_to_output"])
                self.assertIn("#41", payload["requests"][0]["credential_handling"]["commercial_gap_ids"])
                self.assertFalse(payload["requests"][0]["credential_handling"]["secure_token_vault_integrated"])
                self.assertFalse(payload["requests"][0]["credential_handling"]["raw_secret_reveal_allowed"])
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
                self.assertEqual(payload["credential_handling"]["core_accuracy_gates"][0]["gap_id"], "#41")
                self.assertTrue(payload["credential_handling"]["headers_redacted"])
                self.assertTrue(payload["requests"][0]["credential_handling"]["sensitive_values_redacted"])
                self.assertEqual(server.handler_class.request_count, 0)
                self.assertEqual(payload["cloud_api_acquisition_manifest"]["dry_run"], True)
                self.assertEqual(payload["cloud_api_acquisition_manifest"]["request_locator_count"], 1)

    def test_cloud_credential_trusted_diff_controls_authority_gate(self) -> None:
        rapid = [
            {
                "bearer_token_env": "RAPIDTRIAGE_TEST_TOKEN",
                "credential_storage": "environment-variable-only",
                "scope": "https://graph.microsoft.com/.default",
                "consent_record_id": "consent-1",
                "legal_authority_id": "auth-1",
            }
        ]
        diff = build_cloud_credential_trusted_diff(
            rapid,
            [dict(rapid[0])],
            trusted_tool="provider-oauth-consent-record",
        )
        self.assertEqual(diff["status"], "pass")
        gate = cloud_credential_core_accuracy_gates(
            manifest_path=Path(__file__),
            credential_handling={
                "headers_redacted": True,
                "tokens_written_to_output": False,
                "credential_storage": "environment-variable-only",
                "bearer_token_env": "RAPIDTRIAGE_TEST_TOKEN",
                "legal_warning": "authorized only",
                "audit_required": True,
                "credential_trusted_diff": diff,
            },
            requests=[],
        )[0]
        self.assertIn("trusted credential authority/audit diff pass", gate["satisfied_checks"])

        mismatch = build_cloud_credential_trusted_diff(
            rapid,
            [{**rapid[0], "legal_authority_id": "changed"}],
            trusted_tool="provider-oauth-consent-record",
        )
        self.assertEqual(mismatch["status"], "fail")
        self.assertEqual(mismatch["blocker_id"], "cloud-credential-authority-audit-diff-required")

    def test_cloud_api_trusted_diff_controls_provider_accuracy_gate(self) -> None:
        rapid = [
            {
                "name": "google-activity",
                "service": "google",
                "method": "GET",
                "url_sha256": "url-hash",
                "status": 200,
                "response_sha256": "response-hash",
                "response_size": 42,
            }
        ]
        diff = build_cloud_api_trusted_diff(
            rapid,
            [dict(rapid[0])],
            trusted_tool="google-provider-api",
        )

        self.assertEqual(diff["status"], "pass")
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"requests": []}), encoding="utf-8")
            gate = cloud_api_core_accuracy_gates(
                manifest_path=manifest,
                output_dir=root / "out",
                summary={"request_count": 1, "collected_count": 1, "cloud_api_trusted_diff": diff},
                credential_handling={
                    "headers_redacted": True,
                    "tokens_written_to_output": False,
                    "legal_warning": "authorized scope required",
                },
                requests=rapid,
            )[0]
        self.assertIn("trusted cloud API/provider response diff pass", gate["satisfied_checks"])

        mismatch = build_cloud_api_trusted_diff(
            rapid,
            [{**rapid[0], "response_sha256": "changed"}],
            trusted_tool="google-provider-api",
        )
        self.assertEqual(mismatch["status"], "fail")
        self.assertEqual(mismatch["blocker_id"], "cloud-api-provider-response-diff-required")
        self.assertEqual(mismatch["mismatched_fields"][0]["field"], "response_sha256")


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
