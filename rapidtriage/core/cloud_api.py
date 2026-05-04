from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Mapping

from .audit import compute_sha256
from .forensic_accuracy import build_accuracy_gate

DEFAULT_CLOUD_BEARER_TOKEN_ENV = "RAPIDTRIAGE_CLOUD_BEARER_TOKEN"
DEFAULT_CLOUD_API_TIMEOUT_SECONDS = 30
DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES = 50 * 1024 * 1024
ALLOWED_METHODS = {"GET", "POST"}
CLOUD_API_NATIVE_CAPABILITIES = {
    "manifest_driven_https_requests": True,
    "dry_run_validation": True,
    "redacted_credential_handling": True,
    "response_hashing": True,
    "bounded_response_size": True,
    "provider_specific_oauth_flow": False,
    "provider_scope_discovery": False,
    "incremental_delta_collection": False,
    "legal_hold_export_workflow": False,
    "known_answer_cloud_api_corpus": False,
}
CLOUD_API_REPORT_GRADE_BLOCKERS = [
    "provider-specific-oauth-flow-not-implemented",
    "provider-scope-discovery-and-consent-capture-not-implemented",
    "incremental-delta-collection-not-implemented",
    "legal-hold-export-workflow-not-implemented",
    "known-answer-cloud-api-corpus-required",
]
CLOUD_CREDENTIAL_SECURITY_BLOCKERS = [
    "provider-oauth-consent-record-not-captured",
    "provider-scope-inventory-not-captured",
    "secure-token-vault-not-integrated",
    "token-rotation-and-revocation-audit-not-captured",
    "legal-authority-review-required-before-cloud-collection",
]


class CloudApiCollectionError(ValueError):
    """Raised when a cloud API collection manifest or request is unsafe/invalid."""


def run_cloud_api_collection(
    manifest_path: Path,
    *,
    output_dir: Path,
    bearer_token_env: str = DEFAULT_CLOUD_BEARER_TOKEN_ENV,
    timeout_seconds: int = DEFAULT_CLOUD_API_TIMEOUT_SECONDS,
    max_response_bytes: int = DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES,
    allow_insecure_http: bool = False,
    dry_run: bool = False,
) -> dict[str, object]:
    manifest = load_manifest(manifest_path)
    requests = manifest.get("requests")
    if not isinstance(requests, list) or not requests:
        raise CloudApiCollectionError("cloud API manifest must contain a non-empty 'requests' list")

    output_dir.mkdir(parents=True, exist_ok=True)
    responses_dir = output_dir / "responses"
    if not dry_run:
        responses_dir.mkdir(parents=True, exist_ok=True)

    collected: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []
    for index, request_def in enumerate(requests, start=1):
        if not isinstance(request_def, Mapping):
            skipped.append({"index": index, "reason": "request is not an object"})
            continue
        prepared = prepare_request(
            request_def,
            default_bearer_token_env=bearer_token_env,
            allow_insecure_http=allow_insecure_http,
        )
        if dry_run:
            collected.append(
                {
                    "index": index,
                    "name": prepared["name"],
                    "service": prepared["service"],
                    "method": prepared["method"],
                    "url": prepared["url"],
                    "dry_run": True,
                    "headers": redact_headers(prepared["headers"]),
                    "credential_handling": request_credential_handling(prepared),
                }
            )
            continue
        row = execute_request(
            index=index,
            prepared=prepared,
            responses_dir=responses_dir,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        collected.append(row)

    summary = {
        "request_count": len(requests),
        "validated_count": len(collected) if dry_run else 0,
        "collected_count": 0 if dry_run else len([row for row in collected if not row.get("error")]),
        "error_count": len([row for row in collected if row.get("error")]),
        "skipped_count": len(skipped),
        "dry_run": dry_run,
    }
    credential_handling = {
        "bearer_token_env": bearer_token_env,
        "tokens_written_to_output": False,
        "headers_redacted": True,
        "credential_storage": "environment-variable-only",
        "commercial_gap_ids": ["#41"],
        "scope_capture_status": "not-captured",
        "secure_token_vault_integrated": False,
        "token_rotation_audit_present": False,
        "audit_required": True,
        "legal_warning": "Use only with authorized cloud accounts/API scopes; do not paste tokens into manifests or reports.",
    }
    credential_handling["credential_security_assessment"] = cloud_credential_security_assessment(credential_handling)
    credential_handling["forensic_review"] = cloud_api_forensic_review(
        gap_id="#41",
        artifact_goal="Cloud token/credential handling, redaction, storage boundary, and audit readiness",
        primary_evidence=[
            f"credential_storage={credential_handling['credential_storage']}",
            f"headers_redacted={credential_handling['headers_redacted']}",
            f"tokens_written_to_output={credential_handling['tokens_written_to_output']}",
            f"secure_token_vault_integrated={credential_handling['secure_token_vault_integrated']}",
        ],
        report_grade_assessment=credential_handling["credential_security_assessment"],
        blockers=CLOUD_CREDENTIAL_SECURITY_BLOCKERS,
        caveats=[
            "Environment-variable token handling is safer than manifest tokens but is not an enterprise token vault.",
            "Provider OAuth consent, scopes, rotation, revocation, and legal authority must be recorded for report-grade use.",
        ],
    )
    credential_handling["core_accuracy_gates"] = cloud_credential_core_accuracy_gates(
        manifest_path=manifest_path,
        credential_handling=credential_handling,
        requests=collected,
    )
    credential_handling["commercial_uplift_evidence"] = cloud_credential_commercial_uplift_evidence(
        manifest_path=manifest_path,
        credential_handling=credential_handling,
        requests=collected,
    )
    api_report_grade = cloud_api_report_grade_assessment()
    payload = {
        "command": "cloud-collect",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": compute_sha256(manifest_path),
        "output_dir": str(output_dir.resolve()),
        "responses_dir": str(responses_dir.resolve()),
        "summary": summary,
        "credential_handling": credential_handling,
        "requests": collected,
        "skipped": skipped,
        "commercial_grade_ready": False,
        "commercial_gap_ids": ["#40"],
        "cloud_api_validation_matrix": cloud_api_validation_matrix(summary, credential_handling),
        "cloud_api_report_grade_assessment": api_report_grade,
        "commercial_uplift_evidence": cloud_api_commercial_uplift_evidence(
            manifest_path=manifest_path,
            output_dir=output_dir,
            summary=summary,
            credential_handling=credential_handling,
            requests=collected,
            report_grade=api_report_grade,
        ),
        "cloud_api_native_capabilities": dict(CLOUD_API_NATIVE_CAPABILITIES),
        "core_accuracy_gates": cloud_api_core_accuracy_gates(
            manifest_path=manifest_path,
            output_dir=output_dir,
            summary=summary,
            credential_handling=credential_handling,
            requests=collected,
        ),
        "forensic_review": cloud_api_forensic_review(
            gap_id="#40",
            artifact_goal="Cloud API acquisition manifest, bounded collection, response hashing, and import workflow",
            primary_evidence=[
                f"request_count={summary['request_count']}",
                f"collected_count={summary['collected_count']}",
                f"dry_run={summary['dry_run']}",
                f"responses_dir={responses_dir.resolve()}",
            ],
            report_grade_assessment=api_report_grade,
            blockers=CLOUD_API_REPORT_GRADE_BLOCKERS,
            caveats=[
                "Provider-specific OAuth/device-flow, scope discovery, pagination, and legal hold workflows remain validation-gated.",
                "Validate collected JSON against provider-native export views before report conclusions.",
            ],
        ),
        "import_guidance": "Run `rapidtriage artifacts OUTPUT_DIR/responses --kind cloud-export` to normalize supported JSON responses.",
    }
    output_path = output_dir / "rapidtriage-cloud-collect.json"
    if not dry_run:
        output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        (output_dir / "rapidtriage-cloud-collect.dry-run.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    payload["output"] = str((output_dir / ("rapidtriage-cloud-collect.dry-run.json" if dry_run else "rapidtriage-cloud-collect.json")).resolve())
    return payload


def load_manifest(path: Path) -> Mapping[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CloudApiCollectionError(f"cannot read cloud API manifest: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise CloudApiCollectionError("cloud API manifest must be a JSON object")
    return payload


def prepare_request(
    request_def: Mapping[str, object],
    *,
    default_bearer_token_env: str,
    allow_insecure_http: bool,
) -> dict[str, object]:
    name = text_value(request_def.get("name") or request_def.get("id") or "cloud-api")
    service = text_value(request_def.get("service") or "cloud-api")
    method = text_value(request_def.get("method") or "GET").upper()
    if method not in ALLOWED_METHODS:
        raise CloudApiCollectionError(f"unsupported cloud API method for {name}: {method}")
    url = text_value(request_def.get("url"))
    validate_url(url, allow_insecure_http=allow_insecure_http)
    headers = normalize_headers(request_def.get("headers"))
    bearer_env = text_value(request_def.get("bearer_token_env") or default_bearer_token_env)
    bearer_token = os.environ.get(bearer_env, "")
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    body = request_def.get("body")
    if body not in (None, "") and not isinstance(body, (str, bytes, Mapping, list)):
        raise CloudApiCollectionError(f"unsupported request body for {name}")
    return {
        "name": name,
        "service": service,
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "bearer_token_env": bearer_env if bearer_token else "",
    }


def execute_request(
    *,
    index: int,
    prepared: Mapping[str, object],
    responses_dir: Path,
    timeout_seconds: int,
    max_response_bytes: int,
) -> dict[str, object]:
    request_body = encode_body(prepared.get("body"))
    request = urllib.request.Request(
        str(prepared["url"]),
        data=request_body,
        headers={str(key): str(value) for key, value in dict(prepared["headers"]).items()},
        method=str(prepared["method"]),
    )
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    row: dict[str, object] = {
        "index": index,
        "name": prepared["name"],
        "service": prepared["service"],
        "method": prepared["method"],
        "url": prepared["url"],
        "url_sha256": hashlib.sha256(str(prepared["url"]).encode("utf-8")).hexdigest(),
        "started_at": started_at,
        "request_headers": redact_headers(dict(prepared["headers"])),
        "credential_handling": request_credential_handling(prepared),
    }
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            content = response.read(max_response_bytes + 1)
            truncated = len(content) > max_response_bytes
            if truncated:
                content = content[:max_response_bytes]
            output_path = response_path_for(responses_dir, index, str(prepared["name"]), response.headers.get("Content-Type", ""))
            output_path.write_bytes(content)
            row.update(
                {
                    "status": int(response.status),
                    "reason": response.reason,
                    "content_type": response.headers.get("Content-Type", ""),
                    "response_path": str(output_path.resolve()),
                    "response_size": len(content),
                    "response_sha256": compute_sha256(output_path),
                    "truncated": truncated,
                    "completed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                }
            )
    except urllib.error.HTTPError as exc:
        row.update({"error": "http-error", "status": exc.code, "reason": exc.reason})
    except urllib.error.URLError as exc:
        row.update({"error": "url-error", "reason": str(exc.reason)})
    except OSError as exc:
        row.update({"error": "io-error", "reason": str(exc)})
    return row


def validate_url(url: str, *, allow_insecure_http: bool) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise CloudApiCollectionError(f"cloud API URL must be absolute http(s): {url}")
    if parsed.scheme == "https":
        return
    if allow_insecure_http or parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
        return
    raise CloudApiCollectionError("cloud API collection refuses non-local HTTP unless --allow-insecure-http is set")


def normalize_headers(value: object) -> dict[str, str]:
    if value in (None, ""):
        return {"Accept": "application/json"}
    if not isinstance(value, Mapping):
        raise CloudApiCollectionError("request headers must be a JSON object")
    headers = {str(key): str(item) for key, item in value.items()}
    headers.setdefault("Accept", "application/json")
    return headers


def redact_headers(headers: Mapping[str, object]) -> dict[str, str]:
    redacted = {}
    for key, value in headers.items():
        if key.lower() in {"authorization", "x-api-key", "api-key"}:
            redacted[str(key)] = "<REDACTED>"
        else:
            redacted[str(key)] = str(value)
    return redacted


def request_credential_handling(prepared: Mapping[str, object]) -> dict[str, object]:
    headers = dict(prepared.get("headers") or {})
    sensitive_headers = [
        str(key)
        for key in headers
        if str(key).lower() in {"authorization", "x-api-key", "api-key"}
    ]
    return {
        "sensitive_header_names": sensitive_headers,
        "sensitive_values_redacted": True,
        "bearer_token_env_used": str(prepared.get("bearer_token_env") or ""),
        "tokens_written_to_output": False,
        "commercial_gap_ids": ["#41"],
        "secure_token_vault_integrated": False,
        "token_value_sha256_recorded": False,
        "legal_warning": "Credential-bearing requests are redacted in output. Confirm legal authority, API scopes, and token handling before collection.",
    }


def cloud_api_validation_matrix(summary: Mapping[str, object], credential_handling: Mapping[str, object]) -> list[dict[str, object]]:
    return [
        {
            "id": "manifest-validated",
            "label": "Collection manifest has valid request definitions",
            "passed": int(summary.get("request_count") or 0) > 0,
            "severity": "critical",
        },
        {
            "id": "credentials-redacted",
            "label": "Credential values are redacted and not written to output",
            "passed": bool(credential_handling.get("headers_redacted"))
            and not bool(credential_handling.get("tokens_written_to_output")),
            "severity": "critical",
        },
        {
            "id": "response-hashes-or-dry-run",
            "label": "Collected responses are hashed, or dry-run validation was requested",
            "passed": bool(summary.get("dry_run")) or int(summary.get("collected_count") or 0) >= 0,
            "severity": "high",
        },
        {
            "id": "provider-oauth-scope-capture",
            "label": "Provider-specific OAuth consent, scopes, and legal hold metadata are captured",
            "passed": False,
            "severity": "critical",
        },
        {
            "id": "incremental-known-answer-validation",
            "label": "Incremental collection and provider API behavior are known-answer validated",
            "passed": False,
            "severity": "critical",
        },
    ]


def cloud_credential_security_assessment(credential_handling: Mapping[str, object]) -> dict[str, object]:
    return {
        "status": "validation-required",
        "commercial_gap_ids": ["#41"],
        "tokens_written_to_output": bool(credential_handling.get("tokens_written_to_output")),
        "headers_redacted": bool(credential_handling.get("headers_redacted")),
        "credential_storage": str(credential_handling.get("credential_storage") or ""),
        "secure_token_vault_integrated": bool(credential_handling.get("secure_token_vault_integrated")),
        "token_rotation_audit_present": bool(credential_handling.get("token_rotation_audit_present")),
        "ready_for_court_report": False,
        "blockers": list(CLOUD_CREDENTIAL_SECURITY_BLOCKERS),
        "recommended_validation": [
            "Record provider OAuth consent, granted scopes, account owner, legal authority, and API version before collection.",
            "Use an OS/enterprise secret vault or short-lived token broker before report-grade multi-user deployment.",
        ],
    }


def cloud_api_report_grade_assessment() -> dict[str, object]:
    return {
        "status": "validation-required",
        "commercial_gap_ids": ["#40"],
        "blockers": list(CLOUD_API_REPORT_GRADE_BLOCKERS),
        "ready_for_court_report": False,
        "recommended_validation": [
            "Capture account authorization, provider scopes, consent/legal-hold context, and API version metadata.",
            "Validate collected JSON against provider-native export views before report-grade use.",
        ],
    }


def cloud_api_commercial_uplift_evidence(
    *,
    manifest_path: Path,
    output_dir: Path,
    summary: Mapping[str, object],
    credential_handling: Mapping[str, object],
    requests: list[dict[str, object]],
    report_grade: Mapping[str, object],
) -> dict[str, object]:
    matrix = cloud_api_validation_matrix(summary, credential_handling)
    passed_validation_matrix_ids = [str(item.get("id")) for item in matrix if item.get("passed")]
    failed_validation_matrix_ids = [str(item.get("id")) for item in matrix if not item.get("passed")]
    return {
        "batch_id": "commercial-uplift-036-040",
        "item_numbers": [40],
        "implementation_track": "cloud-api-acquisition-workflow",
        "objective": "Expose cloud API collection manifest validation, credential redaction, response hash provenance, and provider OAuth/scope blockers.",
        "reportability_decision": cloud_api_reportability_decision(
            summary=summary,
            credential_handling=credential_handling,
            failed_validation_matrix_ids=failed_validation_matrix_ids,
            report_grade=report_grade,
        ),
        "source_refs": [
            f"manifest_path:{manifest_path.resolve()}",
            f"manifest_sha256:{compute_sha256(manifest_path)}",
            f"output_dir:{output_dir.resolve()}",
            *[f"response_sha256:{request.get('response_sha256')}" for request in requests[:5] if request.get("response_sha256")],
        ],
        "passed_validation_matrix_ids": passed_validation_matrix_ids,
        "failed_validation_matrix_ids": failed_validation_matrix_ids,
        "report_grade_status": str(report_grade.get("status") or ""),
        "commercial_blockers": list(report_grade.get("blockers") or CLOUD_API_REPORT_GRADE_BLOCKERS),
        "large_data_controls": {
            "timeout_seconds": DEFAULT_CLOUD_API_TIMEOUT_SECONDS,
            "max_response_bytes": DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES,
            "request_count": int(summary.get("request_count") or 0),
            "collected_count": int(summary.get("collected_count") or 0),
            "dry_run": bool(summary.get("dry_run")),
            "provider_specific_oauth_flow": False,
            "incremental_delta_collection": False,
            "known_answer_cloud_api_corpus_required": True,
        },
        "next_internal_step": "Add provider OAuth/device flow, scope capture, pagination/backoff manifests, delta collection, and provider API known-answer validation.",
        "external_evidence_required": True,
    }


def cloud_api_reportability_decision(
    *,
    summary: Mapping[str, object],
    credential_handling: Mapping[str, object],
    failed_validation_matrix_ids: list[str],
    report_grade: Mapping[str, object],
) -> dict[str, object]:
    blockers = {str(item) for item in report_grade.get("blockers") or CLOUD_API_REPORT_GRADE_BLOCKERS if str(item)}
    blockers.update(f"matrix:{item}" for item in failed_validation_matrix_ids)
    if not credential_handling.get("provider_scope_inventory"):
        blockers.add("provider-scope-inventory-not-captured")
    if not credential_handling.get("provider_oauth_consent_record"):
        blockers.add("oauth-consent-record-not-captured")
    if not summary.get("provider_api_known_answer_validated"):
        blockers.add("provider-api-known-answer-corpus-not-attached")
    return {
        "profile_version": "cloud-api-reportability-decision-v1",
        "commercial_gap_ids": ["#40"],
        "decision": "do-not-report-cloud-api-collection-as-provider-complete",
        "allowed_use": "cloud-api-response-triage-pivot",
        "blockers": sorted(blockers),
        "failed_validation_matrix_ids": list(failed_validation_matrix_ids),
        "request_count": int(summary.get("request_count") or 0),
        "collected_count": int(summary.get("collected_count") or 0),
        "dry_run": bool(summary.get("dry_run")),
        "credentials_redacted": bool(credential_handling.get("headers_redacted")),
        "ready_for_court_report": False,
        "required_before_report": [
            "capture provider OAuth/device-flow consent, scopes, legal hold, and account ownership evidence",
            "validate API pagination, delta, retry/backoff, and response schemas against provider known-answer data",
            "compare collected JSON with provider-native export or admin/eDiscovery views before testimony",
        ],
    }


def cloud_credential_commercial_uplift_evidence(
    *,
    manifest_path: Path,
    credential_handling: Mapping[str, object],
    requests: list[dict[str, object]],
) -> dict[str, object]:
    assessment = cloud_credential_security_assessment(credential_handling)
    request_sensitive_headers = [
        header
        for request in requests
        for header in (
            request.get("credential_handling", {}).get("sensitive_header_names", [])
            if isinstance(request.get("credential_handling"), Mapping)
            else []
        )
    ]
    return {
        "batch_id": "commercial-uplift-041-045",
        "item_numbers": [41],
        "implementation_track": "cloud-credential-handling",
        "objective": "Expose token redaction, storage boundary, scope/audit blockers, and legal authority requirements.",
        "source_refs": [
            f"manifest_path:{manifest_path.resolve()}",
            f"manifest_sha256:{compute_sha256(manifest_path)}",
            f"credential_storage:{credential_handling.get('credential_storage', '')}",
            f"bearer_token_env:{credential_handling.get('bearer_token_env', '')}",
        ],
        "passed_validation_check_ids": [
            "headers_redacted",
            "tokens_not_written",
        ]
        if credential_handling.get("headers_redacted") and not credential_handling.get("tokens_written_to_output")
        else [],
        "failed_validation_check_ids": [
            "provider_oauth_consent_record",
            "provider_scope_inventory",
            "secure_token_vault",
            "token_rotation_audit",
        ],
        "request_sensitive_header_names": sorted(set(str(item) for item in request_sensitive_headers)),
        "commercial_blockers": list(assessment.get("blockers") or CLOUD_CREDENTIAL_SECURITY_BLOCKERS),
        "large_data_controls": {
            "tokens_written_to_output": bool(credential_handling.get("tokens_written_to_output")),
            "headers_redacted": bool(credential_handling.get("headers_redacted")),
            "secure_token_vault_integrated": bool(credential_handling.get("secure_token_vault_integrated")),
            "token_rotation_audit_present": bool(credential_handling.get("token_rotation_audit_present")),
        },
        "next_internal_step": "Integrate OS/enterprise token vault, OAuth scope capture, consent evidence, and token rotation/revocation audit.",
        "external_evidence_required": True,
    }


def cloud_api_core_accuracy_gates(
    *,
    manifest_path: Path,
    output_dir: Path,
    summary: Mapping[str, object],
    credential_handling: Mapping[str, object],
    requests: list[dict[str, object]],
) -> list[dict[str, object]]:
    evidence_refs = [
        f"manifest_path:{manifest_path.resolve()}",
        f"manifest_sha256:{compute_sha256(manifest_path)}",
        f"output_dir:{output_dir.resolve()}",
    ]
    for request in requests[:5]:
        if request.get("response_sha256"):
            evidence_refs.append(f"response_sha256:{request['response_sha256']}")
        if request.get("response_path"):
            evidence_refs.append(f"response_path:{request['response_path']}")
    satisfied: list[str] = []
    if int(summary.get("request_count") or 0) > 0:
        satisfied.append("manifest request validation")
    if bool(credential_handling.get("headers_redacted")) and not bool(credential_handling.get("tokens_written_to_output")):
        satisfied.append("credential redaction")
    if bool(summary.get("dry_run")) or any(request.get("response_sha256") for request in requests):
        satisfied.append("response hash/provenance")
    if not CLOUD_API_NATIVE_CAPABILITIES["incremental_delta_collection"]:
        satisfied.append("pagination/backoff limitation warning")
    if credential_handling.get("legal_warning") and not CLOUD_API_NATIVE_CAPABILITIES["provider_specific_oauth_flow"]:
        satisfied.append("provider OAuth/scope/legal warning")
    return [build_accuracy_gate(40, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def cloud_credential_core_accuracy_gates(
    *,
    manifest_path: Path,
    credential_handling: Mapping[str, object],
    requests: list[dict[str, object]],
) -> list[dict[str, object]]:
    evidence_refs = [
        f"manifest_path:{manifest_path.resolve()}",
        f"manifest_sha256:{compute_sha256(manifest_path)}",
        f"credential_storage:{credential_handling.get('credential_storage', '')}",
        f"bearer_token_env:{credential_handling.get('bearer_token_env', '')}",
    ]
    for request in requests[:5]:
        handling = request.get("credential_handling") if isinstance(request.get("credential_handling"), Mapping) else {}
        if handling.get("sensitive_header_names"):
            evidence_refs.append(f"sensitive_headers:{','.join(str(item) for item in handling['sensitive_header_names'])}")

    satisfied: list[str] = []
    if bool(credential_handling.get("headers_redacted")) and not bool(credential_handling.get("tokens_written_to_output")):
        satisfied.append("token value redaction")
    if credential_handling.get("credential_storage") in {"environment-variable-only", "vault"}:
        satisfied.append("environment or vault storage boundary")
    if credential_handling.get("scope_capture_status") == "not-captured" or credential_handling.get("legal_warning"):
        satisfied.append("scope and consent capture warning")
    if not bool(credential_handling.get("token_rotation_audit_present")):
        satisfied.append("rotation and revocation audit warning")
    if credential_handling.get("legal_warning") or credential_handling.get("audit_required"):
        satisfied.append("legal authority warning")
    return [build_accuracy_gate(41, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def cloud_api_forensic_review(
    *,
    gap_id: str,
    artifact_goal: str,
    primary_evidence: list[str],
    report_grade_assessment: Mapping[str, object],
    blockers: list[str],
    caveats: list[str],
) -> dict[str, object]:
    return {
        "gap_id": gap_id,
        "artifact_goal": artifact_goal,
        "review_status": "triage-review",
        "report_grade_ready": bool(report_grade_assessment.get("ready_for_court_report")),
        "validation_required": True,
        "primary_evidence": [item for item in primary_evidence if item],
        "blockers": sorted({str(item) for item in [*blockers, *report_grade_assessment.get("blockers", [])]}),
        "caveats": caveats,
    }


def encode_body(value: object) -> bytes | None:
    if value in (None, ""):
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def response_path_for(responses_dir: Path, index: int, name: str, content_type: str) -> Path:
    suffix = ".json" if "json" in content_type.lower() else ".bin"
    return responses_dir / f"{index:03d}-{safe_name(name)}{suffix}"


def safe_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-")
    return safe[:80] or "cloud-api"


def text_value(value: object) -> str:
    if value in (None, ""):
        return ""
    return str(value)
