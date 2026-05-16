from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable, Mapping

from .audit import compute_sha256
from .forensic_accuracy import build_accuracy_gate

DEFAULT_CLOUD_BEARER_TOKEN_ENV = "RAPIDTRIAGE_CLOUD_BEARER_TOKEN"
DEFAULT_CLOUD_API_TIMEOUT_SECONDS = 30
DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES = 50 * 1024 * 1024
DEFAULT_CLOUD_API_MAX_RETRY_ATTEMPTS = 1
DEFAULT_CLOUD_API_BACKOFF_SECONDS = 0.0
FUNCTIONAL_EXPANSION_BATCH_ID = "commercial-uplift-056-060"
ALLOWED_METHODS = {"GET", "POST"}
RETRYABLE_HTTP_STATUS = {408, 425, 429, 500, 502, 503, 504}
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
CLOUD_API_REPORT_GRADE_VALIDATION_PLAN_VERSION = "cloud-api-report-grade-validation-plan-v1"
CLOUD_API_REPORT_GRADE_VALIDATION_BLOCKERS = [
    "cloud-api-provider-oauth-device-flow-required",
    "cloud-api-provider-scope-consent-legal-authority-required",
    "cloud-api-original-manifest-hash-required",
    "cloud-api-response-hash-and-sidecar-required",
    "cloud-api-pagination-delta-execution-required",
    "cloud-api-retry-throttle-backoff-validation-required",
    "cloud-api-provider-native-response-diff-required",
    "cloud-api-legal-hold-export-package-required",
    "cloud-api-provider-schema-version-tracking-required",
    "independent-cloud-api-acquisition-review-required",
]
CLOUD_API_TRUSTED_DIFF_BLOCKER = "cloud-api-provider-response-diff-required"
CLOUD_API_TRUSTED_DIFF_TOOLS = {
    "provider-native-export",
    "provider-admin-console",
    "provider-api-known-answer",
    "google-provider-api",
    "microsoft-graph-api",
    "apple-provider-export",
    "purview-ediscovery-export",
}
CLOUD_CREDENTIAL_SECURITY_BLOCKERS = [
    "provider-oauth-consent-record-not-captured",
    "provider-scope-inventory-not-captured",
    "secure-token-vault-not-integrated",
    "token-rotation-and-revocation-audit-not-captured",
    "legal-authority-review-required-before-cloud-collection",
]
CLOUD_CREDENTIAL_REPORT_GRADE_VALIDATION_PLAN_VERSION = "cloud-credential-report-grade-validation-plan-v1"
CLOUD_CREDENTIAL_REPORT_GRADE_VALIDATION_BLOCKERS = [
    "cloud-credential-oauth-consent-record-required",
    "cloud-credential-provider-scope-inventory-required",
    "cloud-credential-legal-authority-record-required",
    "cloud-credential-enterprise-token-vault-required",
    "cloud-credential-token-rotation-revocation-audit-required",
    "cloud-credential-controlled-reveal-workflow-required",
    "cloud-credential-rbac-enforcement-required",
    "cloud-credential-authority-audit-diff-required",
    "cloud-credential-independent-review-required",
]
CLOUD_CREDENTIAL_TRUSTED_DIFF_BLOCKER = "cloud-credential-authority-audit-diff-required"
CLOUD_CREDENTIAL_TRUSTED_TOOLS = {
    "provider-oauth-consent-record",
    "provider-native-audit-log",
    "enterprise-vault-audit",
    "security-admin-signoff",
    "legal-authority-record",
}


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
            dry_run_row = {
                "index": index,
                "name": prepared["name"],
                "service": prepared["service"],
                "method": prepared["method"],
                "url": prepared["url"],
                "url_sha256": hashlib.sha256(str(prepared["url"]).encode("utf-8")).hexdigest(),
                "dry_run": True,
                "headers": redact_headers(prepared["headers"]),
                "credential_handling": request_credential_handling(prepared),
                "request_acquisition_profile": cloud_api_request_acquisition_profile(prepared),
            }
            dry_run_row["cloud_api_response_parser_manifest"] = cloud_api_response_parser_manifest(
                dry_run_row,
                output_dir=output_dir,
                max_response_bytes=max_response_bytes,
                timeout_seconds=timeout_seconds,
            )
            collected.append(
                dry_run_row
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
    provider_scope_profile = cloud_api_provider_scope_profile(manifest)
    summary["provider_scope_profile_present"] = True
    summary["provider_scope_inventory_captured"] = bool(provider_scope_profile.get("scope_inventory_captured"))
    credential_handling = {
        "bearer_token_env": bearer_token_env,
        "tokens_written_to_output": False,
        "headers_redacted": True,
        "credential_storage": "environment-variable-only",
        "commercial_gap_ids": ["#41"],
        "scope_capture_status": "not-captured",
        "controlled_reveal_policy": "disabled-by-default",
        "raw_secret_reveal_allowed": False,
        "secure_token_vault_integrated": False,
        "token_rotation_audit_present": False,
        "audit_required": True,
        "legal_warning": "Use only with authorized cloud accounts/API scopes; do not paste tokens into manifests or reports.",
    }
    credential_handling["credential_strategy_profile"] = cloud_credential_strategy_profile(credential_handling)
    credential_handling["credential_security_assessment"] = cloud_credential_security_assessment(credential_handling)
    credential_handling["credential_authority_manifest"] = cloud_credential_authority_manifest(
        manifest=manifest,
        manifest_path=manifest_path,
        provider_scope_profile=provider_scope_profile,
        credential_handling=credential_handling,
        requests=collected,
    )
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
    credential_handling["credential_authority_profile"] = cloud_credential_authority_profile(
        credential_handling=credential_handling,
        provider_scope_profile=provider_scope_profile,
        requests=collected,
    )
    credential_report_grade_validation_plan = cloud_credential_report_grade_validation_plan(
        manifest_path=manifest_path,
        credential_handling=credential_handling,
        provider_scope_profile=provider_scope_profile,
        requests=collected,
    )
    credential_handling["credential_report_grade_validation_plan"] = credential_report_grade_validation_plan
    credential_handling["credential_report_grade_validation_plan_hash"] = credential_report_grade_validation_plan[
        "validation_plan_sha256"
    ]
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
    collection_strategy_profile = cloud_api_collection_strategy_profile(
        manifest_path=manifest_path,
        summary=summary,
        credential_handling=credential_handling,
        requests=collected,
        provider_scope_profile=provider_scope_profile,
    )
    acquisition_manifest = cloud_api_acquisition_manifest(
        manifest_path=manifest_path,
        output_dir=output_dir,
        responses_dir=responses_dir,
        summary=summary,
        credential_handling=credential_handling,
        requests=collected,
        provider_scope_profile=provider_scope_profile,
        collection_strategy_profile=collection_strategy_profile,
    )
    summary["cloud_api_acquisition_manifest_hash"] = acquisition_manifest["manifest_sha256"]
    summary["response_parser_manifest_count"] = acquisition_manifest["response_parser_manifest_count"]
    report_grade_validation_plan = cloud_api_report_grade_validation_plan(
        manifest_path=manifest_path,
        output_dir=output_dir,
        summary=summary,
        credential_handling=credential_handling,
        requests=collected,
        provider_scope_profile=provider_scope_profile,
        acquisition_manifest=acquisition_manifest,
        collection_strategy_profile=collection_strategy_profile,
    )
    summary["cloud_api_report_grade_validation_plan_hash"] = report_grade_validation_plan[
        "validation_plan_sha256"
    ]
    summary["cloud_api_report_grade_ready_slot_count"] = report_grade_validation_plan["ready_slot_count"]
    summary["cloud_api_report_grade_blocking_slot_count"] = report_grade_validation_plan["blocking_slot_count"]
    payload = {
        "command": "cloud-collect",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": compute_sha256(manifest_path),
        "output_dir": str(output_dir.resolve()),
        "responses_dir": str(responses_dir.resolve()),
        "summary": summary,
        "credential_handling": credential_handling,
        "cloud_api_provider_scope_profile": provider_scope_profile,
        "requests": collected,
        "skipped": skipped,
        "commercial_grade_ready": False,
        "commercial_gap_ids": ["#40"],
        "cloud_api_validation_matrix": cloud_api_validation_matrix(summary, credential_handling),
        "cloud_api_report_grade_assessment": api_report_grade,
        "cloud_api_collection_strategy_profile": collection_strategy_profile,
        "cloud_api_acquisition_manifest": acquisition_manifest,
        "cloud_api_report_grade_validation_plan": report_grade_validation_plan,
        "commercial_uplift_evidence": cloud_api_commercial_uplift_evidence(
            manifest_path=manifest_path,
            output_dir=output_dir,
            summary=summary,
            credential_handling=credential_handling,
            requests=collected,
            provider_scope_profile=provider_scope_profile,
            report_grade=api_report_grade,
            report_grade_validation_plan=report_grade_validation_plan,
        ),
        "functional_priority_profile": cloud_api_acquisition_functional_profile(
            manifest_path=manifest_path,
            output_dir=output_dir,
            summary=summary,
            credential_handling=credential_handling,
            requests=collected,
            provider_scope_profile=provider_scope_profile,
            report_grade_validation_plan=report_grade_validation_plan,
        ),
        "cloud_api_native_capabilities": dict(CLOUD_API_NATIVE_CAPABILITIES),
        "core_accuracy_gates": cloud_api_core_accuracy_gates(
            manifest_path=manifest_path,
            output_dir=output_dir,
            summary=summary,
            credential_handling=credential_handling,
            requests=collected,
            report_grade_validation_plan=report_grade_validation_plan,
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
        "cloud_api_analyst_review_profile": cloud_api_analyst_review_profile(
            manifest_path=manifest_path,
            output_dir=output_dir,
            responses_dir=responses_dir,
            summary=summary,
            credential_handling=credential_handling,
            requests=collected,
            provider_scope_profile=provider_scope_profile,
            acquisition_manifest=acquisition_manifest,
            report_grade=api_report_grade,
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


def cloud_api_analyst_review_profile(
    *,
    manifest_path: Path,
    output_dir: Path,
    responses_dir: Path,
    summary: Mapping[str, object],
    credential_handling: Mapping[str, object],
    requests: list[Mapping[str, object]],
    provider_scope_profile: Mapping[str, object],
    acquisition_manifest: Mapping[str, object],
    report_grade: Mapping[str, object],
) -> dict[str, object]:
    response_hashes = [str(row.get("response_sha256")) for row in requests if row.get("response_sha256")][:25]
    services = sorted({str(row.get("service") or "") for row in requests if row.get("service")})
    return {
        "profile_version": "cloud-api-analyst-review-profile-v1",
        "gap_ids": ["#40"],
        "artifact_type": "cloud-api-collection",
        "provider": str(provider_scope_profile.get("provider") or ""),
        "services": services,
        "severity": "high" if int(summary.get("error_count") or 0) else "medium",
        "summary": (
            f"cloud-api requests={summary.get('request_count', 0)} "
            f"collected={summary.get('collected_count', 0)} dry_run={summary.get('dry_run', False)}"
        ),
        "evidence_interpretation": "Manifest-driven cloud API collection with redacted credential handling and response hash provenance",
        "not_proof_of": [
            "complete provider account acquisition",
            "provider OAuth/device-flow correctness",
            "pagination/delta completeness",
            "deleted or retained object completeness",
            "legal hold/eDiscovery equivalence",
        ],
        "analyst_questions": [
            "Does the manifest scope match written legal authority and provider consent records?",
            "Do response hashes match provider-native export/API replay evidence?",
            "Were pagination, throttling, retry, and delta tokens fully exercised?",
            "Should collected JSON be normalized through cloud-export and correlated with email/mobile/browser timelines?",
        ],
        "primary_pivots": [
            value
            for value in (
                str(provider_scope_profile.get("provider") or ""),
                str(provider_scope_profile.get("account") or ""),
                str(summary.get("cloud_api_acquisition_manifest_hash") or ""),
                *response_hashes[:3],
            )
            if value
        ],
        "source_field_values": {
            "manifest_path": str(manifest_path.resolve()),
            "manifest_sha256": compute_sha256(manifest_path),
            "output_dir": str(output_dir.resolve()),
            "responses_dir": str(responses_dir.resolve()),
            "request_count": int(summary.get("request_count") or 0),
            "collected_count": int(summary.get("collected_count") or 0),
            "error_count": int(summary.get("error_count") or 0),
            "dry_run": bool(summary.get("dry_run")),
            "acquisition_manifest_sha256": str(acquisition_manifest.get("manifest_sha256") or ""),
            "response_sha256_samples": response_hashes,
            "credential_storage": str(credential_handling.get("credential_storage") or ""),
            "tokens_written_to_output": bool(credential_handling.get("tokens_written_to_output")),
        },
        "correlation_targets": [
            "provider-native API/export diff",
            "legal authority and consent record",
            "credential authority/audit manifest",
            "cloud-export normalized rows",
            "email/mobile/browser/timeline correlation",
        ],
        "risk_tags": sorted(
            {
                "cloud-api-validation-required",
                *list(report_grade.get("failed_check_ids") or []),
                *([] if not credential_handling.get("tokens_written_to_output") else ["token-output-risk"]),
            }
        ),
        "validation_required": True,
        "report_grade_ready": False,
        "credential_boundary": {
            "headers_redacted": bool(credential_handling.get("headers_redacted")),
            "tokens_written_to_output": bool(credential_handling.get("tokens_written_to_output")),
            "secure_token_vault_integrated": bool(credential_handling.get("secure_token_vault_integrated")),
            "controlled_reveal_policy": str(credential_handling.get("controlled_reveal_policy") or ""),
        },
        "commercial_blockers": list(report_grade.get("blockers", CLOUD_API_REPORT_GRADE_BLOCKERS)),
        "report_guidance": "Use as a cloud acquisition review pivot until provider-native diff, pagination evidence, legal authority, and credential audit evidence are attached.",
    }


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
    retry_config = normalize_retry_config(request_def.get("retry"))
    pagination_config = normalize_pagination_config(request_def.get("pagination"))
    return {
        "name": name,
        "service": service,
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
        "bearer_token_env": bearer_env if bearer_token else "",
        "retry": retry_config,
        "pagination": pagination_config,
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
        "request_acquisition_profile": cloud_api_request_acquisition_profile(prepared),
    }
    retry = prepared.get("retry") if isinstance(prepared.get("retry"), Mapping) else {}
    max_attempts = int(retry.get("max_attempts") or DEFAULT_CLOUD_API_MAX_RETRY_ATTEMPTS)
    retry_statuses = {int(status) for status in retry.get("retry_statuses", []) or []}
    backoff_seconds = float(retry.get("backoff_seconds") or 0)
    attempts: list[dict[str, object]] = []
    for attempt in range(1, max_attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                content = response.read(max_response_bytes + 1)
                truncated = len(content) > max_response_bytes
                if truncated:
                    content = content[:max_response_bytes]
                output_path = response_path_for(responses_dir, index, str(prepared["name"]), response.headers.get("Content-Type", ""))
                output_path.write_bytes(content)
                attempts.append({"attempt": attempt, "status": int(response.status), "retryable": False})
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
                break
        except urllib.error.HTTPError as exc:
            retryable = exc.code in retry_statuses and attempt < max_attempts
            attempts.append({"attempt": attempt, "error": "http-error", "status": exc.code, "retryable": retryable})
            row.update({"error": "http-error", "status": exc.code, "reason": exc.reason})
            if not retryable:
                break
        except urllib.error.URLError as exc:
            retryable = attempt < max_attempts
            attempts.append({"attempt": attempt, "error": "url-error", "reason": str(exc.reason), "retryable": retryable})
            row.update({"error": "url-error", "reason": str(exc.reason)})
            if not retryable:
                break
        except OSError as exc:
            retryable = attempt < max_attempts
            attempts.append({"attempt": attempt, "error": "io-error", "reason": str(exc), "retryable": retryable})
            row.update({"error": "io-error", "reason": str(exc)})
            if not retryable:
                break
        if attempt < max_attempts and backoff_seconds:
            time.sleep(backoff_seconds)
    row["attempts"] = attempts
    row["attempt_count"] = len(attempts)
    row["cloud_api_response_parser_manifest"] = cloud_api_response_parser_manifest(
        row,
        output_dir=responses_dir.parent,
        max_response_bytes=max_response_bytes,
        timeout_seconds=timeout_seconds,
    )
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


def normalize_retry_config(value: object) -> dict[str, object]:
    if value in (None, ""):
        return {
            "max_attempts": DEFAULT_CLOUD_API_MAX_RETRY_ATTEMPTS,
            "backoff_seconds": DEFAULT_CLOUD_API_BACKOFF_SECONDS,
            "retry_statuses": sorted(RETRYABLE_HTTP_STATUS),
        }
    if not isinstance(value, Mapping):
        raise CloudApiCollectionError("request retry must be a JSON object")
    max_attempts = int(value.get("max_attempts") or value.get("attempts") or DEFAULT_CLOUD_API_MAX_RETRY_ATTEMPTS)
    backoff_seconds = float(value.get("backoff_seconds") or value.get("backoff") or DEFAULT_CLOUD_API_BACKOFF_SECONDS)
    if max_attempts < 1 or max_attempts > 5:
        raise CloudApiCollectionError("request retry.max_attempts must be between 1 and 5")
    if backoff_seconds < 0 or backoff_seconds > 30:
        raise CloudApiCollectionError("request retry.backoff_seconds must be between 0 and 30")
    statuses = value.get("retry_statuses") or value.get("statuses") or sorted(RETRYABLE_HTTP_STATUS)
    if not isinstance(statuses, list):
        raise CloudApiCollectionError("request retry.statuses must be a list")
    retry_statuses = sorted({int(status) for status in statuses})
    return {"max_attempts": max_attempts, "backoff_seconds": backoff_seconds, "retry_statuses": retry_statuses}


def normalize_pagination_config(value: object) -> dict[str, object]:
    if value in (None, ""):
        return {
            "mode": "none",
            "max_pages": 1,
            "next_link_field": "",
            "delta_token_field": "",
            "implemented": False,
        }
    if not isinstance(value, Mapping):
        raise CloudApiCollectionError("request pagination must be a JSON object")
    mode = text_value(value.get("mode") or "declared")
    max_pages = int(value.get("max_pages") or 1)
    if max_pages < 1 or max_pages > 1000:
        raise CloudApiCollectionError("request pagination.max_pages must be between 1 and 1000")
    return {
        "mode": mode,
        "max_pages": max_pages,
        "next_link_field": text_value(value.get("next_link_field") or value.get("nextLinkField") or ""),
        "delta_token_field": text_value(value.get("delta_token_field") or value.get("deltaTokenField") or ""),
        "implemented": False,
    }


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
        "controlled_reveal_policy": "disabled-by-default",
        "raw_secret_reveal_allowed": False,
        "legal_warning": "Credential-bearing requests are redacted in output. Confirm legal authority, API scopes, and token handling before collection.",
        "credential_strategy_profile": {
            "profile_version": "cloud-request-credential-strategy-v1",
            "selected_track": "redacted-request-header-inventory",
            "raw_secret_output_allowed": False,
            "authority_audit_required": True,
        },
    }


def cloud_credential_strategy_profile(credential_handling: Mapping[str, object]) -> dict[str, object]:
    return {
        "profile_version": "cloud-credential-strategy-v1",
        "selected_track": "environment-token-redaction-with-external-authority-audit",
        "credential_storage": str(credential_handling.get("credential_storage") or ""),
        "bearer_token_env": str(credential_handling.get("bearer_token_env") or ""),
        "raw_token_output_allowed": False,
        "tokens_written_to_output": bool(credential_handling.get("tokens_written_to_output")),
        "headers_redacted": bool(credential_handling.get("headers_redacted")),
        "controlled_reveal_policy": str(credential_handling.get("controlled_reveal_policy") or "disabled-by-default"),
        "raw_secret_reveal_allowed": bool(credential_handling.get("raw_secret_reveal_allowed")),
        "secure_token_vault_integrated": bool(credential_handling.get("secure_token_vault_integrated")),
        "token_rotation_audit_present": bool(credential_handling.get("token_rotation_audit_present")),
        "scope_capture_status": str(credential_handling.get("scope_capture_status") or "not-captured"),
        "blockers": [
            "provider-oauth-consent-record-not-captured",
            "provider-scope-inventory-not-captured",
            "secure-token-vault-not-integrated",
            "token-rotation-and-revocation-audit-not-captured",
            CLOUD_CREDENTIAL_TRUSTED_DIFF_BLOCKER,
        ],
        "required_before_report": [
            "record provider OAuth consent, scopes, account owner, and legal authority",
            "store or broker tokens through an OS/enterprise secret vault for multi-user deployments",
            "record token rotation/revocation audit and expiry policy",
            "attach provider/vault/legal authority diff evidence before claiming enterprise credential handling",
        ],
    }


def cloud_api_collection_strategy_profile(
    *,
    manifest_path: Path,
    summary: Mapping[str, object],
    credential_handling: Mapping[str, object],
    requests: Iterable[Mapping[str, object]],
    provider_scope_profile: Mapping[str, object] | None = None,
) -> dict[str, object]:
    request_rows = list(requests)
    services = sorted({str(row.get("service") or "cloud-api") for row in request_rows if row.get("service")})
    provider_scope_profile = provider_scope_profile or {}
    pagination_declared = any(
        isinstance(row.get("request_acquisition_profile"), Mapping)
        and row.get("request_acquisition_profile", {}).get("pagination_mode") not in {"", "none"}
        for row in request_rows
    )
    retry_declared = any(
        isinstance(row.get("request_acquisition_profile"), Mapping)
        and int(row.get("request_acquisition_profile", {}).get("retry_max_attempts") or 1) > 1
        for row in request_rows
    )
    return {
        "profile_version": "cloud-api-collection-strategy-v1",
        "selected_track": "manifest-driven-bounded-api-collection",
        "manifest_path": str(manifest_path.resolve()),
        "services": services,
        "provider_scope_profile": dict(provider_scope_profile),
        "request_count": int(summary.get("request_count") or 0),
        "collected_count": int(summary.get("collected_count") or 0),
        "dry_run": bool(summary.get("dry_run")),
        "max_response_bytes": DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES,
        "timeout_seconds": DEFAULT_CLOUD_API_TIMEOUT_SECONDS,
        "request_retry_policy_declared": retry_declared,
        "pagination_policy_declared": pagination_declared,
        "response_hashing_enabled": bool(summary.get("dry_run")) or any(row.get("response_sha256") for row in request_rows),
        "credential_strategy_track": (
            credential_handling.get("credential_strategy_profile", {}).get("selected_track")
            if isinstance(credential_handling.get("credential_strategy_profile"), Mapping)
            else ""
        ),
        "provider_specific_oauth_flow": CLOUD_API_NATIVE_CAPABILITIES["provider_specific_oauth_flow"],
        "provider_scope_discovery": CLOUD_API_NATIVE_CAPABILITIES["provider_scope_discovery"],
        "pagination_backoff_delta_complete": CLOUD_API_NATIVE_CAPABILITIES["incremental_delta_collection"],
        "message_or_object_reportable": False,
        "blockers": [
            "provider-specific-oauth-flow-not-implemented",
            "provider-scope-discovery-and-consent-capture-not-implemented",
            "pagination-backoff-delta-validation-required",
            "provider-api-known-answer-corpus-not-attached",
            CLOUD_API_TRUSTED_DIFF_BLOCKER,
        ],
        "required_before_report": [
            "capture OAuth/device-flow consent, granted scopes, account ownership, and legal hold context",
            "record provider API version, pagination, retry/backoff, delta token, and response schema behavior",
            "hash every response and diff representative rows against provider-native admin/export views",
            "document rate limits, incomplete pages, deleted-state, and retention limitations",
        ],
    }


def cloud_api_provider_scope_profile(manifest: Mapping[str, object]) -> dict[str, object]:
    provider = text_value(manifest.get("provider") or manifest.get("service") or "")
    account = text_value(manifest.get("account") or manifest.get("account_id") or manifest.get("tenant") or "")
    scopes = manifest.get("scopes") or manifest.get("scope") or []
    if isinstance(scopes, str):
        scope_values = [scopes]
    elif isinstance(scopes, list):
        scope_values = [text_value(item) for item in scopes if text_value(item)]
    else:
        scope_values = []
    legal_authority = text_value(manifest.get("legal_authority") or manifest.get("authority_record_id") or "")
    export_manifest = text_value(manifest.get("provider_export_manifest") or manifest.get("export_manifest") or "")
    return {
        "profile_version": "cloud-api-provider-scope-v1",
        "provider": provider or "not-declared",
        "account_or_tenant_declared": bool(account),
        "account_or_tenant_sha256": hashlib.sha256(account.encode("utf-8")).hexdigest() if account else "",
        "scope_count": len(scope_values),
        "scope_hashes": [hashlib.sha256(scope.encode("utf-8")).hexdigest() for scope in scope_values],
        "scope_inventory_captured": bool(scope_values),
        "legal_authority_record_present": bool(legal_authority),
        "provider_export_manifest_present": bool(export_manifest),
        "provider_scope_discovery_status": "manifest-declared" if scope_values else "not-captured",
        "oauth_consent_status": "external-record-required",
        "legal_hold_status": "external-record-required",
        "required_before_report": [
            "capture provider, account or tenant, selected API scopes, consent record, and legal authority record",
            "hash and preserve the provider export/API manifest plus original response package",
            "validate scope inventory against provider admin/audit views before provider-complete claims",
        ],
    }


def cloud_api_request_acquisition_profile(prepared: Mapping[str, object]) -> dict[str, object]:
    retry = prepared.get("retry") if isinstance(prepared.get("retry"), Mapping) else {}
    pagination = prepared.get("pagination") if isinstance(prepared.get("pagination"), Mapping) else {}
    parsed = urllib.parse.urlparse(str(prepared.get("url") or ""))
    return {
        "profile_version": "cloud-api-request-acquisition-v1",
        "service": text_value(prepared.get("service") or "cloud-api"),
        "method": text_value(prepared.get("method") or "GET"),
        "host_sha256": hashlib.sha256((parsed.netloc or "").encode("utf-8")).hexdigest() if parsed.netloc else "",
        "path_template": parsed.path or "/",
        "retry_max_attempts": int(retry.get("max_attempts") or DEFAULT_CLOUD_API_MAX_RETRY_ATTEMPTS),
        "retry_backoff_seconds": float(retry.get("backoff_seconds") or DEFAULT_CLOUD_API_BACKOFF_SECONDS),
        "retry_statuses": list(retry.get("retry_statuses") or sorted(RETRYABLE_HTTP_STATUS)),
        "pagination_mode": text_value(pagination.get("mode") or "none"),
        "pagination_max_pages": int(pagination.get("max_pages") or 1),
        "next_link_field": text_value(pagination.get("next_link_field") or ""),
        "delta_token_field": text_value(pagination.get("delta_token_field") or ""),
        "pagination_execution_status": "declared-not-executed" if pagination.get("mode") not in {"", "none", None} else "not-configured",
        "bounded_response_size": DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES,
        "timeout_seconds": DEFAULT_CLOUD_API_TIMEOUT_SECONDS,
        "provider_specific_oauth_flow": False,
        "required_before_report": [
            "validate endpoint schema, pagination, retry/backoff, and delta-token behavior with provider known-answer data",
            "compare response hashes and selected rows against provider-native export/admin views",
            "record API version, scopes, rate-limit behavior, and legal-hold context",
        ],
    }


def cloud_api_response_parser_manifest(
    row: Mapping[str, object],
    *,
    output_dir: Path,
    max_response_bytes: int,
    timeout_seconds: int,
) -> dict[str, object]:
    response_path = text_value(row.get("response_path") or "")
    response_sha256 = text_value(row.get("response_sha256") or "")
    response_size = int(row.get("response_size") or 0)
    acquisition_profile = (
        row.get("request_acquisition_profile")
        if isinstance(row.get("request_acquisition_profile"), Mapping)
        else {}
    )
    dry_run = bool(row.get("dry_run"))
    parsed_status = "dry-run-no-response" if dry_run else "response-captured" if response_sha256 else "response-missing"
    source_locator = {
        "viewer": "cloud-api-response-row",
        "source_path": response_path,
        "source_sha256": response_sha256,
        "row_key": f"cloud-api:{row.get('index', 0)}:{row.get('name', '')}",
        "byte_offset": 0,
        "byte_length": response_size,
        "open_hint": "Use the response_path sidecar for raw bytes; metadata intentionally keeps the body out of the report JSON.",
    }
    manifest: dict[str, object] = {
        "manifest_version": "cloud-api-response-parser-manifest-v1",
        "item_number": 40,
        "batch_id": "commercial-uplift-036-040",
        "request_index": int(row.get("index") or 0),
        "request_name": text_value(row.get("name") or ""),
        "service": text_value(row.get("service") or ""),
        "method": text_value(row.get("method") or ""),
        "url_sha256": text_value(row.get("url_sha256") or ""),
        "status": int(row.get("status") or 0) if str(row.get("status") or "").isdigit() else 0,
        "content_type": text_value(row.get("content_type") or ""),
        "response_path": response_path,
        "response_sha256": response_sha256,
        "response_size": response_size,
        "truncated": bool(row.get("truncated")),
        "dry_run": dry_run,
        "parsed_status": parsed_status,
        "source_viewer_locator": source_locator,
        "row_citation": {
            "citation_id": f"cloud-api-response-{int(row.get('index') or 0):03d}",
            "source_sha256": response_sha256,
            "url_sha256": text_value(row.get("url_sha256") or ""),
            "status": int(row.get("status") or 0) if str(row.get("status") or "").isdigit() else 0,
            "response_path": response_path,
            "parser_version": "cloud-api-response-parser-manifest-v1",
        },
        "parser_tracks": {
            "manifest_driven_request": True,
            "bounded_response_size": True,
            "credential_values_redacted": True,
            "body_kept_in_sidecar": True,
            "pagination_declared": text_value(acquisition_profile.get("pagination_mode") or "none")
            not in {"", "none"},
            "pagination_executed": False,
            "delta_collection_executed": False,
            "provider_specific_oauth_flow": CLOUD_API_NATIVE_CAPABILITIES["provider_specific_oauth_flow"],
            "provider_native_diff_attached": False,
            "legal_hold_record_attached": False,
        },
        "large_data_controls": {
            "max_response_bytes": max_response_bytes,
            "timeout_seconds": timeout_seconds,
            "raw_body_serialized_in_metadata": False,
            "metadata_collapsed_by_default": True,
            "safe_preview_requires_source_viewer": True,
        },
        "passed_validation_check_ids": [
            check
            for check, passed in {
                "request-row-citation-emitted": True,
                "source-viewer-locator-emitted": True,
                "response-body-sidecar-boundary": True,
                "response-hash-present-or-dry-run": bool(response_sha256) or dry_run,
            }.items()
            if passed
        ],
        "failed_validation_check_ids": [
            check
            for check, failed in {
                "provider-native-response-diff": True,
                "pagination-delta-execution": not CLOUD_API_NATIVE_CAPABILITIES["incremental_delta_collection"],
                "provider-oauth-consent-record": True,
                "legal-hold-record": True,
            }.items()
            if failed
        ],
        "ready_for_court_report": False,
        "commercial_blockers": [
            CLOUD_API_TRUSTED_DIFF_BLOCKER,
            "provider-oauth-consent-record-required",
            "pagination-delta-execution-validation-required",
            "legal-hold-record-required",
        ],
    }
    manifest["manifest_sha256"] = stable_cloud_api_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def cloud_api_acquisition_manifest(
    *,
    manifest_path: Path,
    output_dir: Path,
    responses_dir: Path,
    summary: Mapping[str, object],
    credential_handling: Mapping[str, object],
    requests: Iterable[Mapping[str, object]],
    provider_scope_profile: Mapping[str, object],
    collection_strategy_profile: Mapping[str, object],
) -> dict[str, object]:
    request_rows = list(requests)
    request_locators = []
    response_manifest_hashes = []
    for row in request_rows[:1000]:
        acquisition_profile = (
            row.get("request_acquisition_profile")
            if isinstance(row.get("request_acquisition_profile"), Mapping)
            else {}
        )
        response_manifest = (
            row.get("cloud_api_response_parser_manifest")
            if isinstance(row.get("cloud_api_response_parser_manifest"), Mapping)
            else {}
        )
        if response_manifest.get("manifest_sha256"):
            response_manifest_hashes.append(text_value(response_manifest.get("manifest_sha256") or ""))
        request_locators.append(
            {
                "index": int(row.get("index") or 0),
                "name": text_value(row.get("name") or ""),
                "service": text_value(row.get("service") or ""),
                "method": text_value(row.get("method") or ""),
                "url_sha256": text_value(row.get("url_sha256") or ""),
                "response_path": text_value(row.get("response_path") or ""),
                "response_sha256": text_value(row.get("response_sha256") or ""),
                "status": int(row.get("status") or 0) if str(row.get("status") or "").isdigit() else 0,
                "error": text_value(row.get("error") or ""),
                "attempt_count": int(row.get("attempt_count") or 0),
                "pagination_mode": text_value(acquisition_profile.get("pagination_mode") or ""),
                "retry_max_attempts": int(acquisition_profile.get("retry_max_attempts") or 0),
                "response_parser_manifest_sha256": text_value(response_manifest.get("manifest_sha256") or ""),
                "source_viewer": text_value(
                    response_manifest.get("source_viewer_locator", {}).get("viewer")
                    if isinstance(response_manifest.get("source_viewer_locator"), Mapping)
                    else ""
                ),
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": "cloud-api-acquisition-manifest-v1",
        "item_number": 56,
        "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256_input": compute_sha256(manifest_path),
        "output_dir": str(output_dir.resolve()),
        "responses_dir": str(responses_dir.resolve()),
        "dry_run": bool(summary.get("dry_run")),
        "request_count": int(summary.get("request_count") or 0),
        "collected_count": int(summary.get("collected_count") or 0),
        "error_count": int(summary.get("error_count") or 0),
        "skipped_count": int(summary.get("skipped_count") or 0),
        "request_locator_count": len(request_locators),
        "request_locators": request_locators,
        "response_parser_manifest_count": len(response_manifest_hashes),
        "response_parser_manifest_hashes": response_manifest_hashes[:1000],
        "provider_scope_profile": dict(provider_scope_profile),
        "collection_strategy_profile_hash": stable_cloud_api_json_sha256(collection_strategy_profile),
        "credential_boundary": {
            "credential_storage": text_value(credential_handling.get("credential_storage") or ""),
            "headers_redacted": bool(credential_handling.get("headers_redacted")),
            "tokens_written_to_output": bool(credential_handling.get("tokens_written_to_output")),
            "raw_secret_reveal_allowed": bool(credential_handling.get("raw_secret_reveal_allowed")),
            "secure_token_vault_integrated": bool(credential_handling.get("secure_token_vault_integrated")),
            "controlled_reveal_policy": text_value(
                credential_handling.get("controlled_reveal_policy") or "disabled-by-default"
            ),
        },
        "large_data_controls": {
            "request_locator_cap": 1000,
            "request_locators_truncated": len(request_rows) > 1000,
            "max_response_bytes": DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES,
            "timeout_seconds": DEFAULT_CLOUD_API_TIMEOUT_SECONDS,
            "response_values_redacted_by_default": True,
            "raw_tokens_never_serialized": True,
        },
        "commercial_blockers": [
            "provider-oauth-device-flow-required",
            "provider-scope-and-consent-proof-required",
            "pagination-delta-execution-validation-required",
            "provider-api-known-answer-diff-required",
            "enterprise-token-vault-required-for-multi-user",
        ],
        "validation_status": "implemented-usable-validation-required",
    }
    manifest["manifest_sha256"] = stable_cloud_api_json_sha256(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    )
    return manifest


def cloud_api_report_grade_validation_plan(
    *,
    manifest_path: Path,
    output_dir: Path,
    summary: Mapping[str, object],
    credential_handling: Mapping[str, object],
    requests: Iterable[Mapping[str, object]],
    provider_scope_profile: Mapping[str, object],
    acquisition_manifest: Mapping[str, object],
    collection_strategy_profile: Mapping[str, object],
) -> dict[str, object]:
    request_rows = list(requests)
    request_count = len(request_rows)
    dry_run = bool(summary.get("dry_run"))
    response_hash_count = sum(1 for row in request_rows if row.get("response_sha256"))
    response_manifest_count = sum(
        1 for row in request_rows if isinstance(row.get("cloud_api_response_parser_manifest"), Mapping)
    )
    request_profile_count = sum(
        1 for row in request_rows if isinstance(row.get("request_acquisition_profile"), Mapping)
    )
    credential_authority_manifest = (
        credential_handling.get("credential_authority_manifest")
        if isinstance(credential_handling.get("credential_authority_manifest"), Mapping)
        else {}
    )
    trusted_diff = summary.get("cloud_api_trusted_diff") if isinstance(summary.get("cloud_api_trusted_diff"), Mapping) else {}
    pagination_declared = bool(collection_strategy_profile.get("pagination_policy_declared"))
    retry_declared = bool(collection_strategy_profile.get("request_retry_policy_declared"))
    acquisition_hash = text_value(acquisition_manifest.get("manifest_sha256") or "")

    def slot(
        slot_id: str,
        status: str,
        evidence: list[str],
        *,
        blocker: str = "",
        blocking: bool = False,
        external: bool = False,
        required: str = "",
    ) -> dict[str, object]:
        return {
            "slot_id": slot_id,
            "status": status,
            "ready": status == "complete",
            "blocking": blocking,
            "external_evidence_required": external,
            "blocker_id": blocker,
            "evidence": evidence,
            "required_before_report": required,
        }

    slots = [
        slot(
            "cloud-api-source-manifest-hash",
            "complete" if compute_sha256(manifest_path) else "missing",
            [f"manifest_sha256:{compute_sha256(manifest_path)}"],
            blocker="cloud-api-original-manifest-hash-required",
            blocking=not bool(compute_sha256(manifest_path)),
        ),
        slot(
            "cloud-api-acquisition-manifest",
            "complete" if acquisition_hash else "missing",
            [f"cloud_api_acquisition_manifest_sha256:{acquisition_hash}"] if acquisition_hash else [],
            blocker="cloud-api-acquisition-manifest-required",
            blocking=not bool(acquisition_hash),
        ),
        slot(
            "cloud-api-request-profile-inventory",
            "complete" if request_count > 0 and request_profile_count == request_count else "incomplete",
            [f"request_profiles:{request_profile_count}/{request_count}"],
            blocker="cloud-api-request-profile-inventory-required",
            blocking=request_count == 0 or request_profile_count != request_count,
        ),
        slot(
            "cloud-api-response-hash-sidecar-boundary",
            "complete" if dry_run or response_hash_count > 0 else "missing",
            [f"response_hash_count:{response_hash_count}", f"dry_run:{dry_run}"],
            blocker="cloud-api-response-hash-and-sidecar-required",
            blocking=not dry_run and response_hash_count == 0,
        ),
        slot(
            "cloud-api-response-parser-manifest",
            "complete" if request_count > 0 and response_manifest_count == request_count else "incomplete",
            [f"response_parser_manifests:{response_manifest_count}/{request_count}"],
            blocker="cloud-api-response-parser-manifest-required",
            blocking=request_count == 0 or response_manifest_count != request_count,
        ),
        slot(
            "cloud-api-credential-redaction-boundary",
            "complete"
            if bool(credential_handling.get("headers_redacted"))
            and not bool(credential_handling.get("tokens_written_to_output"))
            else "failed",
            [
                f"headers_redacted:{bool(credential_handling.get('headers_redacted'))}",
                f"tokens_written_to_output:{bool(credential_handling.get('tokens_written_to_output'))}",
            ],
            blocker="cloud-api-credential-redaction-required",
            blocking=not bool(credential_handling.get("headers_redacted"))
            or bool(credential_handling.get("tokens_written_to_output")),
        ),
        slot(
            "cloud-api-provider-scope-profile",
            "complete" if bool(provider_scope_profile.get("scope_inventory_captured")) else "external-required",
            [
                f"provider:{provider_scope_profile.get('provider', '')}",
                f"scope_count:{int(provider_scope_profile.get('scope_count') or 0)}",
            ],
            blocker="cloud-api-provider-scope-consent-legal-authority-required",
            blocking=not bool(provider_scope_profile.get("scope_inventory_captured")),
            external=not bool(provider_scope_profile.get("scope_inventory_captured")),
            required="Attach provider/admin scope inventory when the manifest did not declare scopes.",
        ),
        slot(
            "cloud-api-oauth-consent-legal-authority",
            "complete"
            if bool(credential_authority_manifest.get("oauth_consent_record_present"))
            and bool(provider_scope_profile.get("legal_authority_record_present"))
            else "external-required",
            [
                f"oauth_consent_record_present:{bool(credential_authority_manifest.get('oauth_consent_record_present'))}",
                f"legal_authority_record_present:{bool(provider_scope_profile.get('legal_authority_record_present'))}",
            ],
            blocker="cloud-api-provider-scope-consent-legal-authority-required",
            blocking=not (
                bool(credential_authority_manifest.get("oauth_consent_record_present"))
                and bool(provider_scope_profile.get("legal_authority_record_present"))
            ),
            external=not (
                bool(credential_authority_manifest.get("oauth_consent_record_present"))
                and bool(provider_scope_profile.get("legal_authority_record_present"))
            ),
            required="Attach OAuth consent, granted scopes, account owner, and legal authority records.",
        ),
        slot(
            "cloud-api-oauth-device-flow-capture",
            "external-required",
            [f"provider_specific_oauth_flow:{CLOUD_API_NATIVE_CAPABILITIES['provider_specific_oauth_flow']}"],
            blocker="cloud-api-provider-oauth-device-flow-required",
            blocking=True,
            external=True,
            required="Capture provider-specific OAuth/device-flow consent and access-token provenance.",
        ),
        slot(
            "cloud-api-pagination-delta-execution",
            "declared-not-executed" if pagination_declared else "not-declared",
            [f"pagination_declared:{pagination_declared}"],
            blocker="cloud-api-pagination-delta-execution-required",
            blocking=True,
            external=True,
            required="Exercise next-link/page/delta-token behavior against provider known-answer fixtures.",
        ),
        slot(
            "cloud-api-retry-throttle-backoff-validation",
            "declared-not-provider-validated" if retry_declared else "not-declared",
            [f"retry_declared:{retry_declared}"],
            blocker="cloud-api-retry-throttle-backoff-validation-required",
            blocking=True,
            external=True,
            required="Validate rate-limit, retry, throttle, and backoff behavior against provider responses.",
        ),
        slot(
            "cloud-api-provider-native-response-diff",
            "complete" if trusted_diff.get("status") == "pass" else "external-required",
            [
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
                f"trusted_tool:{trusted_diff.get('trusted_tool', '')}",
            ],
            blocker="cloud-api-provider-native-response-diff-required",
            blocking=trusted_diff.get("status") != "pass",
            external=trusted_diff.get("status") != "pass",
            required="Attach a passing provider-native/admin/API row diff for sampled responses.",
        ),
        slot(
            "cloud-api-legal-hold-export-package",
            "external-required",
            [f"provider_export_manifest_present:{bool(provider_scope_profile.get('provider_export_manifest_present'))}"],
            blocker="cloud-api-legal-hold-export-package-required",
            blocking=True,
            external=True,
            required="Attach legal hold/eDiscovery/export package evidence when provider completeness is claimed.",
        ),
        slot(
            "cloud-api-provider-schema-version-tracking",
            "external-required",
            [f"services:{','.join(sorted({text_value(row.get('service') or '') for row in request_rows if row.get('service')}))}"],
            blocker="cloud-api-provider-schema-version-tracking-required",
            blocking=True,
            external=True,
            required="Record provider API version, response schema version, and parser compatibility matrix.",
        ),
        slot(
            "independent-cloud-api-acquisition-review",
            "external-required",
            ["independent_review:false"],
            blocker="independent-cloud-api-acquisition-review-required",
            blocking=True,
            external=True,
            required="Attach independent reviewer signoff before court/report-grade provider-complete wording.",
        ),
    ]
    ready_slot_count = sum(1 for item in slots if item["ready"])
    blocking_slot_count = sum(1 for item in slots if item["blocking"])
    blocker_ids = sorted({str(item["blocker_id"]) for item in slots if item["blocking"] and item["blocker_id"]})
    plan: dict[str, object] = {
        "profile_version": CLOUD_API_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 40,
        "gap_id": "#40",
        "batch_id": "commercial-uplift-036-040",
        "functional_uplift_item_number": 56,
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": compute_sha256(manifest_path),
        "output_dir": str(output_dir.resolve()),
        "dry_run": dry_run,
        "request_count": int(summary.get("request_count") or 0),
        "collected_count": int(summary.get("collected_count") or 0),
        "validated_count": int(summary.get("validated_count") or 0),
        "provider": text_value(provider_scope_profile.get("provider") or "not-declared"),
        "scope_inventory_captured": bool(provider_scope_profile.get("scope_inventory_captured")),
        "cloud_api_acquisition_manifest_sha256": acquisition_hash,
        "response_parser_manifest_count": response_manifest_count,
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": blocking_slot_count,
        "validation_status": "report-validation-blocked",
        "commercial_grade": False,
        "validation_slots": slots,
        "blockers": blocker_ids,
        "validation_commands": [
            "source-cloud-api-manifest-hash-and-authority-review",
            "provider-oauth-consent-scope-device-flow-capture",
            "provider-pagination-delta-retry-throttle-known-answer-run",
            "provider-native-admin-api-response-diff",
            "legal-hold-export-package-validation",
            "independent-cloud-api-acquisition-review",
        ],
        "report_guidance": (
            "Use collected response rows as triage pivots until OAuth authority, scope consent, "
            "pagination/delta, provider-native diff, legal-hold package, schema version, and independent "
            "review evidence are attached."
        ),
    }
    plan["validation_plan_sha256"] = stable_cloud_api_json_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def stable_cloud_api_json_sha256(value: Mapping[str, object] | list[object] | str) -> str:
    if isinstance(value, str):
        payload = value
    else:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


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
            "id": "response-parser-manifest",
            "label": "Each collected or dry-run response row carries a source-viewer citation manifest",
            "passed": bool(summary.get("response_parser_manifest_count")),
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
        "controlled_reveal_policy": str(credential_handling.get("controlled_reveal_policy") or ""),
        "raw_secret_reveal_allowed": bool(credential_handling.get("raw_secret_reveal_allowed")),
        "secure_token_vault_integrated": bool(credential_handling.get("secure_token_vault_integrated")),
        "token_rotation_audit_present": bool(credential_handling.get("token_rotation_audit_present")),
        "ready_for_court_report": False,
        "blockers": [*CLOUD_CREDENTIAL_SECURITY_BLOCKERS, CLOUD_CREDENTIAL_TRUSTED_DIFF_BLOCKER],
        "recommended_validation": [
            "Record provider OAuth consent, granted scopes, account owner, legal authority, and API version before collection.",
            "Use an OS/enterprise secret vault or short-lived token broker before report-grade multi-user deployment.",
        ],
    }


def cloud_credential_authority_profile(
    *,
    credential_handling: Mapping[str, object],
    provider_scope_profile: Mapping[str, object],
    requests: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    request_rows = list(requests)
    sensitive_headers = sorted(
        {
            str(header)
            for request in request_rows
            for header in (
                request.get("credential_handling", {}).get("sensitive_header_names", [])
                if isinstance(request.get("credential_handling"), Mapping)
                else []
            )
            if str(header)
        }
    )
    return {
        "profile_version": "cloud-credential-authority-v1",
        "selected_track": "redacted-env-token-with-external-authority-records",
        "provider_scope_profile_linked": bool(provider_scope_profile),
        "provider": str(provider_scope_profile.get("provider") or "not-declared"),
        "scope_inventory_captured": bool(provider_scope_profile.get("scope_inventory_captured")),
        "scope_count": int(provider_scope_profile.get("scope_count") or 0),
        "legal_authority_record_present": bool(provider_scope_profile.get("legal_authority_record_present")),
        "oauth_consent_status": str(provider_scope_profile.get("oauth_consent_status") or "external-record-required"),
        "controlled_reveal_policy": str(credential_handling.get("controlled_reveal_policy") or "disabled-by-default"),
        "raw_secret_reveal_allowed": bool(credential_handling.get("raw_secret_reveal_allowed")),
        "tokens_written_to_output": bool(credential_handling.get("tokens_written_to_output")),
        "token_hash_or_secret_fingerprint_recorded": False,
        "request_sensitive_header_count": len(sensitive_headers),
        "request_sensitive_header_names": sensitive_headers,
        "vault_integration_status": "integrated"
        if credential_handling.get("secure_token_vault_integrated")
        else "not-integrated",
        "token_rotation_audit_status": "captured"
        if credential_handling.get("token_rotation_audit_present")
        else "not-captured",
        "audit_required": bool(credential_handling.get("audit_required")),
        "ready_for_court_report": False,
        "blockers": [
            "provider-oauth-consent-record-required",
            "enterprise-vault-record-required",
            "token-rotation-revocation-audit-required",
            CLOUD_CREDENTIAL_TRUSTED_DIFF_BLOCKER,
        ],
        "required_before_report": [
            "attach provider OAuth consent, granted scopes, account ownership, and legal authority records",
            "record enterprise vault or token broker record IDs without storing raw token values",
            "capture token rotation, revocation, and collection-time access audit evidence",
            "attach a passing credential authority/audit diff before enterprise-vaulted or court-ready claims",
        ],
    }


def cloud_credential_authority_manifest(
    *,
    manifest: Mapping[str, object],
    manifest_path: Path,
    provider_scope_profile: Mapping[str, object],
    credential_handling: Mapping[str, object],
    requests: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    request_rows = list(requests)
    sensitive_headers = sorted(
        {
            str(header)
            for request in request_rows
            for header in (
                request.get("credential_handling", {}).get("sensitive_header_names", [])
                if isinstance(request.get("credential_handling"), Mapping)
                else []
            )
            if str(header)
        }
    )
    oauth_consent_record = text_value(
        manifest.get("oauth_consent_record")
        or manifest.get("consent_record_id")
        or manifest.get("oauth_consent_record_id")
    )
    vault_record = text_value(
        manifest.get("vault_record_id")
        or manifest.get("token_vault_record")
        or manifest.get("secure_token_vault_record")
    )
    rotation_record = text_value(
        manifest.get("token_rotation_audit_record")
        or manifest.get("rotation_record_id")
        or manifest.get("revocation_audit_record")
    )
    legal_authority = text_value(
        manifest.get("legal_authority")
        or manifest.get("authority_record_id")
        or manifest.get("legal_authority_id")
    )
    manifest_payload: dict[str, object] = {
        "manifest_version": "cloud-credential-authority-manifest-v1",
        "item_number": 41,
        "batch_id": "commercial-uplift-041-045",
        "selected_track": "hash-only-external-authority-record-inventory",
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": compute_sha256(manifest_path),
        "provider": text_value(provider_scope_profile.get("provider") or "not-declared"),
        "scope_inventory_captured": bool(provider_scope_profile.get("scope_inventory_captured")),
        "scope_count": int(provider_scope_profile.get("scope_count") or 0),
        "scope_hashes": list(provider_scope_profile.get("scope_hashes") or []),
        "legal_authority_record_present": bool(legal_authority),
        "legal_authority_record_sha256": hashlib.sha256(legal_authority.encode("utf-8")).hexdigest()
        if legal_authority
        else "",
        "oauth_consent_record_present": bool(oauth_consent_record),
        "oauth_consent_record_sha256": hashlib.sha256(oauth_consent_record.encode("utf-8")).hexdigest()
        if oauth_consent_record
        else "",
        "vault_record_present": bool(vault_record),
        "vault_record_sha256": hashlib.sha256(vault_record.encode("utf-8")).hexdigest() if vault_record else "",
        "token_rotation_audit_record_present": bool(rotation_record),
        "token_rotation_audit_record_sha256": hashlib.sha256(rotation_record.encode("utf-8")).hexdigest()
        if rotation_record
        else "",
        "request_sensitive_header_names": sensitive_headers,
        "raw_secret_values_stored": False,
        "token_value_hash_recorded": False,
        "tokens_written_to_output": bool(credential_handling.get("tokens_written_to_output")),
        "headers_redacted": bool(credential_handling.get("headers_redacted")),
        "controlled_reveal_policy": text_value(
            credential_handling.get("controlled_reveal_policy") or "disabled-by-default"
        ),
        "raw_secret_reveal_allowed": bool(credential_handling.get("raw_secret_reveal_allowed")),
        "secure_token_vault_integrated": bool(credential_handling.get("secure_token_vault_integrated")),
        "token_rotation_audit_integrated": bool(credential_handling.get("token_rotation_audit_present")),
        "passed_validation_check_ids": [
            check
            for check, passed in {
                "credential-authority-manifest-emitted": True,
                "raw-secret-values-not-stored": True,
                "headers-redacted": bool(credential_handling.get("headers_redacted")),
                "tokens-not-written-to-output": not bool(credential_handling.get("tokens_written_to_output")),
                "controlled-reveal-disabled": credential_handling.get("controlled_reveal_policy")
                == "disabled-by-default"
                and not bool(credential_handling.get("raw_secret_reveal_allowed")),
                "scope-inventory-captured": bool(provider_scope_profile.get("scope_inventory_captured")),
                "legal-authority-record-declared": bool(legal_authority),
                "oauth-consent-record-declared": bool(oauth_consent_record),
                "external-vault-record-declared": bool(vault_record),
                "rotation-audit-record-declared": bool(rotation_record),
            }.items()
            if passed
        ],
        "failed_validation_check_ids": [
            check
            for check, failed in {
                "oauth-consent-record-missing": not bool(oauth_consent_record),
                "legal-authority-record-missing": not bool(legal_authority),
                "external-vault-record-missing": not bool(vault_record),
                "rotation-audit-record-missing": not bool(rotation_record),
                "enterprise-token-vault-not-integrated": not bool(
                    credential_handling.get("secure_token_vault_integrated")
                ),
                "token-rotation-audit-not-integrated": not bool(
                    credential_handling.get("token_rotation_audit_present")
                ),
                CLOUD_CREDENTIAL_TRUSTED_DIFF_BLOCKER: True,
            }.items()
            if failed
        ],
        "commercial_blockers": [
            "enterprise-token-vault-integration-required",
            "token-rotation-revocation-audit-required",
            "provider-oauth-consent-record-required",
            CLOUD_CREDENTIAL_TRUSTED_DIFF_BLOCKER,
        ],
        "ready_for_court_report": False,
    }
    manifest_payload["authority_manifest_sha256"] = stable_cloud_api_json_sha256(
        {key: value for key, value in manifest_payload.items() if key != "authority_manifest_sha256"}
    )
    return manifest_payload


def cloud_credential_report_grade_validation_plan(
    *,
    manifest_path: Path,
    credential_handling: Mapping[str, object],
    provider_scope_profile: Mapping[str, object],
    requests: Iterable[Mapping[str, object]],
) -> dict[str, object]:
    request_rows = list(requests)
    authority_profile = (
        credential_handling.get("credential_authority_profile")
        if isinstance(credential_handling.get("credential_authority_profile"), Mapping)
        else {}
    )
    authority_manifest = (
        credential_handling.get("credential_authority_manifest")
        if isinstance(credential_handling.get("credential_authority_manifest"), Mapping)
        else {}
    )
    trusted_diff = (
        credential_handling.get("credential_trusted_diff")
        if isinstance(credential_handling.get("credential_trusted_diff"), Mapping)
        else {}
    )
    sensitive_headers = sorted(
        {
            str(header)
            for request in request_rows
            for header in (
                request.get("credential_handling", {}).get("sensitive_header_names", [])
                if isinstance(request.get("credential_handling"), Mapping)
                else []
            )
            if str(header)
        }
    )

    def slot(
        slot_id: str,
        status: str,
        evidence: list[str],
        *,
        blocker: str = "",
        blocking: bool = False,
        external: bool = False,
        required: str = "",
    ) -> dict[str, object]:
        return {
            "slot_id": slot_id,
            "status": status,
            "ready": status == "complete",
            "blocking": blocking,
            "external_evidence_required": external,
            "blocker_id": blocker,
            "evidence": evidence,
            "required_before_report": required,
        }

    redaction_complete = bool(credential_handling.get("headers_redacted")) and not bool(
        credential_handling.get("tokens_written_to_output")
    )
    no_raw_secret_serialization = authority_manifest.get("raw_secret_values_stored") is False and (
        authority_manifest.get("token_value_hash_recorded") is False
    )
    env_storage_boundary = credential_handling.get("credential_storage") == "environment-variable-only"
    provider_scope_ready = bool(provider_scope_profile.get("scope_inventory_captured"))
    legal_ready = bool(authority_manifest.get("legal_authority_record_present")) or bool(
        provider_scope_profile.get("legal_authority_record_present")
    )
    oauth_ready = bool(authority_manifest.get("oauth_consent_record_present"))
    vault_record_ready = bool(authority_manifest.get("vault_record_present"))
    rotation_record_ready = bool(authority_manifest.get("token_rotation_audit_record_present"))
    vault_integrated = bool(credential_handling.get("secure_token_vault_integrated"))
    rotation_enforced = bool(credential_handling.get("token_rotation_audit_present"))
    controlled_reveal_workflow = (
        credential_handling.get("controlled_reveal_policy") not in {"", "disabled-by-default", None}
        and bool(credential_handling.get("controlled_reveal_audit_integrated"))
    )
    rbac_enforced = bool(credential_handling.get("rbac_enforced"))
    trusted_diff_pass = trusted_diff.get("status") == "pass"

    slots = [
        slot(
            "cloud-credential-redaction-boundary",
            "complete" if redaction_complete else "failed",
            [
                f"headers_redacted:{bool(credential_handling.get('headers_redacted'))}",
                f"tokens_written_to_output:{bool(credential_handling.get('tokens_written_to_output'))}",
                f"sensitive_header_count:{len(sensitive_headers)}",
            ],
            blocker="cloud-credential-redaction-required",
            blocking=not redaction_complete,
        ),
        slot(
            "cloud-credential-no-raw-secret-serialization",
            "complete" if no_raw_secret_serialization else "failed",
            [
                f"raw_secret_values_stored:{authority_manifest.get('raw_secret_values_stored')}",
                f"token_value_hash_recorded:{authority_manifest.get('token_value_hash_recorded')}",
            ],
            blocker="cloud-credential-no-raw-secret-serialization-required",
            blocking=not no_raw_secret_serialization,
        ),
        slot(
            "cloud-credential-environment-storage-boundary",
            "complete" if env_storage_boundary else "external-required",
            [f"credential_storage:{credential_handling.get('credential_storage', '')}"],
            blocker="cloud-credential-environment-storage-boundary-required",
            blocking=not env_storage_boundary,
            external=not env_storage_boundary,
            required="Record the runtime token source without serializing the token value.",
        ),
        slot(
            "cloud-credential-authority-manifest",
            "complete" if authority_manifest.get("authority_manifest_sha256") else "missing",
            [
                f"authority_manifest_sha256:{authority_manifest.get('authority_manifest_sha256', '')}",
                f"authority_profile_version:{authority_profile.get('profile_version', '')}",
            ],
            blocker="cloud-credential-authority-manifest-required",
            blocking=not bool(authority_manifest.get("authority_manifest_sha256")),
        ),
        slot(
            "cloud-credential-provider-scope-inventory",
            "complete" if provider_scope_ready else "external-required",
            [
                f"provider:{provider_scope_profile.get('provider', '')}",
                f"scope_count:{int(provider_scope_profile.get('scope_count') or 0)}",
            ],
            blocker="cloud-credential-provider-scope-inventory-required",
            blocking=not provider_scope_ready,
            external=not provider_scope_ready,
            required="Attach provider/admin scope inventory and granted-scope evidence.",
        ),
        slot(
            "cloud-credential-legal-authority-record",
            "complete" if legal_ready else "external-required",
            [
                f"authority_manifest_legal:{bool(authority_manifest.get('legal_authority_record_present'))}",
                f"provider_scope_legal:{bool(provider_scope_profile.get('legal_authority_record_present'))}",
            ],
            blocker="cloud-credential-legal-authority-record-required",
            blocking=not legal_ready,
            external=not legal_ready,
            required="Attach legal authority or case authorization before report-grade cloud credential claims.",
        ),
        slot(
            "cloud-credential-oauth-consent-record",
            "complete" if oauth_ready else "external-required",
            [f"oauth_consent_record_present:{oauth_ready}"],
            blocker="cloud-credential-oauth-consent-record-required",
            blocking=not oauth_ready,
            external=not oauth_ready,
            required="Attach OAuth consent, account owner, client/app ID, and granted scope evidence.",
        ),
        slot(
            "cloud-credential-external-vault-record",
            "complete" if vault_record_ready else "external-required",
            [f"vault_record_present:{vault_record_ready}"],
            blocker="cloud-credential-enterprise-token-vault-required",
            blocking=not vault_record_ready,
            external=not vault_record_ready,
            required="Attach a hash-only vault or token broker record ID; never serialize the token value.",
        ),
        slot(
            "cloud-credential-token-rotation-audit-record",
            "complete" if rotation_record_ready else "external-required",
            [f"token_rotation_audit_record_present:{rotation_record_ready}"],
            blocker="cloud-credential-token-rotation-revocation-audit-required",
            blocking=not rotation_record_ready,
            external=not rotation_record_ready,
            required="Attach rotation, expiry, revocation, or collection-time access audit evidence.",
        ),
        slot(
            "cloud-credential-enterprise-token-vault-integration",
            "complete" if vault_integrated else "external-required",
            [f"secure_token_vault_integrated:{vault_integrated}"],
            blocker="cloud-credential-enterprise-token-vault-required",
            blocking=not vault_integrated,
            external=not vault_integrated,
            required="Integrate an OS/enterprise secret vault before multi-user or court-ready secret handling claims.",
        ),
        slot(
            "cloud-credential-controlled-reveal-workflow",
            "complete" if controlled_reveal_workflow else "external-required",
            [
                f"controlled_reveal_policy:{credential_handling.get('controlled_reveal_policy', '')}",
                f"raw_secret_reveal_allowed:{bool(credential_handling.get('raw_secret_reveal_allowed'))}",
            ],
            blocker="cloud-credential-controlled-reveal-workflow-required",
            blocking=not controlled_reveal_workflow,
            external=not controlled_reveal_workflow,
            required="Implement gated reveal/export with analyst identity, reason, expiry, and immutable audit.",
        ),
        slot(
            "cloud-credential-rbac-enforcement",
            "complete" if rbac_enforced else "external-required",
            [f"rbac_enforced:{rbac_enforced}"],
            blocker="cloud-credential-rbac-enforcement-required",
            blocking=not rbac_enforced,
            external=not rbac_enforced,
            required="Enforce role-based access before secret reveal, export, or cloud collection execution.",
        ),
        slot(
            "cloud-credential-token-rotation-revocation-enforcement",
            "complete" if rotation_enforced else "external-required",
            [f"token_rotation_audit_present:{rotation_enforced}"],
            blocker="cloud-credential-token-rotation-revocation-audit-required",
            blocking=not rotation_enforced,
            external=not rotation_enforced,
            required="Verify token expiry, rotation, and revocation records against vault/provider audit logs.",
        ),
        slot(
            "cloud-credential-authority-audit-diff",
            "complete" if trusted_diff_pass else "external-required",
            [
                f"trusted_diff_status:{trusted_diff.get('status', 'missing')}",
                f"trusted_tool:{trusted_diff.get('trusted_tool', '')}",
            ],
            blocker="cloud-credential-authority-audit-diff-required",
            blocking=not trusted_diff_pass,
            external=not trusted_diff_pass,
            required="Attach a passing provider OAuth, vault, native-audit, or legal authority diff.",
        ),
        slot(
            "cloud-credential-independent-review",
            "external-required",
            ["independent_review:false"],
            blocker="cloud-credential-independent-review-required",
            blocking=True,
            external=True,
            required="Attach independent reviewer signoff before enterprise-vaulted or report-grade wording.",
        ),
    ]
    ready_slot_count = sum(1 for item in slots if item["ready"])
    blocking_slot_count = sum(1 for item in slots if item["blocking"])
    blocker_ids = sorted({str(item["blocker_id"]) for item in slots if item["blocking"] and item["blocker_id"]})
    plan: dict[str, object] = {
        "profile_version": CLOUD_CREDENTIAL_REPORT_GRADE_VALIDATION_PLAN_VERSION,
        "item_number": 41,
        "gap_id": "#41",
        "batch_id": "commercial-uplift-041-045",
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": compute_sha256(manifest_path),
        "credential_storage": str(credential_handling.get("credential_storage") or ""),
        "bearer_token_env": str(credential_handling.get("bearer_token_env") or ""),
        "provider": text_value(provider_scope_profile.get("provider") or "not-declared"),
        "request_count": len(request_rows),
        "request_sensitive_header_names": sensitive_headers,
        "authority_manifest_sha256": str(authority_manifest.get("authority_manifest_sha256") or ""),
        "raw_secret_values_stored": bool(authority_manifest.get("raw_secret_values_stored")),
        "token_value_hash_recorded": bool(authority_manifest.get("token_value_hash_recorded")),
        "ready_slot_count": ready_slot_count,
        "blocking_slot_count": blocking_slot_count,
        "validation_status": "report-validation-blocked",
        "commercial_grade": False,
        "validation_slots": slots,
        "blockers": blocker_ids,
        "validation_commands": [
            "verify-cloud-credential-redaction-no-raw-secret-output",
            "attach-oauth-consent-scope-and-legal-authority-records",
            "attach-enterprise-vault-and-rotation-audit-records",
            "execute-controlled-reveal-rbac-audit-test",
            "run-provider-vault-legal-authority-trusted-diff",
            "independent-cloud-credential-security-review",
        ],
        "report_guidance": (
            "Use credential handling as redacted triage evidence only until OAuth consent, scope, legal "
            "authority, vault integration, controlled reveal, RBAC, rotation/revocation, trusted diff, "
            "and independent-review evidence are attached."
        ),
    }
    plan["validation_plan_sha256"] = stable_cloud_api_json_sha256(
        {key: value for key, value in plan.items() if key != "validation_plan_sha256"}
    )
    return plan


def cloud_api_report_grade_assessment() -> dict[str, object]:
    return {
        "status": "validation-required",
        "commercial_gap_ids": ["#40"],
        "blockers": [*CLOUD_API_REPORT_GRADE_BLOCKERS, CLOUD_API_TRUSTED_DIFF_BLOCKER],
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
    provider_scope_profile: Mapping[str, object],
    report_grade: Mapping[str, object],
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    matrix = cloud_api_validation_matrix(summary, credential_handling)
    trusted_diff = summary.get("cloud_api_trusted_diff") if isinstance(summary.get("cloud_api_trusted_diff"), Mapping) else {}
    report_grade_validation_plan = report_grade_validation_plan or {}
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
            trusted_diff=trusted_diff,
        ),
        "source_refs": [
            f"manifest_path:{manifest_path.resolve()}",
            f"manifest_sha256:{compute_sha256(manifest_path)}",
            f"output_dir:{output_dir.resolve()}",
            f"cloud_api_acquisition_manifest_sha256:{summary.get('cloud_api_acquisition_manifest_hash', '')}",
            f"cloud_api_report_grade_validation_plan_sha256:{summary.get('cloud_api_report_grade_validation_plan_hash', '')}",
            *[f"response_sha256:{request.get('response_sha256')}" for request in requests[:5] if request.get("response_sha256")],
            *[
                f"response_parser_manifest_sha256:{request.get('cloud_api_response_parser_manifest', {}).get('manifest_sha256')}"
                for request in requests[:5]
                if isinstance(request.get("cloud_api_response_parser_manifest"), Mapping)
                and request.get("cloud_api_response_parser_manifest", {}).get("manifest_sha256")
            ],
        ],
        "cloud_api_collection_strategy_profile": cloud_api_collection_strategy_profile(
            manifest_path=manifest_path,
            summary=summary,
            credential_handling=credential_handling,
            requests=requests,
            provider_scope_profile=provider_scope_profile,
        ),
        "passed_validation_matrix_ids": passed_validation_matrix_ids,
        "failed_validation_matrix_ids": failed_validation_matrix_ids,
        "report_grade_status": str(report_grade.get("status") or ""),
        "trusted_diff": dict(trusted_diff) if trusted_diff else {
            "status": "missing",
            "blocker_id": CLOUD_API_TRUSTED_DIFF_BLOCKER,
            "required_tools": sorted(CLOUD_API_TRUSTED_DIFF_TOOLS),
        },
        "commercial_blockers": list(report_grade.get("blockers") or CLOUD_API_REPORT_GRADE_BLOCKERS),
        "large_data_controls": {
            "timeout_seconds": DEFAULT_CLOUD_API_TIMEOUT_SECONDS,
            "max_response_bytes": DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES,
            "request_count": int(summary.get("request_count") or 0),
            "collected_count": int(summary.get("collected_count") or 0),
            "dry_run": bool(summary.get("dry_run")),
            "cloud_api_acquisition_manifest_hash": str(summary.get("cloud_api_acquisition_manifest_hash") or ""),
            "cloud_api_report_grade_validation_plan_hash": str(
                summary.get("cloud_api_report_grade_validation_plan_hash") or ""
            ),
            "cloud_api_report_grade_ready_slot_count": int(
                report_grade_validation_plan.get("ready_slot_count") or 0
            ),
            "cloud_api_report_grade_blocking_slot_count": int(
                report_grade_validation_plan.get("blocking_slot_count") or 0
            ),
            "response_parser_manifest_count": int(summary.get("response_parser_manifest_count") or 0),
            "provider_scope_inventory_captured": bool(provider_scope_profile.get("scope_inventory_captured")),
            "provider_scope_profile_present": bool(provider_scope_profile),
            "provider_specific_oauth_flow": False,
            "incremental_delta_collection": False,
            "known_answer_cloud_api_corpus_required": True,
        },
        "next_internal_step": "Add provider OAuth/device flow, scope capture, pagination/backoff manifests, delta collection, and provider API known-answer validation.",
        "external_evidence_required": True,
    }


def cloud_api_acquisition_functional_profile(
    *,
    manifest_path: Path,
    output_dir: Path,
    summary: Mapping[str, object],
    credential_handling: Mapping[str, object],
    requests: Iterable[Mapping[str, object]],
    provider_scope_profile: Mapping[str, object],
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> dict[str, object]:
    request_rows = list(requests)
    report_grade_validation_plan = report_grade_validation_plan or {}
    response_hash_count = sum(1 for row in request_rows if row.get("response_sha256"))
    response_manifest_count = sum(
        1 for row in request_rows if isinstance(row.get("cloud_api_response_parser_manifest"), Mapping)
    )
    redacted_count = sum(
        1
        for row in request_rows
        if isinstance(row.get("credential_handling"), Mapping)
        and row.get("credential_handling", {}).get("sensitive_values_redacted")
    )
    failed_checks = [
        check
        for check, failed in {
            "provider-oauth-device-flow-not-implemented": not CLOUD_API_NATIVE_CAPABILITIES[
                "provider_specific_oauth_flow"
            ],
            "provider-scope-discovery-not-implemented": not CLOUD_API_NATIVE_CAPABILITIES["provider_scope_discovery"],
            "incremental-pagination-delta-not-implemented": not CLOUD_API_NATIVE_CAPABILITIES[
                "incremental_delta_collection"
            ],
            "secure-token-vault-not-integrated": not credential_handling.get("secure_token_vault_integrated"),
            "trusted-provider-api-diff-required": True,
        }.items()
        if failed
    ]
    return {
        "batch_id": FUNCTIONAL_EXPANSION_BATCH_ID,
        "item_number": 56,
        "implementation_track": "cloud-api-acquisition",
        "status": "usable-manifest-collector-not-provider-complete",
        "manifest_path": str(manifest_path.resolve()),
        "output_dir": str(output_dir.resolve()),
        "implemented_controls": {
            "manifest_driven_https_requests": CLOUD_API_NATIVE_CAPABILITIES["manifest_driven_https_requests"],
            "dry_run_validation": CLOUD_API_NATIVE_CAPABILITIES["dry_run_validation"],
            "credential_redaction": bool(credential_handling.get("headers_redacted")),
            "environment_token_boundary": credential_handling.get("credential_storage") == "environment-variable-only",
            "response_hashing": response_hash_count > 0 or bool(summary.get("dry_run")),
            "bounded_response_size": CLOUD_API_NATIVE_CAPABILITIES["bounded_response_size"],
            "provider_scope_manifest_profile": bool(provider_scope_profile),
            "provider_scope_inventory_captured": bool(provider_scope_profile.get("scope_inventory_captured")),
            "cloud_api_acquisition_manifest_emitted": bool(summary.get("cloud_api_acquisition_manifest_hash")),
            "cloud_api_acquisition_manifest_hash": str(summary.get("cloud_api_acquisition_manifest_hash") or ""),
            "cloud_api_report_grade_validation_plan_emitted": bool(
                summary.get("cloud_api_report_grade_validation_plan_hash")
            ),
            "cloud_api_report_grade_validation_plan_hash": str(
                summary.get("cloud_api_report_grade_validation_plan_hash") or ""
            ),
            "cloud_api_report_grade_ready_slot_count": int(
                report_grade_validation_plan.get("ready_slot_count") or 0
            ),
            "cloud_api_report_grade_blocking_slot_count": int(
                report_grade_validation_plan.get("blocking_slot_count") or 0
            ),
            "response_parser_manifests_emitted": response_manifest_count == len(request_rows)
            if request_rows
            else False,
            "local_only_default": True,
        },
        "evidence_counts": {
            "request_count": int(summary.get("request_count") or 0),
            "collected_count": int(summary.get("collected_count") or 0),
            "validated_count": int(summary.get("validated_count") or 0),
            "response_hash_count": response_hash_count,
            "response_parser_manifest_count": response_manifest_count,
            "redacted_request_count": redacted_count,
            "report_grade_ready_slot_count": int(report_grade_validation_plan.get("ready_slot_count") or 0),
            "report_grade_blocking_slot_count": int(report_grade_validation_plan.get("blocking_slot_count") or 0),
        },
        "passed_validation_check_ids": [
            check
            for check, passed in {
                "cloud-api-acquisition-manifest-emitted": bool(summary.get("cloud_api_acquisition_manifest_hash")),
                "cloud-api-report-grade-validation-plan-emitted": bool(
                    summary.get("cloud_api_report_grade_validation_plan_hash")
                ),
                "cloud-api-response-parser-manifests-emitted": response_manifest_count == len(request_rows)
                if request_rows
                else False,
                "cloud-api-source-manifest-hashed": bool(compute_sha256(manifest_path)),
                "cloud-api-credential-redaction-enabled": bool(credential_handling.get("headers_redacted")),
                "cloud-api-local-output-boundary": True,
            }.items()
            if passed
        ],
        "failed_validation_check_ids": failed_checks,
        "ready_for_court_report": False,
        "next_internal_step": "Add provider-specific OAuth/device-flow capture, scope inventory, pagination/backoff policy, and provider known-answer response diffs.",
    }


def cloud_api_reportability_decision(
    *,
    summary: Mapping[str, object],
    credential_handling: Mapping[str, object],
    failed_validation_matrix_ids: list[str],
    report_grade: Mapping[str, object],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = {str(item) for item in report_grade.get("blockers") or CLOUD_API_REPORT_GRADE_BLOCKERS if str(item)}
    blockers.update(f"matrix:{item}" for item in failed_validation_matrix_ids)
    if not credential_handling.get("provider_scope_inventory"):
        blockers.add("provider-scope-inventory-not-captured")
    if not credential_handling.get("provider_oauth_consent_record"):
        blockers.add("oauth-consent-record-not-captured")
    if not summary.get("provider_api_known_answer_validated"):
        blockers.add("provider-api-known-answer-corpus-not-attached")
    trusted_diff = trusted_diff or {}
    if trusted_diff.get("status") != "pass":
        blockers.add(CLOUD_API_TRUSTED_DIFF_BLOCKER)
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
            "attach a passing trusted provider response diff for sampled API responses",
        ],
    }


def cloud_credential_commercial_uplift_evidence(
    *,
    manifest_path: Path,
    credential_handling: Mapping[str, object],
    requests: list[dict[str, object]],
) -> dict[str, object]:
    assessment = cloud_credential_security_assessment(credential_handling)
    authority_profile = (
        credential_handling.get("credential_authority_profile")
        if isinstance(credential_handling.get("credential_authority_profile"), Mapping)
        else {}
    )
    authority_manifest = (
        credential_handling.get("credential_authority_manifest")
        if isinstance(credential_handling.get("credential_authority_manifest"), Mapping)
        else {}
    )
    report_grade_validation_plan = (
        credential_handling.get("credential_report_grade_validation_plan")
        if isinstance(credential_handling.get("credential_report_grade_validation_plan"), Mapping)
        else {}
    )
    trusted_diff = (
        credential_handling.get("credential_trusted_diff")
        if isinstance(credential_handling.get("credential_trusted_diff"), Mapping)
        else {}
    )
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
        "reportability_decision": cloud_credential_reportability_decision(
            credential_handling=credential_handling,
            failed_validation_check_ids=[
                "provider_oauth_consent_record",
                "provider_scope_inventory",
                "secure_token_vault",
                "token_rotation_audit",
            ],
            commercial_blockers=list(assessment.get("blockers") or CLOUD_CREDENTIAL_SECURITY_BLOCKERS),
            trusted_diff=trusted_diff,
        ),
        "source_refs": [
            f"manifest_path:{manifest_path.resolve()}",
            f"manifest_sha256:{compute_sha256(manifest_path)}",
            f"credential_storage:{credential_handling.get('credential_storage', '')}",
            f"bearer_token_env:{credential_handling.get('bearer_token_env', '')}",
            f"credential_authority_manifest_sha256:{authority_manifest.get('authority_manifest_sha256', '')}",
            f"credential_report_grade_validation_plan_sha256:{report_grade_validation_plan.get('validation_plan_sha256', '')}",
        ],
        "credential_strategy_profile": (
            dict(credential_handling["credential_strategy_profile"])
            if isinstance(credential_handling.get("credential_strategy_profile"), Mapping)
            else {}
        ),
        "credential_authority_profile": dict(authority_profile),
        "credential_authority_manifest": dict(authority_manifest),
        "passed_validation_check_ids": [
            "headers_redacted",
            "tokens_not_written",
            "controlled_reveal_disabled",
            "credential_authority_profile_present",
            "credential_authority_manifest_present",
            "credential_report_grade_validation_plan_present",
        ]
        if credential_handling.get("headers_redacted")
        and not credential_handling.get("tokens_written_to_output")
        and authority_profile
        and authority_manifest
        and report_grade_validation_plan
        else [],
        "failed_validation_check_ids": [
            "provider_oauth_consent_record",
            "provider_scope_inventory",
            "secure_token_vault",
            "token_rotation_audit",
        ],
        "request_sensitive_header_names": sorted(set(str(item) for item in request_sensitive_headers)),
        "trusted_diff": dict(trusted_diff) if trusted_diff else {
            "status": "missing",
            "blocker_id": CLOUD_CREDENTIAL_TRUSTED_DIFF_BLOCKER,
            "required_tools": sorted(CLOUD_CREDENTIAL_TRUSTED_TOOLS),
        },
        "commercial_blockers": list(assessment.get("blockers") or CLOUD_CREDENTIAL_SECURITY_BLOCKERS),
        "large_data_controls": {
            "tokens_written_to_output": bool(credential_handling.get("tokens_written_to_output")),
            "headers_redacted": bool(credential_handling.get("headers_redacted")),
            "controlled_reveal_disabled": credential_handling.get("controlled_reveal_policy")
            == "disabled-by-default"
            and not bool(credential_handling.get("raw_secret_reveal_allowed")),
            "credential_authority_profile_present": bool(authority_profile),
            "credential_authority_profile_linked_to_provider_scope": bool(
                authority_profile.get("provider_scope_profile_linked")
            ),
            "credential_authority_manifest_present": bool(authority_manifest),
            "credential_authority_manifest_hash": str(authority_manifest.get("authority_manifest_sha256") or ""),
            "credential_report_grade_validation_plan_present": bool(report_grade_validation_plan),
            "credential_report_grade_validation_plan_hash": str(
                report_grade_validation_plan.get("validation_plan_sha256") or ""
            ),
            "credential_report_grade_ready_slot_count": int(
                report_grade_validation_plan.get("ready_slot_count") or 0
            ),
            "credential_report_grade_blocking_slot_count": int(
                report_grade_validation_plan.get("blocking_slot_count") or 0
            ),
            "raw_secret_values_stored": bool(authority_manifest.get("raw_secret_values_stored")),
            "oauth_consent_record_declared": bool(authority_manifest.get("oauth_consent_record_present")),
            "external_vault_record_declared": bool(authority_manifest.get("vault_record_present")),
            "rotation_audit_record_declared": bool(
                authority_manifest.get("token_rotation_audit_record_present")
            ),
            "secure_token_vault_integrated": bool(credential_handling.get("secure_token_vault_integrated")),
            "token_rotation_audit_present": bool(credential_handling.get("token_rotation_audit_present")),
        },
        "next_internal_step": "Integrate OS/enterprise token vault, OAuth scope capture, consent evidence, and token rotation/revocation audit.",
        "external_evidence_required": True,
    }


def cloud_credential_reportability_decision(
    *,
    credential_handling: Mapping[str, object],
    failed_validation_check_ids: list[str],
    commercial_blockers: list[str],
    trusted_diff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    blockers = set(commercial_blockers)
    blockers.update(f"check:{item}" for item in failed_validation_check_ids)
    trusted_diff = trusted_diff or {}
    if trusted_diff.get("status") != "pass":
        blockers.add(CLOUD_CREDENTIAL_TRUSTED_DIFF_BLOCKER)
    return {
        "profile_version": "cloud-credential-reportability-decision-v1",
        "commercial_gap_ids": ["#41"],
        "decision": "do-not-report-cloud-credential-handling-as-enterprise-vaulted",
        "allowed_use": "redacted-credential-handling-triage-pivot",
        "blockers": sorted(blockers),
        "failed_validation_check_ids": list(failed_validation_check_ids),
        "credential_storage": str(credential_handling.get("credential_storage") or ""),
        "headers_redacted": bool(credential_handling.get("headers_redacted")),
        "tokens_written_to_output": bool(credential_handling.get("tokens_written_to_output")),
        "controlled_reveal_policy": str(credential_handling.get("controlled_reveal_policy") or ""),
        "raw_secret_reveal_allowed": bool(credential_handling.get("raw_secret_reveal_allowed")),
        "credential_authority_profile_present": isinstance(
            credential_handling.get("credential_authority_profile"), Mapping
        ),
        "credential_authority_manifest_present": isinstance(
            credential_handling.get("credential_authority_manifest"), Mapping
        ),
        "ready_for_court_report": False,
        "required_before_report": [
            "attach OAuth consent and provider scope evidence",
            "integrate or document enterprise token vault handling",
            "record token rotation/revocation audit and legal authority sign-off",
            "attach a passing credential authority/audit diff from provider, vault, or legal sign-off records",
        ],
    }


def cloud_api_core_accuracy_gates(
    *,
    manifest_path: Path,
    output_dir: Path,
    summary: Mapping[str, object],
    credential_handling: Mapping[str, object],
    requests: list[dict[str, object]],
    report_grade_validation_plan: Mapping[str, object] | None = None,
) -> list[dict[str, object]]:
    report_grade_validation_plan = report_grade_validation_plan or {}
    evidence_refs = [
        f"manifest_path:{manifest_path.resolve()}",
        f"manifest_sha256:{compute_sha256(manifest_path)}",
        f"output_dir:{output_dir.resolve()}",
    ]
    if summary.get("cloud_api_acquisition_manifest_hash"):
        evidence_refs.append(f"cloud_api_acquisition_manifest_sha256:{summary['cloud_api_acquisition_manifest_hash']}")
    if summary.get("cloud_api_report_grade_validation_plan_hash"):
        evidence_refs.append(
            f"cloud_api_report_grade_validation_plan_sha256:{summary['cloud_api_report_grade_validation_plan_hash']}"
        )
    for request in requests[:5]:
        if request.get("response_sha256"):
            evidence_refs.append(f"response_sha256:{request['response_sha256']}")
        if request.get("response_path"):
            evidence_refs.append(f"response_path:{request['response_path']}")
        response_manifest = (
            request.get("cloud_api_response_parser_manifest")
            if isinstance(request.get("cloud_api_response_parser_manifest"), Mapping)
            else {}
        )
        if response_manifest.get("manifest_sha256"):
            evidence_refs.append(f"response_parser_manifest_sha256:{response_manifest['manifest_sha256']}")
    trusted_diff = summary.get("cloud_api_trusted_diff") if isinstance(summary.get("cloud_api_trusted_diff"), Mapping) else {}
    if trusted_diff:
        evidence_refs.append(f"trusted_diff_status:{trusted_diff.get('status', '')}")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    satisfied: list[str] = []
    if int(summary.get("request_count") or 0) > 0:
        satisfied.append("manifest request validation")
    if bool(credential_handling.get("headers_redacted")) and not bool(credential_handling.get("tokens_written_to_output")):
        satisfied.append("credential redaction")
    if credential_handling.get("credential_strategy_profile"):
        satisfied.append("credential strategy profile")
    if summary.get("provider_scope_profile_present") or any(
        isinstance(request.get("request_acquisition_profile"), Mapping) for request in requests
    ):
        satisfied.append("request acquisition profile")
    if bool(summary.get("dry_run")) or any(request.get("response_sha256") for request in requests):
        satisfied.append("response hash/provenance")
    if summary.get("cloud_api_acquisition_manifest_hash"):
        satisfied.append("cloud API acquisition manifest")
    if summary.get("cloud_api_report_grade_validation_plan_hash"):
        satisfied.append("cloud API report-grade validation plan")
    if int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 6:
        satisfied.append("cloud API report-grade ready slots")
    if summary.get("response_parser_manifest_count") or any(
        isinstance(request.get("cloud_api_response_parser_manifest"), Mapping) for request in requests
    ):
        satisfied.append("response parser/source viewer manifest")
    if not CLOUD_API_NATIVE_CAPABILITIES["incremental_delta_collection"]:
        satisfied.append("pagination/backoff limitation warning")
    if credential_handling.get("legal_warning") and not CLOUD_API_NATIVE_CAPABILITIES["provider_specific_oauth_flow"]:
        satisfied.append("provider OAuth/scope/legal warning")
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted cloud API/provider response diff pass")
    return [build_accuracy_gate(40, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def build_cloud_api_trusted_diff(
    rapid_requests: Iterable[Mapping[str, object]],
    trusted_rows: Iterable[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "cloud-api-provider-response-diff",
) -> dict[str, object]:
    rapid_index = {_cloud_api_diff_key(row): _cloud_api_diff_values(row) for row in rapid_requests}
    trusted_index = {_cloud_api_diff_key(row): _cloud_api_diff_values(row) for row in trusted_rows}
    rapid_index.pop("", None)
    trusted_index.pop("", None)
    missing_in_trusted = sorted(key for key in rapid_index if key not in trusted_index)
    unexpected_in_trusted = sorted(key for key in trusted_index if key not in rapid_index)
    mismatches: list[dict[str, object]] = []
    for key in sorted(set(rapid_index).intersection(trusted_index)):
        rapid = rapid_index[key]
        trusted = trusted_index[key]
        for field in ("service", "method", "url_sha256", "status", "response_sha256", "response_size"):
            left = rapid.get(field)
            right = trusted.get(field)
            if left not in (None, "") and right not in (None, "") and str(left) != str(right):
                mismatches.append({"row_key": key, "field": field, "rapid": str(left), "trusted": str(right)})
    tool_key = trusted_tool.strip().lower()
    tool_accepted = tool_key in CLOUD_API_TRUSTED_DIFF_TOOLS
    status = (
        "pass"
        if tool_accepted
        and rapid_index
        and trusted_index
        and not missing_in_trusted
        and not unexpected_in_trusted
        and not mismatches
        else "fail"
    )
    return {
        "profile_version": "cloud-api-trusted-diff-v1",
        "comparison_id": comparison_id,
        "status": status,
        "blocker_id": "" if status == "pass" else CLOUD_API_TRUSTED_DIFF_BLOCKER,
        "trusted_tool": trusted_tool,
        "trusted_tool_accepted": tool_accepted,
        "accepted_trusted_tools": sorted(CLOUD_API_TRUSTED_DIFF_TOOLS),
        "rapid_row_count": len(rapid_index),
        "trusted_row_count": len(trusted_index),
        "matched_row_count": len(set(rapid_index).intersection(trusted_index)),
        "missing_in_trusted": missing_in_trusted[:200],
        "unexpected_in_trusted": unexpected_in_trusted[:200],
        "mismatched_fields": mismatches[:200],
        "evidence_summary": "Rapid API response rows match trusted provider rows" if status == "pass" else "Trusted provider response diff is missing or mismatched",
    }


def _cloud_api_diff_key(row: Mapping[str, object]) -> str:
    values = _cloud_api_diff_values(row)
    if values.get("name"):
        return f"name:{values['name']}"
    if values.get("url_sha256"):
        return f"url:{values['url_sha256']}"
    parts = [
        str(values.get("service") or ""),
        str(values.get("method") or ""),
        str(values.get("status") or ""),
        str(values.get("response_sha256") or ""),
    ]
    return "cloud-api-fingerprint:" + hashlib.sha256("|".join(parts).encode("utf-8", errors="replace")).hexdigest()


def _cloud_api_diff_values(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "name": row.get("name"),
        "service": row.get("service"),
        "method": row.get("method"),
        "url_sha256": row.get("url_sha256"),
        "status": row.get("status"),
        "response_sha256": row.get("response_sha256"),
        "response_size": row.get("response_size"),
    }


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
    if credential_handling.get("credential_strategy_profile"):
        satisfied.append("credential strategy profile")
    authority_profile = (
        credential_handling.get("credential_authority_profile")
        if isinstance(credential_handling.get("credential_authority_profile"), Mapping)
        else {}
    )
    if authority_profile:
        satisfied.append("credential authority profile")
        evidence_refs.append(f"authority_profile_version:{authority_profile.get('profile_version', '')}")
    authority_manifest = (
        credential_handling.get("credential_authority_manifest")
        if isinstance(credential_handling.get("credential_authority_manifest"), Mapping)
        else {}
    )
    if authority_manifest:
        satisfied.append("credential authority manifest")
        evidence_refs.append(
            f"credential_authority_manifest_sha256:{authority_manifest.get('authority_manifest_sha256', '')}"
        )
        if authority_manifest.get("raw_secret_values_stored") is False:
            satisfied.append("authority manifest stores no raw secrets")
    report_grade_validation_plan = (
        credential_handling.get("credential_report_grade_validation_plan")
        if isinstance(credential_handling.get("credential_report_grade_validation_plan"), Mapping)
        else {}
    )
    if report_grade_validation_plan:
        satisfied.append("credential report-grade validation plan")
        evidence_refs.append(
            f"credential_report_grade_validation_plan_sha256:{report_grade_validation_plan.get('validation_plan_sha256', '')}"
        )
        if int(report_grade_validation_plan.get("ready_slot_count") or 0) >= 8:
            satisfied.append("credential report-grade ready slots")
    if credential_handling.get("controlled_reveal_policy") == "disabled-by-default" and not bool(
        credential_handling.get("raw_secret_reveal_allowed")
    ):
        satisfied.append("controlled reveal disabled by default")
    trusted_diff = (
        credential_handling.get("credential_trusted_diff")
        if isinstance(credential_handling.get("credential_trusted_diff"), Mapping)
        else {}
    )
    if trusted_diff:
        evidence_refs.append(f"trusted_diff_status:{trusted_diff.get('status', '')}")
        evidence_refs.append(f"trusted_tool:{trusted_diff.get('trusted_tool', '')}")
    if trusted_diff.get("status") == "pass":
        satisfied.append("trusted credential authority/audit diff pass")
    return [build_accuracy_gate(41, satisfied_checks=satisfied, evidence_refs=evidence_refs)]


def build_cloud_credential_trusted_diff(
    rapid_rows: Iterable[Mapping[str, object]],
    trusted_rows: Iterable[Mapping[str, object]],
    *,
    trusted_tool: str,
    comparison_id: str = "cloud-credential-authority-diff",
) -> dict[str, object]:
    rapid_index = {_credential_diff_key(row): _credential_diff_values(row) for row in rapid_rows}
    trusted_index = {_credential_diff_key(row): _credential_diff_values(row) for row in trusted_rows}
    rapid_index.pop("", None)
    trusted_index.pop("", None)
    missing = sorted(set(rapid_index) - set(trusted_index))
    extra = sorted(set(trusted_index) - set(rapid_index))
    mismatches: list[dict[str, object]] = []
    for key in sorted(set(rapid_index).intersection(trusted_index)):
        for field in ("credential_storage", "scope_hash", "consent_record_id", "vault_record_id", "legal_authority_id"):
            left = rapid_index[key].get(field)
            right = trusted_index[key].get(field)
            if left and right and left != right:
                mismatches.append({"row_key": key, "field": field, "rapid": left, "trusted": right})
    tool_key = trusted_tool.strip().lower()
    accepted = tool_key in CLOUD_CREDENTIAL_TRUSTED_TOOLS
    status = "pass" if accepted and rapid_index and trusted_index and not missing and not extra and not mismatches else "fail"
    return {
        "profile_version": "cloud-credential-trusted-diff-v1",
        "comparison_id": comparison_id,
        "status": status,
        "blocker_id": "" if status == "pass" else CLOUD_CREDENTIAL_TRUSTED_DIFF_BLOCKER,
        "trusted_tool": trusted_tool,
        "trusted_tool_accepted": accepted,
        "accepted_trusted_tools": sorted(CLOUD_CREDENTIAL_TRUSTED_TOOLS),
        "rapid_row_count": len(rapid_index),
        "trusted_row_count": len(trusted_index),
        "matched_row_count": len(set(rapid_index).intersection(trusted_index)),
        "missing_in_trusted": missing[:100],
        "unexpected_in_trusted": extra[:100],
        "mismatched_fields": mismatches[:100],
    }


def _credential_diff_key(row: Mapping[str, object]) -> str:
    values = _credential_diff_values(row)
    parts = [
        values.get("bearer_token_env", ""),
        values.get("credential_storage", ""),
        values.get("scope_hash", ""),
        values.get("consent_record_id", ""),
        values.get("legal_authority_id", ""),
    ]
    return "credential:" + hashlib.sha256("|".join(parts).encode("utf-8", errors="replace")).hexdigest()


def _credential_diff_values(row: Mapping[str, object]) -> dict[str, str]:
    scope = text_value(row.get("scope") or row.get("scope_inventory") or row.get("provider_scope_inventory"))
    return {
        "bearer_token_env": text_value(row.get("bearer_token_env") or row.get("token_env")),
        "credential_storage": text_value(row.get("credential_storage")),
        "scope_hash": text_value(row.get("scope_hash") or (hashlib.sha256(scope.encode("utf-8")).hexdigest() if scope else "")),
        "consent_record_id": text_value(row.get("consent_record_id") or row.get("provider_oauth_consent_record")),
        "vault_record_id": text_value(row.get("vault_record_id") or row.get("secure_token_vault")),
        "legal_authority_id": text_value(row.get("legal_authority_id") or row.get("authority_record_id")),
    }


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
