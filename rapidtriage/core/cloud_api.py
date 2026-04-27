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

DEFAULT_CLOUD_BEARER_TOKEN_ENV = "RAPIDTRIAGE_CLOUD_BEARER_TOKEN"
DEFAULT_CLOUD_API_TIMEOUT_SECONDS = 30
DEFAULT_CLOUD_API_MAX_RESPONSE_BYTES = 50 * 1024 * 1024
ALLOWED_METHODS = {"GET", "POST"}


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
    payload = {
        "command": "cloud-collect",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": compute_sha256(manifest_path),
        "output_dir": str(output_dir.resolve()),
        "responses_dir": str(responses_dir.resolve()),
        "summary": summary,
        "requests": collected,
        "skipped": skipped,
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
