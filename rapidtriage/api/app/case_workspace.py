"""Workspace case DB for the console's cases (AXIOM adoption E1).

One ``rapidtriage-cases.db`` per server (``RAPIDTRIAGE_CASES_DB``, else next to
the run job state ``runs.json``, else a per-process temp directory) holds the
cases the examiner creates: case info, evidence list, notes and the processing
snapshot of every run started for a case. Runs keep their own per-run
``rapidtriage-case.db`` (persist step); this DB only links runs to cases.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
import threading
from collections.abc import Mapping
from pathlib import Path

from fastapi import HTTPException

from ...core.case_db import CaseDatabase
from ...core.case_db.base import now_iso
from ...core.case_db.intake import CaseIntake, ensure_intake_schema
from ...core.e01 import is_e01_path
from ...core.e01_hash import run_e01_streaming_hash
from ...core.evidence import identify_evidence
from ...core.jobs import RunJob, RunJobStore, RunRequest
from ...core.run.profiles import RUN_PROFILES
from .analyses import confine_path, extra_analysis_roots, lexical_absolute_path

LOGGER = logging.getLogger(__name__)
CASES_DB_ENV = "RAPIDTRIAGE_CASES_DB"
CASES_DB_NAME = "rapidtriage-cases.db"
SNAPSHOT_FILE_NAME = "processing-snapshot.json"
#: Linked (already finished) runs get their snapshot file here, never in the run's output folder.
LINKED_SNAPSHOT_DIR = "rapidtriage-processing-snapshots"
SNAPSHOT_VERSION = "processing-snapshot-v1"
HEX_HASH = re.compile(r"^[0-9a-fA-F]+$")
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def as_422(exc: HTTPException) -> HTTPException:
    """Path-policy errors (400/403 elsewhere) are request validation errors (422) on case routes."""
    return HTTPException(status_code=422, detail=exc.detail)


def checked_local_path(raw: str, *, label: str, confine_to_analysis_roots: bool = False) -> str:
    """Absolute local path or 422 (UNC, ``\\\\?\\``, relative, ``~``; ``RAPIDTRIAGE_ANALYSIS_ROOTS``)."""
    try:
        lexical = lexical_absolute_path(raw, label=label)
        if confine_to_analysis_roots:
            roots = extra_analysis_roots()
            if roots:
                confine_path(lexical, roots, label=label, scope="RAPIDTRIAGE_ANALYSIS_ROOTS")
    except HTTPException as exc:
        raise as_422(exc) from exc
    return lexical


def same_path(left: str, right: str) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


def expected_hash_algorithm(value: str) -> str | None:
    text = value.strip()
    if not text:
        return None
    if not HEX_HASH.fullmatch(text) or len(text) not in HASH_LENGTHS:
        raise HTTPException(status_code=422, detail="기대 해시는 MD5(32자)·SHA-1(40자)·SHA-256(64자) 16진수여야 합니다")
    return HASH_LENGTHS[len(text)]


def validate_evidence_kind(path: Path, source_type: str) -> None:
    if not path.exists():
        raise HTTPException(status_code=422, detail=f"증거 경로가 없습니다: {path}")
    if source_type == "folder" and not path.is_dir():
        raise HTTPException(status_code=422, detail="폴더 증거는 폴더 경로여야 합니다")
    if source_type == "e01" and not (path.is_file() and is_e01_path(path)):
        raise HTTPException(status_code=422, detail="E01 증거는 .E01/.Ex01 이미지 파일이어야 합니다")


def infer_source_type(path: Path) -> str:
    if path.is_dir():
        return "folder"
    if is_e01_path(path):
        return "e01"
    return "export"


def run_readiness(path: Path) -> tuple[bool, str]:
    """``(runnable, reason)``: the same gate as ``validate_run_evidence_source`` (folders always run;
    a file runs only when an adapter can read it directly), with a Korean reason for register-only."""
    try:
        if path.is_dir():
            return True, ""
        if not path.exists():
            return False, f"증거 경로가 없습니다: {path}"
        result = identify_evidence(path).to_dict()
    except OSError as exc:
        return False, f"증거를 읽을 수 없습니다: {exc}"
    if bool(result.get("can_extract")):
        return True, ""
    detected = str(result.get("detected_format") or path.suffix.lstrip(".") or "알 수 없음")
    return False, (
        f"바로 처리할 수 없는 형식입니다 ({detected}) — 증거로 등록만 됩니다. "
        "마운트하거나 압축을 푼 폴더를 증거로 추가해 실행하세요"
    )


def evidence_slug(evidence_number: str) -> str:
    text = re.sub(r"[^\w.-]+", "-", evidence_number.strip(), flags=re.UNICODE).strip("-.")
    return text[:40] or "evidence"


def build_processing_snapshot(
    *,
    run_request: RunRequest,
    case: Mapping[str, object] | None,
    evidence: Mapping[str, object] | None,
    origin: str,
    summary: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Options fixed when a run starts (or, for a linked run, as recorded by the run)."""
    profile = RUN_PROFILES.get(run_request.mode)
    summary_profile = summary.get("profile") if isinstance(summary, Mapping) else None
    if isinstance(summary_profile, Mapping):
        profile_block = {"mode": run_request.mode, **{key: summary_profile.get(key) for key in (
            "description", "keywords", "artifacts_kinds", "file_scan_categories", "docs_extract_kinds",
            "file_extract_categories")}}
    elif profile is not None:
        profile_block = {
            "mode": profile.mode,
            "description": profile.description,
            "keywords": list(profile.keywords),
            "artifacts_kinds": list(profile.artifacts_kinds),
            "file_scan_categories": list(profile.file_scan_categories),
            "docs_extract_kinds": list(profile.docs_extract_kinds),
            "file_extract_categories": list(profile.file_extract_categories),
        }
    else:
        profile_block = {"mode": run_request.mode}
    snapshot: dict[str, object] = {
        "version": SNAPSHOT_VERSION,
        "captured_at": now_iso(),
        "origin": origin,
        "case": (
            {key: case.get(key) for key in (
                "case_id", "case_number", "name", "case_type", "examiner", "requester", "citation_prefix")}
            if case else None
        ),
        "evidence": (
            {key: evidence.get(key) for key in (
                "citation_id", "evidence_number", "display_name", "source_type", "path", "hash_status")}
            if evidence else None
        ),
        "request": run_request.to_dict(),
        "profile": profile_block,
    }
    if isinstance(summary, Mapping):
        for key in ("resource_caps",):
            if isinstance(summary.get(key), Mapping):
                snapshot[key] = dict(summary[key])  # type: ignore[index]
        safety = summary.get("safety")
        if isinstance(safety, Mapping):
            snapshot["safety"] = {key: safety.get(key) for key in (
                "dry_run", "read_only", "memory_cap_bytes", "memory_cap_source", "resume_effective",
                "known_good_hash_feeds", "hide_known_good") if key in safety}
    return snapshot


class CaseWorkspace:
    """Lazily opened workspace case DB plus the evidence-hash worker threads."""

    def __init__(self, store: RunJobStore, path: Path | None = None) -> None:
        self._store = store
        self._explicit = path
        self._lock = threading.Lock()
        self._intake: CaseIntake | None = None
        self._path: Path | None = None
        self._hash_threads: dict[str, threading.Thread] = {}
        self._readiness: dict[tuple[str, int, int], tuple[bool, str]] = {}
        # Rows saved as `hashing` before this server started have no worker any more.
        self._started_at = now_iso()

    def path(self) -> Path:
        if self._path is None:
            explicit = self._explicit or (Path(os.environ[CASES_DB_ENV]) if os.environ.get(CASES_DB_ENV) else None)
            if explicit is not None:
                self._path = explicit.expanduser().resolve()
            elif self._store.state_path is not None:
                self._path = self._store.state_path.parent / CASES_DB_NAME
            else:
                self._path = Path(tempfile.mkdtemp(prefix="rapidtriage-cases-")) / CASES_DB_NAME
                LOGGER.warning(
                    "no run state path and no %s: cases are kept in a temporary DB that is lost on exit: %s",
                    CASES_DB_ENV, self._path,
                )
        return self._path

    @property
    def intake(self) -> CaseIntake:
        with self._lock:
            if self._intake is None:
                database = CaseDatabase(self.path())
                database.initialize()
                with database.connect() as connection:
                    ensure_intake_schema(connection)
                intake = CaseIntake(database.connect)
                # Hash workers do not survive a restart: store `interrupted` (audited) so the row
                # can be hashed again instead of reading `hashing` forever.
                for citation_id in intake.mark_interrupted_hashes(self._started_at):
                    LOGGER.warning("evidence hash interrupted by a server restart: %s", citation_id)
                self._intake = intake
            return self._intake

    def linked_snapshot_dir(self, run_id: str) -> Path:
        return self.path().parent / LINKED_SNAPSHOT_DIR / evidence_slug(run_id)

    def hash_dir(self, case_id: str, citation_id: str) -> Path:
        return self.path().parent / "rapidtriage-evidence-hash" / evidence_slug(case_id) / evidence_slug(citation_id)

    # --- evidence hashing ------------------------------------------------------

    def start_hash(self, *, case_id: str, citation_id: str, path: Path, expected: str) -> None:
        thread = threading.Thread(
            target=self._hash_worker,
            args=(case_id, citation_id, path, expected.strip().lower()),
            name=f"rapidtriage-evidence-hash-{citation_id}",
            daemon=True,
        )
        with self._lock:
            self._hash_threads[citation_id] = thread
        thread.start()

    def _hash_worker(self, case_id: str, citation_id: str, path: Path, expected: str) -> None:
        try:
            payload = run_e01_streaming_hash(
                source_path=path, output_dir=self.hash_dir(case_id, citation_id), overwrite=True
            )
            digests = {str(k): str(v) for k, v in dict(payload.get("digests") or {}).items()}
            if expected:
                algorithm = HASH_LENGTHS.get(len(expected), "")
                actual = digests.get(algorithm, "")
                status = "matched" if actual and actual.lower() == expected else "mismatched"
                message = f"파일 바이트 {algorithm.upper()} 기대값 {expected} / 계산값 {actual or '없음'}"
            else:
                status, message = "computed", "기대 해시가 없어 계산값만 기록했습니다 (파일·컨테이너 바이트 기준)"
            self.intake.set_evidence_hash(citation_id, status=status, message=message, digests=digests)
        except Exception as exc:  # recorded on the evidence row, never raised into the server
            LOGGER.warning("evidence hash failed for %s: %s", citation_id, exc)
            try:
                self.intake.set_evidence_hash(citation_id, status="failed", message=str(exc))
            except Exception:
                LOGGER.exception("could not record evidence hash failure for %s", citation_id)
        finally:
            with self._lock:
                self._hash_threads.pop(citation_id, None)

    def hash_running(self, citation_id: str) -> bool:
        with self._lock:
            thread = self._hash_threads.get(citation_id)
        return thread is not None and thread.is_alive()

    def join_hash_jobs(self, timeout: float = 30.0) -> None:
        """Tests: wait for the evidence-hash threads."""
        with self._lock:
            threads = list(self._hash_threads.values())
        for thread in threads:
            thread.join(timeout)

    def readiness(self, raw_path: str) -> tuple[bool, str]:
        """``run_readiness`` cached per (path, size, mtime): E01 identification probes the image."""
        path = Path(raw_path)
        try:
            stat = path.stat()
            key = (raw_path, stat.st_size, stat.st_mtime_ns)
        except OSError:
            return run_readiness(path)
        with self._lock:
            cached = self._readiness.get(key)
        if cached is None:
            cached = run_readiness(path)
            with self._lock:
                if len(self._readiness) > 512:
                    self._readiness.clear()
                self._readiness[key] = cached
        return cached

    def present_evidence(self, evidence: dict[str, object]) -> dict[str, object]:
        """Adds ``runnable``/``run_blocked_reason``; a ``hashing`` row with no live worker reads as
        ``interrupted`` (rows from before this server started are already stored that way)."""
        if (
            evidence.get("hash_status") == "hashing"
            and str(evidence.get("added_at") or "") < self._started_at
            and not self.hash_running(str(evidence["citation_id"]))
        ):
            evidence = {**evidence, "hash_status": "interrupted", "hash_status_label": "해시 계산 중단됨 (서버 재시작)"}
        runnable, reason = self.readiness(str(evidence.get("path") or ""))
        return {**evidence, "runnable": runnable, "run_blocked_reason": reason}


def run_brief(store: RunJobStore, run_id: str) -> dict[str, object]:
    try:
        job: RunJob | None = store.get(run_id)
    except KeyError:
        job = None
    if job is None:
        return {"run_id": run_id, "exists": False, "status": "missing", "created_at": None, "completed_at": None,
                "mode": None, "root": None}
    return {
        "run_id": run_id,
        "exists": True,
        "status": job.status,
        "created_at": job.created_at,
        "completed_at": job.completed_at,
        "mode": job.request.mode,
        "root": job.request.root,
    }

