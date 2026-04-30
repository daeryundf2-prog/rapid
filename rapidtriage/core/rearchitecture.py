from __future__ import annotations

import shutil
from pathlib import Path

from .columnar_store import build_columnar_benchmark_plan, columnar_capabilities


def build_rearchitecture_status(*, repo_root: Path | None = None) -> dict[str, object]:
    root = (repo_root or Path(__file__).resolve().parents[2]).expanduser().resolve()
    checks = [
        file_check(
            "plan",
            root / ".omx" / "plans" / "rapidtriage-commercial-rearchitecture-plan.md",
            "Commercial re-architecture plan exists",
        ),
        file_check(
            "adr-001",
            root / "docs" / "architecture" / "adr-001-hybrid-python-rust.md",
            "Hybrid Python/Rust architecture decision is documented",
        ),
        file_check(
            "progress-1-12",
            root / "docs" / "architecture" / "rearchitecture-progress-1-12.md",
            "Current 1-12 re-architecture progress and remaining gates are documented",
        ),
        file_check(
            "rust-workspace",
            root / "engines" / "rust" / "Cargo.toml",
            "Rust workspace skeleton exists",
        ),
        file_check(
            "rapidcore-crate",
            root / "engines" / "rust" / "crates" / "rapidcore" / "src" / "lib.rs",
            "Rust shared artifact model crate exists",
        ),
        file_check(
            "rapid-worker-crate",
            root / "engines" / "rust" / "crates" / "rapid-worker" / "src" / "main.rs",
            "Rust worker crate exists",
        ),
        file_check(
            "artifact-record-schema",
            root / "rapidtriage" / "schemas" / "artifact-record-v1.schema.json",
            "ArtifactRecordV1 JSON schema exists",
        ),
        file_check(
            "python-worker-client",
            root / "rapidtriage" / "core" / "worker.py",
            "Python RustWorkerClient exists",
        ),
        file_check(
            "jsonl-artifact-store",
            root / "rapidtriage" / "core" / "artifact_store.py",
            "Streaming JSONL artifact store exists",
        ),
        file_check(
            "worker-jsonl-pipeline",
            root / "tests" / "test_rapidtriage_worker.py",
            "Worker output to JSONL artifact store pipeline is tested",
        ),
        content_check(
            "worker-parse-cli",
            root / "rapidtriage" / "cli.py",
            "CLI can run an isolated worker and write ArtifactRecordV1 JSONL",
            required_markers=("worker-parse", "RustWorkerClient", "parse_to_jsonl"),
        ),
        content_check(
            "worker-jsonl-case-db-import",
            root / "rapidtriage" / "cli.py",
            "Case DB can import worker ArtifactRecordV1 JSONL into searchable artifacts",
            required_markers=("import_worker_jsonl", "--import-worker-jsonl", "imported_worker_jsonl"),
        ),
        content_check(
            "rust-evtx-inventory-contract",
            root / "engines" / "rust" / "crates" / "rapidcore" / "src" / "lib.rs",
            "Rust ArtifactRecordV1 model exposes an EVTX inventory contract",
            required_markers=("evtx_inventory", "windows-eventlog", "cross-tool-validation-required"),
        ),
        content_check(
            "rust-evtx-inventory-worker",
            root / "engines" / "rust" / "crates" / "rapid-worker" / "src" / "main.rs",
            "Rust worker can emit EVTX inventory records",
            required_markers=("evtx-inventory", "emit_evtx_inventory", "read_evtx_header"),
        ),
        content_check(
            "rust-evtx-binxml-fields",
            root / "engines" / "rust" / "crates" / "rapid-worker" / "src" / "main.rs",
            "Rust EVTX worker promotes common BinXML fields and built-in validation-required messages",
            required_markers=("extract_binxml_fields", "render_builtin_event_message", "provider_message_resource_resolved"),
        ),
        content_check(
            "rust-evtx-chunk-streaming",
            root / "engines" / "rust" / "crates" / "rapid-worker" / "src" / "main.rs",
            "Rust EVTX worker uses chunk-bounded parsing for large log files",
            required_markers=("parse_evtx_file_streaming", "CHUNK_SIZE", "SeekFrom::Start"),
        ),
        content_check(
            "windows-registry-native-coverage",
            root / "rapidtriage" / "artifacts" / "windows" / "registry.py",
            "Windows Registry/NTUSER/UsrClass triage coverage exists outside the EVTX lane",
            required_markers=(
                "registry-key-tree-node",
                "registry-value-recovery-candidate",
                "registry-user-activity",
                "NTUSER.DAT",
            ),
        ),
        content_check(
            "windows-os-account-coverage",
            root / "rapidtriage" / "artifacts" / "windows" / "os_account.py",
            "Windows SAM/SECURITY account and privilege coverage exists outside the EVTX lane",
            required_markers=(
                "windows-sam-account-candidate",
                "windows-sam-group-candidate",
                "windows-privilege-assignment",
                "SECURITY",
            ),
        ),
        content_check(
            "windows-execution-coverage",
            root / "rapidtriage" / "artifacts" / "windows" / "execution.py",
            "Windows execution artifact coverage exists outside the EVTX lane",
            required_markers=("Amcache", "ShimCache", "BAM", "PowerShell"),
        ),
        content_check(
            "windows-ese-coverage",
            root / "rapidtriage" / "artifacts" / "windows" / "srum_ese.py",
            "Windows ESE/SRUM/Search-index triage coverage exists outside the EVTX lane",
            required_markers=("build_srudb_validation", "native_srum_table_candidates", "row_level_decoding_available"),
        ),
        content_check(
            "windows-filesystem-coverage",
            root / "rapidtriage" / "artifacts" / "windows" / "filesystem.py",
            "Windows MFT/USN filesystem artifact coverage exists outside the EVTX lane",
            required_markers=("MFT", "USN", "commercial", "validation"),
        ),
        content_check(
            "browser-ai-coverage",
            root / "rapidtriage" / "artifacts" / "windows" / "browser.py",
            "Browser and AI-service usage artifact coverage exists outside the EVTX lane",
            required_markers=("ChatGPT", "Claude", "Gemini", "Perplexity"),
        ),
        content_check(
            "viewer-review-coverage",
            root / "rapidtriage" / "api" / "app.py",
            "Source viewer and review workflow coverage exists outside the EVTX lane",
            required_markers=("source-preview", "viewer_sandbox", "review_workflow", "compare_workflow"),
        ),
        content_check(
            "mobile-cloud-coverage",
            root / "rapidtriage" / "artifacts" / "mobile.py",
            "Mobile export artifact coverage exists outside the EVTX lane",
            required_markers=("Cellebrite", "XRY", "GrayKey", "AXIOM"),
        ),
        file_check(
            "columnar-store",
            root / "rapidtriage" / "core" / "columnar_store.py",
            "Optional Arrow/Parquet columnar store exists",
        ),
        content_check(
            "columnar-benchmark-cli",
            root / "rapidtriage" / "cli.py",
            "CLI can benchmark JSONL baseline and optional Parquet artifact storage",
            required_markers=("columnar-benchmark", "run_columnar_benchmark", "--record-count"),
        ),
        content_check(
            "columnar-convert-cli",
            root / "rapidtriage" / "cli.py",
            "CLI can convert worker ArtifactRecordV1 JSONL into row-grouped Parquet",
            required_markers=("columnar-convert", "convert_jsonl_to_parquet", "--input-jsonl"),
        ),
        content_check(
            "columnar-release-evidence",
            root / "scripts" / "verify-release-evidence.py",
            "Release evidence verifier can validate columnar benchmark outputs",
            required_markers=(
                "--columnar-benchmark-dir",
                "check_columnar_benchmark_output",
                "columnar-benchmark-commercial-disclosure",
            ),
        ),
        file_check(
            "worker-case-db-smoke",
            root / "scripts" / "worker-case-db-smoke.py",
            "End-to-end worker JSONL to Case DB smoke test exists",
        ),
        tool_check("cargo", "Rust compiler/package toolchain is available"),
        tool_check("rustfmt", "Rust formatter is available"),
    ]
    passed = sum(1 for item in checks if item["status"] == "pass")
    blocked = [item for item in checks if item["status"] == "blocked"]
    failed = [item for item in checks if item["status"] == "fail"]
    capabilities = columnar_capabilities()
    columnar_benchmark_plan = build_columnar_benchmark_plan()
    balanced_next_stage_plan = build_balanced_next_stage_plan()
    phases = [
        {
            "phase": "phase-0-boundary-freeze",
            "status": "partial-complete",
            "evidence": ["plan", "adr-001", "progress-1-12"],
            "remaining": ["commercial-readiness gate stays strict", "full regression before each migration"],
        },
        {
            "phase": "phase-1-rust-worker-foundation",
            "status": "implementation-started-toolchain-verified",
            "evidence": [
                "rust-workspace",
                "rapidcore-crate",
                "rapid-worker-crate",
                "python-worker-client",
                "worker-parse-cli",
                "rust-evtx-inventory-contract",
                "rust-evtx-inventory-worker",
                "rust-evtx-binxml-fields",
                "rust-evtx-chunk-streaming",
                "worker-case-db-smoke",
            ],
            "remaining": [
                "complete remaining EVTX BinXML grammar branches",
                "replace validation-required built-in rendering with provider resource rendering",
            ],
        },
        {
            "phase": "phase-1b-windows-artifact-breadth",
            "status": "implementation-started-validation-required",
            "evidence": [
                "windows-registry-native-coverage",
                "windows-os-account-coverage",
                "windows-execution-coverage",
                "windows-ese-coverage",
                "windows-filesystem-coverage",
                "browser-ai-coverage",
            ],
            "remaining": [
                "promote candidate parsers into known-answer validated native parsers",
                "add binary fixture corpora for registry, execution, ESE, filesystem, browser AI artifacts",
            ],
        },
        {
            "phase": "phase-1c-reviewer-ux-and-mobile-breadth",
            "status": "implementation-started-validation-required",
            "evidence": ["viewer-review-coverage", "mobile-cloud-coverage"],
            "remaining": [
                "test massive-result viewer behavior with real case-scale data",
                "validate mobile/cloud import schemas against vendor exports",
            ],
        },
        {
            "phase": "phase-2-high-volume-storage",
            "status": "implementation-started",
            "evidence": [
                "jsonl-artifact-store",
                "worker-jsonl-pipeline",
                "worker-jsonl-case-db-import",
                "columnar-store",
                "columnar-benchmark-cli",
                "columnar-convert-cli",
                "columnar-release-evidence",
            ],
            "remaining": [
                "install pyarrow/duckdb optional dependencies",
                "publish Parquet/DuckDB benchmark evidence",
                "run columnar-convert on real worker JSONL corpora",
            ],
        },
    ]
    return {
        "command": "rearchitecture-status",
        "root": str(root),
        "overall_status": "blocked" if blocked else ("fail" if failed else "in-progress"),
        "check_count": len(checks),
        "passed_count": passed,
        "blocked_count": len(blocked),
        "failed_count": len(failed),
        "checks": checks,
        "phases": phases,
        "columnar_capabilities": capabilities,
        "columnar_benchmark_plan": columnar_benchmark_plan,
        "balanced_next_stage_plan": balanced_next_stage_plan,
        "focus_balance": summarize_focus_balance(balanced_next_stage_plan),
        "next_steps": [
            "Advance EVTX only as one lane; keep Registry/execution/ESE/filesystem/browser-AI/mobile/viewer lanes moving in parallel.",
            "Promote validation-required candidate parsers into known-answer validated parsers with fixture corpora.",
            "Run columnar-benchmark with pyarrow/duckdb installed and publish 100k/1M/10M evidence.",
        ],
    }


def build_balanced_next_stage_plan() -> list[dict[str, object]]:
    return [
        stage(1, "EVTX native parser hardening", "core-forensics", "in-progress", "#1-#3"),
        stage(2, "Registry/NTUSER/SAM/SECURITY parser hardening", "core-forensics", "in-progress", "#4-#6"),
        stage(3, "Execution artifacts: Amcache/ShimCache/BAM/Prefetch", "core-forensics", "in-progress", "#7-#9/#16"),
        stage(4, "SRUM/Windows.edb/ESE parser hardening", "core-forensics", "in-progress", "#10-#11"),
        stage(5, "MFT/USN/LNK/JumpList/ShellBags hardening", "core-forensics", "in-progress", "#12-#15/#17"),
        stage(6, "WER/Defender/Firewall/Task Scheduler/WMI depth", "core-forensics", "in-progress", "#18"),
        stage(7, "Browser unified timeline and cache/session/extension artifacts", "browser-ai", "in-progress", "#19-#20"),
        stage(8, "AI service transcript extraction and validation", "browser-ai", "in-progress", "#21"),
        stage(9, "Disk image and container workflows", "evidence-inputs", "partial", "#22-#25"),
        stage(10, "Mobile/vendor export importers", "mobile-cloud-apps", "partial", "#26-#45"),
        stage(11, "Search clustering, entities, graph, timeline, workbook", "search-analysis-ux", "partial", "#46-#50"),
        stage(12, "Reviewer workflow, compare, viewer specialization", "search-analysis-ux", "partial", "#51-#59"),
        stage(13, "Search quality: dedupe, fuzzy, keyword packs, IOC/TI", "search-analysis-ux", "partial", "#60-#63"),
        stage(14, "Report citations, evidence selection, version history", "validation-legal", "partial", "#64-#65"),
        stage(15, "Large-case performance, columnar storage, checkpoints", "performance-large-scale", "in-progress", "#66-#80"),
        stage(16, "Known-answer validation and court evidence package", "validation-legal", "partial", "#81-#100"),
        stage(17, "Cross-platform installers and release operations", "deployment-operations", "partial", "#101-#120"),
        stage(18, "Commercial-readiness scoring and anti-overclaim gates", "product-governance", "in-progress", "all"),
    ]


def stage(
    number: int,
    title: str,
    lane: str,
    status: str,
    backlog_scope: str,
) -> dict[str, object]:
    return {
        "number": number,
        "title": title,
        "lane": lane,
        "status": status,
        "backlog_scope": backlog_scope,
        "commercial_rule": "validation-required until known-answer fixtures, performance evidence, and reviewer UX checks pass",
    }


def summarize_focus_balance(plan: list[dict[str, object]]) -> dict[str, object]:
    lanes: dict[str, int] = {}
    for item in plan:
        lane = str(item.get("lane") or "unknown")
        lanes[lane] = lanes.get(lane, 0) + 1
    return {
        "lane_count": len(lanes),
        "lanes": lanes,
        "evtx_is_not_the_only_lane": len(lanes) > 1,
        "guidance": "Do not let EVTX consume all work; every release should advance parser breadth, UX, scale, and validation evidence.",
    }


def file_check(check_id: str, path: Path, description: str) -> dict[str, object]:
    exists = path.is_file()
    return {
        "id": check_id,
        "status": "pass" if exists else "fail",
        "description": description,
        "path": str(path),
    }


def content_check(
    check_id: str,
    path: Path,
    description: str,
    *,
    required_markers: tuple[str, ...],
) -> dict[str, object]:
    result = file_check(check_id, path, description)
    if result["status"] != "pass":
        result["missing_markers"] = list(required_markers)
        return result
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        result["status"] = "fail"
        result["error"] = str(exc)
        result["missing_markers"] = list(required_markers)
        return result
    missing = [marker for marker in required_markers if marker not in text]
    if missing:
        result["status"] = "fail"
        result["missing_markers"] = missing
    return result


def tool_check(tool: str, description: str) -> dict[str, object]:
    path = shutil.which(tool)
    return {
        "id": f"tool-{tool}",
        "status": "pass" if path else "blocked",
        "description": description,
        "path": path or "",
        "blocker": "" if path else f"{tool} is not installed in this environment",
    }
