"""Parser registration for image, volume shadow copy and E01 commands."""

from __future__ import annotations

import argparse
import textwrap

from ...core.carving import (
    DEFAULT_MAX_CANDIDATES,
    DEFAULT_MAX_CARVE_BYTES,
    DEFAULT_MAX_SCAN_BYTES,
)
from ...core.input_root import SUPPORTED_INPUT_ROOT_KINDS
from ...core.run import SUPPORTED_RUN_MODES


def register_volume(sub: argparse._SubParsersAction) -> None:
    """Register vsc-compare, vsc-discover, vsc-extract, carve, ntfs-meta."""
    vsc_compare = sub.add_parser(
        "vsc-compare",
        help="Compare current files against one or more Volume Shadow Copy snapshot folders",
        description="Compare current files against one or more Volume Shadow Copy snapshot folders",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage vsc-compare ./current ./snapshot-1 --output vsc-delta.json
              rapidtriage vsc-compare ./current ./snapshot-1 ./snapshot-2 --hash --max-records 5000
            """
        ),
    )
    vsc_compare.add_argument("current_root", help="Current mounted/exported file tree")
    vsc_compare.add_argument("snapshot_roots", nargs="+", help="One or more VSC snapshot file trees to compare")
    vsc_compare.add_argument("--output", default="rapidtriage-vsc-compare.json", help="JSON output path")
    vsc_compare.add_argument("--hash", action="store_true", help="Hash common files before deciding modified status")
    vsc_compare.add_argument("--case-sensitive", action="store_true", help="Compare paths case-sensitively")
    vsc_compare.add_argument("--max-records", type=int, default=10000, help="Maximum change records per snapshot (0 means unlimited)")
    vsc_compare.add_argument("--json", action="store_true", help="Print the full JSON comparison after saving it")

    vsc_discover = sub.add_parser(
        "vsc-discover",
        help="Discover likely mounted/exported Volume Shadow Copy snapshot folders",
        description="Discover likely VSC snapshot folders near a mounted/exported current volume root",
    )
    vsc_discover.add_argument("current_root", help="Current mounted/exported file tree")
    vsc_discover.add_argument("--output", default="rapidtriage-vsc-discovery.json", help="JSON output path")
    vsc_discover.add_argument("--max-depth", type=int, default=3, help="Maximum directory depth to inspect around the current root")
    vsc_discover.add_argument("--json", action="store_true", help="Print the full JSON discovery report after saving it")

    vsc_extract = sub.add_parser(
        "vsc-extract",
        help="Copy deleted/modified Volume Shadow Copy candidates into an evidence package",
        description="Compare current files against VSC snapshot folders and copy selected snapshot/current files with hashes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage vsc-extract ./current ./vss/snapshot-1 --output-dir ./vsc-evidence
              rapidtriage vsc-extract ./current ./vss/snapshot-1 --status deleted --status modified --max-file-count 500
            """
        ),
    )
    vsc_extract.add_argument("current_root", help="Current mounted/exported file tree")
    vsc_extract.add_argument("snapshot_roots", nargs="+", help="One or more VSC snapshot file trees to compare/extract")
    vsc_extract.add_argument("--output-dir", required=True, help="Directory that receives rapidtriage-vsc-extract.json and copied evidence")
    vsc_extract.add_argument("--manifest", help="Manifest JSON output path (default: OUTPUT_DIR/rapidtriage-vsc-extract.json)")
    vsc_extract.add_argument("--status", action="append", choices=["deleted", "modified", "added"], help="Change status to copy; repeatable. Defaults to deleted+modified")
    vsc_extract.add_argument("--no-hash", action="store_true", help="Skip comparison-time hashing; copied files are still hashed after copy")
    vsc_extract.add_argument("--case-sensitive", action="store_true", help="Compare paths case-sensitively")
    vsc_extract.add_argument("--overwrite", action="store_true", help="Allow overwriting existing files in OUTPUT_DIR/evidence")
    vsc_extract.add_argument("--max-records", type=int, default=10000, help="Maximum change records per snapshot (0 means unlimited)")
    vsc_extract.add_argument("--max-file-count", type=int, default=1000, help="Maximum files to copy (0 means unlimited)")
    vsc_extract.add_argument("--max-total-bytes", type=int, default=2 * 1024 * 1024 * 1024, help="Maximum copied source bytes (0 means unlimited)")
    vsc_extract.add_argument("--json", action="store_true", help="Print the full JSON extraction manifest after saving it")

    carve = sub.add_parser(
        "carve",
        help="Run bounded signature carving for deleted/recovered file candidates",
        description="Run bounded signature carving for deleted/recovered file candidates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage carve /cases/image-mount --output-dir ./carve-review
              rapidtriage carve disk.raw --output-dir ./carve-review --extract --max-candidates 50
            """
        ),
    )
    carve.add_argument("root", help="Mounted/exported folder or file to scan for carved candidates")
    carve.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    carve.add_argument("--output-dir", required=True, help="Directory that receives rapidtriage-carve.json and optional carved files")
    carve.add_argument("--extract", action="store_true", help="Write carved candidate bytes under OUTPUT_DIR/carved")
    carve.add_argument("--max-scan-bytes", type=int, default=DEFAULT_MAX_SCAN_BYTES, help="Maximum bytes to inspect per source file")
    carve.add_argument("--max-carve-bytes", type=int, default=DEFAULT_MAX_CARVE_BYTES, help="Maximum bytes to copy for one carved candidate")
    carve.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES, help="Maximum carving candidates to report")
    carve.add_argument("--ext", action="append", help="Only scan source files with this extension (repeatable)")
    carve.add_argument(
        "--kind",
        action="append",
        help="Only carve these signature kinds (repeatable; default all: jpeg, png, pdf, zip, sqlite, gif, 7z, rar)",
    )
    carve.add_argument("--resume", action="store_true", help="Resume from rapidtriage-carve.checkpoint.json in OUTPUT_DIR when the carving options match")
    carve.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    ntfs_meta = sub.add_parser(
        "ntfs-meta",
        help="Extract NTFS $MFT and $UsnJrnl:$J from a raw/E01 image via Sleuth Kit",
        description=(
            "Extract NTFS metadata files ($MFT, $UsnJrnl:$J) from a disk image using "
            "mmls/fls/icat, then optionally run the native parsers and report record "
            "counts and candidate-kind classifications."
        ),
    )
    ntfs_meta.add_argument("image", help="Raw/dd or E01 image readable by the installed Sleuth Kit build")
    ntfs_meta.add_argument("--output-dir", required=True, help="Directory that receives MFT.bin, UsnJrnl_J.bin, and the manifest")
    ntfs_meta.add_argument("--partition-offset", type=int, help="Filesystem partition start sector (default: largest filesystem partition from mmls)")
    ntfs_meta.add_argument("--full-journal", action="store_true", help="Write the full $J stream including sparse holes (default omits holes; offsets are then relative to the compacted output)")
    ntfs_meta.add_argument("--parse", action="store_true", help="Run the native MFT/USN parsers over the extracted metadata")
    ntfs_meta.add_argument("--json", action="store_true", help="Print machine-readable JSON")


def register_evidence(sub: argparse._SubParsersAction) -> None:
    """Register evidence, e01-known-answer, e01-smoke, e01-hash."""
    evidence = sub.add_parser(
        "evidence",
        help="Identify the evidence adapter that would handle a source path",
        description="Identify the evidence adapter that would handle a source path",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage evidence ./mounted-folder
              rapidtriage evidence ./case.E01 --json
            """
        ),
    )
    evidence.add_argument("source", help="Evidence source path to identify")
    evidence.add_argument("--output", help="Optional JSON output path for the evidence preflight/runbook")
    evidence.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    e01_known_answer = sub.add_parser(
        "e01-known-answer",
        help="Build a Windows 11 E01 known-answer manifest draft",
        description="Build a Windows 11 E01 known-answer manifest draft for single-case validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage e01-known-answer ./case.E01 --output ./windows11-e01-known-answer.json
              rapidtriage e01-known-answer ./case.E01 --case-id CASE-001 --expected-partition-start-sector 2048 --expected-artifact "Security.evtx event 4624"
            """
        ),
    )
    e01_known_answer.add_argument("source", help="Windows 11 E01/Ex01 source image")
    e01_known_answer.add_argument("--case-id", default="windows11-e01-known-answer", help="Case identifier for the manifest")
    e01_known_answer.add_argument("--expected-partition-start-sector", type=int, help="Expected Windows filesystem start sector")
    e01_known_answer.add_argument("--expected-artifact", action="append", default=[], help="Expected high-value artifact assertion; repeatable")
    e01_known_answer.add_argument("--validation-command", action="append", default=[], help="Validation command to preserve in the manifest; repeatable")
    e01_known_answer.add_argument("--output", help="Optional JSON output path")
    e01_known_answer.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    e01_smoke = sub.add_parser(
        "e01-smoke",
        help="Run a Windows 11 E01 single-case workflow smoke report",
        description="Run a Windows 11 E01 workflow smoke report from preflight through report generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage e01-smoke ./case.E01 --output-dir ./case-smoke --case-id CASE-001
              rapidtriage e01-smoke ./case.E01 --output-dir ./case-smoke --expected-partition-start-sector 2048 --plan-only
            """
        ),
    )
    e01_smoke.add_argument("source", help="Windows 11 E01/Ex01 source image")
    e01_smoke.add_argument("--output-dir", required=True, help="Directory for smoke report outputs")
    e01_smoke.add_argument("--case-id", default="windows11-e01-smoke", help="Case identifier for the smoke report")
    e01_smoke.add_argument("--mode", choices=sorted(SUPPORTED_RUN_MODES), default="hacking", help="Run mode for artifact triage")
    e01_smoke.add_argument("--input-kind", choices=SUPPORTED_INPUT_ROOT_KINDS, help="Override input root kind")
    e01_smoke.add_argument("--expected-partition-start-sector", type=int, help="Expected Windows filesystem start sector")
    e01_smoke.add_argument("--expected-artifact", action="append", default=[], help="Expected high-value artifact assertion; repeatable")
    e01_smoke.add_argument("--validation-command", action="append", default=[], help="Validation command to preserve in the manifest; repeatable")
    e01_smoke.add_argument("--plan-only", action="store_true", help="Write preflight/known-answer files without attempting extraction")
    e01_smoke.add_argument("--write-extracts", action="store_true", help="Allow extracted files to be written during the run stage")
    e01_smoke.add_argument("--resume", action="store_true", help="Reuse resumable stage outputs when possible")
    e01_smoke.add_argument("--max-file-count", type=int, default=0, help="Maximum extracted file count during run stage")
    e01_smoke.add_argument("--max-extract-size-bytes", type=int, default=0, help="Maximum extracted byte budget during run stage")
    e01_smoke.add_argument("--memory-cap-bytes", type=int, default=0, help="Soft memory cap for run stages")
    e01_smoke.add_argument("--json", action="store_true", help="Print machine-readable JSON")

    e01_hash = sub.add_parser(
        "e01-hash",
        help="Compute streaming full-image hashes for E01/Ex01 evidence files",
        description="Compute SHA256/SHA1/MD5 over the selected evidence image with progress checkpoints for report-grade hash evidence",
    )
    e01_hash.add_argument("source", help="Path to the E01/Ex01 or raw image file to hash")
    e01_hash.add_argument("--output-dir", required=True, help="Directory for hash JSON, Markdown, and checkpoint outputs")
    e01_hash.add_argument("--algorithm", action="append", help="Hash algorithm to compute; repeatable; defaults to sha256/sha1/md5")
    e01_hash.add_argument("--chunk-size", type=int, default=8 * 1024 * 1024, help="Read chunk size in bytes")
    e01_hash.add_argument("--checkpoint-interval-bytes", type=int, default=128 * 1024 * 1024, help="Bytes between checkpoint writes")
    e01_hash.add_argument("--overwrite", action="store_true", help="Allow writing into a non-empty hash output directory")
    e01_hash.add_argument("--json", action="store_true", help="Print machine-readable JSON")
