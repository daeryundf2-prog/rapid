"""Argparse parser construction for the rapidtriage CLI."""

from __future__ import annotations

import argparse
import textwrap

from ..core.cli_constants import DEFAULT_EXTRACT_MANIFEST_NAME
from .parsers import case, collect, image, kakao, meta, run, validation, web

HELP_FORMATTER = argparse.RawDescriptionHelpFormatter
TOP_LEVEL_EPILOG = """Examples:
  rapidtriage manifest . --output rapidtriage-manifest.json
  rapidtriage docs . -k incident -k registry --output rapidtriage-docs.json
  rapidtriage files . --category documents --ext docx --modified-after 2025-01-01
  rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf
"""
MANIFEST_EPILOG = """Examples:
  rapidtriage manifest .
  rapidtriage manifest /cases/image-mount --output case-manifest.json
"""
DOCS_EPILOG = """Examples:
  rapidtriage docs . -k incident -k registry
  rapidtriage docs /cases/image-mount -k password --limit 250 --output docs-hits.json
  rapidtriage docs /cases/image-mount -k password --index-output docs-index.json
"""
FILES_EPILOG = """Examples:
  rapidtriage files .
  rapidtriage files /cases/image-mount --category executables --ext exe --modified-after 2025-01-01
  rapidtriage files . --name-contains note --path-contains desktop --output desktop-notes.json
"""
EXTRACT_EPILOG = f"""Examples:
  rapidtriage extract rapidtriage-files.json ./extract-out
  rapidtriage extract rapidtriage-files.json ./extract-out --category documents --ext txt
  rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf --manifest ./docs-out/{DEFAULT_EXTRACT_MANIFEST_NAME}
  rapidtriage extract rapidtriage-files.json ./extract-out --dry-run --max-file-count 100
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rapidtriage",
        description="Lightweight forensic triage CLI with OS-independent core and pluggable artifact providers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage manifest . --output rapidtriage-manifest.json
              rapidtriage docs . -k incident -k registry --output rapidtriage-docs.json
              rapidtriage docs . -k incident --index-output rapidtriage-docs-index.json
              rapidtriage docs-index-search rapidtriage-docs-index.json -k incident
              rapidtriage files . --output rapidtriage-files.json
              rapidtriage collect-plan /Volumes/case-mount --profile intrusion --output rapidtriage-collect-plan.json
              rapidtriage collect-export /Volumes/case-mount ./collect-export --profile intrusion --copy
              rapidtriage compare ./before.txt ./after.txt --output compare.json
              rapidtriage vsc-compare ./current ./vss/snapshot-1 --output vsc-delta.json
              rapidtriage carve /cases/image-mount --output-dir ./carve-review --extract
              rapidtriage files . --category executables --ext exe --modified-after 2025-01-01 --output recent-executables.json
              rapidtriage extract rapidtriage-files.json ./extract-out --category documents --ext txt
              rapidtriage extract rapidtriage-docs.json ./docs-out --kind pdf
              rapidtriage extract rapidtriage-files.json ./extract-out --dry-run --max-file-count 100
              rapidtriage artifacts . --kind browser --output rapidtriage-artifacts-browser.json
              rapidtriage cloud-collect ./cloud-api-manifest.json --output-dir ./cloud-api-raw
              rapidtriage timeline . --output rapidtriage-timeline.json --report rapidtriage-timeline-report.md
              rapidtriage case ./incident-case.json --source rapidtriage-timeline.json --pointer /events/0 --tag suspicious
              rapidtriage manifest /Volumes/case-mount --input-kind mounted-image
              rapidtriage run . --mode fraud --output-dir ../rapidtriage-run --read-only
              rapidtriage run ./case.E01 --mode fraud --output-dir ./rapidtriage-run-e01
              rapidtriage search ./rapidtriage-run-fraud -k invoice -k password
              rapidtriage indicators ./rapidtriage-run-fraud --output rapidtriage-indicators.json
              rapidtriage sample --run --overwrite
              rapidtriage case-db ./rapidtriage-case.db --create-case CASE-001 --name "Case 001"
              rapidtriage case-search ./rapidtriage-case.db --case-id CASE-001 -k password
              rapidtriage case-review ./rapidtriage-case.db --case-id CASE-001 --target-type indexed_document --target-id 1 --status relevant --verification-status source_opened
              rapidtriage case-db-report ./rapidtriage-case.db --case-id CASE-001 --output report-candidates.json
              rapidtriage evidence ./case.E01
              rapidtriage benchmark --output-dir ./rapidtriage-benchmark --file-count 1000
              rapidtriage validation --output-dir ./rapidtriage-validation --overwrite
              rapidtriage commercial-readiness --output-dir ./commercial-readiness --json
              rapidtriage cross-tool-validate --rapid-output rapidtriage-artifacts-eventlog.json --reference-output evtxecmd=EvtxECmd.csv
              rapidtriage confidence-dashboard ./rapidtriage-run --json
              rapidtriage case-catalog --add-run ./rapidtriage-run --case-id CASE-001 --list
              rapidtriage timeline-export ./rapidtriage-run --source artifacts --output timeline-export.json
              rapidtriage normalize ./rapidtriage-run --output normalized-case.json
              rapidtriage bundle ./rapidtriage-case.json --allowed-root /cases/mount --output-dir ./submission-bundle
              rapidtriage plugins --list
              rapidtriage doctor --json
              rapidtriage web --host 127.0.0.1 --port 8765
            """
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    # Registration order is the --help and choices order; keep it.
    collect.register_sources(sub)
    kakao.register(sub)
    collect.register_cloud(sub)
    run.register_files(sub)
    collect.register_plans(sub)
    image.register_volume(sub)
    run.register_analysis(sub)
    meta.register_system(sub)
    case.register_case_db(sub)
    image.register_evidence(sub)
    validation.register(sub)
    case.register_catalog(sub)
    meta.register_plugins(sub)
    run.register_run(sub)
    web.register(sub)
    return parser

__all__ = [
    "DOCS_EPILOG",
    "EXTRACT_EPILOG",
    "FILES_EPILOG",
    "HELP_FORMATTER",
    "MANIFEST_EPILOG",
    "TOP_LEVEL_EPILOG",
    "build_parser",
]
