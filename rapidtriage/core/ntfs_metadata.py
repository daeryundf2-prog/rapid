"""Extract NTFS metadata files ($MFT, $UsnJrnl:$J) from disk images.

Uses Sleuth Kit ``mmls``/``fls``/``icat`` so the same code path works on
raw/dd images and on E01/Ex01 images when the installed TSK build has
libewf support. Extraction streams tool output to disk so multi-GB
metadata files never load into memory.

This is evidence-metadata extraction for analysis, not acquisition: the
source image is read only through the tools, and every emitted artifact
carries its command line and output hash for provenance.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from .e01 import (
    CommandRunner,
    E01ExtractionError,
    default_runner,
    mmls_sector_size_bytes,
    parse_mmls_partitions,
    select_mmls_filesystem,
)

NTFS_METADATA_REQUIRED_TOOLS = ("mmls", "fls", "icat")

MFT_INODE = 0
EXTEND_INODE = 11
USN_JOURNAL_NAME = "$UsnJrnl"
USN_JOURNAL_DATA_STREAM = "$J"

# icat streams can be tens of GB; bound the wall-clock budget generously
# but fail rather than hang forever on a wedged tool.
ICAT_TIMEOUT_SECONDS = 6 * 60 * 60

StreamRunner = Callable[[Sequence[str], Path], "subprocess.CompletedProcess[bytes]"]

_FLS_ATTR_ROW = re.compile(
    r"^r/r\s+(?P<inum>\d+)-(?P<attr_type>\d+)-(?P<attr_id>\d+):\s*(?P<name>.+?)\s*$"
)


class NTFSMetadataError(RuntimeError):
    """Raised when NTFS metadata extraction cannot complete safely."""


def missing_ntfs_metadata_tools(tool_resolver: Callable[[str], str | None] = shutil.which) -> list[str]:
    return [tool for tool in NTFS_METADATA_REQUIRED_TOOLS if tool_resolver(tool) is None]


def default_stream_runner(
    command: Sequence[str], output_path: Path
) -> subprocess.CompletedProcess[bytes]:
    """Run ``command`` streaming stdout into ``output_path``.

    Returns a CompletedProcess with empty stdout (it lives in the file)
    and captured stderr for diagnostics.
    """
    with output_path.open("wb") as handle:
        proc = subprocess.run(
            list(command),
            stdout=handle,
            stderr=subprocess.PIPE,
            timeout=ICAT_TIMEOUT_SECONDS,
            check=False,
        )
    return subprocess.CompletedProcess(list(command), proc.returncode, b"", proc.stderr)


def find_usn_journal_attribute(fls_output: str) -> dict[str, object] | None:
    """Parse ``fls`` output of $Extend for the $UsnJrnl:$J attribute."""
    inum: int | None = None
    for line in fls_output.splitlines():
        match = _FLS_ATTR_ROW.match(line.strip())
        if match is None:
            continue
        name = match.group("name")
        if name == USN_JOURNAL_NAME:
            inum = int(match.group("inum"))
            continue
        if name == f"{USN_JOURNAL_NAME}:{USN_JOURNAL_DATA_STREAM}":
            return {
                "inode": int(match.group("inum")),
                "attribute": f"{match.group('inum')}-{match.group('attr_type')}-{match.group('attr_id')}",
                "attribute_type": int(match.group("attr_type")),
                "attribute_id": int(match.group("attr_id")),
            }
    # $UsnJrnl present but no $J stream row yet; report the inode so the
    # caller can attempt the unnamed stream or fail with a clear reason.
    if inum is not None:
        return {"inode": inum, "attribute": str(inum), "attribute_type": None, "attribute_id": None}
    return None


def partition_has_ntfs_oem_id(image: Path, byte_offset: int) -> bool:
    """Check the NTFS OEM ID ('NTFS    ') at partition boot-sector offset +3.

    Only meaningful for raw/dd images — on EWF containers the byte at that
    file offset is container data, not the partition boot sector.
    """
    try:
        with image.open("rb") as handle:
            handle.seek(byte_offset + 3)
            return handle.read(8) == b"NTFS    "
    except OSError:
        return False


def image_is_ewf(image: Path) -> bool:
    """Detect Expert Witness Format by its 8-byte file signature."""
    try:
        with image.open("rb") as handle:
            return handle.read(8) == b"EVF\x09\x0d\x0a\xff\x00"
    except OSError:
        return False


def probe_partition_filesystem(
    runner: CommandRunner, image: Path, start_sector: int
) -> str:
    """Return the filesystem type ``fsstat`` reports, or ``""`` on failure.

    Goes through the TSK image layer so it works on both raw and E01.
    """
    result = runner(["fsstat", "-o", str(start_sector), str(image)])
    if result.returncode != 0:
        return ""
    for line in (result.stdout or "").splitlines():
        lowered = line.strip().lower()
        if lowered.startswith("file system type"):
            return lowered.rsplit(":", 1)[-1].strip()
    return ""


def hash_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_ntfs_metadata(
    image_path: Path,
    output_dir: Path,
    *,
    partition_start_sector: int | None = None,
    sparse_journal: bool = True,
    runner: CommandRunner = default_runner,
    stream_runner: StreamRunner = default_stream_runner,
    tool_resolver: Callable[[str], str | None] = shutil.which,
) -> dict[str, object]:
    """Extract $MFT and $UsnJrnl:$J from an image via Sleuth Kit.

    ``sparse_journal=True`` passes ``icat -h`` which omits sparse holes in
    the $J stream; byte offsets in the output are then relative to the
    compacted stream, not the logical journal — the manifest records
    this limitation explicitly.
    """
    source = Path(image_path).expanduser().resolve()
    if not source.is_file():
        raise NTFSMetadataError(f"image not found: {source}")
    missing = missing_ntfs_metadata_tools(tool_resolver)
    if missing:
        raise NTFSMetadataError(f"missing Sleuth Kit tools: {', '.join(missing)}")

    out_dir = Path(output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    mmls_result = runner(["mmls", str(source)])
    if mmls_result.returncode != 0:
        raise NTFSMetadataError(f"mmls failed: {(mmls_result.stderr or '').strip()[:400]}")
    partitions = parse_mmls_partitions(mmls_result.stdout or "")
    if not partitions:
        raise NTFSMetadataError("mmls produced no partition rows")
    sector = partition_start_sector
    selection_method = "operator-specified"
    if sector is None:
        try:
            sector = select_mmls_filesystem(mmls_result.stdout or "")
        except E01ExtractionError as exc:
            raise NTFSMetadataError(str(exc)) from exc
        selection_method = "mmls-description"
        if sector is None:
            # Localized/corrupted mmls description text (e.g. codepage
            # mojibake) defeats token matching; probe candidate partitions
            # for NTFS instead. Raw images can check the boot-sector OEM
            # ID directly; EWF containers must go through fsstat.
            ewf = image_is_ewf(source)
            for row in sorted(partitions, key=lambda r: -int(r.get("sector_count") or 0)):
                if not ewf and partition_has_ntfs_oem_id(
                    source, int(row.get("byte_offset") or 0)
                ):
                    sector = int(row["start_sector"])
                    selection_method = "ntfs-oem-id-probe"
                    break
                fs_type = probe_partition_filesystem(
                    runner, source, int(row["start_sector"])
                )
                if "ntfs" in fs_type:
                    sector = int(row["start_sector"])
                    selection_method = "fsstat-probe"
                    break
        if sector is None:
            raise NTFSMetadataError("no filesystem partition found in mmls output")
    elif not any(int(row.get("start_sector") or -1) == sector for row in partitions):
        raise NTFSMetadataError(
            f"requested partition start sector {sector} was not found in mmls output"
        )
    sector_size = mmls_sector_size_bytes(mmls_result.stdout or "") or 512
    partition_row = next(
        (row for row in partitions if int(row.get("start_sector") or -1) == sector),
        {"start_sector": sector},
    )

    manifest: dict[str, object] = {
        "command": "ntfs-meta",
        "image": str(source),
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "partition": {
            "start_sector": sector,
            "byte_offset": sector * sector_size,
            "sector_size_bytes": sector_size,
            "filesystem_guess": partition_row.get("filesystem_guess", ""),
            "description": partition_row.get("description", ""),
            "selection_method": selection_method,
            "filesystem_verified": (
                "ntfs" in probe_partition_filesystem(runner, source, sector)
                if image_is_ewf(source)
                else partition_has_ntfs_oem_id(source, sector * sector_size)
            ),
        },
        "tools": {
            tool: str(tool_resolver(tool))
            for tool in (*NTFS_METADATA_REQUIRED_TOOLS, "fsstat")
            if tool_resolver(tool) is not None
        },
        "outputs": {},
        "skipped": [],
        "limitations": [
            "icat output is the content stream of the metadata file, not a forensic acquisition; acquisition integrity remains the source image hash chain.",
        ],
    }

    # --- $MFT ---
    mft_path = out_dir / "MFT.bin"
    mft_command = ["icat", "-o", str(sector), str(source), str(MFT_INODE)]
    mft_result = stream_runner(mft_command, mft_path)
    if mft_result.returncode == 0 and mft_path.is_file() and mft_path.stat().st_size > 0:
        manifest["outputs"]["mft"] = {
            "path": str(mft_path),
            "size_bytes": mft_path.stat().st_size,
            "sha256": hash_file_sha256(mft_path),
            "inode": MFT_INODE,
            "command": mft_command,
            "extraction_mode": "full-stream",
        }
    else:
        manifest["skipped"].append(
            {
                "target": "mft",
                "reason": f"icat exit {mft_result.returncode}: {(mft_result.stderr or b'').decode('utf-8', 'replace').strip()[:300]}",
            }
        )
        mft_path.unlink(missing_ok=True)

    # --- $UsnJrnl:$J ---
    fls_result = runner(["fls", "-o", str(sector), str(source), str(EXTEND_INODE)])
    journal_entry: dict[str, object] = {}
    if fls_result.returncode == 0:
        journal_entry = find_usn_journal_attribute(fls_result.stdout or "") or {}
    if not journal_entry:
        manifest["skipped"].append(
            {
                "target": "usn_journal",
                "reason": (
                    f"$UsnJrnl not found under $Extend "
                    f"(fls exit {fls_result.returncode})"
                ),
            }
        )
    else:
        journal_path = out_dir / "UsnJrnl_J.bin"
        journal_command = [
            "icat",
            *(["-h"] if sparse_journal else []),
            "-o",
            str(sector),
            str(source),
            str(journal_entry["attribute"]),
        ]
        journal_result = stream_runner(journal_command, journal_path)
        if journal_result.returncode == 0 and journal_path.is_file() and journal_path.stat().st_size > 0:
            output: dict[str, object] = {
                "path": str(journal_path),
                "size_bytes": journal_path.stat().st_size,
                "sha256": hash_file_sha256(journal_path),
                "inode": journal_entry["inode"],
                "attribute": journal_entry["attribute"],
                "command": journal_command,
                "extraction_mode": "sparse-holes-omitted" if sparse_journal else "full-stream",
            }
            if sparse_journal:
                output["limitations"] = [
                    "Sparse holes were omitted during extraction; byte offsets are relative to the compacted output, not the logical $J stream.",
                ]
            manifest["outputs"]["usn_journal"] = output
        else:
            manifest["skipped"].append(
                {
                    "target": "usn_journal",
                    "reason": f"icat exit {journal_result.returncode}: {(journal_result.stderr or b'').decode('utf-8', 'replace').strip()[:300]}",
                }
            )
            journal_path.unlink(missing_ok=True)

    manifest["extraction_status"] = (
        "complete" if len(manifest["outputs"]) == 2 else ("partial" if manifest["outputs"] else "blocked")
    )
    manifest_path = out_dir / "rapidtriage-ntfs-meta.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest["manifest_path"] = str(manifest_path)
    return manifest
