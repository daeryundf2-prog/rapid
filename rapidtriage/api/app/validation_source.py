"""Source identity and integrity of the run validation package (R8 T-179).

For an image run the evidence is ``summary.source.source_path`` (the E01/raw/archive/virtual-disk
file), not ``summary.root`` (the folder it was extracted to). An E01/Ex01 source lists every
discovered segment. Digests are re-read from disk when the package is generated; the read-only
``GET`` lists names and sizes with ``hash_status: deferred-to-generation``.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from ...core.e01 import discover_e01_segments, ewf_segment_number
from ...core.hash_cache import compute_hashes_fresh

#: ``summary.source.type`` values whose ``source_path`` is an image/container file and whose
#: ``summary.root`` is only the extraction folder the run analysed (``core/run/source.py``).
IMAGE_SOURCE_TYPES = frozenset({"e01", "e01-derived", "raw-image", "archive-image", "virtual-disk"})

#: ``hash_status`` of the source (and each segment) in a package built for reading only
#: (``GET /validation-package``): fresh digests are computed only when the package is generated.
HASH_DEFERRED = "deferred-to-generation"

_EWF_SIBLING_SUFFIX = re.compile(r"\.(?:E|Ex)[A-Z0-9]{2}", re.IGNORECASE)


def validation_source_path(summary: Mapping[str, object]) -> tuple[Path | None, str]:
    """The evidence the run was made from, and where that answer came from.

    For an image run (E01/Ex01, raw/split, archive, virtual disk) ``summary.root`` is the folder
    the image was extracted to (``…\\_e01\\fs``); the evidence is ``summary.source.source_path``
    (R8 T-179 review P1-1). Other runs use ``root`` (else ``scan_scope_root``)."""
    source = summary.get("source")
    if isinstance(source, Mapping) and str(source.get("type") or "") in IMAGE_SOURCE_TYPES:
        raw_source = source.get("source_path")
        if raw_source:
            return Path(str(raw_source)).expanduser().resolve(), "source.source_path"
    raw_root = summary.get("root") or summary.get("scan_scope_root")
    if raw_root:
        return Path(str(raw_root)).expanduser().resolve(), "root" if summary.get("root") else "scan_scope_root"
    return None, ""


def build_run_validation_source_integrity(
    summary: Mapping[str, object], *, compute_hashes: bool = True
) -> dict[str, object]:
    """Source identity and integrity for the run validation package.

    ``compute_hashes=False`` (the read-only ``GET``) lists the same source and segments with
    names and sizes but leaves every digest ``deferred-to-generation``: a multi-hundred-GB image
    is re-read in full only when the package is generated (``POST``), never on a read, and never
    from a metadata-keyed cache."""
    root, path_origin = validation_source_path(summary)
    result: dict[str, object] = {
        "path": str(root) if root else "",
        "path_origin": path_origin,
        "exists": bool(root and root.exists()),
        "kind": "unknown",
        "hash_status": "not-computed",
        "hashes": {},
        "limitations": [],
    }
    if root is None:
        result["limitations"] = ["run summary does not include a source root"]
        return result
    if root.is_file():
        result["kind"] = "file"
        result["size"] = root.stat().st_size
        if compute_hashes:
            # R8 T-179: integrity values are re-read from disk, never served from the metadata-keyed
            # cache, so a same-size, mtime-preserving modification still changes the digest.
            result["hashes"] = compute_hashes_fresh(root)
            result["hash_status"] = "computed"
            result["hash_source"] = "fresh-file-read"
        else:
            result["hash_status"] = HASH_DEFERRED
            result["limitations"] = [
                "source hashes are computed only when the validation package is generated (POST)"
            ]
        if ewf_segment_number(root) is not None:
            result["kind"] = "e01"
            result["scope"] = "container-segments"
            result["segments"] = build_container_segment_hashes(
                root,
                selected_hashes=result["hashes"] if compute_hashes else None,
                compute_hashes=compute_hashes,
            )
            segment_warnings = ewf_segment_set_warnings(root, result["segments"])
            if segment_warnings:
                result["segment_warnings"] = segment_warnings
                result["limitations"] = [*result["limitations"], *segment_warnings]
    elif root.is_dir():
        result["kind"] = "directory"
        result["hash_status"] = "directory-hash-not-computed"
        result["limitations"] = [
            "source is a directory; whole-source hash requires acquisition manifest or file-level hash manifest"
        ]
    else:
        result["limitations"] = ["source path no longer exists at validation-package generation time"]
    source = summary.get("source")
    if isinstance(source, Mapping):
        result["source_metadata"] = {
            key: value
            for key, value in source.items()
            if key in {"type", "input_kind", "source_path", "analysis_root", "stage_dir", "workflow_status", "e01_metadata"}
        }
    return result


def ewf_segment_set_warnings(selected: Path, segments: Sequence[Mapping[str, object]]) -> list[str]:
    """Gaps in the discovered EWF set, and same-named siblings the discovery did not list.

    Segment discovery (``core.e01.discover_e01_segments``, engine code) matches only two-digit
    ``.E01-.E99`` / ``.Ex01-.Ex99`` suffixes with a case-sensitive stem, so ``.EAA…`` segments of
    a 100+ segment set are not listed. The package names those siblings instead of claiming the
    listed segments are the whole container."""
    warnings: list[str] = []
    numbers = sorted(int(n) for row in segments if isinstance(n := row.get("segment_number"), int))
    if numbers:
        missing = sorted(set(range(min(numbers), max(numbers) + 1)) - set(numbers))
        if missing:
            warnings.append(f"EWF segment numbers missing from the set: {missing}")
        if min(numbers) != 1:
            warnings.append(f"EWF segment set starts at {min(numbers)}, not 1")
    listed = {str(row.get("name") or "").casefold() for row in segments}
    stem = selected.stem.casefold()
    try:
        siblings = sorted(
            candidate.name
            for candidate in selected.parent.iterdir()
            if candidate.stem.casefold() == stem
            and _EWF_SIBLING_SUFFIX.fullmatch(candidate.suffix)
            and candidate.name.casefold() not in listed
        )
    except OSError:
        siblings = []
    if siblings:
        warnings.append(
            "same-named EWF files not included in the segment list (not hashed): " + ", ".join(siblings)
        )
    return warnings


def sha256_fresh(path: Path, *, chunk_size: int = 8 * 1024 * 1024) -> str:
    """SHA-256 of the file bytes read now (no cache): the one digest a segment row keeps."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_container_segment_hashes(
    selected: Path,
    *,
    selected_hashes: Mapping[str, str] | None = None,
    compute_hashes: bool = True,
) -> list[dict[str, object]]:
    """Every discovered segment of an E01/Ex01 container (name, size, fresh SHA-256), in order.

    The selected segment alone does not identify the evidence: the package lists the whole set
    (``scope: container-segments``) so a missing or altered later segment is visible.
    ``selected_hashes`` (the selected segment's digests just read) avoids reading it twice."""
    selected_resolved = selected.resolve()
    rows: list[dict[str, object]] = []
    for segment in discover_e01_segments(selected):
        row: dict[str, object] = {"name": segment.name, "path": str(segment), "segment_number": ewf_segment_number(segment)}
        if segment.is_file():
            row["size"] = segment.stat().st_size
            if not compute_hashes:
                row["sha256"] = ""
                row["hash_status"] = HASH_DEFERRED
            elif selected_hashes is not None and segment.resolve() == selected_resolved:
                row["sha256"] = str(selected_hashes.get("sha256") or "")
            else:
                row["sha256"] = sha256_fresh(segment)
        else:
            row["size"] = None
            row["sha256"] = ""
            row["hash_status"] = "missing"
        rows.append(row)
    return rows
