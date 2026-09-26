"""Cross-device IOC correlation (R4-2).

Correlates indicator values across multiple runs/devices (e.g. a suspect's PC,
laptop, and USB image) to surface shared indicators of compromise and movement
hints such as the same file hash appearing on two different devices.

Forensic boundary: shared sightings are *correlation candidates*, not
attribution. Every shared IOC keeps per-run source pointers so the reviewer
can verify each sighting before reporting.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone

CROSS_DEVICE_IOC_PROFILE = "cross-device-ioc-v1"

# Indicator types whose sighting on a second device is meaningful for
# movement/exfiltration reasoning (hashes, identifiers, removable media).
MOVEMENT_SIGNIFICANT_TYPES = {
    "hash",
    "md5",
    "sha1",
    "sha256",
    "sha-256",
    "file-hash",
    "filename",
    "path",
    "usb",
    "serial",
    "volume-serial",
    "device-id",
    "mac",
    "email",
    "account",
    "sid",
}


def _normalize_ioc_key(indicator: Mapping[str, object]) -> tuple[str, str] | None:
    indicator_type = str(indicator.get("type") or "").strip().lower()
    value = str(indicator.get("value") or "").strip().lower()
    if not indicator_type or not value:
        return None
    return indicator_type, value


def _compact_sighting(
    *,
    run_id: str,
    label: str,
    root: str,
    indicator: Mapping[str, object],
    max_sources: int,
) -> dict[str, object]:
    sources = indicator.get("sources")
    compact_sources: list[dict[str, object]] = []
    if isinstance(sources, Sequence) and not isinstance(sources, str):
        for source in list(sources)[:max_sources]:
            if isinstance(source, Mapping):
                compact_sources.append(
                    {
                        key: source[key]
                        for key in ("path", "artifact", "pointer", "source")
                        if source.get(key) is not None
                    }
                )
    return {
        "run_id": run_id,
        "device_label": label,
        "device_root": root,
        "count": int(indicator.get("count") or 0),
        "sources": compact_sources,
    }


def build_cross_device_ioc_package(
    run_entries: Sequence[Mapping[str, object]],
    *,
    min_runs: int = 2,
    max_shared: int = 500,
    max_sources_per_sighting: int = 5,
) -> dict[str, object]:
    """Correlate indicator sightings across runs.

    ``run_entries`` items: ``{run_id, label, root, indicators: [...]}``.
    Returns the shared-IOC package; runs without indicators still appear in
    ``devices`` with zero counts.
    """
    devices: list[dict[str, object]] = []
    sightings: dict[tuple[str, str], list[dict[str, object]]] = {}
    total_indicators = 0

    for entry in run_entries:
        run_id = str(entry.get("run_id") or "")
        label = str(entry.get("label") or run_id)
        root = str(entry.get("root") or "")
        indicators = entry.get("indicators") or []
        run_indicator_keys: set[tuple[str, str]] = set()
        for indicator in indicators:
            if not isinstance(indicator, Mapping):
                continue
            key = _normalize_ioc_key(indicator)
            if key is None:
                continue
            run_indicator_keys.add(key)
            total_indicators += 1
            sightings.setdefault(key, []).append(
                _compact_sighting(
                    run_id=run_id,
                    label=label,
                    root=root,
                    indicator=indicator,
                    max_sources=max_sources_per_sighting,
                )
            )
        devices.append(
            {
                "run_id": run_id,
                "device_label": label,
                "device_root": root,
                "indicator_count": len(run_indicator_keys),
            }
        )

    shared_iocs: list[dict[str, object]] = []
    movement_hints: list[dict[str, object]] = []
    for (indicator_type, value), seen in sightings.items():
        run_ids = {sighting["run_id"] for sighting in seen}
        if len(run_ids) < min_runs:
            continue
        roots = {sighting["device_root"] for sighting in seen}
        entry = {
            "type": indicator_type,
            "value": value,
            "run_count": len(run_ids),
            "device_count": len(roots),
            "total_count": sum(int(sighting["count"]) for sighting in seen),
            "sightings": seen,
            "movement_significant": indicator_type in MOVEMENT_SIGNIFICANT_TYPES,
        }
        shared_iocs.append(entry)
        if indicator_type in MOVEMENT_SIGNIFICANT_TYPES or len(roots) > 1:
            movement_hints.append(
                {
                    "type": indicator_type,
                    "value": value,
                    "devices": sorted({s["device_label"] for s in seen}),
                    "run_ids": sorted(run_ids),
                    "hint": (
                        f"{indicator_type} '{value}' sighted on {len(roots)} "
                        "device source(s) — review each sighting's source path "
                        "for movement/exfiltration assessment"
                    ),
                }
            )

    shared_iocs.sort(
        key=lambda item: (
            -int(item["run_count"]),
            -int(item["total_count"]),
            str(item["type"]),
            str(item["value"]),
        )
    )
    shared_iocs = shared_iocs[:max_shared]
    movement_hints.sort(key=lambda item: (item["type"], item["value"]))
    movement_hints = movement_hints[:max_shared]

    shared_keys = {(item["type"], item["value"]) for item in shared_iocs}
    for device in devices:
        run_id = device["run_id"]
        device["shared_count"] = sum(
            1 for key in shared_keys if any(s["run_id"] == run_id for s in sightings[key])
        )
        device["unique_count"] = int(device["indicator_count"]) - int(device["shared_count"])

    return {
        "profile_version": CROSS_DEVICE_IOC_PROFILE,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "parameters": {
            "min_runs": min_runs,
            "max_shared": max_shared,
            "max_sources_per_sighting": max_sources_per_sighting,
        },
        "summary": {
            "run_count": len(run_entries),
            "device_count": len({d["device_root"] for d in devices}) or len(devices),
            "indicator_rows_seen": total_indicators,
            "shared_ioc_count": len(shared_iocs),
            "movement_hint_count": len(movement_hints),
        },
        "devices": devices,
        "shared_iocs": shared_iocs,
        "movement_hints": movement_hints,
        "report_use_boundary": (
            "Shared sightings are correlation candidates, not attribution. "
            "Verify each sighting's source path and artifact context before "
            "reporting movement or exfiltration."
        ),
    }
