"""Fixtures of ``rapidtriage.core.triage_rules.execution`` (see ``tests.triage_cases``)."""

from __future__ import annotations

VOLUME = r"\VOLUME{01d9a0b1c2d3e4f5-1a2b3c4d}"


def prefetch(name: str, folder: str, run_times: list[str] | None = None) -> dict[str, object]:
    """Decoded Prefetch row (parser v10) of ``name`` whose file metrics include ``<VOLUME>\\<folder>\\<name>``.

    The executable's path is only in ``referenced_files`` (decoded file-metrics
    entries), so the rules must read the decoded field.
    """
    files = [rf"{VOLUME}\WINDOWS\SYSTEM32\NTDLL.DLL", rf"{VOLUME}\{folder}\{name}"]
    return {
        "kind": "windows-prefetch",
        "row": {
            "artifact_type": "prefetch-file",
            "path": rf"C:\Windows\Prefetch\{name}-1A2B3C4D.pf",
            "details": {
                "executable_hint": name,
                "referenced_files": [
                    {"path": path, "mft_entry": 1000 + index, "mft_sequence": 3, "source_offset": 0x400 + 0x60 * index}
                    for index, path in enumerate(files)
                ],
                "referenced_file_count": len(files),
                "run_count": len(run_times or []) or 1,
                "last_run_times": run_times or ["2024-05-01T10:00:00Z"],
                "volumes": [{"volume_device_path": VOLUME, "volume_serial_number": "1A2B3C4D"}],
            },
        },
    }


def trace(artifact_type: str, path: str, **details: object) -> dict[str, object]:
    return {
        "kind": "windows-execution",
        "row": {"artifact_type": artifact_type, "path": r"C:\Windows\appcompat\Programs\Amcache.hve", "details": {"executable_path": path, **details}},
    }


def listed(path: str) -> dict[str, object]:
    return {"files": "candidates", "row": {"path": path, "name": path.rsplit("\\", 1)[-1]}}


def srum(app: str, sent: int) -> dict[str, object]:
    return trace("srum-network-usage", app, bytes_sent=sent, bytes_received=1024, timestamp="2024-05-01T10:00:00Z")


BURST = [f"2024-05-01T10:{minute:02d}:00Z" for minute in range(0, 40, 5)]
DAILY = [f"2024-05-{day:02d}T09:00:00Z" for day in range(1, 9)]

CASES = {
    "execution.suspicious_path": {
        "positive": {
            "rows": [
                trace("amcache-entry", r"C:\Users\user1\AppData\Local\Temp\x1\dropper.exe"),
                # Decoded Prefetch (MAM, parser v10): the path comes from referenced_files.
                prefetch("DROPPER.EXE", r"USERS\USER1\DOWNLOADS"),
            ],
            "flagged": [0, 1],
        },
        # Per-user installed app (AppData\Local\Programs): excluded by the catalogue's exclude_markers.
        "negative": {"rows": [trace("amcache-entry", r"C:\Users\user1\AppData\Local\Programs\VendorApp\vendorapp.exe")], "flagged": []},
    },
    "execution.runcount_spike": {
        "positive": {"rows": [prefetch("TOOL.EXE", r"USERS\USER1\DESKTOP", BURST)], "flagged": [0]},
        # Daily scheduled run: eight runs spread over eight days.
        "negative": {"rows": [prefetch("TOOL.EXE", r"USERS\USER1\DESKTOP", DAILY)], "flagged": []},
    },
    "execution.name_mismatch": {
        "positive": {"rows": [trace("amcache-entry", r"C:\Users\Public\svchost.exe")], "flagged": [0]},
        # BAM device path of the genuine System32 binary.
        "negative": {"rows": [trace("bam-entry", r"\Device\HarddiskVolume3\Windows\System32\svchost.exe")], "flagged": []},
    },
    "execution.deleted_executable": {
        "positive": {
            "rows": [listed(r"C:\Users\user1\Downloads\readme.txt"), trace("amcache-entry", r"C:\Users\user1\Downloads\wiper.exe")],
            "flagged": [1],
        },
        # The executable is still in the listing.
        "negative": {
            "rows": [
                listed(r"C:\Users\user1\Downloads\readme.txt"),
                listed(r"C:\Users\user1\Downloads\wiper.exe"),
                trace("amcache-entry", r"C:\Users\user1\Downloads\wiper.exe"),
            ],
            "flagged": [],
        },
    },
    "execution.cross_mismatch": {
        "positive": {
            "rows": [prefetch("OTHER.EXE", r"USERS\USER1\DESKTOP"), trace("shimcache-entry", r"C:\Users\user1\Desktop\scanner.exe")],
            "flagged": [1],
        },
        # Server without Prefetch/Amcache at all: nothing to compare against.
        "negative": {"rows": [trace("shimcache-entry", r"C:\Users\user1\Desktop\scanner.exe")], "flagged": []},
    },
    "execution.srum_bulk_upload": {
        "positive": {"rows": [srum(r"\Device\HarddiskVolume3\Users\user1\AppData\Local\Temp\rclone.exe", 2_000_000_000)], "flagged": [0]},
        # Sync client in allowed_apps.
        "negative": {"rows": [srum(r"\Device\HarddiskVolume3\Users\user1\AppData\Local\Microsoft\OneDrive\OneDrive.exe", 2_000_000_000)], "flagged": []},
    },
    "execution.multi_source": {
        "positive": {
            "rows": [
                prefetch("SYNCTOOL.EXE", r"USERS\USER1\DESKTOP"),
                trace("amcache-entry", r"C:\Users\user1\Desktop\synctool.exe"),
                trace("bam-entry", r"\Device\HarddiskVolume3\Users\user1\Desktop\synctool.exe"),
            ],
            "flagged": [0, 1, 2],
        },
        # Installed application under Program Files: not reported.
        "negative": {
            "rows": [
                prefetch("APP.EXE", r"PROGRAM FILES\VENDORX"),
                trace("amcache-entry", r"C:\Program Files\VendorX\app.exe"),
                trace("bam-entry", r"\Device\HarddiskVolume3\Program Files\VendorX\app.exe"),
            ],
            "flagged": [],
        },
    },
}
