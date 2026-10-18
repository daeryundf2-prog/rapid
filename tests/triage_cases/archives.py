"""Fixtures of ``rapidtriage.core.triage_rules.archives`` (see ``tests.triage_cases``).

Archive rows are ``generic-documents`` ``archive-file-inventory`` rows shaped like
``collect_archive_inventory``; signature rows are ``windows-filesystem``
``file-signature-mismatch`` rows shaped like the signature scan.
"""

from __future__ import annotations

DESKTOP = r"C:\Users\analyst\Desktop"


def archive(name: str, *, mtime: str = "2024-05-01T09:00:00+00:00", fmt: str = "zip", encrypted: int = 0, ratio: float = 2.5, **profile: object) -> dict[str, object]:
    path = rf"{DESKTOP}\{name}"
    details: dict[str, object] = {
        "parser": "archive-file-inventory",
        "source_path": path,
        "source_size": 1048576,
        "source_file_mtime": mtime,
        "archive_format": fmt,
        "entry_count": 4,
        "encrypted_entry_count": encrypted,
        "compression_ratio": ratio,
        "archive_inventory_profile": {"profile_version": "archive-inventory-profile-v1", "entry_count": 4, "encrypted_entry_count": encrypted, **profile},
        "risk_flags": ["archive-file-inventory"],
    }
    return {"kind": "generic-documents", "row": {"artifact_type": "archive-file-inventory", "path": path, "details": details}}


def mismatch(path: str, extension: str, kind: str, *, basis: str = "magic", entropy: float = 7.2, size: int = 65536) -> dict[str, object]:
    details = {
        "parser": "windows-file-signature-mismatch",
        "source_path": path,
        "source_size": size,
        "source_file_mtime": "2024-05-01T09:00:00+00:00",
        "actual_extension": extension,
        "detected_signature_kind": kind,
        "detected_content_basis": basis,
        "content_entropy": entropy,
        "mismatch_direction": "magic-not-expected-for-extension" if basis == "magic" else "extension-expected-signature-missing",
    }
    return {"kind": "windows-filesystem", "row": {"artifact_type": "file-signature-mismatch", "path": path, "details": details}}


def shortcut(target: str, drive: str) -> dict[str, object]:
    name = target.rsplit("\\", 1)[-1]
    return {
        "kind": "recent-files",
        "row": {
            "artifact_type": "recent-shortcut",
            "path": rf"C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Recent\{name}.lnk",
            "details": {"target_path": target, "drive_type_name": drive, "lnk_parse_status": "parsed"},
        },
    }


def usb_device(arrival: str) -> dict[str, object]:
    return {
        "kind": "windows-registry",
        "row": {
            "artifact_type": "windows-usb-device",
            "path": r"C:\Windows\System32\config\SYSTEM",
            "details": {"device_description": "USB Mass Storage", "serial_number": "0000TESTSERIAL01", "last_arrival_at": arrival},
        },
    }


CASES = {
    "archives.enc_archive_with_exfil": {
        "positive": {
            "rows": [
                # Encrypted archive later opened from a removable drive.
                archive("q2-data.zip", encrypted=3),
                shortcut(r"E:\q2-data.zip", "removable"),
                # Encrypted 7z written two hours before a USB stick arrived.
                archive("handover.7z", fmt="7z", encrypted=1, mtime="2024-05-01T09:00:00+00:00"),
                usb_device("2024-05-01T11:00:00+00:00"),
            ],
            "flagged": [0, 2],
        },
        # Work zips: the encrypted one only opened locally and USB arrived days later; the one on USB is not encrypted.
        "negative": {
            "rows": [
                archive("payroll.zip", encrypted=2, mtime="2024-05-01T09:00:00+00:00"),
                shortcut(rf"{DESKTOP}\payroll.zip", "fixed"),
                archive("brochure.zip"),
                shortcut(r"E:\brochure.zip", "removable"),
                usb_device("2024-05-04T09:00:00+00:00"),
            ],
            "flagged": [],
        },
    },
    "archives.header_encrypted_list_hidden": {
        "positive": {"rows": [archive("archive.7z", fmt="7z", encrypted=1, header_encrypted=True)], "flagged": [0]},
        # Password-protected entries but a readable file list (plain ZipCrypto/AES).
        "negative": {"rows": [archive("contract.zip", encrypted=4, header_encrypted=False)], "flagged": []},
    },
    "archives.high_entropy_no_sig": {
        # Random-looking 500 MiB ".docx" with no magic (sniffed only as high-entropy binary).
        "positive": {
            "rows": [mismatch(r"C:\Users\analyst\Documents\notes.docx", ".docx", "high-entropy-binary", basis="heuristic", entropy=7.953, size=524288000)],
            "flagged": [0],
        },
        # 7z archive behind a wrong extension (has a magic) and a high-entropy blob whose size is not a 64 multiple.
        "negative": {
            "rows": [
                mismatch(r"C:\Users\analyst\Documents\backup.pdf", ".pdf", "7zip", entropy=7.97, size=524288000),
                mismatch(r"C:\Users\analyst\Documents\scan.jpg", ".jpg", "high-entropy-binary", basis="heuristic", entropy=7.95, size=2000003),
            ],
            "flagged": [],
        },
    },
    "archives.ext_mismatch_container": {
        "positive": {
            "rows": [
                mismatch(rf"{DESKTOP}\holiday.jpg", ".jpg", "zip-ooxml"),
                mismatch(rf"{DESKTOP}\report.pdf", ".pdf", "rar"),
            ],
            "flagged": [0, 1],
        },
        # ZIP-family formats (HWPX) and a non-archive mismatch (JPEG saved as .png).
        "negative": {
            "rows": [
                mismatch(rf"{DESKTOP}\minutes.hwpx", ".hwpx", "zip-ooxml"),
                mismatch(rf"{DESKTOP}\photo.png", ".png", "jpeg"),
                # Windows 10+ Prefetch is MAM-compressed and sniffed as gzip (run-subset10).
                mismatch(r"C:\Windows\Prefetch\MSEDGEWEBVIEW2.EXE-493C77DB.pf", ".pf", "gzip"),
            ],
            "flagged": [],
        },
    },
    "archives.nested_deep": {
        "positive": {"rows": [archive("deliver.zip", nested_archive_entry_count=1, max_nested_depth=4)], "flagged": [0]},
        # Installer bundle: several inner archives, one level deep.
        "negative": {"rows": [archive("driver-pack.zip", nested_archive_entry_count=5, max_nested_depth=2)], "flagged": []},
    },
    "archives.zip_bomb_ratio": {
        "positive": {"rows": [archive("bomb.zip", ratio=1031.5, total_compressed_size=4362000, total_uncompressed_size=4500000000)], "flagged": [0]},
        # Large log archive: high but ordinary text compression ratio.
        "negative": {"rows": [archive("logs-2024-04.zip", ratio=45.0, total_compressed_size=47700000, total_uncompressed_size=2147000000)], "flagged": []},
    },
    "archives.sfx_exe": {
        "positive": {
            "rows": [
                archive("tools.zip", sfx=True),
                mismatch(rf"{DESKTOP}\setup_data.exe", ".exe", "rar"),
            ],
            "flagged": [0, 1],
        },
        # Partially recovered (zero-filled) executable and an ordinary zip.
        "negative": {
            "rows": [
                mismatch(rf"{DESKTOP}\installer.exe", ".exe", "zero-filled", basis="heuristic", entropy=0.0),
                archive("tools.zip", sfx=False),
            ],
            "flagged": [],
        },
    },
    "archives.entry_time_later_than_container": {
        # Entry dated a year after the archive file itself (DOS times as the parser writes them).
        "positive": {
            "rows": [
                archive(
                    "evidence.zip",
                    mtime="2023-03-10T12:00:00+00:00",
                    sample_entries=[
                        {"name": "a.txt", "last_modified": "2023-03-09T18:00:00", "timezone": "local-unknown"},
                        {"name": "b.xlsx", "last_modified": "2024-06-01T09:00:00", "timezone": "local-unknown"},
                    ],
                )
            ],
            "flagged": [0],
        },
        # KST DOS time read as UTC: 9 h "later" than the container, inside the slack.
        "negative": {
            "rows": [
                archive(
                    "evidence.zip",
                    mtime="2023-03-10T03:00:00+00:00",
                    sample_entries=[{"name": "a.txt", "last_modified": "2023-03-10T12:00:00", "timezone": "local-unknown"}],
                )
            ],
            "flagged": [],
        },
    },
}
