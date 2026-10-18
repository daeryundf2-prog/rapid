"""Fixtures of ``rapidtriage.core.triage_rules.generic`` (see ``tests.triage_cases``)."""

from __future__ import annotations


def shortcut(**details: object) -> dict[str, object]:
    return {
        "kind": "recent-files",
        "row": {"artifact_type": "recent-shortcut", "path": r"C:\Users\u\AppData\Roaming\Microsoft\Windows\Recent\a.lnk", "details": details},
    }


CASES = {
    "generic.timestamp_out_of_range": {
        # A carved LNK with a 1628 target time, a parser that read a 2087 date, a files row from 1975.
        "positive": {
            "rows": [
                shortcut(target_created_at="1628-03-04T05:06:07+00:00", target_modified_at="2024-01-02T03:04:05+00:00"),
                shortcut(target_accessed_at="2087-01-01T00:00:00+00:00"),
                {"files": "candidates", "row": {"path": r"C:\Users\u\x.doc", "name": "x.doc", "fs_modified_at": "1975-06-01T00:00:00+00:00"}},
                shortcut(target_modified_at="2024-01-02T03:04:05+00:00"),
            ],
            "flagged": [0, 1, 2],
        },
        # FILETIME/Unix zero placeholders, a far-future cookie expiry, a contact birthday, an EXIF-style text field.
        "negative": {
            "rows": [
                shortcut(target_created_at="1601-01-01T00:00:00+00:00", target_accessed_at="1970-01-01T00:00:00Z"),
                # DOS date 0 = 1980-01-01 00:00 KST, stored as UTC (run-subset10 LNK).
                shortcut(target_created_at="1979-12-31T15:00:00+00:00"),
                {"kind": "browser", "row": {"artifact_type": "browser-cookie", "details": {"expires_at": "2099-12-31T23:59:59Z", "created_at": "2024-02-01T00:00:00Z"}}},
                {"kind": "mobile-export", "row": {"artifact_type": "mobile-contact", "details": {"birth_date": "1950-05-05", "updated_at": "2023-01-01T00:00:00Z"}}},
                {"kind": "media-image", "row": {"artifact_type": "media-image", "details": {"datetime_original": "1950:01:01 00:00:00"}}},
                # PE link times of reproducible builds are hashes; driver version dates are not event times.
                {
                    "kind": "windows-execution",
                    "row": {
                        "artifact_type": "amcache-entry",
                        "details": {"link_date": "2093-12-26T15:23:06+00:00", "driver_version_date": "1968-07-18"},
                    },
                },
                # R3: an ntfs-meta timestamp-mismatch row repeats its MFT row's times (that row is checked).
                {
                    "analysis": "ntfs-meta",
                    "row": {
                        "artifact_type": "ntfs-timestamp-mismatch",
                        "details": {"source": "timestamp-mismatch", "si_accessed_at": "2091-01-01T00:00:00+00:00"},
                    },
                },
            ],
            "flagged": [],
        },
    },
}
