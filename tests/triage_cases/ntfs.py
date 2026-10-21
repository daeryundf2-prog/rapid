"""Fixtures of ``rapidtriage.core.triage_rules.ntfs`` (see ``tests.triage_cases``).

MFT / USN rows are ``ntfs-meta`` analysis rows shaped like ``parse_mft_file`` /
``parse_usn_file`` output; ADS / Zone.Identifier / Recycle Bin rows are
``windows-filesystem`` artifact rows.
"""

from __future__ import annotations


def mft(entry: int, path: str, *, in_use: bool = True, directory: bool = False, **times: str) -> dict[str, object]:
    """An ``ntfs-meta`` MFT row; ``times`` = ``si_*`` / ``fn_*`` fields."""
    name = path.rsplit("\\", 1)[-1]
    return {
        "analysis": "ntfs-meta",
        "row": {
            "artifact_type": "ntfs-meta-row",
            "path": path,
            "details": {
                "source": "mft",
                "entry_number": entry,
                "sequence_number": 3,
                "in_use": in_use,
                "directory": directory,
                "name": name,
                "path": path,
                "parent_path": path.rsplit("\\", 1)[0] or "\\",
                **times,
            },
        },
    }


def usn(entry: int, path: str, reasons: list[str], timestamp: str, usn_number: int = 1000) -> dict[str, object]:
    """An ``ntfs-meta`` USN row."""
    return {
        "analysis": "ntfs-meta",
        "row": {
            "artifact_type": "ntfs-meta-row",
            "path": path,
            "details": {
                "source": "usn",
                "usn": usn_number,
                "reason": "|".join(reasons),
                "reason_flags": reasons,
                "file_name": path.rsplit("\\", 1)[-1],
                "timestamp": timestamp,
                "entry_number": entry,
                "path": path,
            },
        },
    }


def fs_row(artifact_type: str, path: str, **details: object) -> dict[str, object]:
    return {"kind": "windows-filesystem", "row": {"artifact_type": artifact_type, "path": path, "details": {"source_path": path, **details}}}


DOC = r"\Users\analyst\Documents\quarterly-plan.docx"
TOOL = r"\Users\analyst\AppData\Local\Temp\svc-helper.exe"


def burst(start_second: int, step_seconds: int, count: int, reasons: list[str]) -> list[dict[str, object]]:
    """``count`` USN rows ``step_seconds`` apart from 10:00:00 + ``start_second``."""
    rows = []
    for index in range(count):
        total = start_second + index * step_seconds
        stamp = f"2024-05-01T{10 + total // 3600:02d}:{total // 60 % 60:02d}:{total % 60:02d}.1000000Z"
        rows.append(usn(5000 + index, rf"\Users\analyst\Documents\file-{index:03d}.xlsx.locked", reasons, stamp, 9000 + index))
    return rows


FN_TIME = "2024-05-01T10:15:30.1234567Z"
SI_BEFORE_FN_GRADES = ["A", "A", "C", "B"]  # grade of each positive row (tests.test_rapidtriage_triage_rules)


def copied(entry: int, path: str, fn_created_at: str = FN_TIME) -> dict[str, object]:
    """A timestamp-preserving copy/extraction: old $SI created/modified with sub-seconds, $SI MFT-modified = copy time."""
    return mft(
        entry,
        path,
        si_created_at="2021-07-07T12:00:00.5550000Z",
        si_modified_at="2021-07-07T12:00:00.5550000Z",
        si_mft_modified_at=fn_created_at,
        fn_created_at=fn_created_at,
        fn_modified_at=fn_created_at,
    )


CASES = {
    "ntfs.si_before_fn": {
        # $SI Created set back years before the $FILE_NAME creation; grades in SI_BEFORE_FN_GRADES.
        "positive": {
            "rows": [
                # A: second-precision timestomp -- every $SI time .0000000 ($SI MFT-modified recent), $FN has sub-seconds.
                mft(
                    1201,
                    TOOL,
                    si_created_at="2019-03-01T09:00:00.0000000Z",
                    si_modified_at="2019-03-01T09:00:00.0000000Z",
                    si_mft_modified_at="2024-05-01T10:15:30.0000000Z",
                    fn_created_at=FN_TIME,
                    fn_modified_at=FN_TIME,
                ),
                # A: all four $SI times rewritten with sub-seconds ($SI MFT-modified also before the name existed).
                mft(
                    1203,
                    r"\Users\analyst\Documents\ledger-2019.xlsx",
                    si_created_at="2019-03-01T09:00:00.1234567Z",
                    si_modified_at="2019-03-02T11:20:00.7654321Z",
                    si_mft_modified_at="2019-03-02T11:20:00.7654321Z",
                    fn_created_at=FN_TIME,
                    fn_modified_at=FN_TIME,
                ),
                # C: plain timestamp-preserving copy of a document (sub-second $SI, fresh $SI MFT-modified).
                copied(1204, DOC),
                # B: the same plain copy, but an executable under a user-writable folder.
                copied(1205, r"\Users\analyst\Downloads\setup-helper.exe"),
            ],
            "flagged": [0, 1, 2, 3],
        },
        # Not flagged: a bulk copy (>= bulk_min_records hits whose $FN created falls in one hour), a
        # WinSxS servicing file, and a plain copy whose $SI/$FN Created are both the copy time.
        "negative": {
            "params": {"bulk_min_records": 3},
            "rows": [
                copied(1210, r"\Users\analyst\Documents\tree\a.docx", "2024-05-01T10:01:00.1000000Z"),
                copied(1211, r"\Users\analyst\Documents\tree\b.pdf", "2024-05-01T10:20:00.2000000Z"),
                copied(1212, r"\Users\analyst\Documents\tree\c.exe", "2024-05-01T10:59:00.3000000Z"),
                copied(1213, r"\Windows\WinSxS\amd64_microsoft-windows-shell32_31bf3856ad364e35\shell32.dll", "2024-06-02T08:00:00.4000000Z"),
                mft(
                    1202,
                    DOC,
                    si_created_at=FN_TIME,
                    si_modified_at="2021-07-07T12:00:00.5550000Z",
                    fn_created_at=FN_TIME,
                    fn_modified_at=FN_TIME,
                ),
            ],
            "flagged": [],
        },
    },
    "ntfs.zero_subsecond": {
        "positive": {
            "rows": [
                mft(
                    1301,
                    TOOL,
                    si_created_at="2020-01-15T08:30:00.0000000Z",
                    si_modified_at="2020-01-15T08:30:00.0000000Z",
                    fn_created_at="2024-05-01T10:15:30.1234567Z",
                )
            ],
            "flagged": [0],
        },
        # Copied from a FAT stick: only the preserved $SI Modified has FAT (2 s) precision.
        "negative": {
            "rows": [
                mft(
                    1302,
                    DOC,
                    si_created_at="2024-05-01T10:15:30.1234567Z",
                    si_modified_at="2023-11-20T08:42:16.0000000Z",
                    fn_created_at="2024-05-01T10:15:30.1234567Z",
                )
            ],
            "flagged": [],
        },
    },
    "ntfs.fn_manipulation": {
        # Renamed on 05-01 but $FN changed in 2023: $FN times written back after the rename.
        "positive": {
            "rows": [
                mft(
                    2050,
                    TOOL,
                    si_created_at="2023-01-10T08:00:00.0000000Z",
                    fn_created_at="2023-01-10T08:00:00.0000000Z",
                    fn_mft_modified_at="2023-01-10T08:00:00.0000000Z",
                ),
                usn(2050, r"\Users\analyst\AppData\Local\Temp\update.tmp", ["RENAME_OLD_NAME"], "2024-05-01T10:00:00.0000000Z", 700),
                usn(2050, TOOL, ["RENAME_NEW_NAME"], "2024-05-01T10:00:00.0010000Z", 701),
                usn(2050, TOOL, ["RENAME_NEW_NAME", "CLOSE"], "2024-05-01T10:00:00.0020000Z", 702),
            ],
            "flagged": [3],
        },
        # Ordinary rename/move: $FN change time follows the rename.
        "negative": {
            "rows": [
                mft(
                    2051,
                    DOC,
                    si_created_at="2023-01-10T08:00:00.0000000Z",
                    fn_created_at="2023-01-10T08:00:00.0000000Z",
                    fn_mft_modified_at="2024-05-01T10:00:00.0030000Z",
                ),
                usn(2051, r"\Users\analyst\Documents\draft.docx", ["RENAME_OLD_NAME"], "2024-05-01T10:00:00.0000000Z", 710),
                usn(2051, DOC, ["RENAME_NEW_NAME", "CLOSE"], "2024-05-01T10:00:00.0020000Z", 711),
            ],
            "flagged": [],
        },
    },
    "ntfs.usn_basic_info_change": {
        "positive": {
            "rows": [
                mft(3100, TOOL, si_created_at="2020-02-02T02:02:02.0000000Z", si_modified_at="2020-02-02T02:02:02.0000000Z"),
                usn(3100, TOOL, ["DATA_EXTEND", "CLOSE"], "2024-05-01T09:59:00.0000000Z", 800),
                usn(3100, TOOL, ["BASIC_INFO_CHANGE", "CLOSE"], "2024-05-01T10:00:00.0000000Z", 801),
            ],
            "flagged": [2],
        },
        # Attribute change (hidden/archive bit) on a file edited the same morning.
        "negative": {
            "rows": [
                mft(3101, DOC, si_created_at="2024-04-20T09:00:00.1000000Z", si_modified_at="2024-05-01T09:30:00.1000000Z"),
                usn(3101, DOC, ["BASIC_INFO_CHANGE", "CLOSE"], "2024-05-01T10:00:00.0000000Z", 810),
            ],
            "flagged": [],
        },
    },
    "ntfs.time_inversion": {
        "positive": {
            "rows": [mft(4100, DOC, si_created_at="2024-05-01T10:15:30.1234567Z", si_modified_at="2021-07-07T12:00:00.5550000Z")],
            "flagged": [0],
        },
        # Created and first written in the same second (sub-second ordering noise).
        "negative": {
            "rows": [mft(4101, DOC, si_created_at="2024-05-01T10:15:30.9000000Z", si_modified_at="2024-05-01T10:15:30.4000000Z")],
            "flagged": [],
        },
    },
    "ntfs.ads_executable": {
        "positive": {
            "rows": [
                # ADS export file (name:stream) carrying an MZ header.
                fs_row(
                    "ads-stream-candidate",
                    r"C:\Users\analyst\Documents\notes.txt:svc.bin",
                    host_file_name="notes.txt",
                    stream_name="svc.bin",
                    stream_type="$DATA",
                    stream_family="embedded-windows-pe",
                    detected_signature_kind="windows-pe",
                    signature_hex="4d5a",
                ),
                # icat-recovered stream: only the sniffed kind, no signature bytes.
                fs_row(
                    "ads-stream-candidate",
                    r"C:\Users\Public\readme.txt:cfg",
                    host_file_path=r"C:\Users\Public\readme.txt",
                    host_file_name="readme.txt",
                    stream_name="cfg",
                    stream_type="$DATA",
                    stream_family="embedded-windows-pe",
                    detected_signature_kind="windows-pe",
                ),
            ],
            "flagged": [0, 1],
        },
        # Security-product tag stream (text) and a Zone.Identifier stream.
        "negative": {
            "rows": [
                fs_row(
                    "ads-stream-candidate",
                    r"C:\Users\analyst\Downloads\tool.zip:{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",
                    host_file_name="tool.zip",
                    stream_name="{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",
                    stream_type="$DATA",
                    stream_family="named-data-stream",
                    detected_signature_kind="",
                    bounded_preview="scanned=1;engine=1.1.24000",
                ),
                fs_row(
                    "ads-stream-candidate",
                    r"C:\Users\analyst\Downloads\tool.zip:Zone.Identifier",
                    host_file_name="tool.zip",
                    stream_name="Zone.Identifier",
                    stream_type="$DATA",
                    stream_family="download-provenance",
                    detected_signature_kind="",
                    zone_id="3",
                ),
            ],
            "flagged": [],
        },
    },
    "ntfs.zone_identifier": {
        "positive": {
            "rows": [
                fs_row(
                    "zone-identifier",
                    r"C:\Users\analyst\Downloads\setup.zip:Zone.Identifier",
                    host_file_path=r"C:\Users\analyst\Downloads\setup.zip",
                    host_file_name="setup.zip",
                    stream_name="Zone.Identifier",
                    zone_id="3",
                    zone_name="internet",
                    host_url="https://downloads.example.com/files/setup.zip",
                    referrer_url="https://www.example.com/download",
                )
            ],
            "flagged": [0],
        },
        # Intranet share copy and an Internet-zone mark written without a HostUrl (saved mail attachment).
        "negative": {
            "rows": [
                fs_row(
                    "zone-identifier",
                    r"C:\Users\analyst\Documents\form.docx:Zone.Identifier",
                    host_file_name="form.docx",
                    stream_name="Zone.Identifier",
                    zone_id="1",
                    zone_name="local-intranet",
                    host_url="file://fileserver.corp.example/share/form.docx",
                ),
                fs_row(
                    "zone-identifier",
                    r"C:\Users\analyst\Documents\invoice.pdf:Zone.Identifier",
                    host_file_name="invoice.pdf",
                    stream_name="Zone.Identifier",
                    zone_id="3",
                    zone_name="internet",
                ),
            ],
            "flagged": [],
        },
    },
    "ntfs.deletion_trace": {
        "positive": {
            "rows": [
                fs_row(
                    "recycle-bin-entry",
                    r"C:\$Recycle.Bin\S-1-5-21-1000-1000-1000-1001\$IAB12CD.xlsx",
                    original_path=r"C:\Users\analyst\Documents\budget-2024.xlsx",
                    deleted_at="2024-05-01T10:20:00Z",
                    deleted_file_size=48213,
                    recycle_id="AB12CD.xlsx",
                ),
                mft(6100, r"\Users\analyst\Desktop\handover.docx", in_use=False),
            ],
            "flagged": [0, 1],
        },
        # Recycled shortcut, deleted temp file, deleted folder named like an archive, live document.
        "negative": {
            "rows": [
                fs_row(
                    "recycle-bin-entry",
                    r"C:\$Recycle.Bin\S-1-5-21-1000-1000-1000-1001\$IEF34GH.lnk",
                    original_path=r"C:\Users\analyst\Desktop\Old App.lnk",
                    deleted_at="2024-05-01T10:20:00Z",
                    deleted_file_size=1520,
                ),
                mft(6101, r"\Users\analyst\AppData\Local\Temp\~DF1A2B.tmp", in_use=False),
                mft(6102, r"\Users\analyst\Downloads\photos.zip", in_use=False, directory=True),
                mft(6103, DOC, in_use=True),
            ],
            "flagged": [],
        },
    },
    "ntfs.mass_change": {
        # Ransomware-style burst: 6 renames within 5 seconds (threshold lowered to 5 for the fixture).
        "positive": {
            "rows": burst(0, 1, 6, ["RENAME_NEW_NAME"]),
            "flagged": [0, 1, 2, 3, 4, 5],
            "params": {"window_seconds": 60, "min_count": 5},
        },
        # Same number of renames spread over a working hour, plus a write burst (not RENAME/DELETE).
        "negative": {
            "rows": [*burst(0, 600, 6, ["RENAME_NEW_NAME"]), *burst(3, 1, 6, ["DATA_EXTEND", "CLOSE"])],
            "flagged": [],
            "params": {"window_seconds": 60, "min_count": 5},
        },
    },
}
