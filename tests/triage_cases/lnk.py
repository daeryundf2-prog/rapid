"""Fixtures of ``rapidtriage.core.triage_rules.lnk`` (see ``tests.triage_cases``)."""

from __future__ import annotations

TIMES = {
    "target_created_at": "2024-04-01T09:00:00Z",
    "target_modified_at": "2024-04-02T09:00:00Z",
    "target_accessed_at": "2024-05-01T09:00:00Z",
}


def shortcut(target: str, *, drive_type: str = "fixed", vsn: str = "0C1D2E3F", times: bool = True, **details: object) -> dict[str, object]:
    """Recent-items LNK row (fields as ``recent_files.parse_lnk_metadata`` writes them)."""
    link_info: dict[str, object] = {}
    if drive_type != "unc":
        link_info = {"local_base_path": target, "drive_type_name": drive_type, "volume_serial_number": vsn}
    row_details: dict[str, object] = {
        "target_path": target,
        "drive_type_name": link_info.get("drive_type_name", ""),
        "volume_serial_number": link_info.get("volume_serial_number", ""),
        "local_base_path": link_info.get("local_base_path", ""),
        "link_info": link_info,
        **(TIMES if times else {}),
        **details,
    }
    name = target.replace("/", "\\").rsplit("\\", 1)[-1]
    return {
        "kind": "recent-files",
        "row": {
            "artifact_type": "recent-shortcut",
            "path": rf"C:\Users\user1\AppData\Roaming\Microsoft\Windows\Recent\{name}.lnk",
            "details": row_details,
        },
    }


def mounted(letter: str, removable: bool) -> dict[str, object]:
    return {
        "kind": "windows-registry",
        "row": {
            "artifact_type": "windows-mounted-device",
            "details": {"mount_name": rf"\DosDevices\{letter}", "drive_letter": letter, "removable_usb": removable},
        },
    }


def computer_name(name: str) -> dict[str, object]:
    return {"kind": "windows-registry", "row": {"artifact_type": "windows-computer-name", "details": {"computer_name": name}}}


def listed(path: str) -> dict[str, object]:
    return {"files": "candidates", "row": {"path": path, "name": path.rsplit("\\", 1)[-1]}}


CASES = {
    "lnk.removable_target": {
        "positive": {
            "rows": [
                shortcut(r"E:\Export\plan.docx", drive_type="removable", vsn="1A2B3C4D"),
                # USB hard disk reports DriveType fixed; F: is a MountedDevices USBSTOR letter.
                mounted("F:", True),
                shortcut(r"F:\Backup\list.xlsx", vsn="2B3C4D5E"),
                # Same USB volume (VSN of the first row) later mounted as G:.
                shortcut(r"G:\Export\plan2.docx", vsn="1A2B3C4D"),
            ],
            "flagged": [0, 2, 3],
        },
        # Document on the fixed system disk.
        "negative": {"rows": [shortcut(r"C:\Users\user1\Documents\plan.docx")], "flagged": []},
    },
    "lnk.network_target": {
        "positive": {
            "rows": [
                shortcut(r"\\fileserver01\share\report.xlsx", drive_type="unc", net_name=r"\\FILESERVER01\SHARE"),
                # Mapped network drive: LinkInfo DriveType 4 is written as "remote" by the parser.
                shortcut(r"Z:\Finance\q3.xlsx", drive_type="remote", vsn="5E6F7A8B"),
                computer_name("WS-TEST01"),
            ],
            "flagged": [0, 1],
        },
        # Loopback share of the examined computer itself (NetName host = its computer name).
        "negative": {
            "rows": [
                computer_name("WS-TEST01"),
                shortcut(r"C:\Users\user1\Documents\report.xlsx", net_name=r"\\WS-TEST01\Users"),
            ],
            "flagged": [],
        },
    },
    "lnk.target_missing": {
        "positive": {
            "rows": [listed(r"C:\Users\user1\Documents\notes.txt"), shortcut(r"C:\Users\user1\Documents\secret.docx")],
            "flagged": [1],
        },
        # Target on a removable drive that is no longer attached: cannot tell.
        "negative": {
            "rows": [listed(r"C:\Users\user1\Documents\notes.txt"), shortcut(r"E:\Export\secret.docx", drive_type="removable", vsn="1A2B3C4D")],
            "flagged": [],
        },
    },
    "lnk.user_path_exec": {
        "positive": {"rows": [shortcut(r"C:\Users\user1\Downloads\invoice.pdf.exe")], "flagged": [0]},
        # A downloaded document, not an executable.
        "negative": {"rows": [shortcut(r"C:\Users\user1\Downloads\invoice.pdf")], "flagged": []},
    },
    "lnk.foreign_machine": {
        "positive": {
            "rows": [computer_name("WS-TEST01"), shortcut(r"C:\Users\user1\Documents\a.docx", tracker_machine_id="other-pc07")],
            "flagged": [1],
        },
        # Stock Windows PowerShell Start-menu shortcuts (built on the vendor's machine) and the
        # same host's NetBIOS name in a different case.
        "negative": {
            "rows": [
                computer_name("WS-TEST01"),
                shortcut(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", tracker_machine_id="build-host01"),
                shortcut(r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe", tracker_machine_id="build-host01"),
                shortcut(r"C:\Users\user1\Documents\a.docx", tracker_machine_id="ws-test01"),
            ],
            "flagged": [],
        },
    },
    "lnk.timestamp_anomaly": {
        "positive": {
            "rows": [
                shortcut(r"C:\Users\user1\Documents\a.docx", modified_at="2024-03-01T09:00:00Z"),
                shortcut(r"C:\Users\user1\Documents\b.docx", times=False),
            ],
            "flagged": [0, 1],
        },
        # Ordinary shortcut: target created before the shortcut was written, target times present.
        "negative": {"rows": [shortcut(r"C:\Users\user1\Documents\a.docx", modified_at="2024-05-01T09:00:05Z")], "flagged": []},
    },
}
