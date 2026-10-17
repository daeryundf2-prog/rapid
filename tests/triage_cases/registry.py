"""Fixtures of ``rapidtriage.core.triage_rules.registry`` (see ``tests.triage_cases``)."""

from __future__ import annotations

INCIDENT = ("2024-05-01T00:00:00Z", "2024-05-02T00:00:00Z")
RUN_KEY = r"HKU\S-1-5-21-1000-1001\Software\Microsoft\Windows\CurrentVersion\Run"
TYPED_PATHS = r"HKU\S-1-5-21-1000-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"


def reg(artifact_type: str, kind: str = "windows-registry", **details: object) -> dict[str, object]:
    return {"kind": kind, "row": {"artifact_type": artifact_type, "path": r"C:\Users\user1\NTUSER.DAT", "details": details}}


def run_entry(command: str, value_name: str = "Updater", **details: object) -> dict[str, object]:
    return reg(
        "registry-persistence-entry",
        key_path=RUN_KEY,
        value_name=value_name,
        command=command,
        persistence_category="Run",
        **details,
    )


def service(image_path: str, **details: object) -> dict[str, object]:
    return reg("windows-service-config", service_name="TestSvc", image_path=image_path, start_label="자동", **details)


def usb_device(serial: str, **details: object) -> dict[str, object]:
    return reg(
        "windows-usb-device",
        device_class_id="Disk&Ven_Generic&Prod_Flash_Disk&Rev_1.00",
        serial_number=serial,
        friendly_name="Generic Flash Disk USB Device",
        **details,
    )


def mounted(letter: str, *, removable: bool, serial: str = "", guid: str = "") -> dict[str, object]:
    return reg(
        "windows-mounted-device",
        mount_name=rf"\DosDevices\{letter}",
        drive_letter=letter,
        removable_usb=removable,
        usb_serial_number=serial,
        volume_guid=guid,
    )


def shellbag(shell_path: str, network: str = "") -> dict[str, object]:
    return reg(
        "shellbag-entry",
        kind="windows-shellbags",
        shell_path=shell_path,
        network_location=network,
        key_path=r"HKU\S-1-5-21-1000-1001_Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1",
    )


def typed(value: str) -> dict[str, object]:
    return reg("registry-user-activity", key_path=TYPED_PATHS, value_name="url1", activity_value=value)


def userassist(path: str) -> dict[str, object]:
    return reg("userassist-entry", kind="windows-execution", decoded_name=path, run_counter=3)


CASES = {
    "registry.run_user_path": {
        "positive": {
            "rows": [
                run_entry(r'"C:\Users\user1\AppData\Roaming\updsvc\upd.exe" /silent'),
                # A Squirrel-looking value name does not excuse a Temp payload.
                run_entry(r"C:\Users\user1\AppData\Local\Temp\slack.exe --startup", value_name="com.squirrel.slack.slack"),
            ],
            "flagged": [0, 1],
        },
        # Slack's standard Squirrel per-user autostart (squirrel_value_prefixes) and a per-user
        # auto-updater under AppData\Local\Microsoft (exclude_markers).
        "negative": {
            "rows": [
                run_entry(r"C:\Users\user1\AppData\Local\slack\slack.exe --process-start-args --startup", value_name="com.squirrel.slack.slack"),
                run_entry(r'"C:\Users\user1\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background', value_name="OneDrive"),
            ],
            "flagged": [],
        },
    },
    "registry.service_anomaly": {
        "positive": {"rows": [service(r"C:\Windows\Temp\svcupd.exe")], "flagged": [0]},
        # msiexec under System32 (Windows Installer service): LOLBin reason dropped for system-dir images.
        "negative": {"rows": [service(r"C:\Windows\system32\msiexec.exe /V")], "flagged": []},
    },
    "registry.persistence_lastwrite_window": {
        "positive": {
            "rows": [run_entry(r"C:\Program Files\VendorX\tray.exe", key_last_written_at="2024-05-01T10:00:00Z")],
            "flagged": [0],
            "incident": INCIDENT,
        },
        # Key last written by an earlier patch, outside the incident window.
        "negative": {
            "rows": [run_entry(r"C:\Program Files\VendorX\tray.exe", key_last_written_at="2024-03-12T03:00:00Z")],
            "flagged": [],
            "incident": INCIDENT,
        },
    },
    "registry.usb_serial_cross": {
        "positive": {
            "rows": [usb_device("AA00112233445566&0"), mounted("E:", removable=True, serial="AA00112233445566&0")],
            "flagged": [0],
        },
        # Device whose volume never got a MountedDevices entry (only the fixed system disk is listed).
        "negative": {
            "rows": [usb_device("BB99887766554433&0"), mounted("C:", removable=False)],
            "flagged": [],
        },
    },
    "registry.userassist_path": {
        "positive": {
            "rows": [userassist(r"C:\Users\user1\Downloads\tool.exe"), userassist(r"C:\Users\user1\AppData\Local\Temp\run.ps1")],
            "flagged": [0, 1],
        },
        # The user double-clicking ordinary desktop shortcuts (own and Public desktop).
        "negative": {
            "rows": [userassist(r"C:\Users\user1\Desktop\Report.lnk"), userassist(r"C:\Users\Public\Desktop\VendorApp.lnk")],
            "flagged": [],
        },
    },
    "registry.shellbag_removable_network": {
        "positive": {"rows": [mounted("E:", removable=True), shellbag(r"E:\Export\Q2")], "flagged": [1]},
        # Second fixed disk D: while the only removable letter is E:.
        "negative": {"rows": [mounted("E:", removable=True), shellbag(r"D:\Projects\Reports")], "flagged": []},
    },
    "registry.typedpaths_unc": {
        "positive": {"rows": [typed(r"\\fileserver01\c$\Users")], "flagged": [0]},
        "negative": {"rows": [typed(r"C:\Users\user1\Documents\Reports")], "flagged": []},
    },
}
