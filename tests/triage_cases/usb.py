"""Fixtures of ``rapidtriage.core.triage_rules.usb`` (see ``tests.triage_cases``)."""

from __future__ import annotations

INCIDENT = ("2024-05-01T00:00:00Z", "2024-05-02T00:00:00Z")
PARTITION = "Microsoft-Windows-Partition/Diagnostic"
KEYBOARD_GUID = "{4d36e96b-e325-11ce-bfc1-08002be10318}"


def usb_device(serial: str = "AA00112233445566&0", *, vid: str = "0951", pid: str = "1666", **details: object) -> dict[str, object]:
    """USBSTOR row as the native SYSTEM-hive parser writes it."""
    return {
        "kind": "windows-registry",
        "row": {
            "artifact_type": "windows-usb-device",
            "details": {
                "device_class_id": "Disk&Ven_Generic&Prod_Flash_Disk&Rev_1.00",
                "serial_number": serial,
                "serial_is_os_generated": len(serial) > 1 and serial[1] == "&",
                "friendly_name": "Generic Flash Disk USB Device",
                "vid": vid,
                "pid": pid,
                **details,
            },
        },
    }


def pnp(description: str, device_class: str, class_guid: str, installed: str, enumerator: str = "USB") -> dict[str, object]:
    """Amcache InventoryDevicePnp row."""
    return {
        "kind": "windows-execution",
        "row": {
            "artifact_type": "amcache-device-pnp",
            "details": {
                "description": description,
                "device_class": device_class,
                "class_guid": class_guid,
                "enumerator": enumerator,
                "first_install_date": installed,
            },
        },
    }


def shellbag(written: str) -> dict[str, object]:
    return {
        "kind": "windows-shellbags",
        "row": {"artifact_type": "shellbag-entry", "details": {"shell_path": r"C:\Users\user1\Documents\Projects", "key_last_written_at": written}},
    }


def ntfs_vbr(vsn: int) -> str:
    data = bytearray(512)
    data[0:3] = b"\xeb\x52\x90"
    data[3:11] = b"NTFS    "
    data[0x48:0x50] = (0x5566778800000000 | vsn).to_bytes(8, "little")
    return data.hex()


def event(event_id: str, channel: str, **event_data: object) -> dict[str, object]:
    return {
        "kind": "eventlog",
        "row": {
            "artifact_type": "eventlog-event",
            "details": {"event_id": event_id, "channel": channel, "timestamp": "2024-05-01T10:00:00Z", "event_data": event_data},
        },
    }


def partition_1006(serial: str, vsn: int) -> dict[str, object]:
    return event("1006", PARTITION, SerialNumber=serial, Vbr0=ntfs_vbr(vsn))


def shortcut(target: str, vsn: str) -> dict[str, object]:
    return {
        "kind": "recent-files",
        "row": {
            "artifact_type": "recent-shortcut",
            "details": {
                "target_path": target,
                "volume_serial_number": vsn,
                "drive_type_name": "removable",
                "link_info": {"local_base_path": target, "drive_type_name": "removable", "volume_serial_number": vsn},
            },
        },
    }


def system_events(count: int) -> list[dict[str, object]]:
    return [event("7036", "System") for _ in range(count)]


BURST = [f"2024-05-01T10:{minute:02d}:00Z" for minute in range(0, 40, 2)]  # 20 folders in 40 minutes
SPREAD = [f"2024-05-{day:02d}T{hour:02d}:00:00Z" for day in range(2, 12) for hour in (9, 15)]  # 20 over ten days

CASES = {
    "usb.new_device": {
        "positive": {"rows": [usb_device(first_install_at="2024-05-01T10:00:00Z")], "flagged": [0], "incident": INCIDENT},
        # Long-used stick: first installed months before the incident.
        "negative": {"rows": [usb_device(first_install_at="2023-11-20T08:00:00Z")], "flagged": [], "incident": INCIDENT},
    },
    "usb.serial_missing": {
        "positive": {
            "rows": [
                usb_device("7&2A3B4C5D&0"),
                usb_device("000000000000&0"),
                usb_device("CC11223344&0", vid="0951", pid="1666"),
                usb_device("CC11223344&0", vid="abcd", pid="1234"),
            ],
            "flagged": [0, 1, 2, 3],
        },
        # Same stick seen twice (two control sets): one VID/PID, a real serial.
        "negative": {
            "rows": [usb_device("AA00112233445566&0", control_set="ControlSet001"), usb_device("AA00112233445566&0", control_set="ControlSet002")],
            "flagged": [],
        },
    },
    "usb.mass_storage_activity": {
        "positive": {"rows": [usb_device(last_arrival_at="2024-05-01T10:10:00Z"), *(shellbag(moment) for moment in BURST)], "flagged": [0]},
        # Ordinary folder browsing spread over days around the connection.
        "negative": {"rows": [usb_device(last_arrival_at="2024-05-01T10:10:00Z"), *(shellbag(moment) for moment in SPREAD)], "flagged": []},
    },
    "usb.non_storage_hid": {
        "positive": {
            "rows": [pnp("HID Keyboard Device", "Keyboard", KEYBOARD_GUID, "2024-05-01T10:00:00Z")],
            "flagged": [0],
            "incident": INCIDENT,
        },
        # Built-in PS/2 keyboard (ACPI, not USB) and a HID keyboard enumerated in the same minute as
        # a batch of other devices (OS install / driver enumeration).
        "negative": {
            "rows": [
                pnp("Standard PS/2 Keyboard", "Keyboard", KEYBOARD_GUID, "2024-05-01T08:00:00Z", enumerator="ACPI"),
                pnp("HID Keyboard Device", "Keyboard", KEYBOARD_GUID, "2024-05-01T10:00:05Z", enumerator="HID"),
                pnp("USB Root Hub (USB 3.0)", "USB", "{36fc9e60-c465-11cf-8056-444553540000}", "2024-05-01T10:00:05Z"),
                pnp("Generic USB Hub", "USB", "{36fc9e60-c465-11cf-8056-444553540000}", "2024-05-01T10:00:06Z"),
                pnp("High Definition Audio Device", "MEDIA", "{4d36e96c-e325-11ce-bfc1-08002be10318}", "2024-05-01T10:00:07Z", enumerator="HDAUDIO"),
            ],
            "flagged": [],
            "incident": INCIDENT,
        },
    },
    "usb.cross_match": {
        "positive": {
            "rows": [partition_1006("AA00112233445566", 0x1A2B3C4D), usb_device(), shortcut(r"E:\Export\plan.docx", "1A2B3C4D")],
            "flagged": [1, 2],
        },
        # The stick was reformatted: its current VBR serial differs from the shortcut's.
        "negative": {
            "rows": [partition_1006("AA00112233445566", 0x7E8F9A0B), usb_device(), shortcut(r"E:\Export\plan.docx", "1A2B3C4D")],
            "flagged": [],
        },
    },
    "usb.logging_disabled": {
        "positive": {"rows": [usb_device(), *system_events(100)], "flagged": [0]},
        # Partition/Diagnostic is present, so device connections are logged.
        "negative": {"rows": [usb_device(), *system_events(100), partition_1006("AA00112233445566", 0x1A2B3C4D)], "flagged": []},
    },
}
