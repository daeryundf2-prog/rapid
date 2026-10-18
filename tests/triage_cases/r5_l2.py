"""Fixtures of the R5 L2 rules (``execution.startup_user_path``, ``antiforensics.crypto_wallet_present``,
``antiforensics.vm_present``); see ``tests.triage_cases``."""

from __future__ import annotations


def startup(kind: str, name: str, command: str, *, enabled: object = True, item_kind: str = "") -> dict[str, object]:
    details: dict[str, object] = {"item_name": name, "command": command, "enabled": enabled, "scope": "user"}
    if item_kind:
        details["item_kind"] = item_kind
    return {
        "kind": kind,
        "row": {"artifact_type": "startup-item", "path": r"C:\Users\alice\NTUSER.DAT", "details": details},
    }


def wallet(product: str, files: int, size: int) -> dict[str, object]:
    return {
        "kind": "windows-system",
        "row": {
            "artifact_type": "crypto-wallet-presence",
            "path": rf"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\{product}",
            "details": {"wallet_product": product, "wallet_kind": "browser-extension", "file_count": files, "total_size": size},
        },
    }


def vm(name: str, config: str) -> dict[str, object]:
    return {
        "kind": "windows-system",
        "row": {
            "artifact_type": "vm-config",
            "path": config,
            "details": {"vm_product": "hyper-v", "vm_name": name, "vm_config_path": config, "config_source": "vmcx"},
        },
    }


CASES = {
    "execution.startup_user_path": {
        "positive": {
            "rows": [
                startup("windows-registry", "Updater", r"C:\Users\alice\AppData\Roaming\upd\upd.exe /silent"),
                startup("windows-system", "run.bat", r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.bat", enabled=None, item_kind="script"),
                startup("windows-registry", "Program", r'"C:\Program Files\Vendor\agent.exe" /tray'),
            ],
            "flagged": [0, 1],
        },
        # Disabled in Task Manager (StartupApproved 03) and an AppData\Local\Programs install: not flagged.
        "negative": {
            "rows": [
                startup("windows-registry", "Updater", r"C:\Users\alice\AppData\Roaming\upd\upd.exe /silent", enabled=False),
                startup("windows-registry", "Teams", r"C:\Users\alice\AppData\Local\Programs\Teams\Update.exe --processStart Teams.exe"),
            ],
            "flagged": [],
        },
    },
    "antiforensics.crypto_wallet_present": {
        "positive": {"rows": [wallet("metamask", 3, 4096)], "flagged": [0]},
        # The extension folder exists but holds nothing (installed, never set up).
        "negative": {"rows": [wallet("phantom", 0, 0)], "flagged": []},
    },
    "antiforensics.vm_present": {
        "positive": {"rows": [vm("Tails", r"C:\Users\alice\VirtualBox VMs\Tails\Tails.vbox")], "flagged": [0]},
        # Docker Desktop's utility VM (ignore_name_markers).
        "negative": {
            "rows": [vm("", r"C:\ProgramData\Microsoft\Windows\Hyper-V\Virtual Machines\DockerDesktopVM.vmcx")],
            "flagged": [],
        },
    },
}
