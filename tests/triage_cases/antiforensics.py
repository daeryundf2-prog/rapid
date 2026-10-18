"""Fixtures of ``rapidtriage.core.triage_rules.antiforensics`` (see ``tests.triage_cases``)."""

from __future__ import annotations

from .eventlog import security


def program(name: str, publisher: str = "") -> dict[str, object]:
    return {
        "kind": "windows-registry",
        "row": {
            "artifact_type": "windows-installed-program",
            "path": r"C:\Windows\System32\config\SOFTWARE",
            "details": {"display_name": name, "publisher": publisher, "key_last_written_at": "2024-04-01T00:00:00Z"},
        },
    }


def prefetch(name: str, run_times: list[str]) -> dict[str, object]:
    return {
        "kind": "windows-prefetch",
        "row": {
            "artifact_type": "prefetch-file",
            "path": rf"C:\Windows\Prefetch\{name.upper()}-1A2B3C4D.pf",
            "details": {"executable_hint": name.upper(), "run_count": len(run_times), "last_run_times": run_times},
        },
    }


def service(name: str, image: str) -> dict[str, object]:
    return {
        "kind": "windows-registry",
        "row": {
            "artifact_type": "windows-service-config",
            "path": r"C:\Windows\System32\config\SYSTEM",
            "details": {"service_name": name, "image_path": image},
        },
    }


def listed(path: str) -> dict[str, object]:
    return {"files": "candidates", "row": {"path": path, "name": path.rsplit("\\", 1)[-1]}}


def history(command: str, at: str) -> dict[str, object]:
    return {
        "kind": "windows-execution",
        "row": {
            "artifact_type": "powershell-history-command",
            "path": r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
            "details": {"command": command, "timestamp": at},
        },
    }


def pca(path: str, at: str) -> dict[str, object]:
    return {
        "kind": "windows-execution",
        "row": {
            "artifact_type": "execution-pca",
            "path": r"C:\Windows\appcompat\pca\PcaAppLaunchDic.txt",
            "details": {"executable_path": path, "last_run_at": at},
        },
    }


INCIDENT = ("2024-05-01T00:00:00Z", "2024-05-03T00:00:00Z")

CASES = {
    "antiforensics.tool_present": {
        # CCleaner installed, VeraCrypt driver service, sdelete on disk, cipher /w typed in PowerShell.
        "positive": {
            "rows": [
                program("CCleaner", "Piriform Software"),
                service("veracrypt", r"\SystemRoot\System32\drivers\veracrypt.sys"),
                listed(r"C:\Users\alice\Downloads\SDelete\sdelete64.exe"),
                history("cipher /w:C:\\Users\\alice", "2024-05-02T10:00:00Z"),
                # R3 review: quoted executable paths, the PowerShell call operator, a cmd /c
                # wrapper, and tools installed under Program Files / Windows\Temp.
                history(r'& "C:\tools\sdelete64.exe" -p 3 -s C:\x', "2024-05-02T10:00:00Z"),
                history('cmd /c "cipher /w:D:"', "2024-05-02T10:00:00Z"),
                history(r'dir ; "C:\Windows\system32\cipher.exe" /w:C:\ ', "2024-05-02T10:00:00Z"),
                listed(r"C:\Program Files\VeraCrypt\VeraCrypt.exe"),
                listed(r"C:\Windows\Temp\sdelete64.exe"),
            ],
            "flagged": [0, 1, 2, 3, 4, 5, 6, 7, 8],
        },
        # Look-alikes: unrelated "… Cleaner" / "… Eraser" apps (Samsung PC Cleaner is on the BSH QA
        # image: pccleaner2service.exe must not read as CCleaner), Windows' own cipher.exe and BitLocker
        # wizard files in System32, and an encrypt-only cipher command.
        "negative": {
            "rows": [
                program("Samsung PC Cleaner", "Samsung Electronics Co., Ltd."),
                service("PCCleaner2Service", r"C:\Program Files\Samsung\Samsung PC Cleaner 2 Service\PCCleaner2Service.exe"),
                listed(r"C:\Program Files\Samsung\Samsung PC Cleaner 2 Service\PCCleaner2Status.exe"),
                program("Smart PC Cleaner Pro", "Example Soft"),
                program("Photo Eraser Studio"),
                listed(r"C:\Windows\System32\cipher.exe"),
                listed(r"C:\Windows\System32\bitlockerwizardelev.exe"),
                history("cipher /e C:\\Users\\alice\\secret", "2024-05-02T10:00:00Z"),
                # R3 review: a tool merely mentioned inside another command is not a match.
                history('Write-Host "please do not run sdelete or cipher /w here"', "2024-05-02T10:00:00Z"),
                history("Get-Process | Where-Object Name -eq sdelete", "2024-05-02T10:00:00Z"),
            ],
            "flagged": [],
        },
    },
    "antiforensics.wiper_run_after_incident": {
        # sdelete run during the incident, BleachBit launched (PCA) a day after it; an install row has no run time.
        "positive": {
            "rows": [
                prefetch("sdelete64.exe", ["2024-05-02T22:10:00Z", "2024-04-01T08:00:00Z"]),
                pca(r"C:\Users\alice\Downloads\BleachBit\bleachbit.exe", "2024-05-04T01:02:03Z"),
                program("CCleaner"),
                # R3 review A13: a Prefetch row with only last_run_at (no run-time list).
                {
                    "kind": "windows-prefetch",
                    "row": {
                        "artifact_type": "prefetch-file",
                        "path": r"C:\Windows\Prefetch\BLEACHBIT.EXE-11223344.pf",
                        "details": {"executable_hint": "BLEACHBIT.EXE", "last_run_at": "2024-05-02T08:00:00Z"},
                    },
                },
                # R3 review A7: 4688 with a quoted executable path.
                security(
                    "4688",
                    timestamp="2024-05-02T10:00:00Z",
                    event_data={"CommandLine": r'"C:\Windows\system32\cipher.exe" /w:C:\ ', "NewProcessName": r"C:\Windows\System32\cipher.exe"},
                ),
            ],
            "flagged": [0, 1, 3, 4],
            "incident": INCIDENT,
        },
        # The same tools run weeks before the incident, and VeraCrypt (encryption, not a wiper) run during it.
        "negative": {
            "rows": [
                prefetch("sdelete64.exe", ["2024-03-02T22:10:00Z"]),
                pca(r"C:\Users\alice\Downloads\BleachBit\bleachbit.exe", "2024-04-04T01:02:03Z"),
                prefetch("veracrypt.exe", ["2024-05-02T09:00:00Z"]),
            ],
            "flagged": [],
            "incident": INCIDENT,
        },
    },
}
