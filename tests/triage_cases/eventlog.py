"""Fixtures of ``rapidtriage.core.triage_rules.eventlog`` (see ``tests.triage_cases``)."""

from __future__ import annotations

import datetime as dt

SECURITY_EVTX = r"C:\Windows\System32\winevt\Logs\Security.evtx"
SYSTEM_EVTX = r"C:\Windows\System32\winevt\Logs\System.evtx"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
BASE = dt.datetime(2024, 5, 1, 10, 0, tzinfo=dt.timezone.utc)


def at(seconds: float = 0, *, base: dt.datetime = BASE) -> str:
    return (base + dt.timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def event(event_id: str, channel: str, provider: str = "", *, path: str = SECURITY_EVTX, **details: object) -> dict[str, object]:
    return {
        "kind": "eventlog",
        "row": {
            "artifact_type": "eventlog-event",
            "path": path,
            "details": {"event_id": event_id, "channel": channel, "provider_name": provider, "timestamp": "2024-05-01T10:00:00Z", **details},
        },
    }


def security(event_id: str, **details: object) -> dict[str, object]:
    return event(event_id, "Security", "Microsoft-Windows-Security-Auditing", computer="WS01", **details)


def logon(ip: str, seconds: float = 0, user: str = "user01", logon_type: str = "10") -> dict[str, object]:
    return security("4624", timestamp=at(seconds), logon_type=logon_type, source_ip=ip, target_user_name=user)


def failed(ip: str, seconds: float = 0, user: str = "user01") -> dict[str, object]:
    return security("4625", timestamp=at(seconds), logon_type="3", source_ip=ip, target_user_name=user)


def record(record_id: int, path: str = SECURITY_EVTX) -> dict[str, object]:
    return security("4634", path=path, record_id=record_id, evtx_record_state="live")


def sysmon(event_id: str, **event_data: object) -> dict[str, object]:
    return event(event_id, SYSMON, "Microsoft-Windows-Sysmon", event_data=event_data)


def kst_logon(day: int, hour: int, user: str = "user01") -> dict[str, object]:
    """Interactive logon at local (UTC+9) ``hour`` of May ``day``."""
    moment = dt.datetime(2024, 5, day, hour, 5, tzinfo=dt.timezone(dt.timedelta(hours=9)))
    return security("4624", timestamp=moment.astimezone(dt.timezone.utc).isoformat(), logon_type="2", target_user_name=user)


def service_7045(name: str, image: str) -> dict[str, object]:
    return event("7045", "System", "Service Control Manager", path=SYSTEM_EVTX, event_data={"ServiceName": name, "ImagePath": image, "AccountName": "LocalSystem"})


def task_xml(command: str, arguments: str = "") -> str:
    args = f"<Arguments>{arguments}</Arguments>" if arguments else ""
    return f"<Task><Actions><Exec><Command>{command}</Command>{args}</Exec></Actions></Task>"


DAY_HOURS = [9, 10, 11, 13, 14, 15, 16, 17]
WORKDAY_LOGONS = [kst_logon(1 + index // len(DAY_HOURS), DAY_HOURS[index % len(DAY_HOURS)]) for index in range(40)]

CASES = {
    "eventlog.rdp_external_ip": {
        "positive": {"rows": [logon("8.8.8.8")], "flagged": [0]},
        # VPN concentrator NAT: the RDP logon arrives from the internal VPN pool address.
        "negative": {"rows": [logon("10.8.0.15")], "flagged": []},
    },
    "eventlog.failed_logon_burst": {
        "positive": {"rows": [failed("8.8.8.8", index * 20) for index in range(10)], "flagged": list(range(10))},
        # A phone with a stale password retrying every 6 minutes: same source, not a burst.
        "negative": {"rows": [failed("10.0.0.40", index * 360) for index in range(10)], "flagged": []},
    },
    "eventlog.burst_then_success": {
        "positive": {"rows": [*(failed("8.8.8.8", index * 20) for index in range(10)), logon("8.8.8.8", 600)], "flagged": [10]},
        # The user mistypes the password three times, then logs on.
        "negative": {"rows": [*(failed("10.0.0.40", index * 20) for index in range(3)), logon("10.0.0.40", 90)], "flagged": []},
    },
    "eventlog.log_cleared": {
        "positive": {"rows": [event("1102", "Security", "Microsoft-Windows-Eventlog")], "flagged": [0]},
        "negative": {"rows": [event("104", "Microsoft-Windows-Kernel-Cache/Operational", "Microsoft-Windows-Kernel-Cache")], "flagged": []},
    },
    "eventlog.record_id_gap": {
        "positive": {"rows": [record(100), record(101), record(102), record(150)], "flagged": [3]},
        # Two .evtx files with far-apart record ids interleaved: consecutive within each file.
        "negative": {
            "rows": [record(100), record(5000, SYSTEM_EVTX), record(101), record(5001, SYSTEM_EVTX), record(102)],
            "flagged": [],
        },
    },
    "eventlog.new_service": {
        "positive": {
            "rows": [
                service_7045("svcupd", r"C:\Users\Public\svcupd.exe"),
                service_7045("syshelper", r"C:\ProgramData\SysHelper\svc.exe"),
            ],
            "flagged": [0, 1],
        },
        # Microsoft Defender's own platform / definition-update services under ProgramData (seen on run-subset10).
        "negative": {
            "rows": [
                service_7045("MpDefenderCoreService", r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24030-0\MpDefenderCoreService.exe"'),
                service_7045("MpKslDrv", r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{0F5B1F1E-0000-4000-8000-000000000001}\MpKslDrv.sys"),
            ],
            "flagged": [],
        },
    },
    "eventlog.encoded_powershell": {
        "positive": {"rows": [security("4688", command_line="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")], "flagged": [0]},
        # An admin maintenance script launched with -ExecutionPolicy Bypass -File.
        "negative": {"rows": [security("4688", command_line=r"powershell.exe -ExecutionPolicy Bypass -File C:\Scripts\backup.ps1")], "flagged": []},
    },
    "eventlog.task_created": {
        "positive": {
            "rows": [security("4698", event_data={"TaskName": r"\Updater", "TaskContent": task_xml(r"C:\Users\user01\AppData\Local\Temp\upd.exe")})],
            "flagged": [0],
        },
        # A vendor updater task from Program Files.
        "negative": {
            "rows": [security("4698", event_data={"TaskName": r"\VendorUpdate", "TaskContent": task_xml(r"C:\Program Files\Vendor\updater.exe", "/check")})],
            "flagged": [],
        },
    },
    "eventlog.account_manipulation": {
        "positive": {
            "rows": [
                security("4720", timestamp=at(0), target_user_name="svc_tmp", event_data={"TargetSid": "S-1-5-21-1-2-3-1010", "TargetUserName": "svc_tmp"}),
                security("4732", timestamp=at(300), event_data={"MemberSid": "S-1-5-21-1-2-3-1010", "TargetUserName": "Administrators", "TargetSid": "S-1-5-32-544"}),
                security("4724", timestamp=at(400), subject_user_name="intruder", target_user_name="user02"),
            ],
            "flagged": [0, 1, 2],
        },
        # Provisioning: the account is added to a group the next day; the user resets their own password.
        "negative": {
            "rows": [
                security("4720", timestamp=at(0), target_user_name="newhire", event_data={"TargetSid": "S-1-5-21-1-2-3-1011", "TargetUserName": "newhire"}),
                security("4732", timestamp=at(86400), event_data={"MemberSid": "S-1-5-21-1-2-3-1011", "TargetUserName": "Remote Desktop Users"}),
                security("4724", timestamp=at(90000), subject_user_name="newhire", target_user_name="newhire"),
            ],
            "flagged": [],
        },
    },
    "eventlog.explicit_credentials": {
        "positive": {
            "rows": [security("4648", subject_user_name="user01", event_data={"TargetServerName": "fileserver02", "ProcessName": r"C:\Users\user01\Downloads\tool.exe", "TargetUserName": "admin"})],
            "flagged": [0],
        },
        # Network drive mapping / scheduled work: svchost to a remote server, and a local RunAs.
        "negative": {
            "rows": [
                security("4648", event_data={"TargetServerName": "fileserver02", "ProcessName": r"C:\Windows\System32\svchost.exe"}),
                security("4648", event_data={"TargetServerName": "localhost", "ProcessName": r"C:\Windows\System32\runas.exe"}),
            ],
            "flagged": [],
        },
    },
    "eventlog.off_hours_logon": {
        "positive": {"rows": [*WORKDAY_LOGONS, kst_logon(9, 3)], "flagged": [40]},
        # A night-shift worker: 03:00 logons are routine for the account (and DWM sessions are skipped).
        "negative": {
            "rows": [*WORKDAY_LOGONS[:36], *(kst_logon(10 + day, 3) for day in range(5)), kst_logon(20, 3, "DWM-1")],
            "flagged": [],
        },
    },
    "eventlog.sysmon_injection": {
        "positive": {
            "rows": [
                sysmon("10", SourceImage=r"C:\Users\user01\AppData\Local\Temp\d.exe", TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1410")
            ],
            "flagged": [0],
        },
        # Defender scanning lsass from its ProgramData platform folder.
        "negative": {
            "rows": [
                sysmon(
                    "10",
                    SourceImage=r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24030-0\MsMpEng.exe",
                    TargetImage=r"C:\Windows\System32\lsass.exe",
                    GrantedAccess="0x1410",
                )
            ],
            "flagged": [],
        },
    },
    "eventlog.audit_gap": {
        "positive": {"rows": [security("4634", timestamp=at(index)) for index in range(100)], "flagged": [0]},
        # Process-creation auditing on: the Security log holds 4688 records.
        "negative": {"rows": [*(security("4634", timestamp=at(index)) for index in range(99)), security("4688", command_line="notepad.exe")], "flagged": []},
    },
}
