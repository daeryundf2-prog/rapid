"""Fixtures of ``rapidtriage.core.triage_rules.accounts`` (see ``tests.triage_cases``)."""

from __future__ import annotations

from .eventlog import security

TREE = r"ROOT\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"


def artifact(kind: str, artifact_type: str, path: str = "", **details: object) -> dict[str, object]:
    return {"kind": kind, "row": {"artifact_type": artifact_type, "path": path, "details": details}}


def sam_account(name: str, rid: int) -> dict[str, object]:
    return artifact("windows-os-account", "windows-sam-account", r"C:\Windows\System32\config\SAM", user_name=name, rid=rid)


def task(uri: str, command: str = "", arguments: str = "", **details: object) -> dict[str, object]:
    path = "C:\\Windows\\System32\\Tasks" + uri
    return artifact("windows-system", "task-scheduler-task", path, task_uri=uri, command=command, arguments=arguments, **details)


def tree_node(name: str, *values: str) -> dict[str, object]:
    key = TREE + "\\" + name if name else TREE
    return artifact("windows-registry", "registry-key-tree-node", r"C:\Windows\System32\config\SOFTWARE", key_path=key, value_names=list(values))


def service(name: str, dll: str) -> dict[str, object]:
    return artifact("windows-registry", "windows-service-config", r"C:\Windows\System32\config\SYSTEM", service_name=name, service_dll=dll)


def profile(sid: str, path: str) -> dict[str, object]:
    return artifact("windows-registry", "windows-profile-list-entry", r"C:\Windows\System32\config\SOFTWARE", sid=sid, profile_image_path=path)


def wer(application: str) -> dict[str, object]:
    return artifact("windows-system", "wer-report", r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive\AppCrash_x\Report.wer", application_path=application, event_time="2024-05-01T10:00:00Z")


def listed(path: str) -> dict[str, object]:
    return {"files": "inventory", "row": {"path": path, "name": path.rsplit("\\", 1)[-1]}}


def account_created(name: str, timestamp: str) -> dict[str, object]:
    return security("4720", timestamp=timestamp, target_user_name=name, event_data={"TargetSid": "S-1-5-21-1-2-3-1012", "SubjectUserName": "admin01"})


def group_add(group: str, group_sid: str) -> dict[str, object]:
    return security("4732", event_data={"TargetUserName": group, "TargetSid": group_sid, "MemberSid": "S-1-5-21-1-2-3-1012", "SubjectUserName": "admin01"})


INCIDENT = ("2024-05-01T00:00:00Z", "2024-05-03T00:00:00Z")

CASES = {
    "accounts.new_account": {
        "positive": {
            "rows": [account_created("svc_tmp", "2024-05-01T10:00:00Z"), sam_account("helpdesk$", 1013)],
            "flagged": [0, 1],
            "incident": INCIDENT,
        },
        # Routine provisioning months before the incident window; ordinary SAM accounts.
        "negative": {
            "rows": [account_created("newhire", "2024-01-15T09:00:00Z"), sam_account("Administrator", 500), sam_account("user01", 1001)],
            "flagged": [],
            "incident": INCIDENT,
        },
    },
    "accounts.admin_added": {
        "positive": {
            "rows": [group_add("Administrators", "S-1-5-32-544"), security("4728", event_data={"TargetUserName": "Domain Admins", "TargetSid": "S-1-5-21-1-2-3-512", "MemberName": "CN=user01"})],
            "flagged": [0, 1],
        },
        # Ordinary access work: Remote Desktop Users / a project group.
        "negative": {
            "rows": [group_add("Remote Desktop Users", "S-1-5-32-555"), security("4728", event_data={"TargetUserName": "Project Users", "TargetSid": "S-1-5-21-1-2-3-3001", "MemberName": "CN=user01"})],
            "flagged": [],
        },
    },
    "accounts.task_suspicious": {
        "positive": {
            "rows": [
                task(r"\Updater", r"C:\Users\user01\AppData\Roaming\upd\upd.exe"),
                task(r"\SyncHelper", r"C:\Program Files\SyncHelper\sync.exe", hidden=True, user_id="S-1-5-18"),
                task(r"\Beacon", r"C:\Program Files\Beacon\b.exe", hidden=True, user_id="S-1-5-21-1-2-3-1001", trigger_details=[{"trigger_type": "TimeTrigger", "repetition_interval": "PT1M"}]),
            ],
            "flagged": [0, 1, 2],
        },
        # Windows' own hidden SYSTEM tasks (binary / COM handler), a vendor updater, and a hidden task whose
        # trigger only has a one-minute start *delay*.
        "negative": {
            "rows": [
                task(r"\Microsoft\Windows\Defrag\ScheduledDefrag", r"%windir%\system32\defrag.exe", "-c -h -o -$", hidden=True, user_id="S-1-5-18"),
                task(r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan", hidden=True, user_id="S-1-5-18"),
                task(r"\VendorUpdate", r"C:\Program Files\Vendor\updater.exe", "/check", user_id="S-1-5-18"),
                task(r"\VendorTray", r"C:\Program Files\Vendor\tray.exe", hidden=True, user_id="S-1-5-21-1-2-3-1001", trigger_details=[{"trigger_type": "LogonTrigger", "delay": "PT1M"}]),
            ],
            "flagged": [],
        },
    },
    "accounts.task_mismatch": {
        "positive": {
            "rows": [
                task(r"\Present", r"C:\Program Files\Vendor\a.exe"),
                task(r"\Orphan", r"C:\Program Files\Vendor\b.exe"),
                tree_node("Present", "Id", "Index", "SD"),
                tree_node("NoSd", "Id", "Index"),
                tree_node("Ghost", "Id", "Index", "SD"),
            ],
            "flagged": [1, 3, 4],
        },
        # Every task has its TaskCache key; folder nodes carry no Id.
        "negative": {
            "rows": [
                task(r"\Microsoft\Windows\Defrag\ScheduledDefrag", r"%windir%\system32\defrag.exe"),
                tree_node(r"Microsoft\Windows\Defrag\ScheduledDefrag", "Id", "Index", "SD"),
                tree_node(r"Microsoft\Windows\Defrag"),
                tree_node("Microsoft", "SD"),
            ],
            "flagged": [],
        },
    },
    "accounts.service_suspicious": {
        "positive": {"rows": [service("svchelper", r"C:\Users\Public\svchelper.dll"), service("netagent", r"C:\Program Files\NetAgent\agent.dll")], "flagged": [0, 1]},
        # Windows ServiceDll values written with environment variables / SysWOW64.
        "negative": {
            "rows": [service("wuauserv", r"%systemroot%\system32\wuaueng.dll"), service("legacy32", r"C:\Windows\SysWOW64\legacy32.dll")],
            "flagged": [],
        },
    },
    "accounts.profile_anomaly": {
        "positive": {"rows": [profile("S-1-5-21-1-2-3-1013", r"C:\Temp\prof")], "flagged": [0]},
        # Service, system and older-OS profile locations.
        "negative": {
            "rows": [
                profile("S-1-5-19", r"%systemroot%\ServiceProfiles\LocalService"),
                profile("S-1-5-18", r"%systemroot%\system32\config\systemprofile"),
                profile("S-1-5-21-1-2-3-1001", r"C:\Users\user01"),
                profile("S-1-5-21-1-2-3-1002", r"C:\Documents and Settings\user02"),
            ],
            "flagged": [],
        },
    },
    "accounts.wer_anomaly": {
        "positive": {
            "rows": [
                wer(r"C:\Users\user01\Downloads\tool.exe"),
                listed(r"C:\Program Files\Gone\helper.dll"),
                wer(r"C:\Program Files\Gone\gone.exe"),
            ],
            "flagged": [0, 2],
        },
        # Ordinary crashes of installed apps (Program Files; per-user installs under AppData\Local\Programs).
        "negative": {
            "rows": [
                listed(r"C:\Program Files\Vendor\app.exe"),
                wer(r"C:\Program Files\Vendor\app.exe"),
                wer(r"C:\Users\user01\AppData\Local\Programs\Editor\editor.exe"),
            ],
            "flagged": [],
        },
    },
}
