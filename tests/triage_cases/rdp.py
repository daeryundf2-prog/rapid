"""Fixtures of ``rapidtriage.core.triage_rules.rdp`` (see ``tests.triage_cases``)."""

from __future__ import annotations

from .eventlog import at, event, logon, security

RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
RDPCORE = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"
CLIENT = "Microsoft-Windows-TerminalServices-RDPClient/Operational"
DENY_TS = r"HKLM\System\CurrentControlSet\Control\Terminal Server\fDenyTSConnections"


def auth_1149(user: str, ip: str, seconds: float = 0) -> dict[str, object]:
    return event("1149", RCM, "Microsoft-Windows-TerminalServices-RemoteConnectionManager", timestamp=at(seconds), event_data={"Param1": user, "Param2": "CORP", "Param3": ip})


def session_21(user: str, address: str, seconds: float = 0) -> dict[str, object]:
    return event("21", LSM, "Microsoft-Windows-TerminalServices-LocalSessionManager", timestamp=at(seconds), event_data={"User": f"CORP\\{user}", "SessionID": "2", "Address": address})


def reconnect_4778(user: str, ip: str, seconds: float) -> dict[str, object]:
    return security("4778", timestamp=at(seconds), event_data={"AccountName": user, "AccountDomain": "CORP", "ClientName": "LAPTOP7", "ClientAddress": ip})


def client_1024(server: str, seconds: float = 0) -> dict[str, object]:
    return event("1024", CLIENT, "Microsoft-Windows-TerminalServices-ClientActiveXCore", timestamp=at(seconds), event_data={"Value": server})


def explicit_4648(server: str, seconds: float = 0) -> dict[str, object]:
    return security("4648", timestamp=at(seconds), event_data={"TargetServerName": server, "ProcessName": r"C:\Windows\System32\mstsc.exe"})


def sysmon_13(target: str, details: str) -> dict[str, object]:
    return event("13", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", event_data={"TargetObject": target, "Details": details})


def registry_value(name: str, data: str) -> dict[str, object]:
    return {
        "kind": "windows-registry",
        "row": {
            "artifact_type": "registry-value",
            "path": r"C:\Windows\System32\config\SYSTEM",
            "details": {"key_path": r"ControlSet001\Control\Terminal Server", "name": name, "value_data": data},
        },
    }


def rdp_logon_on(computer: str, seconds: float, user: str = "admin01") -> dict[str, object]:
    row = logon("10.0.0.5", seconds, user)
    row["row"]["details"]["computer"] = computer
    return row


CASES = {
    "rdp.external_ip": {
        "positive": {
            "rows": [auth_1149("user01", "8.8.8.8"), event("131", RDPCORE, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", event_data={"ClientIP": "1.1.1.1:52344"})],
            "flagged": [0, 1],
        },
        # A VPN pool address (private) in front of the RDP host.
        "negative": {
            "rows": [auth_1149("user01", "172.16.5.20"), event("131", RDPCORE, "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", event_data={"ClientIP": "172.16.5.20:52344"})],
            "flagged": [],
        },
    },
    "rdp.pairing_mismatch": {
        "positive": {
            "rows": [auth_1149("user01", "10.0.0.5", 0), auth_1149("user02", "10.0.0.6", 600), session_21("user02", "10.0.0.6", 605), session_21("user03", "10.0.0.7", 1200)],
            "flagged": [0, 3],
        },
        # Normal pair a few seconds apart, plus a console (LOCAL) logon that never authenticates over the network.
        "negative": {
            "rows": [auth_1149("user01", "10.0.0.5", 0), session_21("user01", "10.0.0.5", 4), session_21("user02", "LOCAL", 900)],
            "flagged": [],
        },
    },
    "rdp.session_hijack": {
        "positive": {"rows": [logon("10.0.0.5", 0), reconnect_4778("user01", "10.0.0.99", 3600)], "flagged": [1]},
        # The user moved: a fresh logon from the new address precedes the reconnect from it.
        "negative": {
            "rows": [logon("10.0.0.5", 0), reconnect_4778("user01", "10.0.0.5", 1800), logon("10.0.0.77", 7200), reconnect_4778("user01", "10.0.0.77", 9000)],
            "flagged": [],
        },
    },
    "rdp.outbound": {
        "positive": {"rows": [client_1024("srv01.corp.example", 0), explicit_4648("srv01.corp.example", 30)], "flagged": [0]},
        # Saved-credential RDP client use with an unrelated network-drive 4648 hours earlier.
        "negative": {"rows": [explicit_4648("fileserver02", 0), client_1024("srv01.corp.example", 7200)], "flagged": []},
    },
    "rdp.enabled": {
        "positive": {"rows": [sysmon_13(DENY_TS, "DWORD (0x00000000)"), registry_value("fDenyTSConnections", "0")], "flagged": [0, 1]},
        # RDP being disabled (value 1) and a look-alike value under the same key.
        "negative": {
            "rows": [sysmon_13(DENY_TS, "DWORD (0x00000001)"), registry_value("fDenyTSConnections", "1"), registry_value("fSingleSessionPerUser", "0")],
            "flagged": [],
        },
    },
    "rdp.multi_host": {
        "positive": {"rows": [rdp_logon_on("SRV01", 0), rdp_logon_on("SRV02", 600), rdp_logon_on("SRV03", 1200)], "flagged": [0, 1, 2]},
        # An operations admin visiting three servers over a working day.
        "negative": {"rows": [rdp_logon_on("SRV01", 0), rdp_logon_on("SRV02", 7200), rdp_logon_on("SRV03", 14400)], "flagged": []},
    },
}
