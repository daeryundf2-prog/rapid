"""Synthetic hives / ``.reg`` exports / PCA and BitLocker files for the R3 O1 registry-depth tests.

Everything is generated in code (no real evidence): the hives use the minimal regf
writer of ``tests.test_parser_quality_registry``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from tests.test_parser_quality_registry import (
    REG_BINARY,
    REG_DWORD,
    REG_SZ,
    HiveWriter,
    Key,
    filetime,
    sz,
)

REG_EXPAND_SZ = 2
PROFILE_GUID = "{6F0B2B4E-8C1D-4E7A-9A51-0123456789AB}"
WIFI_GUID = "{7A1C3D5E-1111-2222-3333-444455556666}"
INTERFACE_GUID = "{11112222-3333-4444-5555-666677778888}"
WLAN_PROFILE_GUID = "{AAAABBBB-CCCC-DDDD-EEEE-FFFF00001111}"
KEY_ID = "6D3A8B2C-1A2B-4C3D-8E9F-0A1B2C3D4E5F"
# 8 groups, each <= 720885 and divisible by 11 (synthetic, not a real key).
RECOVERY_PASSWORD = "000011-000022-000033-000044-000055-000066-000077-000088"
OFFICE_TIME = datetime(2024, 3, 4, 5, 6, 7, tzinfo=timezone.utc)


def systemtime(year: int, month: int, day: int, hour: int, minute: int, second: int, weekday: int = 0) -> bytes:
    return b"".join(part.to_bytes(2, "little") for part in (year, month, weekday, day, hour, minute, second, 0))


def software_hive() -> bytes:
    root = Key("ROOT")
    profiles = root.path(r"Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")
    profiles.path(PROFILE_GUID).value("ProfileName", REG_SZ, sz("본사-유선")).value(
        "Description", REG_SZ, sz("본사 네트워크")
    ).value("Category", REG_DWORD, (2).to_bytes(4, "little")).value("NameType", REG_DWORD, (6).to_bytes(4, "little")).value(
        "Managed", REG_DWORD, (1).to_bytes(4, "little")
    ).value("DateCreated", REG_BINARY, systemtime(2024, 1, 2, 9, 0, 0)).value(
        "DateLastConnected", REG_BINARY, systemtime(2024, 5, 1, 18, 30, 15)
    )
    profiles.path(WIFI_GUID).value("ProfileName", REG_SZ, sz("Cafe_WiFi")).value(
        "NameType", REG_DWORD, (71).to_bytes(4, "little")
    ).value("Category", REG_DWORD, (0).to_bytes(4, "little")).value(
        "DateCreated", REG_BINARY, systemtime(2024, 4, 1, 12, 0, 0)
    ).value("DateLastConnected", REG_BINARY, systemtime(2024, 4, 30, 21, 5, 0))
    signatures = root.path(r"Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures")
    signatures.path("Managed\\010103000F0000F0080000000F0000F0").value("ProfileGuid", REG_SZ, sz(PROFILE_GUID)).value(
        "DefaultGatewayMac", REG_BINARY, bytes.fromhex("001122aabbcc")
    ).value("DnsSuffix", REG_SZ, sz("corp.example.com")).value("FirstNetwork", REG_SZ, sz("본사-유선"))
    signatures.path("Unmanaged\\010103000F0000F0A00000000F0000F0").value("ProfileGuid", REG_SZ, sz(WIFI_GUID)).value(
        "DefaultGatewayMac", REG_BINARY, bytes.fromhex("a0b1c2d3e4f5")
    )
    wlan = root.path(rf"Microsoft\WlanSvc\Interfaces\{INTERFACE_GUID}\Profiles\{WLAN_PROFILE_GUID}")
    wlan.value("ProfileIndex", REG_DWORD, (3).to_bytes(4, "little"))
    ssid = "HomeNet-5G".encode()
    wlan.path("MetaData").value("Channel Hints", REG_BINARY, len(ssid).to_bytes(4, "little") + ssid.ljust(32, b"\x00") + b"\x01\x00")
    root.path(r"Microsoft\Windows\CurrentVersion\App Paths\VeraCrypt.exe").value(
        "", REG_SZ, sz(r"C:\Program Files\VeraCrypt\VeraCrypt.exe")
    ).value("Path", REG_SZ, sz(r"C:\Program Files\VeraCrypt"))
    root.path(
        r"Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\00002109610090400000000000F01FEC\InstallProperties"
    ).value("DisplayName", REG_SZ, sz("Microsoft Office Professional Plus 2016")).value(
        "DisplayVersion", REG_SZ, sz("16.0.4266.1001")
    ).value("Publisher", REG_SZ, sz("Microsoft Corporation")).value("InstallDate", REG_SZ, sz("20240105")).value(
        "LocalPackage", REG_SZ, sz(r"C:\Windows\Installer\1a2b3c.msi")
    )
    return HiveWriter().build(root)


def system_hive() -> bytes:
    root = Key("ROOT")
    root.path("Select").value("Current", REG_DWORD, (1).to_bytes(4, "little"))
    known = root.path(r"ControlSet001\Control\Session Manager\KnownDLLs")
    known.value("kernel32", REG_SZ, sz("kernel32.dll")).value("user32", REG_SZ, sz("user32.dll")).value(
        "DllDirectory", REG_EXPAND_SZ, sz(r"%SystemRoot%\system32")
    ).value("evilhook", REG_SZ, sz("evilhook.dll"))
    return HiveWriter().build(root)


def office_item(path: str) -> bytes:
    ticks = filetime(OFFICE_TIME)
    return sz(f"[F00000000][T{ticks:016X}][O00000000]*{path}")


def ntuser_hive() -> bytes:
    root = Key("ROOT")
    explorer = root.path(r"Software\Microsoft\Windows\CurrentVersion\Explorer")
    mount = explorer.path("MountPoints2")
    mount.path("##fileserver#인사팀").value("_LabelFromReg", REG_SZ, sz("인사팀 공유"))
    mount.path("{a03fc990-3c72-11f0-90f3-8cb0e992a14a}").value("BaseClass", REG_SZ, sz("Drive"))
    explorer.path("Map Network Drive MRU").value("a", REG_SZ, sz(r"\\nas01\backup")).value(
        "b", REG_SZ, sz(r"\\fileserver\인사팀")
    ).value("MRUList", REG_SZ, sz("ba"))
    root.path(r"Network\Z").value("RemotePath", REG_SZ, sz(r"\\nas01\backup")).value(
        "UserName", REG_SZ, sz(r"CORP\alice")
    ).value("ProviderName", REG_SZ, sz("Microsoft Windows Network")).value("ConnectionType", REG_DWORD, (1).to_bytes(4, "little"))
    word = root.path(r"Software\Microsoft\Office\16.0\Word")
    word.path("File MRU").value("Item 1", REG_SZ, office_item(r"C:\Users\alice\Documents\급여대장.docx")).value(
        "Item 2", REG_SZ, office_item(r"\\fileserver\인사팀\평가.docx")
    ).value("Item Metadata 1", REG_SZ, sz("<Metadata />"))
    word.path(r"User MRU\ADAL_ABCDEF\Place MRU").value("Item 1", REG_SZ, office_item(r"C:\Users\alice\Documents\\"))
    root.path(r"Software\Microsoft\Office\Common").value("x", REG_SZ, sz("ignored"))
    choice = r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations"
    root.path(rf"{choice}\http\UserChoice").value("ProgId", REG_SZ, sz("WhaleHTML")).value("Hash", REG_SZ, sz("abc="))
    root.path(rf"{choice}\https\UserChoice").value("ProgId", REG_SZ, sz("ChromeHTML")).value("Hash", REG_SZ, sz("def="))
    pca = root.path(r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store")
    pca.value(r"C:\Users\alice\Downloads\sdelete64.exe", REG_BINARY, b"SACP\x01\x00\x00\x00" + b"\x00" * 16)
    usage = explorer.path("FeatureUsage")
    usage.path("AppSwitched").value(r"{6D809377-6AF0-444B-8957-A3773F02200E}\VeraCrypt\VeraCrypt.exe", REG_DWORD, (14).to_bytes(4, "little"))
    usage.path("AppLaunch").value("Microsoft.Windows.Explorer", REG_DWORD, (52).to_bytes(4, "little"))
    return HiveWriter().build(root)


def reg_export_text() -> str:
    """A ``regedit /e`` style export (UTF-16 when written) with a continued hex line."""
    ticks = filetime(OFFICE_TIME)
    mac = "00,11,22,aa,bb,cc"
    created = ",".join(f"{byte:02x}" for byte in systemtime(2024, 2, 3, 8, 15, 0))
    last = ",".join(f"{byte:02x}" for byte in systemtime(2024, 5, 2, 10, 0, 0))
    return "\r\n".join(
        [
            "Windows Registry Editor Version 5.00",
            "",
            rf"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{PROFILE_GUID}]",
            '"ProfileName"="지점-VPN"',
            '"NameType"=dword:00000017',
            '"Category"=dword:00000001',
            f'"DateCreated"=hex:{created[:23]},\\',
            f"  {created[24:]}",
            f'"DateLastConnected"=hex:{last}',
            "",
            r"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\0101]",
            f'"ProfileGuid"="{PROFILE_GUID}"',
            f'"DefaultGatewayMac"=hex:{mac}',
            '"DnsSuffix"="branch.example.com"',
            "",
            r"[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\##nas02#share]",
            '"_LabelFromReg"="백업"',
            "",
            r"[HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Excel\File MRU]",
            f'"Item 1"="[F00000000][T{ticks:016X}][O00000000]*C:\\\\Users\\\\bob\\\\매출.xlsx"',
            "",
            r"[HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice]",
            '"ProgId"="MSEdgeHTM"',
            "",
            r"[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView]",
            '"Microsoft.Office.WINWORD.EXE.15"=dword:00000005',
            "",
            r"[HKEY_USERS\S-1-5-21-9-9-9-1002\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store]",
            '"C:\\\\Tools\\\\CCleaner64.exe"=hex:53,41,43,50',
            "",
            r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs]",
            '"ole32"="ole32.dll"',
            "",
            r"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\sdelete.exe]",
            '@="C:\\\\Tools\\\\sdelete.exe"',
            "",
        ]
    )


def pca_app_launch_dic() -> bytes:
    lines = [
        r"C:\Users\alice\Downloads\BleachBit\bleachbit.exe|2024-05-02 01:02:03.456",
        r"C:\Program Files\Notepad++\notepad++.exe|2024-05-01 09:00:00.000",
        "garbage line without separator",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("utf-16")


def pca_general_db() -> bytes:
    lines = [
        r"2024-05-02 01:05:00.000|2|%USERPROFILE%\Downloads\eraser.exe|Eraser|Eraser Project|6.2.0.2993|0006abc|Abnormal process exit with code 0x1",
        "not|a|time",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("utf-16-le")


def bitlocker_key_text(language: str = "en") -> bytes:
    if language == "ko":
        body = f"BitLocker 드라이브 암호화 복구 키\r\n\r\n식별자:\r\n\r\n\t{KEY_ID}\r\n\r\n복구 키:\r\n\r\n\t{RECOVERY_PASSWORD}\r\n"
    else:
        body = (
            "BitLocker Drive Encryption recovery key\r\n\r\nTo verify that this is the correct recovery key, compare the start "
            f"of the following identifier with the identifier value displayed on your PC.\r\n\r\nIdentifier:\r\n\r\n\t{KEY_ID}\r\n\r\n"
            f"Recovery Key:\r\n\r\n\t{RECOVERY_PASSWORD}\r\n"
        )
    return body.encode("utf-16")


def bek_file() -> bytes:
    header = bytearray(0x30)
    header[0:4] = (0x30 + 0x2C).to_bytes(4, "little")
    header[4:8] = (1).to_bytes(4, "little")
    header[8:12] = (0x30).to_bytes(4, "little")
    header[12:16] = (0x30 + 0x2C).to_bytes(4, "little")
    header[16:32] = uuid.UUID(KEY_ID).bytes_le
    header[40:48] = filetime(datetime(2024, 1, 10, 3, 0, 0, tzinfo=timezone.utc)).to_bytes(8, "little")
    entry = bytearray(0x2C)
    entry[0:2] = (0x2C).to_bytes(2, "little")
    entry[12:44] = bytes(range(1, 33))  # synthetic external key bytes
    return bytes(header) + bytes(entry)
