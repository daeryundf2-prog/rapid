"""Synthetic inputs of the R5 L2 tests (OS, system and policy-presence rows).

Everything is generated in code: hives use the minimal regf writer of
``tests.test_parser_quality_registry``, Shell Links the builder of
``tests.test_parser_quality_prefetch_lnk``. No real evidence, no real keys:
every secret below is a marker string that the tests assert never reaches any
output (row, run output file, docs index).
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from datetime import datetime, timezone
from pathlib import Path

from tests.test_parser_quality_prefetch_lnk import build_lnk, link_info_local
from tests.test_parser_quality_registry import (
    REG_BINARY,
    REG_DWORD,
    REG_SZ,
    HiveWriter,
    Key,
    filetime,
    sz,
    write_hive,
)

# --- planted secrets (must never appear in any output) ------------------------------------
SSH_PRIVATE_SECRET = b"SSHPRIVATESECRETBODY-r5l2-0123456789"
PEM_PRIVATE_SECRET = b"PEMPRIVATESECRETBODY-r5l2-9876543210"
PPK_PRIVATE_SECRET = b"PPKPRIVATESECRETBODY-r5l2-5555555555"
PUTTY_PROXY_PASSWORD = "PUTTYPROXYSECRET-r5l2"
WINSCP_PASSWORD = "A35C4F5B5D6E2E333D3B3B6D6E2E3B3D3B3B6E6D2E3B3D-WINSCPSECRET"
WINSCP_INI_PASSWORD = "A35C1E2D3C4B5A69788796A5B4C3D2E1-WINSCPINISECRET"
ELECTRUM_XPRV = "xprv9s21ZrQH143K2SECRETELECTRUMXPRVr5l2abcdefghijklmnopqrstuvwxyzABCDEF"
ELECTRUM_SEED = "abandon secret ability able about above absent absorb abstract absurd abuse access"
WALLET_DAT_SECRET = b"WALLETDATSECRETKEYMATERIAL-r5l2"
EXODUS_SEED_SECRET = b"EXODUSSEEDSECRET-r5l2"
METAMASK_VAULT_SECRET = b'{"vault":"METAMASKVAULTSECRET-r5l2"}'
CREDENTIAL_BLOB_SECRET = b"CREDBLOBSECRET-r5l2-password=Hunter2"
VAULT_SECRET = b"VAULTVCRDSECRET-r5l2"
MASTERKEY_SECRET = b"DPAPIMASTERKEYSECRET-r5l2"
SECRETS: tuple[bytes, ...] = (
    SSH_PRIVATE_SECRET,
    PEM_PRIVATE_SECRET,
    PPK_PRIVATE_SECRET,
    PUTTY_PROXY_PASSWORD.encode(),
    WINSCP_PASSWORD.encode(),
    WINSCP_INI_PASSWORD.encode(),
    ELECTRUM_XPRV.encode(),
    ELECTRUM_SEED.encode(),
    WALLET_DAT_SECRET,
    EXODUS_SEED_SECRET,
    b"METAMASKVAULTSECRET-r5l2",
    CREDENTIAL_BLOB_SECRET,
    VAULT_SECRET,
    MASTERKEY_SECRET,
)

DISABLED_AT = datetime(2024, 5, 1, 8, 30, 0, tzinfo=timezone.utc)
VSN = 0x1A2B3C4D5E6F7788
VSN_LOW = "5E6F7788"
ELECTRUM_ADDRESSES = ["bc1qr5l2receive0000000000000000000000000aa", "bc1qr5l2change00000000000000000000000000bb"]
ETH_ADDRESS = "00112233445566778899aabbccddeeff00112233"
METAMASK_ID = "nkbihfbeogaeaoehlefnkodbefgpgknn"
PHANTOM_ID = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
KAIKAS_ID = "jblndlipeogpafnldhgmapagcccfchpi"


def startup_value(state: int, moment: datetime | None = None) -> bytes:
    ticks = filetime(moment) if moment is not None else 0
    return bytes([state, 0, 0, 0]) + ticks.to_bytes(8, "little")


def ntuser_hive() -> bytes:
    root = Key("ROOT")
    cv = r"Software\Microsoft\Windows\CurrentVersion"
    root.path(rf"{cv}\Run").value("Updater", REG_SZ, sz(r"C:\Users\alice\AppData\Roaming\upd\upd.exe /silent")).value(
        "OneDrive", REG_SZ, sz(r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background')
    )
    approved = rf"{cv}\Explorer\StartupApproved"
    root.path(rf"{approved}\Run").value("Updater", REG_BINARY, startup_value(0x02)).value(
        "OneDrive", REG_BINARY, startup_value(0x03, DISABLED_AT)
    ).value("Corrupt", REG_BINARY, b"\x09")
    root.path(rf"{approved}\StartupFolder").value("evil.lnk", REG_BINARY, startup_value(0x06))
    putty = r"Software\SimonTatham\PuTTY"
    root.path(rf"{putty}\SshHostKeys").value("ssh-ed25519@22:203.0.113.5", REG_SZ, sz("0x1234abcd,0x5678ef01"))
    root.path(rf"{putty}\Sessions\prod%20server").value("HostName", REG_SZ, sz("203.0.113.5")).value(
        "UserName", REG_SZ, sz("root")
    ).value("PortNumber", REG_DWORD, (2222).to_bytes(4, "little")).value("Protocol", REG_SZ, sz("ssh")).value(
        "ProxyPassword", REG_SZ, sz(PUTTY_PROXY_PASSWORD)
    ).value("PublicKeyFile", REG_SZ, sz(r"C:\Users\alice\.ssh\legacy.ppk"))
    root.path(rf"{putty}\Sessions\Default%20Settings").value("HostName", REG_SZ, sz(""))
    winscp = r"Software\Martin Prikryl\WinSCP 2"
    root.path(rf"{winscp}\Sessions\backup@files.example.org").value("HostName", REG_SZ, sz("files.example.org")).value(
        "UserName", REG_SZ, sz("backup")
    ).value("PortNumber", REG_DWORD, (22).to_bytes(4, "little")).value("FSProtocol", REG_DWORD, (2).to_bytes(4, "little")).value(
        "Password", REG_SZ, sz(WINSCP_PASSWORD)
    )
    root.path(rf"{winscp}\SshHostKeys").value("ssh-rsa@22:files.example.org", REG_SZ, sz("0x10001,0xabcdef"))
    identities = r"Software\Microsoft\Office\16.0\Common\Identity\Identities"
    root.path(rf"{identities}\0a1b2c3d_ADAL").value("EmailAddress", REG_SZ, sz("alice@corp.example")).value(
        "FriendlyName", REG_SZ, sz("Alice Kim")
    ).value("ProviderId", REG_SZ, sz("ADAL")).value("TenantId", REG_SZ, sz("11111111-2222-3333-4444-555555555555"))
    root.path(rf"{identities}\9f8e7d6c_LiveId").value("EmailAddress", REG_SZ, sz("alice.personal@example.com")).value(
        "ProviderId", REG_SZ, sz("LiveId")
    )
    original = r"C:\Users\alice\Pictures\beach.jpg"
    root.path(r"Control Panel\Desktop").value(
        "WallPaper", REG_SZ, sz(r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper")
    ).value("TranscodedImageCache", REG_BINARY, b"\x7a\xc3\x01\x00" + b"\x00" * 20 + original.encode("utf-16-le") + b"\x00" * 8).value(
        "WallpaperStyle", REG_SZ, sz("10")
    )
    root.path(rf"{cv}\Explorer\Wallpapers").value("BackgroundHistoryPath0", REG_SZ, sz(original)).value(
        "BackgroundHistoryPath1", REG_SZ, sz(r"C:\Users\alice\Pictures\city.jpg")
    )
    return HiveWriter().build(root)


def software_hive() -> bytes:
    root = Key("ROOT")
    root.path(r"Microsoft\Windows\CurrentVersion\Policies\System").value("legalnoticecaption", REG_SZ, sz("보안 서약")).value(
        "legalnoticetext", REG_SZ, sz("이 시스템의 모든 사용은 모니터링됩니다. 무단 반출을 금지합니다.")
    )
    root.path(r"Microsoft\Windows NT\CurrentVersion\Winlogon").value("LegalNoticeCaption", REG_SZ, sz("")).value(
        "LegalNoticeText", REG_SZ, sz("")
    )
    root.path(r"Microsoft\Windows\CurrentVersion\Run").value("SecurityHealth", REG_SZ, sz(r"%windir%\system32\SecurityHealthSystray.exe"))
    root.path(r"Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run").value("SecurityHealth", REG_BINARY, startup_value(0x06))
    return HiveWriter().build(root)


# --- SSH ---------------------------------------------------------------------------------------


def ssh_string(data: bytes) -> bytes:
    return len(data).to_bytes(4, "big") + data


def ed25519_public_blob(seed: int) -> bytes:
    return ssh_string(b"ssh-ed25519") + ssh_string(hashlib.sha256(f"r5l2-key-{seed}".encode()).digest())


def public_line(seed: int, comment: str) -> str:
    return f"ssh-ed25519 {base64.b64encode(ed25519_public_blob(seed)).decode()} {comment}"


def fingerprint(seed: int) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(ed25519_public_blob(seed)).digest()).decode().rstrip("=")


def wrap(text: str, width: int = 70) -> str:
    return "\n".join(text[index : index + width] for index in range(0, len(text), width))


def openssh_private_key(seed: int, *, cipher: bytes = b"none") -> bytes:
    private = (1234).to_bytes(4, "big") * 2 + ssh_string(b"ssh-ed25519") + ssh_string(SSH_PRIVATE_SECRET) + ssh_string(b"alice@pc")
    body = (
        b"openssh-key-v1\x00"
        + ssh_string(cipher)
        + ssh_string(b"none" if cipher == b"none" else b"bcrypt")
        + ssh_string(b"")
        + (1).to_bytes(4, "big")
        + ssh_string(ed25519_public_blob(seed))
        + ssh_string(private)
    )
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + wrap(base64.b64encode(body).decode()) + "\n-----END OPENSSH PRIVATE KEY-----\n"
    return text.encode("ascii")


def openssh_private_body_b64(seed: int) -> str:
    text = openssh_private_key(seed).decode()
    return "".join(line for line in text.splitlines() if not line.startswith("-----"))


def pem_encrypted_rsa() -> bytes:
    body = wrap(base64.b64encode(PEM_PRIVATE_SECRET * 4).decode(), 64)
    return (
        "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\n"
        + body
        + "\n-----END RSA PRIVATE KEY-----\n"
    ).encode("ascii")


def ppk_file(seed: int) -> bytes:
    public = wrap(base64.b64encode(ed25519_public_blob(seed)).decode(), 64).splitlines()
    private = wrap(base64.b64encode(PPK_PRIVATE_SECRET).decode(), 64).splitlines()
    lines = [
        "PuTTY-User-Key-File-3: ssh-ed25519",
        "Encryption: none",
        "Comment: legacy-key",
        f"Public-Lines: {len(public)}",
        *public,
        f"Private-Lines: {len(private)}",
        *private,
        "Private-MAC: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    ]
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def write(path: Path, data: bytes | str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
    return path


# --- NTFS --------------------------------------------------------------------------------------


def boot_sector() -> bytes:
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x52\x90"
    boot[3:11] = b"NTFS    "
    struct.pack_into("<HB", boot, 0x0B, 512, 8)
    boot[0x15] = 0xF8
    struct.pack_into("<I", boot, 0x1C, 2048)
    struct.pack_into("<QQQ", boot, 0x28, 488_396_799, 786_432, 2)
    boot[0x40] = 0xF6  # 2**10 = 1024-byte MFT records
    boot[0x44] = 0x01
    struct.pack_into("<Q", boot, 0x48, VSN)
    boot[510:512] = b"\x55\xaa"
    return bytes(boot)


def mft_with_volume_record(label: str = "증거볼륨", dirty: bool = True) -> bytes:
    records = bytearray(4 * 1024)
    for number in range(4):
        start = number * 1024
        record = bytearray(1024)
        record[0:4] = b"FILE"
        struct.pack_into("<HH", record, 4, 0x30, 3)  # update sequence array at 0x30, 3 entries
        struct.pack_into("<H", record, 0x14, 0x38)  # first attribute
        offset = 0x38
        if number == 3:
            name = label.encode("utf-16-le")
            attr = bytearray(0x18 + len(name))
            struct.pack_into("<IIBBHHH", attr, 0, 0x60, 0, 0, 0, 0, 0, 0)
            struct.pack_into("<IH", attr, 0x10, len(name), 0x18)
            attr[0x18:] = name
            attr += b"\x00" * ((-len(attr)) % 8)
            struct.pack_into("<I", attr, 4, len(attr))
            record[offset : offset + len(attr)] = attr
            offset += len(attr)
            info = bytearray(0x18 + 12)
            struct.pack_into("<II", info, 0, 0x70, len(info))
            struct.pack_into("<IH", info, 0x10, 12, 0x18)
            info[0x18 + 8] = 3
            info[0x18 + 9] = 1
            struct.pack_into("<H", info, 0x18 + 10, 0x0001 if dirty else 0)
            record[offset : offset + len(info)] = info
            offset += len(info)
        struct.pack_into("<I", record, offset, 0xFFFFFFFF)
        usn = b"\x07\x00"
        record[0x30:0x32] = usn
        for sector in (1, 2):
            end = sector * 512
            record[0x30 + sector * 2 : 0x32 + sector * 2] = record[end - 2 : end]
            record[end - 2 : end] = usn
        records[start : start + 1024] = record
    return bytes(records)


# --- whole evidence tree -----------------------------------------------------------------------


def jpeg(width: int, height: int) -> bytes:
    sof = b"\xff\xc0" + (17).to_bytes(2, "big") + b"\x08" + height.to_bytes(2, "big") + width.to_bytes(2, "big") + b"\x03" + b"\x00" * 9
    return b"\xff\xd8\xff\xe0" + (16).to_bytes(2, "big") + b"JFIF\x00" + b"\x00" * 9 + sof + b"\xff\xd9"


def build_tree(root: Path) -> Path:
    """Write the synthetic evidence tree under ``root`` and return it."""
    write_hive(root, "Users/alice/NTUSER.DAT", ntuser_hive())
    write_hive(root, "Windows/System32/config/SOFTWARE", software_hive())
    home = root / "Users" / "alice"
    roaming = home / "AppData" / "Roaming"
    local = home / "AppData" / "Local"
    moment = datetime(2024, 4, 2, 3, 4, 5, tzinfo=timezone.utc)
    startup = roaming / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    write(
        startup / "evil.lnk",
        build_lnk(
            link_info_local(VSN & 0xFFFFFFFF, "로컬 디스크", "C:\\Users\\alice\\AppData\\Local\\Temp\\", "evil.exe"),
            created=moment,
            accessed=moment,
            modified=moment,
        ),
    )
    write(startup / "run.bat", "@echo off\r\nstart C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe\r\n")
    write(startup / "desktop.ini", "[.ShellClassInfo]\r\n")
    write(startup / "broken.lnk", b"L\x00\x00\x00garbage")
    write(
        root / "ProgramData" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp" / "Vendor Agent.lnk",
        build_lnk(
            link_info_local(VSN & 0xFFFFFFFF, "로컬 디스크", "C:\\Program Files\\Vendor\\", "agent.exe"),
            created=moment,
            accessed=moment,
            modified=moment,
        ),
    )
    ssh = home / ".ssh"
    hashed = "|1|c2FsdHNhbHRzYWx0c2FsdHNhbHQ=|aGFzaGhhc2hoYXNoaGFzaGhhc2g="
    write(
        ssh / "known_hosts",
        "\n".join(
            [
                "# comment",
                f"git.example.org,198.51.100.20 {public_line(1, '')}".strip(),
                f"[jump.example.org]:2200 {public_line(2, '')}".strip(),
                f"{hashed} {public_line(3, '')}".strip(),
                "garbage-line-without-key",
            ]
        )
        + "\n",
    )
    write(ssh / "authorized_keys", f'from="10.0.0.0/8",command="/usr/bin/backup" {public_line(4, "ops@backup")}\n{public_line(5, "bob@laptop")}\n')
    write(
        ssh / "config",
        "Host prod\n  HostName 203.0.113.10\n  User deploy\n  Port 2022\n  IdentityFile ~/.ssh/id_ed25519\n  LocalForward 5432 db:5432\n\nHost *.internal\n  ProxyJump bastion\n",
    )
    write(ssh / "id_ed25519", openssh_private_key(6))
    write(ssh / "id_ed25519.pub", public_line(6, "alice@pc") + "\n")
    write(ssh / "id_rsa", pem_encrypted_rsa())
    write(ssh / "legacy.ppk", ppk_file(7))
    program_ssh = root / "ProgramData" / "ssh"
    write(program_ssh / "sshd_config", "Port 22\nPasswordAuthentication yes\nPermitEmptyPasswords no\nAllowUsers alice deploy\nSubsystem sftp sftp-server.exe\n")
    write(program_ssh / "administrators_authorized_keys", public_line(8, "admin@corp") + "\n")
    write(program_ssh / "ssh_host_ed25519_key", openssh_private_key(9))
    write(program_ssh / "ssh_host_ed25519_key.pub", public_line(9, "root@host") + "\n")
    write(
        roaming / "WinSCP.ini",
        "[Configuration\\Interface]\r\nRandomSeedFile=x\r\n[Sessions\\nas%20backup]\r\nHostName=nas.example.org\r\nUserName=admin\r\nPortNumber=2222\r\nFSProtocol=2\r\n"
        f"Password={WINSCP_INI_PASSWORD}\r\n[SshHostKeys]\r\nssh-ed25519@2222:nas.example.org=0x11,0x22\r\n",
    )
    backstage = local / "Microsoft" / "Office" / "16.0" / "BackstageInAppNavCache"
    write(
        backstage / "MyComputer" / "nav.json",
        json.dumps(
            {
                "Version": 1,
                "Folders": [{"DisplayName": "Documents", "Url": "C:\\Users\\alice\\Documents", "LastModified": "2026-10-01T09:00:00Z"}],
                "Files": [
                    {
                        "DisplayName": "설계도.docx",
                        "Url": "https://corp.sharepoint.com/sites/rnd/Shared%20Documents/design.docx",
                        "LastModified": "2026-10-02T10:00:00Z",
                        "LastModifiedBy": "Bob Lee",
                    }
                ],
            },
            ensure_ascii=False,
        ),
    )
    write(backstage / "OneDrive" / "broken.json", "{not json")
    vms = home / "Documents" / "Virtual Machines"
    write(
        vms / "Win10" / "Win10.vmx",
        '.encoding = "UTF-8"\ndisplayName = "Win10-익명"\nguestOS = "windows9-64"\nscsi0:0.fileName = "Win10.vmdk"\n'
        'ethernet0.generatedAddress = "00:0C:29:AA:BB:CC"\nsharedFolder0.hostPath = "C:\\Users\\alice\\Desktop\\반출"\nuuid.bios = "56 4d 11 22"\n',
    )
    write(
        roaming / "VMware" / "preferences.ini",
        '.encoding = "UTF-8"\npref.mruVM0.filename = "C:\\Users\\alice\\Documents\\Virtual Machines\\Win10\\Win10.vmx"\npref.mruVM0.displayName = "Win10-익명"\n',
    )
    write(roaming / "VMware" / "inventory.vmls", 'vmlist1.config = "D:\\VMs\\Kali\\Kali.vmx"\nvmlist1.DisplayName = "Kali"\n')
    write(
        home / ".VirtualBox" / "VirtualBox.xml",
        '<?xml version="1.0"?><VirtualBox xmlns="http://www.virtualbox.org/" version="1.12-windows"><Global><MachineRegistry>'
        '<MachineEntry uuid="{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}" src="C:\\Users\\alice\\VirtualBox VMs\\Tails\\Tails.vbox"/>'
        "</MachineRegistry></Global></VirtualBox>",
    )
    write(
        home / "VirtualBox VMs" / "Tails" / "Tails.vbox",
        '<?xml version="1.0"?><VirtualBox xmlns="http://www.virtualbox.org/" version="1.16-windows">'
        '<Machine uuid="{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}" name="Tails" OSType="Debian_64" lastStateChange="2026-09-30T12:00:00Z">'
        '<MediaRegistry><HardDisks><HardDisk uuid="{1}" location="Tails.vdi" format="VDI"/></HardDisks></MediaRegistry>'
        '<Hardware><Network><Adapter slot="0" MACAddress="080027ABCDEF" enabled="true"/></Network>'
        '<SharedFolders><SharedFolder name="out" hostPath="E:\\out"/></SharedFolders></Hardware><Snapshot uuid="{2}" name="s1"/></Machine></VirtualBox>',
    )
    write(home / "VirtualBox VMs" / "Broken" / "Broken.vbox", "<VirtualBox><Machine name='x'")
    write(root / "ProgramData" / "Microsoft" / "Windows" / "Hyper-V" / "Virtual Machines" / "11111111-2222-3333-4444-555555555555.vmcx", b"\x00" * 64)
    write(root / "ProgramData" / "Microsoft" / "Windows" / "Hyper-V" / "Virtual Machines" / "DockerDesktopVM.vmcx", b"\x00" * 64)
    # wallets
    bdb = bytearray(64)
    struct.pack_into("<I", bdb, 12, 0x00053162)
    write(roaming / "Bitcoin" / "wallet.dat", bytes(bdb) + b"\x04mkey\x01" + WALLET_DAT_SECRET)
    write(
        roaming / "Electrum" / "wallets" / "default_wallet",
        json.dumps(
            {
                "addresses": {"receiving": [ELECTRUM_ADDRESSES[0]], "change": [ELECTRUM_ADDRESSES[1]]},
                "keystore": {"type": "bip32", "xprv": ELECTRUM_XPRV, "seed": ELECTRUM_SEED, "xpub": "xpubPUBLIC"},
                "seed_version": 18,
                "use_encryption": False,
                "wallet_type": "standard",
            }
        ),
    )
    write(roaming / "Electrum" / "wallets" / "locked_wallet", "QklFMQ" + base64.b64encode(b"encrypted-blob" * 4).decode())
    write(roaming / "Electrum" / "wallets" / "broken_wallet", "{broken json")
    write(roaming / "Exodus" / "exodus.wallet" / "seed.seco", EXODUS_SEED_SECRET)
    write(roaming / "Exodus" / "exodus.wallet" / "passphrase.json", b'{"passphrase":"x"}')
    write(roaming / "Ledger Live" / "app.json", b'{"data":"encrypted"}')
    write(roaming / "Ethereum" / "keystore" / f"UTC--2020-01-01T00-00-00.000000000Z--{ETH_ADDRESS}", b'{"crypto":{"ciphertext":"x"}}')
    profile = local / "Google" / "Chrome" / "User Data" / "Default"
    write(profile / "Local Extension Settings" / METAMASK_ID / "000003.log", METAMASK_VAULT_SECRET)
    (profile / "Local Extension Settings" / PHANTOM_ID).mkdir(parents=True, exist_ok=True)
    write(profile / "IndexedDB" / f"chrome-extension_{KAIKAS_ID}_0.indexeddb.leveldb" / "000001.log", b"kaikas-data")
    sqlite_head = b"SQLite format 3\x00" + b"\x00" * 84
    write(root / "Backup" / "old" / "wallet.dat", sqlite_head)
    # credential stores
    write(roaming / "Microsoft" / "Credentials" / "DFBE70A7E5CC19A398EBF1B96859CE5D", b"\x01\x00\x00\x00" + CREDENTIAL_BLOB_SECRET)
    write(local / "Microsoft" / "Credentials" / "5E4D3C2B1A09F8E7D6C5B4A392817060", b"\x01\x00\x00\x00" + CREDENTIAL_BLOB_SECRET)
    vault = local / "Microsoft" / "Vault" / "4BF4C442-9B8A-41A0-B380-DD4A704DDB28"
    write(vault / "Policy.vpol", b"\x01" + VAULT_SECRET)
    write(vault / "0A1B2C3D4E5F60718293A4B5C6D7E8F9.vcrd", b"\x01" + VAULT_SECRET)
    protect = roaming / "Microsoft" / "Protect" / "S-1-5-21-1111-2222-3333-1001"
    write(protect / "8a0f1b2c-3d4e-5f60-7182-93a4b5c6d7e8", b"\x02\x00\x00\x00" + MASTERKEY_SECRET)
    write(protect / "Preferred", b"\x00" * 24)
    write(root / "Windows" / "System32" / "Microsoft" / "Protect" / "S-1-5-18" / "User" / "11111111-2222-3333-4444-555555555555", MASTERKEY_SECRET)
    # McAfee
    write(
        root / "ProgramData" / "McAfee" / "Endpoint Security" / "Logs" / "OnDemandScan_Activity.log",
        "10/18/2026 09:15:01.123 AM mfeesp(1234.5678) <NT AUTHORITY\\SYSTEM> ThreatPrevention.ODS.Activity: Scan found: "
        "C:\\Users\\alice\\Downloads\\invoice.exe contains Trojan-FRTX!AB12CD34EF56 (Trojan). Action: Deleted\n"
        "10/18/2026 09:20:00.000 AM mfeesp(1234.5678) <SYSTEM> ThreatPrevention.ODS.Activity: Scan completed. No threats found.\n"
        "garbage \x00\x01 line detected without time\n",
    )
    write(
        root / "ProgramData" / "McAfee" / "DesktopProtection" / "OnAccessScanLog.txt",
        "10/17/2026\t2:05:11 PM\tDeleted\tCORP\\alice\tC:\\Windows\\explorer.exe\tC:\\Users\\alice\\Desktop\\keygen.exe\tGeneric.dx!abc (Trojan)\n",
    )
    # wallpaper
    themes = roaming / "Microsoft" / "Windows" / "Themes"
    write(themes / "TranscodedWallpaper", jpeg(1920, 1080))
    write(themes / "CachedFiles" / "CachedImage_1920_1080_POS4.jpg", jpeg(1920, 1080))
    # NTFS metadata ($Boot + $MFT record 3) and a truncated boot sector elsewhere
    write(root / "ntfs" / "C" / "$Boot", boot_sector())
    write(root / "ntfs" / "C" / "$MFT", mft_with_volume_record())
    write(root / "ntfs" / "broken" / "$Boot", b"\xeb\x52\x90NTFS")
    # LogMeIn log (windows-remote-access)
    write(root / "ProgramData" / "LogMeIn" / "LMI20261018.log", "2026-10-18 10:01:02 Remote control session started from 198.51.100.7 user alice\n")
    return root
