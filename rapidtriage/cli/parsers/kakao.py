"""Parser registration for KakaoTalk commands."""

from __future__ import annotations

import argparse
import textwrap

from ...core.cli_constants import (
    DEFAULT_MACOS_REPORT_MAX_CONTEXT_ROWS,
    DEFAULT_MACOS_REPORT_MAX_MESSAGES,
    DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT,
    DEFAULT_MEMORY_SQLCIPHER_KEY_RESIDUE_LIMIT,
    DEFAULT_MEMORY_SQLITE_MAX_CARVE_BYTES,
    DEFAULT_MEMORY_SQLITE_MAX_HITS,
)
from ..helpers import DefaultOutput


def register(sub: argparse._SubParsersAction) -> None:
    """Register the kakaotalk-* commands."""
    kakao_decrypt = sub.add_parser(
        "kakaotalk-decrypt",
        help="Decrypt authorized Windows KakaoTalk chatLogs_*.edb files and summarize message tables",
        description="Decrypt authorized Windows KakaoTalk chatLogs_*.edb files and summarize message tables",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              RAPIDTRIAGE_KAKAO_KEY_HEX=... RAPIDTRIAGE_KAKAO_IV_HEX=... rapidtriage kakaotalk-decrypt ./KakaoTalk --output kakao-decrypt.json
              RAPIDTRIAGE_KAKAO_PRAGMA=... RAPIDTRIAGE_KAKAO_USER_ID=12345 rapidtriage kakaotalk-decrypt ./KakaoTalk --include-message-preview
            """
        ),
    )
    kakao_decrypt.add_argument("root", help="Extracted KakaoTalk user/app-data folder to scan")
    kakao_decrypt.add_argument("--output", default=DefaultOutput("rapidtriage-kakaotalk-decrypt.json"), help="JSON output path")
    kakao_decrypt.add_argument("--key-hex", help="Authorized 16-byte AES key as hex; prefer env to avoid shell history")
    kakao_decrypt.add_argument("--iv-hex", help="Authorized 16-byte AES IV as hex; prefer env to avoid shell history")
    kakao_decrypt.add_argument("--key-hex-env", default="RAPIDTRIAGE_KAKAO_KEY_HEX", help="Environment variable for AES key hex")
    kakao_decrypt.add_argument("--iv-hex-env", default="RAPIDTRIAGE_KAKAO_IV_HEX", help="Environment variable for AES IV hex")
    kakao_decrypt.add_argument("--pragma", help="Authorized KakaoTalk pragma value; prefer env to avoid shell history")
    kakao_decrypt.add_argument("--user-id", help="Authorized KakaoTalk userId paired with pragma; prefer env")
    kakao_decrypt.add_argument("--pragma-key-hex", help="Authorized 16-byte DeviceInfo pragma-generation key as hex")
    kakao_decrypt.add_argument("--sys-uuid", help="Override DeviceInfo sys_uuid; otherwise NTUSER.DAT/env is used")
    kakao_decrypt.add_argument("--hdd-model", help="Override DeviceInfo hdd_model; otherwise NTUSER.DAT/env is used")
    kakao_decrypt.add_argument("--hdd-serial", help="Override DeviceInfo hdd_serial; otherwise NTUSER.DAT/env is used")
    kakao_decrypt.add_argument("--pragma-env", default="RAPIDTRIAGE_KAKAO_PRAGMA", help="Environment variable for pragma")
    kakao_decrypt.add_argument("--user-id-env", default="RAPIDTRIAGE_KAKAO_USER_ID", help="Environment variable for userId")
    kakao_decrypt.add_argument("--pragma-key-hex-env", default="RAPIDTRIAGE_KAKAO_PRAGMA_KEY_HEX", help="Environment variable for DeviceInfo pragma-generation key hex")
    kakao_decrypt.add_argument("--sys-uuid-env", default="RAPIDTRIAGE_KAKAO_SYS_UUID", help="Environment variable for DeviceInfo sys_uuid")
    kakao_decrypt.add_argument("--hdd-model-env", default="RAPIDTRIAGE_KAKAO_HDD_MODEL", help="Environment variable for DeviceInfo hdd_model")
    kakao_decrypt.add_argument("--hdd-serial-env", default="RAPIDTRIAGE_KAKAO_HDD_SERIAL", help="Environment variable for DeviceInfo hdd_serial")
    kakao_decrypt.add_argument("--include-message-preview", action="store_true", help="Include bounded raw message previews in JSON")
    kakao_decrypt.add_argument("--write-decrypted", action="store_true", help="Write decrypted SQLite files to --decrypted-dir")
    kakao_decrypt.add_argument("--decrypted-dir", help="Directory for decrypted SQLite files when --write-decrypted is set")
    kakao_decrypt.add_argument("--max-databases", type=int, default=0, help="Limit chatLogs databases processed (0 means all)")
    kakao_decrypt.add_argument("--max-messages-per-db", type=int, default=20, help="Bounded preview rows per database")
    kakao_decrypt.add_argument("--openssl-bin", default="openssl", help="OpenSSL binary used for AES-CBC pages")
    kakao_decrypt.add_argument(
        "--no-postpatch-memory-carve",
        action="store_true",
        help="Disable fallback SQLite carving from KakaoTalk process memory dumps when legacy decrypt fails",
    )
    kakao_decrypt.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

    kakao_macos_report = sub.add_parser(
        "kakaotalk-macos-report",
        help="Export authorized macOS KakaoTalk messages into CSV and a static HTML viewer",
        description=(
            "Build a reviewable macOS KakaoTalk report package from a Mac home, mounted Mac root, "
            "KakaoTalk container, or extracted collection folder"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage kakaotalk-macos-report ~/Library/Containers/com.kakao.KakaoTalkMac --output-dir ./kakao-mac-report
              RAPIDTRIAGE_KAKAO_MAC_USER_ID=12345 RAPIDTRIAGE_KAKAO_MAC_UUID=... rapidtriage kakaotalk-macos-report /Volumes/MacHD --output-dir ./kakao-mac-report --include-message-text
            """
        ),
    )
    kakao_macos_report.add_argument("root", help="Mac home, mounted Mac root, KakaoTalk container, or extracted folder")
    kakao_macos_report.add_argument("--output-dir", required=True, help="Directory for JSON, CSV, and HTML report outputs")
    kakao_macos_report.add_argument(
        "--include-message-text",
        action="store_true",
        help="Include raw message/body fields in CSV and HTML; default exports hashes/lengths only",
    )
    kakao_macos_report.add_argument(
        "--max-messages",
        type=int,
        default=DEFAULT_MACOS_REPORT_MAX_MESSAGES,
        help=f"Maximum message rows to export ({DEFAULT_MACOS_REPORT_MAX_MESSAGES} default, 0 means all)",
    )
    kakao_macos_report.add_argument(
        "--max-context-rows",
        type=int,
        default=DEFAULT_MACOS_REPORT_MAX_CONTEXT_ROWS,
        help=(
            "Maximum room/user context rows to export per context table "
            f"({DEFAULT_MACOS_REPORT_MAX_CONTEXT_ROWS} default, 0 means all)"
        ),
    )
    kakao_macos_report.add_argument(
        "--user-id-file",
        help="File containing an authorized macOS KakaoTalk numeric UserID; value is read in-memory and not exported",
    )
    kakao_macos_report.add_argument("--sqlcipher-bin", default="sqlcipher", help="SQLCipher binary for encrypted stores")
    kakao_macos_report.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

    kakao_collect = sub.add_parser(
        "kakaotalk-collect-windows",
        help="Collect authorized Windows PC KakaoTalk data into a ZIP and optionally analyze it",
        description="Collect authorized Windows PC KakaoTalk data into a ZIP and optionally run the KakaoTalk SQLCipher/report workflow",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage kakaotalk-collect-windows --output-root ./cases --analyze --no-xlsx
              rapidtriage kakaotalk-collect-windows --kakao-root "C:\\Users\\USER\\AppData\\Local\\Kakao\\KakaoTalk" --output-root D:\\Cases
              rapidtriage kakaotalk-collect-windows --include-memory-dump --analyze --sqlcipher-bin C:\\Tools\\sqlcipher.exe
            """
        ),
    )
    kakao_collect.add_argument("--output-root", default="kakaotalk_auto_cases", help="Directory where collection case folders are created")
    kakao_collect.add_argument("--kakao-root", help="Override KakaoTalk root; default is %%LOCALAPPDATA%%\\Kakao\\KakaoTalk on Windows")
    kakao_collect.add_argument("--include-memory-dump", action="store_true", help="Also attempt a KakaoTalk.exe memory dump; may require Administrator")
    kakao_collect.add_argument("--analyze", action="store_true", help="Run post-patch SQLCipher/message/media analysis after collection")
    kakao_collect.add_argument("--sqlcipher-bin", default="sqlcipher", help="SQLCipher binary used when --analyze is set")
    kakao_collect.add_argument("--timeout-seconds", type=float, default=5.0, help="Timeout per SQLCipher probe when --analyze is set")
    kakao_collect.add_argument("--max-message-residues", type=int, default=1000, help="Maximum memory message residues when --analyze is set")
    kakao_collect.add_argument("--no-xlsx", action="store_true", help="Record that XLSX output should be skipped by wrapper tooling")
    kakao_collect.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

    kakao_memory_carve = sub.add_parser(
        "kakaotalk-memory-carve",
        help="Carve decrypted SQLite residues from authorized KakaoTalk process memory dumps",
        description="Carve decrypted SQLite residues from authorized KakaoTalk process memory dumps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage kakaotalk-memory-carve ./KakaoTalk --output kakao-memory-carve.json
              rapidtriage kakaotalk-memory-carve ./KakaoTalk --write-carves --carve-dir ./memory-carves
            """
        ),
    )
    kakao_memory_carve.add_argument("root", help="Extracted KakaoTalk folder containing KakaoTalk.DMP or memory dumps")
    kakao_memory_carve.add_argument("--output", default=DefaultOutput("rapidtriage-kakaotalk-memory-carve.json"), help="JSON output path")
    kakao_memory_carve.add_argument("--carve-dir", help="Directory for carved SQLite files when --write-carves is set")
    kakao_memory_carve.add_argument("--write-carves", action="store_true", help="Write carved SQLite fragments to --carve-dir")
    kakao_memory_carve.add_argument("--max-hits", type=int, default=DEFAULT_MEMORY_SQLITE_MAX_HITS, help="Maximum SQLite headers to carve (0 means all)")
    kakao_memory_carve.add_argument("--max-carve-bytes", type=int, default=DEFAULT_MEMORY_SQLITE_MAX_CARVE_BYTES, help="Maximum bytes to carve for one SQLite header")
    kakao_memory_carve.add_argument("--include-row-preview", action="store_true", help="Include bounded row previews when readable")
    kakao_memory_carve.add_argument("--include-message-preview", action="store_true", help="Include process-memory chat message body previews")
    kakao_memory_carve.add_argument("--message-csv", help="Optional UTF-8-SIG CSV path for process-memory chat message body residues")
    kakao_memory_carve.add_argument("--max-rows-per-table", type=int, default=3, help="Bounded row previews per table")
    kakao_memory_carve.add_argument(
        "--max-message-residues",
        type=int,
        default=DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT,
        help="Maximum process-memory chat JSON message residues to report (0 means all)",
    )
    kakao_memory_carve.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

    kakao_sqlcipher_probe = sub.add_parser(
        "kakaotalk-sqlcipher-probe",
        help="Probe post-patch KakaoTalk chatLogs_*.edb with redacted SQLCipher key residues from memory",
        description="Probe post-patch KakaoTalk chatLogs_*.edb with redacted SQLCipher key residues from memory",
    )
    kakao_sqlcipher_probe.add_argument("root", help="Extracted KakaoTalk folder containing chatLogs_*.edb and memory dumps")
    kakao_sqlcipher_probe.add_argument("--output", default=DefaultOutput("rapidtriage-kakaotalk-sqlcipher-probe.json"), help="JSON output path")
    kakao_sqlcipher_probe.add_argument("--sqlcipher-bin", default="sqlcipher", help="SQLCipher binary to use for temp-copy probes")
    kakao_sqlcipher_probe.add_argument("--max-keys", type=int, default=DEFAULT_MEMORY_SQLCIPHER_KEY_RESIDUE_LIMIT, help="Maximum unique SQLCipher key residues to test (0 means all)")
    kakao_sqlcipher_probe.add_argument("--max-databases", type=int, default=0, help="Maximum chatLogs databases to test (0 means all)")
    kakao_sqlcipher_probe.add_argument("--max-message-residues", type=int, default=DEFAULT_MEMORY_MESSAGE_RESIDUE_LIMIT, help="Maximum post-patch message JSON residues to collect from memory (0 means all)")
    kakao_sqlcipher_probe.add_argument("--include-message-preview", action="store_true", help="Include recovered message text previews in JSON output")
    kakao_sqlcipher_probe.add_argument("--timeout-seconds", type=float, default=2.0, help="Timeout per SQLCipher key/database/compatibility probe")
    kakao_sqlcipher_probe.add_argument("--export-opened-dir", help="Optional directory to export SQLCipher-openable EDBs as plaintext SQLite")
    kakao_sqlcipher_probe.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

    kakao_key_store = sub.add_parser(
        "kakaotalk-key-store-inspect",
        help="Inspect post-patch KakaoTalk appstate.dat wrapped-DEK key stores without exporting secrets",
        description="Inspect post-patch KakaoTalk appstate.dat wrapped-DEK key stores without exporting secrets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage kakaotalk-key-store-inspect ./KakaoTalk --output kakao-key-store.json
              rapidtriage kakaotalk-key-store-inspect ./KakaoTalk --max-memory-sources 1 --json
            """
        ),
    )
    kakao_key_store.add_argument("root", help="Extracted KakaoTalk folder containing appstate.dat and chatLogs_*.edb")
    kakao_key_store.add_argument("--output", default=DefaultOutput("rapidtriage-kakaotalk-key-store.json"), help="JSON output path")
    kakao_key_store.add_argument("--max-memory-sources", type=int, default=2, help="Maximum memory dumps to check for key-store residency (0 disables memory checks)")
    kakao_key_store.add_argument("--json", action="store_true", help="Print JSON payload to stdout")

    kakao_userdir = sub.add_parser(
        "kakaotalk-userdir-bruteforce",
        help="Find an authorized Windows KakaoTalk userId from a users/<userDir> folder name",
        description="Find an authorized Windows KakaoTalk userId from a users/<userDir> folder name",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage kakaotalk-userdir-bruteforce ./KakaoTalk --userdir-home "C:\\Users\\USER\\AppData\\Local\\Kakao\\KakaoTalk\\users" --pragma-key-hex ...
              rapidtriage kakaotalk-userdir-bruteforce ./KakaoTalk --pragma ... --start-id 1 --end-id 400000000 --chunk-size 10000000
            """
        ),
    )
    kakao_userdir.add_argument("root", help="Extracted KakaoTalk user/app-data folder to scan")
    kakao_userdir.add_argument("--output", default=DefaultOutput("rapidtriage-kakaotalk-userdir-bruteforce.json"), help="JSON output path")
    kakao_userdir.add_argument("--userdir", help="40-hex users/<userDir> folder name; inferred when omitted")
    kakao_userdir.add_argument("--userdir-home", help=r'Original Windows users path, e.g. C:\Users\USER\AppData\Local\Kakao\KakaoTalk\users')
    kakao_userdir.add_argument("--pragma", help="Authorized KakaoTalk pragma value; prefer env/file handling outside shell history")
    kakao_userdir.add_argument("--pragma-key-hex", help="Authorized 16-byte DeviceInfo pragma-generation key as hex")
    kakao_userdir.add_argument("--sys-uuid", help="Override DeviceInfo sys_uuid; otherwise NTUSER.DAT is used")
    kakao_userdir.add_argument("--hdd-model", help="Override DeviceInfo hdd_model; otherwise NTUSER.DAT is used")
    kakao_userdir.add_argument("--hdd-serial", help="Override DeviceInfo hdd_serial; otherwise NTUSER.DAT is used")
    kakao_userdir.add_argument("--start-id", type=int, default=1, help="First numeric userId to test")
    kakao_userdir.add_argument("--end-id", type=int, default=400_000_000, help="Last numeric userId to test")
    kakao_userdir.add_argument("--chunk-size", type=int, default=10_000_000, help="Range size per checkpointed native-helper run")
    kakao_userdir.add_argument("--compiler", default="cc", help="C compiler for the native CommonCrypto accelerator")
    kakao_userdir.add_argument("--openssl-bin", default="openssl", help="OpenSSL binary used for DeviceInfo pragma derivation checks")
    kakao_userdir.add_argument("--json", action="store_true", help="Print JSON payload to stdout")
