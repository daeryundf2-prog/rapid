"""``rapidtriage audit-verify <file> [--json]``: check an export audit chain (R8 T-359).

Calls the T-029 check (``core.audit.verify_audit_chain``). Exit 0 when the chain is intact
(lines written before the chain existed are counted as ``pre_chain_lines``, not broken), exit 3
with ``first_broken_line`` when a line was changed, removed or cannot be read, or when the file
holds no audit record at all, exit 4 when the file is missing or cannot be read (r8-contracts D.8).
``--expect-last <sha256>`` compares the last ``record_sha256`` with a value kept elsewhere; without
it the output lists what the check cannot prove (``not_proven``: tail deletion, whole rewrite).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..core.audit import verify_audit_chain

__all__ = ["HANDLERS", "handle_audit_verify"]

EXIT_INTACT = 0
EXIT_BROKEN = 3
EXIT_MISSING = 4


def handle_audit_verify(args: argparse.Namespace, parser: argparse.ArgumentParser, rule_set) -> int:
    path = Path(args.audit_file).expanduser()
    if not path.is_file():
        return _missing(args, path, "감사 파일을 찾지 못했습니다")
    try:
        result = verify_audit_chain(path, expected_last_sha256=getattr(args, "expect_last", None))
    except OSError:
        return _missing(args, path, "감사 파일을 읽지 못했습니다")
    report = {"command": "audit-verify", **result}
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"감사 사슬: {path}")
        print(f"기록 {report['records']}줄 · 사슬 {report['chained']}줄 · {report['pre_chain_label']}")
        if report["ok"]:
            print("결과: 온전함")
        elif report["records"] == 0 and report["first_broken_line"] == 0:
            print("결과: 확인 불가 — 감사 기록이 0줄")
        else:
            print(f"결과: 깨짐 — 첫 번째 깨진 줄 {report['first_broken_line']}")
            for item in report["broken_lines"]:
                where = "파일" if item["line"] == 0 else f"{item['line']}번째 줄"
                print(f"  {where}: {item['reason']}")
        if report.get("last_record_sha256"):
            print(f"마지막 기록 해시: {report['last_record_sha256']}")
        for limit in report.get("not_proven") or []:
            print(f"알 수 없는 것: {limit}")
    return EXIT_INTACT if report["ok"] else EXIT_BROKEN


def _missing(args: argparse.Namespace, path: Path, message: str) -> int:
    payload = {"command": "audit-verify", "path": str(path), "ok": False, "error": message}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"{message}: {path}")
    return EXIT_MISSING


HANDLERS = {"audit-verify": handle_audit_verify}
