"""``rapidtriage audit-verify <file> [--json]``: check an export audit chain (R8 T-359).

Calls the T-029 check (``core.audit.verify_audit_chain``). Exit 0 when the chain is intact
(lines written before the chain existed are counted as ``pre_chain_lines``, not broken), exit 3
with ``first_broken_line`` when a line was changed, removed or cannot be read, exit 4 when the
file is missing (r8-contracts D.8).
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
        payload = {"command": "audit-verify", "path": str(path), "ok": False, "error": "감사 파일을 찾지 못했습니다"}
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"감사 파일을 찾지 못했습니다: {path}")
        return EXIT_MISSING
    report = {"command": "audit-verify", **verify_audit_chain(path)}
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"감사 사슬: {path}")
        print(f"기록 {report['records']}줄 · 사슬 {report['chained']}줄 · {report['pre_chain_label']}")
        if report["ok"]:
            print("결과: 온전함")
        else:
            print(f"결과: 깨짐 — 첫 번째 깨진 줄 {report['first_broken_line']}")
            for item in report["broken_lines"]:
                print(f"  {item['line']}번째 줄: {item['reason']}")
    return EXIT_INTACT if report["ok"] else EXIT_BROKEN


HANDLERS = {"audit-verify": handle_audit_verify}
