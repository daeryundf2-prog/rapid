#!/usr/bin/env python3
"""Synthetic rich run-result fixture for R8 CI checks (T-004, GAP-057, IS-121 CI only).

Writes an importable RapidTriage result folder (``rapidtriage-run-summary.json`` plus one
``artifacts/rapidtriage-artifacts-<kind>.json`` summary and ``.jsonl`` row stream per kind)
built ONLY from invented values. Every Tier 1 card (documents, email, messenger, web, exfil
paths/USB, program execution, deleted/recovered, accounts/logon, AI usage) gets rows with
known counts, recorded in ``r8-fixture-manifest.json`` (and committed as
``tests/fixtures/r8_rich/manifest.json``) so QA can assert exact numbers.

Deliberate oddities, also counted in the manifest:
* planted FAKE secrets/identifiers (documentation example keys, invalid-checksum resident
  numbers on impossible dates, a published test card number, reserved ``example.*`` mail,
  RFC 5737 IP addresses, 010-0000-xxxx phones) — ``scripts/r8-log-scan.py`` must report
  exactly ``expected_log_scan`` hits and nothing else (anything more is a real-looking leak);
* rows whose time is the acquisition copy time (``timestamp_is_copy_time``);
* one ``failed_isolated`` collection step;
* one big kind (``windows-filesystem``) to drive a scan-budget stop
  (``RAPIDTRIAGE_SEARCH_SCAN_BUDGET_SECONDS`` small).

Paths are evidence-relative (``\\Users\\synth-user01\\...``, no drive letter) and every
output path in the summary is relative, so the same seed gives byte-identical folders
wherever they are written. SYN is a CI gate only: never completion evidence (IS-121).

  python scripts/make-r8-fixture.py --output <tmp>/r8 --seed 8
  python scripts/make-r8-fixture.py --output <tmp>/r8 --seed 8 --check      # vs committed manifest
  python scripts/make-r8-fixture.py --output <tmp>/r8 --seed 8 --write-manifest
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import shutil
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
COMMITTED_MANIFEST = REPO / "tests" / "fixtures" / "r8_rich" / "manifest.json"
SCHEMA = "r8-rich-fixture/1"
GENERATOR_VERSION = "1"
GENERATED_AT = "2026-03-09T01:30:00+00:00"
ACQUISITION_COPY_TIME = "2026-03-09T01:00:00+00:00"
WINDOW_START = datetime(2026, 3, 2, 0, 0, tzinfo=timezone.utc)
WINDOW_SECONDS = 5 * 24 * 3600
BIG_KIND_ROWS = 40_000
MANIFEST_NAME = "r8-fixture-manifest.json"
USERS = ("synth-user01", "synth-user02")
PEOPLE = ("합성인물01", "합성인물02", "합성인물03", "Synth Person 04")
MAIL_DOMAINS = ("example.com", "example.org", "example.net")
IPS = ("192.0.2.10", "198.51.100.23", "203.0.113.77")
SITES = ("https://www.example.com/", "https://docs.example.org/report", "https://share.example.net/f/")

# Planted fake values: label -> (value, r8-log-scan pattern it must hit or None).
# Keys are public documentation examples or assembled obvious fakes; never real.
FAKES: dict[str, tuple[str, str | None]] = {
    "aws_doc_example_key": ("AKIA" + "IOSFODNN7EXAMPLE", "aws_access_key"),
    "openai_style_fake_key": ("sk-" + "SYNTHFAKE" + "x" * 16 + "r8", "openai_style_key"),
    "github_style_fake_token": ("ghp_" + "SYNTHFAKE" + "x" * 27 + "r8", "github_token"),
    "password_assignment_fake": ("password=" + "SYNTH-FAKE-0001", "secret_assignment"),
    "luhn_valid_published_test_card": ("4111 1111 1111 1111", "card_number"),
    "luhn_invalid_card": ("4111-1111-1111-1112", None),
}

# Tier 1 card -> list of (kind, provider, artifact_type, rows).
CARDS: dict[str, list[tuple[str, str, str, int]]] = {
    "documents": [
        ("generic-documents", "generic-documents", "office-document", 24),
        ("recent-files", "windows-recent-files", "lnk-file", 12),
        ("recent-files", "windows-recent-files", "jumplist-entry", 6),
    ],
    "email": [("email", "email-artifacts", "email-message", 18)],
    "messenger": [
        ("kakaotalk-windows", "kakaotalk-windows-correlation", "kakaotalk-message", 30),
        ("mobile-export", "mobile-export-artifacts", "mobile-message", 6),
    ],
    "web": [
        ("browser", "windows-browser-artifacts", "browser-history", 40),
        ("browser", "windows-browser-artifacts", "browser-download", 8),
    ],
    "exfil": [
        ("windows-registry", "windows-registry", "windows-usb-device", 3),
        ("windows-system", "windows-system-artifacts", "usb-setupapi-device-install-candidate", 3),
        ("cloud-sync", "cloud-sync-clients", "cloud-sync-file", 10),
    ],
    "execution": [
        ("windows-prefetch", "windows-prefetch", "prefetch-file", 15),
        ("windows-execution", "windows-execution", "amcache-entry", 10),
    ],
    "deleted": [
        ("windows-filesystem", "windows-filesystem", "recycle-bin-entry", 6),
        ("windows-filesystem", "windows-filesystem", "usn-record", 10),
        ("windows-filesystem", "windows-filesystem", "deleted-mft-entry", 8),
    ],
    "accounts_logon": [
        ("windows-os-account", "windows-os-account", "windows-user-profile", 2),
        ("eventlog", "windows-eventlog", "logon-success", 20),
        ("eventlog", "windows-eventlog", "logon-failure", 5),
    ],
    "ai_usage": [
        ("ai-agent", "ai-agents", "ai-agent-session", 4),
        ("ai-agent", "ai-agents", "ai-agent-message", 16),
        ("ai-agent", "ai-agents", "ai-credential-presence", 2),
    ],
}
BIG = ("windows-filesystem", "windows-filesystem", "mft-entry", BIG_KIND_ROWS)
FAILED_ISOLATED = ("windows-shellbags", "windows-shellbags")
COPY_TIME_ROWS = {"office-document": 4, "lnk-file": 2}
DIGIT_RUN = re.compile(r"\d{13}")


class Gen:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.planted: Counter[str] = Counter()

    def plant(self, label: str) -> str:
        self.planted[label] += 1
        return FAKES[label][0]

    def ts(self) -> str:
        moment = WINDOW_START + timedelta(seconds=self.rng.randrange(WINDOW_SECONDS))
        return moment.isoformat()

    def sha256(self) -> str:
        while True:  # no 13+ digit runs: they would look like resident/card numbers
            value = f"{self.rng.getrandbits(256):064x}"
            if not DIGIT_RUN.search(value):
                return value

    def user(self) -> str:
        return self.rng.choice(USERS)

    def mail(self) -> str:
        return f"synth.{self.rng.randrange(1, 40):02d}@{self.rng.choice(MAIL_DOMAINS)}"


def fake_rrn(gen: Gen, n: int) -> str:
    """Resident-number SHAPE on an impossible date (Feb 30/31) with a wrong check digit."""
    body = f"9902{30 + n % 2}{1 + n % 4}{n % 1000:03d}00"
    weights = (2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5)
    check = (11 - sum(int(d) * w for d, w in zip(body, weights)) % 11) % 10
    gen.planted["invalid_rrn_impossible_date"] += 1
    return f"{body[:6]}-{body[6:]}{(check + 1) % 10}"


def details_for(gen: Gen, atype: str, i: int) -> tuple[str, dict[str, object]]:
    user = gen.user()
    home = f"\\Users\\{user}"
    t = gen.ts()
    d: dict[str, object] = {"timestamp": t, "user_name": user}
    if atype == "office-document":
        path = f"{home}\\Documents\\합성_보고서_{i:03d}.docx"
        d.update(title=f"합성 문서 {i:03d}", author=PEOPLE[i % len(PEOPLE)], size=1024 + i * 37)
        if i == 0:
            d["body_preview"] = f"주민번호 {fake_rrn(gen, i)} 카드 {gen.plant('luhn_invalid_card')}"
    elif atype in ("lnk-file", "jumplist-entry"):
        path = f"{home}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\합성_{i:03d}.lnk"
        d.update(target_path=f"E:\\반출\\합성_{i:03d}.xlsx", volume_label="SYNTH-USB")
    elif atype == "email-message":
        path = f"{home}\\Documents\\Outlook\\synth.pst"
        d.update(subject=f"합성 메일 {i:02d}", sender=gen.mail(), recipients=[gen.mail(), gen.mail()],
                 client_ip=gen.rng.choice(IPS), phone=f"010-0000-{i:04d}")
        if i == 1:
            d["body_preview"] = f"결제 테스트 카드 {gen.plant('luhn_valid_published_test_card')}"
        if i == 2:
            d["body_preview"] = f"신원 확인 {fake_rrn(gen, i)}"
    elif atype in ("kakaotalk-message", "mobile-message"):
        path = f"{home}\\AppData\\Local\\Kakao\\KakaoTalk\\users\\synth\\chat_data\\synth.edb"
        d.update(chat_room=f"합성 대화방 {i % 3}", sender=PEOPLE[i % len(PEOPLE)],
                 message=f"합성 메시지 {i:03d}", phone=f"010-0000-{100 + i:04d}")
        if atype == "kakaotalk-message" and i == 3:
            d["message"] = f"접속 정보 {gen.plant('password_assignment_fake')}"
    elif atype in ("browser-history", "browser-download"):
        path = f"{home}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
        d.update(url=f"{gen.rng.choice(SITES)}{i}", title=f"합성 페이지 {i}", browser="Chrome",
                 visit_count=1 + i % 5)
        if atype == "browser-download":
            d["target_path"] = f"{home}\\Downloads\\합성_다운로드_{i:02d}.zip"
    elif atype in ("windows-usb-device", "usb-setupapi-device-install-candidate"):
        path = "\\Windows\\System32\\config\\SYSTEM" if atype == "windows-usb-device" else "\\Windows\\INF\\setupapi.dev.log"
        d.update(vendor="SynthVendor", product=f"SYNTH-USB-{i}", serial=f"SYNTHSERIAL{i:04d}",
                 drive_letter="E:", volume_label="SYNTH-USB")
    elif atype == "cloud-sync-file":
        path = f"{home}\\AppData\\Local\\Microsoft\\OneDrive\\logs\\synth.odl"
        d.update(service="OneDrive", file_name=f"합성_공유_{i:02d}.pdf", direction="upload",
                 account=gen.mail())
    elif atype == "prefetch-file":
        exe = ("SYNTHTOOL.EXE", "7ZSYNTH.EXE", "NOTEPAD.EXE")[i % 3]
        path = f"\\Windows\\Prefetch\\{exe}-{i:08X}.pf"
        d.update(executable=exe, run_count=1 + i, last_run_times=[t])
    elif atype == "amcache-entry":
        path = "\\Windows\\AppCompat\\Programs\\Amcache.hve"
        d.update(program_path=f"{home}\\Downloads\\synthtool_{i}.exe", sha1=gen.sha256()[:40], publisher="Synth Corp")
    elif atype == "recycle-bin-entry":
        path = f"\\$Recycle.Bin\\S-1-5-21-0-0-0-1001\\$I{i:06d}.docx"
        d.update(original_path=f"{home}\\Documents\\합성_삭제_{i:02d}.docx", deleted_at=t, size=2048 + i)
    elif atype == "usn-record":
        path = "\\$Extend\\$UsnJrnl:$J"
        d.update(file_name=f"합성_삭제_{i:02d}.tmp", reason="FILE_DELETE|CLOSE", usn=1000 + i)
    elif atype == "deleted-mft-entry":
        path = f"{home}\\Desktop\\합성_복구_{i:02d}.hwp"
        d.update(deleted=True, recoverable=i % 2 == 0, mft_entry=5000 + i)
    elif atype == "windows-user-profile":
        path = home if i < len(USERS) else f"\\Users\\synth-user{i + 1:02d}"
        d.update(profile_path=path, user_name=USERS[i % len(USERS)], sid=f"S-1-5-21-0-0-0-{1001 + i}")
    elif atype in ("logon-success", "logon-failure"):
        path = "\\Windows\\System32\\winevt\\Logs\\Security.evtx"
        d.update(event_id=4624 if atype == "logon-success" else 4625, logon_type=(2, 3, 10)[i % 3],
                 source_ip=gen.rng.choice(IPS), target_user=user)
    elif atype == "ai-agent-session":
        path = f"{home}\\.claude\\projects\\synth-proj\\sess-{i}.jsonl"
        d.update(service="Claude Code", session_id=f"synth-session-{i}", model="synth-model")
    elif atype == "ai-agent-message":
        path = f"{home}\\.claude\\projects\\synth-proj\\sess-{i % 4}.jsonl"
        d.update(service="Claude Code", role=("user", "assistant")[i % 2], text=f"합성 질문·답변 {i:02d}")
        if i == 5:
            d["text"] = f"이 키로 호출해 줘 {gen.plant('openai_style_fake_key')}"
        if i == 6:
            d["text"] = f"저장소 접근값 {gen.plant('github_style_fake_token')}"
    elif atype == "ai-credential-presence":
        path = f"{home}\\.aws\\credentials" if i == 0 else f"{home}\\.config\\synth-ai\\auth.json"
        d.update(service="AWS CLI" if i == 0 else "Synth AI", credential_preview=gen.plant("aws_doc_example_key") if i == 0 else "redacted")
    elif atype == "mft-entry":
        path = f"{home}\\AppData\\Local\\Temp\\synth_{i:05d}.dat"
        d.update(mft_entry=100_000 + i, size=i % 9973, deleted=False)
    else:  # pragma: no cover - guarded by CARDS
        raise ValueError(atype)
    if atype != "mft-entry":
        d["sha256"] = gen.sha256()
    return path, d


def build_rows(gen: Gen) -> tuple[dict[str, list[dict]], int]:
    rows: dict[str, list[dict]] = {}
    copy_rows = 0
    specs = [s for card in CARDS.values() for s in card] + [BIG]
    for kind, provider, atype, count in specs:
        for i in range(count):
            path, details = details_for(gen, atype, i)
            if i < COPY_TIME_ROWS.get(atype, 0):
                details["timestamp"] = ACQUISITION_COPY_TIME
                details["timestamp_is_copy_time"] = True
                copy_rows += 1
            details["source_path"] = path
            rows.setdefault(kind, []).append(
                {"provider": provider, "artifact_type": atype, "path": path, "supported": True, "details": details}
            )
    return rows, copy_rows


def dump(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")


def write_kind(out: Path, kind: str, provider: str, rows: list[dict], status: str, errors: int) -> str:
    rel = f"artifacts/rapidtriage-artifacts-{kind}.json"
    jsonl = out / rel.replace(".json", ".jsonl")
    jsonl.parent.mkdir(parents=True, exist_ok=True)
    with jsonl.open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    types = Counter(r["artifact_type"] for r in rows)
    dump(out / rel, {
        "command": "artifacts", "kind": kind, "generated_at": GENERATED_AT, "root": "synthetic/r8-rich",
        "provider": {"name": provider, "description": "SYNTHETIC r8 fixture", "target_platform": "windows", "supported": True},
        "summary": {"artifact_count": len(rows), "artifact_type_counts": dict(sorted(types.items())),
                    "parser_error_count": errors, "collection_status": status},
        "parser_errors": [{"error": "synthetic isolated parser failure"}] * errors,
        "artifacts": [], "record_count": len(rows),
        "records_file": jsonl.name, "records_format": "jsonl",
    })
    return rel


def generate(out: Path, seed: int) -> dict:
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    gen = Gen(seed)
    rows, copy_rows = build_rows(gen)
    providers = {k: p for card in CARDS.values() for k, p, _t, _n in card}
    outputs: dict[str, str] = {"summary": "rapidtriage-run-summary.json"}
    steps: list[dict] = []
    for kind in sorted(rows):
        outputs[f"artifacts_{kind}"] = write_kind(out, kind, providers[kind], rows[kind], "completed", 0)
        steps.append({"name": f"artifacts-{kind}", "status": "completed", "output": outputs[f"artifacts_{kind}"],
                      "artifact_count": len(rows[kind]), "parser_error_count": 0, "warning_level": "none",
                      "warning_messages": [], "reused": False})
    fkind, fprov = FAILED_ISOLATED
    outputs[f"artifacts_{fkind}"] = write_kind(out, fkind, fprov, [], "failed-isolated", 1)
    steps.append({"name": f"artifacts-{fkind}", "status": "failed_isolated", "output": outputs[f"artifacts_{fkind}"],
                  "artifact_count": 0, "parser_error_count": 1, "warning_level": "warning",
                  "warning_messages": ["합성 픽스처: 격리된 파서 실패 1건"], "reused": False})
    kind_counts = {k: len(v) for k, v in sorted(rows.items())}
    dump(out / "rapidtriage-run-summary.json", {
        "command": "run", "mode": "seizure", "generated_at": GENERATED_AT, "root": "synthetic/r8-rich",
        "output_dir": ".", "input_kind": "folder", "synthetic_fixture": SCHEMA,
        "acquisition": {"copy_time": ACQUISITION_COPY_TIME},
        "safety": {"read_only": True, "dry_run": False}, "outputs": outputs, "steps": steps,
        "summary": {"provider_artifact_counts": {providers.get(k, fprov): n for k, n in kind_counts.items()} | {fprov: 0}},
        "warnings": [], "disclosures": [],
    })
    planted = dict(sorted(gen.planted.items()))
    expected_scan: Counter[str] = Counter()
    for label, n in planted.items():
        pattern = "kr_resident_number" if label == "invalid_rrn_impossible_date" else FAKES[label][1]
        if pattern:
            expected_scan[pattern] += n
    files = sorted(p for p in out.rglob("*") if p.is_file())
    digest = hashlib.sha256()
    for p in files:
        digest.update(p.relative_to(out).as_posix().encode() + b"\0" + hashlib.sha256(p.read_bytes()).digest())
    cards = {
        card: {"rows": sum(n for *_x, n in spec),
               "by_kind_type": {f"{k}/{t}": n for k, _p, t, n in spec}}
        for card, spec in CARDS.items()
    }
    manifest = {
        "schema": SCHEMA, "generator_version": GENERATOR_VERSION, "seed": seed,
        "synthetic_only": True, "release_evidence": False,
        "tier1_cards": cards,
        "kind_rows": kind_counts,
        "copy_time_rows": copy_rows, "acquisition_copy_time": ACQUISITION_COPY_TIME,
        "failed_isolated_step": f"artifacts-{fkind}",
        "budget_trigger": {"kind": BIG[0], "artifact_type": BIG[2], "rows": BIG[3],
                           "env": {"RAPIDTRIAGE_SEARCH_SCAN_BUDGET_SECONDS": "0.01"}},
        "planted_fakes": planted,
        "expected_log_scan": {"total_hits": sum(expected_scan.values()), "by_pattern": dict(sorted(expected_scan.items()))},
        "output": {"file_count": len(files), "total_bytes": sum(p.stat().st_size for p in files),
                   "tree_sha256": digest.hexdigest()},
    }
    dump(out / MANIFEST_NAME, manifest)
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--output", type=Path, required=True, help="result folder to (re)create")
    ap.add_argument("--seed", type=int, default=8)
    ap.add_argument("--check", action="store_true", help="fail when the manifest differs from the committed one")
    ap.add_argument("--write-manifest", action="store_true", help="update tests/fixtures/r8_rich/manifest.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if args.output.resolve() == REPO or REPO in args.output.resolve().parents:
        raise SystemExit("--output must be outside the repository (no generated data in Git)")
    started = time.perf_counter()
    manifest = generate(args.output, args.seed)
    elapsed = time.perf_counter() - started
    if args.write_manifest:
        dump(COMMITTED_MANIFEST, manifest)
    if args.json:
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
    else:
        rows = sum(manifest["kind_rows"].values())
        print(f"r8 fixture seed {args.seed}: {rows} rows, {manifest['output']['total_bytes']} bytes, "
              f"{elapsed:.1f} s, tree {manifest['output']['tree_sha256'][:16]}")
    if args.check:
        committed = json.loads(COMMITTED_MANIFEST.read_text(encoding="utf-8"))
        if committed != manifest:
            print("manifest differs from tests/fixtures/r8_rich/manifest.json", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
