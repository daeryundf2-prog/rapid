"""Developer check: ``python -m tests.triage_cases.check <module> [...]`` runs those modules' cases and lists mismatches."""

from __future__ import annotations

import importlib
import sys

from rapidtriage.core.triage_rules import RULE_CLASSES

from . import run_case


def check(module_name: str) -> int:
    module = importlib.import_module(f"tests.triage_cases.{module_name}")
    family_module = importlib.import_module(f"rapidtriage.core.triage_rules.{module_name}")
    expected_rules = sorted(rule_id for rule_id, cls in RULE_CLASSES.items() if cls.__module__ == family_module.__name__)
    cases = getattr(module, "CASES", {})
    failures = 0
    missing = [rule_id for rule_id in expected_rules if rule_id not in cases or set(cases[rule_id]) != {"positive", "negative"}]
    for rule_id in missing:
        print(f"MISSING {rule_id}: needs positive + negative")
        failures += 1
    for rule_id, pair in sorted(cases.items()):
        for name, case in sorted(pair.items()):
            flagged, expected, summary = run_case(case, rule_id)
            errors = summary.get("rule_errors") or {}
            if rule_id in errors:
                print(f"ERROR {rule_id} {name}: {errors[rule_id]}")
                failures += 1
            elif name == "positive" and not expected:
                print(f"BAD {rule_id} positive: flagged list is empty")
                failures += 1
            elif name == "negative" and expected:
                print(f"BAD {rule_id} negative: flagged list must be empty")
                failures += 1
            elif flagged != expected:
                print(f"FAIL {rule_id} {name}: flagged={sorted(flagged)} expected={sorted(expected)}")
                failures += 1
            else:
                print(f"ok   {rule_id} {name}")
    return failures


if __name__ == "__main__":
    total = sum(check(name) for name in sys.argv[1:])
    print(f"{total} problem(s)")
    sys.exit(1 if total else 0)
