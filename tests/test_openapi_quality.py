"""OpenAPI quality ratchet (T-163).

Builds the API's OpenAPI document in-process (``create_app`` with a dummy
token, no server) and checks every operation for four gaps:

* ``missing_tags`` - no ``tags``.
* ``missing_summary_or_description`` - neither ``summary`` nor ``description``.
  (FastAPI fills ``summary`` from the handler name, so this one is rare.)
* ``missing_description`` - no ``description`` (docstring or decorator arg).
* ``empty_2xx_schema`` - the success response has no schema, or a schema
  with no structure (only ``title``), or no 2xx response at all. 204 without
  content is fine.
* ``undeclared_error_responses`` - no 4xx/5xx/``default`` response declared
  beyond FastAPI's automatic 422.

``tests/fixtures/openapi-quality-baseline.json`` lists the operations allowed
to have each gap today. The test fails when a count grows or when an operation
not in that list (a new route, or a fixed one that regressed) has a gap. When
gaps are fixed the test passes and prints a hint; lower the baseline with::

    python tests/test_openapi_quality.py --lower-baseline

That command only drops entries; it never adds an operation.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HAS_FASTAPI = True
try:
    import fastapi  # noqa: F401
except ModuleNotFoundError as exc:
    if exc.name == "fastapi":
        HAS_FASTAPI = False
    else:
        raise

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO_ROOT / "tests" / "fixtures" / "openapi-quality-baseline.json"
DUMMY_TOKEN = "openapi-quality-ratchet"
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "trace")
CATEGORIES = (
    "missing_tags",
    "missing_summary_or_description",
    "missing_description",
    "empty_2xx_schema",
    "undeclared_error_responses",
)
_STRUCTURAL_KEYS = {
    "$ref", "type", "properties", "items", "anyOf", "oneOf", "allOf",
    "enum", "const", "additionalProperties",
}


def build_spec(app=None) -> dict:
    if app is None:
        from rapidtriage.api.app import create_app

        app = create_app(auth_token=DUMMY_TOKEN)
    return app.openapi()


def _has_empty_2xx(op: dict) -> bool:
    success = [(code, r) for code, r in op.get("responses", {}).items() if code.startswith("2")]
    if not success:
        return True
    for code, response in success:
        content = response.get("content") or {}
        if not content:
            if code != "204":
                return True
            continue
        for media in content.values():
            schema = media.get("schema") or {}
            if not _STRUCTURAL_KEYS & schema.keys():
                return True
    return False


def _declares_errors(op: dict) -> bool:
    return any(
        code == "default" or (code[:1] in {"4", "5"} and code != "422")
        for code in op.get("responses", {})
    )


def measure(spec: dict) -> tuple[int, dict[str, list[str]]]:
    """Return (operation count, {category: sorted ["METHOD /path", ...]})."""
    gaps: dict[str, list[str]] = {name: [] for name in CATEGORIES}
    total = 0
    for path, item in spec.get("paths", {}).items():
        for method in HTTP_METHODS:
            op = item.get(method)
            if op is None:
                continue
            total += 1
            key = f"{method.upper()} {path}"
            if not op.get("tags"):
                gaps["missing_tags"].append(key)
            if not op.get("summary") and not op.get("description"):
                gaps["missing_summary_or_description"].append(key)
            if not op.get("description"):
                gaps["missing_description"].append(key)
            if _has_empty_2xx(op):
                gaps["empty_2xx_schema"].append(key)
            if not _declares_errors(op):
                gaps["undeclared_error_responses"].append(key)
    return total, {name: sorted(keys) for name, keys in gaps.items()}


def load_baseline() -> dict:
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def check(baseline: dict, gaps: dict[str, list[str]]) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    hints: list[str] = []
    for name in CATEGORIES:
        allowed = set(baseline["gaps"].get(name, []))
        current = set(gaps[name])
        recorded = baseline["counts"].get(name, 0)
        if len(current) > recorded:
            failures.append(f"{name} grew to {len(current)}; baseline {recorded}")
        failures.extend(
            f"{name}: {key} (not in baseline; fix the route decorator)"
            for key in sorted(current - allowed)
        )
        fixed = sorted(allowed - current)
        if fixed:
            hints.append(f"{name}: {len(fixed)} fixed, now {len(current)} (baseline {recorded})")
    return failures, hints


def _print_hints(hints: list[str]) -> None:
    if hints:
        print(
            "\nOpenAPI quality ratchet can tighten; run "
            "`python tests/test_openapi_quality.py --lower-baseline`:",
            file=sys.stderr,
        )
        for hint in hints:
            print(f"  - {hint}", file=sys.stderr)


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for the OpenAPI quality ratchet")
class OpenApiQualityRatchetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = load_baseline()
        cls.total, cls.gaps = measure(build_spec())

    def test_gaps_do_not_grow(self) -> None:
        failures, hints = check(self.baseline, self.gaps)
        _print_hints(hints)
        self.assertEqual(failures, [], "\n".join(failures))

    def test_baseline_is_consistent(self) -> None:
        for name in CATEGORIES:
            listed = self.baseline["gaps"][name]
            self.assertEqual(self.baseline["counts"][name], len(listed), name)
            self.assertEqual(listed, sorted(set(listed)), name)

    def test_new_untagged_route_fails(self) -> None:
        from rapidtriage.api.app import create_app

        app = create_app(auth_token=DUMMY_TOKEN)

        @app.get("/api/__openapi_ratchet_probe")
        def probe():  # pragma: no cover - never served
            return {}

        app.openapi_schema = None
        _, gaps = measure(build_spec(app))
        failures, _ = check(self.baseline, gaps)
        probe_failures = [f for f in failures if "__openapi_ratchet_probe" in f]
        self.assertTrue(any(f.startswith("missing_tags:") for f in probe_failures))
        self.assertTrue(any(f.startswith("missing_description:") for f in probe_failures))
        self.assertTrue(any(f.startswith("empty_2xx_schema:") for f in probe_failures))

    def test_checker_rules(self) -> None:
        spec = {
            "paths": {
                "/a": {
                    "get": {
                        "tags": ["t"],
                        "summary": "s",
                        "description": "d",
                        "responses": {
                            "200": {"content": {"application/json": {"schema": {"$ref": "#/x"}}}},
                            "404": {"description": "nf"},
                        },
                    },
                    "delete": {"responses": {"204": {"description": "gone"}, "422": {}}},
                },
                "/b": {"post": {"responses": {"200": {"content": {"application/json": {"schema": {"title": "R"}}}}}}},
            }
        }
        total, gaps = measure(spec)
        self.assertEqual(total, 3)
        self.assertEqual(gaps["missing_tags"], ["DELETE /a", "POST /b"])
        self.assertEqual(gaps["missing_summary_or_description"], ["DELETE /a", "POST /b"])
        self.assertEqual(gaps["empty_2xx_schema"], ["POST /b"])
        self.assertEqual(gaps["undeclared_error_responses"], ["DELETE /a", "POST /b"])
        baseline = {"counts": {n: len(k) for n, k in gaps.items()}, "gaps": gaps}
        self.assertEqual(check(baseline, gaps), ([], []))
        shrunk = {n: [] for n in CATEGORIES}
        failures, hints = check(baseline, shrunk)
        self.assertEqual(failures, [])
        self.assertEqual(len(hints), 5)


def write_baseline(total: int, gaps: dict[str, list[str]]) -> None:
    data = {
        "operations": total,
        "counts": {name: len(gaps[name]) for name in CATEGORIES},
        "gaps": {name: gaps[name] for name in CATEGORIES},
    }
    BASELINE_PATH.write_bytes((json.dumps(data, indent=2) + "\n").encode("utf-8"))


def lower_baseline() -> None:
    baseline = load_baseline()
    total, gaps = measure(build_spec())
    kept = {
        name: sorted(set(baseline["gaps"].get(name, [])) & set(gaps[name])) for name in CATEGORIES
    }
    write_baseline(total, kept)
    print(f"lowered {BASELINE_PATH.relative_to(REPO_ROOT).as_posix()}")


if __name__ == "__main__":
    sys.path.insert(0, str(REPO_ROOT))
    if sys.argv[1:] == ["--lower-baseline"]:
        lower_baseline()
    else:
        unittest.main()
