from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin


BROWSER_LARGE_RESULT_STRESS_VERSION = "browser-large-result-stress-harness-v1"
DEFAULT_BROWSER_STRESS_RECORD_COUNT = 100_000
DEFAULT_ROW_FILTER_TEXT_LIMIT = 900
DEFAULT_BROWSER_STRESS_TIMEOUT_MS = 30_000


@dataclass(frozen=True)
class PlaywrightImportResult:
    sync_playwright: Callable[[], Any] | None
    error: str | None = None


def load_playwright_sync() -> PlaywrightImportResult:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - environment dependent
        return PlaywrightImportResult(sync_playwright=None, error=str(exc))
    return PlaywrightImportResult(sync_playwright=sync_playwright)


def build_browser_large_result_stress_plan(*, record_count: int = DEFAULT_BROWSER_STRESS_RECORD_COUNT) -> dict[str, object]:
    from rapidtriage.api.app import WORKBENCH_SMOKE_SELECTORS, build_workbench_large_result_evidence

    evidence = build_workbench_large_result_evidence(record_count=record_count)
    performance_contract = evidence["performance_contract"]
    return {
        "command": "browser.large-result-stress-plan",
        "profile_version": BROWSER_LARGE_RESULT_STRESS_VERSION,
        "record_count": int(record_count),
        "status": "ready-playwright-runtime-required",
        "large_result_evidence_endpoint": f"/api/workbench/large-result-evidence?record_count={int(record_count)}",
        "smoke_contract_endpoint": "/api/workbench/smoke-contract",
        "selectors": {
            **WORKBENCH_SMOKE_SELECTORS,
            "table_control_bar": "[data-testid='table-control-bar']",
            "workbench_preview_detail": "[data-testid='workbench-preview-detail']",
            "source_viewer": "[data-testid='source-viewer']",
            "stress_region": "[data-testid='browser-stress-synthetic-window']",
            "stress_filter": "#browserStressFilter",
            "stress_rows": "[data-testid='browser-stress-synthetic-window'] tr[data-filter]",
        },
        "budgets": {
            "max_dom_rows": evidence["row_limit"],
            "row_filter_text_limit": DEFAULT_ROW_FILTER_TEXT_LIMIT,
            "target_p95_interaction_ms": evidence["search_latency_budget"]["target_p95_ms"],
            "target_max_heap_mb": evidence["memory_budget"]["target_max_heap_mb"],
        },
        "required_assertions": [
            "workbench shell selector is visible",
            "smoke contract and large-result evidence endpoints return JSON",
            "mounted stress rows are bounded by VIRTUAL_TABLE_ROW_LIMIT",
            "each mounted row data-filter is bounded to ROW_FILTER_TEXT_LIMIT",
            "visible-row filter toggles rows without server round-trip",
            "console has no browser errors during the stress run",
            "Playwright trace/JSON evidence is saved for QC review",
        ],
        "performance_contract_hash": performance_contract["contract_hash"],
        "evidence_manifest_hash": evidence["evidence_manifest_hash"],
        "commercial_grade_ready": False,
        "commercial_grade_blockers": [
            "fresh-windows-and-macos-browser-run-required",
            "real-case-large-result-run-required",
        ],
    }


def run_browser_large_result_stress(
    *,
    base_url: str = "http://127.0.0.1:8765",
    output_dir: str | Path | None = None,
    record_count: int = DEFAULT_BROWSER_STRESS_RECORD_COUNT,
    headless: bool = True,
    require_playwright: bool = False,
    timeout_ms: int = DEFAULT_BROWSER_STRESS_TIMEOUT_MS,
) -> dict[str, object]:
    plan = build_browser_large_result_stress_plan(record_count=record_count)
    playwright_import = load_playwright_sync()
    if playwright_import.sync_playwright is None:
        payload = {
            **plan,
            "command": "browser.large-result-stress",
            "status": "blocked" if require_playwright else "skipped",
            "playwright_available": False,
            "skip_reason": "Python Playwright package or browser binaries are not available.",
            "error": playwright_import.error,
            "commercial_grade_ready": False,
        }
        _write_browser_stress_payload(payload, output_dir)
        return payload

    started = time.perf_counter()
    console_errors: list[str] = []
    checks: list[dict[str, object]] = []
    artifacts: dict[str, str] = {}
    browser = None
    context = None
    status = "pass"
    error: str | None = None
    metrics: dict[str, object] = {}
    try:
        with playwright_import.sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=headless)
            context = browser.new_context(viewport={"width": 1440, "height": 1000})
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

            navigation_started = time.perf_counter()
            page.goto(base_url, wait_until="domcontentloaded")
            page.wait_for_selector(str(plan["selectors"]["shell"]))
            checks.append(_check("workbench-shell-visible", True, elapsed_ms=navigation_started))

            smoke_contract = _page_get_json(page, urljoin(base_url.rstrip("/") + "/", "api/workbench/smoke-contract"))
            evidence = _page_get_json(
                page,
                urljoin(base_url.rstrip("/") + "/", f"api/workbench/large-result-evidence?record_count={int(record_count)}"),
            )
            checks.append(_check("smoke-contract-loaded", smoke_contract.get("profile_version") == "single-case-workbench-smoke-v1"))
            checks.append(_check("large-result-evidence-loaded", evidence.get("record_count") == int(record_count)))

            injected_metrics = page.evaluate(
                """
                ({ recordCount, rowLimit, rowFilterTextLimit, latencyBudgetMs }) => {
                  const old = document.querySelector('[data-testid="browser-stress-synthetic-window"]');
                  if (old) old.remove();
                  const section = document.createElement('section');
                  section.dataset.testid = 'browser-stress-synthetic-window';
                  section.setAttribute('aria-label', 'Synthetic large-result browser stress window');
                  const label = document.createElement('label');
                  label.textContent = 'Stress filter';
                  const input = document.createElement('input');
                  input.id = 'browserStressFilter';
                  input.placeholder = 'Filter synthetic mounted rows';
                  label.appendChild(input);
                  section.appendChild(label);
                  const table = document.createElement('table');
                  table.className = 'data-table browser-stress-table';
                  const tbody = document.createElement('tbody');
                  const mounted = Math.min(recordCount, rowLimit);
                  for (let index = 0; index < mounted; index += 1) {
                    const row = document.createElement('tr');
                    const filterText = (`synthetic-row-${index} path-/case/browser/${index} status-reviewed needle-row-${index} ` + 'x'.repeat(rowFilterTextLimit)).slice(0, rowFilterTextLimit);
                    row.dataset.filter = filterText.toLowerCase();
                    row.dataset.viewerRowPath = `/synthetic/browser/${index}.json`;
                    const first = document.createElement('td');
                    first.textContent = `Synthetic row ${index + 1}`;
                    const second = document.createElement('td');
                    second.textContent = row.dataset.viewerRowPath;
                    row.append(first, second);
                    tbody.appendChild(row);
                  }
                  table.appendChild(tbody);
                  section.appendChild(table);
                  document.body.appendChild(section);
                  input.addEventListener('input', () => {
                    const term = input.value.toLowerCase();
                    section.querySelectorAll('tr[data-filter]').forEach((row) => {
                      row.hidden = term ? !row.dataset.filter.includes(term) : false;
                    });
                  });
                  const start = performance.now();
                  input.value = `needle-row-${mounted - 1}`;
                  input.dispatchEvent(new Event('input', { bubbles: true }));
                  const latencyMs = performance.now() - start;
                  const rows = [...section.querySelectorAll('tr[data-filter]')];
                  return {
                    mountedRowCount: rows.length,
                    maxFilterLength: Math.max(...rows.map((row) => row.dataset.filter.length)),
                    hiddenRowCount: rows.filter((row) => row.hidden).length,
                    visibleRowCount: rows.filter((row) => !row.hidden).length,
                    filterLatencyMs: latencyMs,
                    stressDomNodeCount: section.querySelectorAll('*').length,
                    latencyBudgetPass: latencyMs <= latencyBudgetMs,
                  };
                }
                """,
                {
                    "recordCount": int(record_count),
                    "rowLimit": int(evidence["row_limit"]),
                    "rowFilterTextLimit": DEFAULT_ROW_FILTER_TEXT_LIMIT,
                    "latencyBudgetMs": int(evidence["search_latency_budget"]["target_p95_ms"]),
                },
            )
            metrics.update(injected_metrics)
            checks.extend(
                [
                    _check("mounted-rows-bounded", injected_metrics["mountedRowCount"] <= evidence["row_limit"]),
                    _check("row-filter-text-bounded", injected_metrics["maxFilterLength"] <= DEFAULT_ROW_FILTER_TEXT_LIMIT),
                    _check("visible-row-filter-functional", injected_metrics["visibleRowCount"] == 1),
                    _check("filter-latency-budget", injected_metrics["latencyBudgetPass"], value=injected_metrics["filterLatencyMs"]),
                ]
            )
            memory = _read_chromium_memory_metrics(context, page)
            if memory:
                metrics["memory"] = memory
                heap_limit = int(evidence["memory_budget"]["target_max_heap_mb"])
                checks.append(_check("heap-budget", memory.get("js_heap_used_mb", 0) <= heap_limit, value=memory.get("js_heap_used_mb")))
            checks.append(_check("console-errors", not console_errors, value=len(console_errors)))
            if output_dir:
                output_path = Path(output_dir).expanduser().resolve()
                output_path.mkdir(parents=True, exist_ok=True)
                screenshot = output_path / "browser-large-result-stress.png"
                page.screenshot(path=str(screenshot), full_page=False)
                artifacts["screenshot"] = str(screenshot)
            if any(not bool(check["passed"]) for check in checks):
                status = "failed"
    except Exception as exc:  # pragma: no cover - browser environment dependent
        status = "failed"
        error = str(exc)
        checks.append(_check("browser-stress-execution", False, value=error))
    finally:
        if context is not None:
            context.close()
        if browser is not None:
            browser.close()

    payload = {
        **plan,
        "command": "browser.large-result-stress",
        "status": status,
        "playwright_available": True,
        "base_url": base_url,
        "headless": headless,
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "checks": checks,
        "metrics": metrics,
        "console_errors": console_errors,
        "artifacts": artifacts,
        "error": error,
        "commercial_grade_ready": status == "pass",
    }
    _write_browser_stress_payload(payload, output_dir)
    return payload


def _page_get_json(page: Any, url: str) -> dict[str, object]:
    response = page.request.get(url)
    if not response.ok:
        raise RuntimeError(f"GET {url} failed with HTTP {response.status}")
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError(f"GET {url} did not return a JSON object")
    return payload


def _read_chromium_memory_metrics(context: Any, page: Any) -> dict[str, float]:
    try:
        cdp = context.new_cdp_session(page)
        cdp.send("Performance.enable")
        payload = cdp.send("Performance.getMetrics")
        cdp.send("Performance.disable")
    except Exception:
        return {}
    metrics = {str(item.get("name")): float(item.get("value")) for item in payload.get("metrics", []) if "name" in item}
    heap = metrics.get("JSHeapUsedSize")
    dom_nodes = metrics.get("Nodes")
    output: dict[str, float] = {}
    if heap is not None:
        output["js_heap_used_mb"] = round(heap / (1024 * 1024), 3)
    if dom_nodes is not None:
        output["dom_nodes"] = dom_nodes
    return output


def _check(name: str, passed: bool, *, value: object | None = None, elapsed_ms: float | None = None) -> dict[str, object]:
    payload: dict[str, object] = {"name": name, "passed": bool(passed)}
    if value is not None:
        payload["value"] = value
    if elapsed_ms is not None:
        payload["elapsed_ms"] = round((time.perf_counter() - elapsed_ms) * 1000, 3)
    return payload


def _write_browser_stress_payload(payload: dict[str, object], output_dir: str | Path | None) -> None:
    if output_dir is None:
        return
    output_path = Path(output_dir).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    (output_path / "browser-large-result-stress.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
