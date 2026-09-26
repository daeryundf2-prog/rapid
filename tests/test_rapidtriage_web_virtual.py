"""Virtual-scroll and feature-module wiring tests for the web console.

Covers the R2 viewer modules (virtual table, KakaoTalk, hex viewer, timeline
heatmap, power-reviewer shortcuts), the R3-1 store contract, and the R3-2
screen-module decomposition invariants.
"""
from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = REPO_ROOT / "rapidtriage" / "web" / "static"
JS_TEST_DIR = REPO_ROOT / "tests" / "js"

# R3-2: console bundle = app.js + extracted screen/feature modules.
APP_JS_BUNDLE = "\n".join(
    path.read_text(encoding="utf-8")
    for path in sorted(STATIC_DIR.glob("app*.js"))
)

# R3-3: screen styles live in per-screen stylesheets loaded after styles.css.
STYLES_BUNDLE = "\n".join(
    path.read_text(encoding="utf-8")
    for path in sorted(STATIC_DIR.glob("*.css"))
)


class RapidTriageWebVirtualScrollTests(unittest.TestCase):
    def _run_node_suite(self, script: str, marker: str) -> None:
        result = subprocess.run(
            ["node", str(JS_TEST_DIR / script)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, f"{script} failed:\n{result.stdout}\n{result.stderr}")
        self.assertIn(marker, result.stdout)

    def test_app_js_integrates_virtual_tables_for_artifacts_and_search(self) -> None:
        app_js = APP_JS_BUNDLE

        self.assertIn("VirtualTable", app_js)
        self.assertIn("registerVirtualTable", app_js)
        self.assertIn('data-virtual-key="artifacts"', app_js)
        self.assertIn("queueArtifactsNextPage", app_js)
        self.assertIn("flattenArtifactRows", app_js)
        self.assertIn("onNeedMore", app_js)
        self.assertIn("renderArtifactRow", app_js)

    def test_virtual_table_module_exposes_bounded_dom_contract(self) -> None:
        module = (STATIC_DIR / "app_virtual.js").read_text(encoding="utf-8")

        self.assertIn("export class VirtualTable", module)
        self.assertIn("setItems", module)
        self.assertIn("appendItems", module)
        self.assertIn("setFilter", module)
        self.assertIn("scrollToIndex", module)
        self.assertIn("overscan", module)
        self.assertIn("registerVirtualTable", module)
        self.assertIn("applyVirtualTableFilter", module)
        self.assertIn('from "./app_virtual.js"', (STATIC_DIR / "app.js").read_text(encoding="utf-8"))

    def test_virtual_table_behavioral_suite(self) -> None:
        self._run_node_suite("test_virtual_table.mjs", "all virtual-table tests passed")

    def test_kakao_viewer_suite(self) -> None:
        self._run_node_suite("test_app_kakao.mjs", "all kakao-viewer tests passed")

    def test_kakao_viewer_is_separate_render_module(self) -> None:
        module = (STATIC_DIR / "app_kakao.js").read_text(encoding="utf-8")
        app_js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
        index = (STATIC_DIR / "index.html").read_text(encoding="utf-8")

        self.assertIn("collectKakaoMessages", module)
        self.assertIn("renderKakaoChat", module)
        self.assertIn("renderKakaoArtifactChatCard", module)
        # Bubble markup must not live inside app.js itself.
        self.assertNotIn("kakao-bubble", app_js)
        self.assertIn('from "./app_kakao.js"', app_js)
        self.assertIn("kakao.css", index)

    def test_hex_viewer_suite(self) -> None:
        self._run_node_suite("test_app_hexview.mjs", "all hex-viewer tests passed")

    def test_hex_viewer_is_separate_module(self) -> None:
        module = (STATIC_DIR / "app_hexview.js").read_text(encoding="utf-8")
        index = (STATIC_DIR / "index.html").read_text(encoding="utf-8")

        self.assertIn("drawHexRange", module)
        self.assertIn("scanSignatures", module)
        self.assertIn("<canvas", module)
        self.assertIn("source-hex-range", APP_JS_BUNDLE)
        self.assertIn("mountHexViewers", APP_JS_BUNDLE)
        self.assertIn("hexview.css", index)

    def test_heatmap_suite(self) -> None:
        self._run_node_suite("test_app_heatmap.mjs", "all heatmap tests passed")

    def test_heatmap_wiring(self) -> None:
        module = (STATIC_DIR / "app_heatmap.js").read_text(encoding="utf-8")
        index = (STATIC_DIR / "index.html").read_text(encoding="utf-8")

        self.assertIn("mountTimelineHeatmap", module)
        self.assertIn("renderTimelineHeatmapShell", module)
        self.assertIn("timeline-histogram", APP_JS_BUNDLE)
        self.assertIn("mountTimelineHeatmap", APP_JS_BUNDLE)
        self.assertIn("data-timeline-ts", APP_JS_BUNDLE)
        self.assertIn("heatmap.css", index)

    def test_power_reviewer_shortcut_suite(self) -> None:
        self._run_node_suite("test_app_shortcuts.mjs", "all shortcut tests passed")

    def test_workbench_store_contract_suite(self) -> None:
        self._run_node_suite("test_app_store.mjs", "all store-contract tests passed")

    def test_no_leaf_module_imports_app_js(self) -> None:
        # R3-1: leaf modules must go through the store/config contract so the
        # module graph stays acyclic.
        for name in ("app_state.js", "app_compare.js", "app_intake.js"):
            text = (STATIC_DIR / name).read_text(encoding="utf-8")
            self.assertNotIn('from "./app.js"', text, f"{name} still imports app.js")
        store = (STATIC_DIR / "app_store.js").read_text(encoding="utf-8")
        self.assertIn("workbenchState", store)
        self.assertIn("registerWorkbenchBinding", store)
        self.assertIn("syncWorkbenchState", store)
        app_js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
        self.assertIn("registerWorkbenchBinding(name, fn)", app_js)
        self.assertIn("flushWorkbenchState", app_js)

    def test_screen_modules_are_split_and_wired(self) -> None:
        # R3-2: the four screen renderers live in dedicated modules wired
        # through init*(deps) contracts so the graph stays acyclic.
        app_js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
        for module_name, init_name in (
            ("app_case_header.js", "initCaseHeader"),
            ("app_artifact_grid.js", "initArtifactGrid"),
            ("app_timeline_view.js", "initTimelineView"),
            ("app_detail_panel.js", "initDetailPanel"),
        ):
            text = (STATIC_DIR / module_name).read_text(encoding="utf-8")
            self.assertNotIn('from "./app.js"', text, f"{module_name} imports app.js")
            self.assertIn(f"export function {init_name}", text)
            self.assertIn(init_name, app_js)
            self.assertIn(f'from "./{module_name}"', app_js)
        # Screens must not import each other's heavy internals back into app.js
        # callers: renderDetailShell stays the shell entry point.
        self.assertIn("renderDetailShell(selectedRun, activeTab)", app_js)


if __name__ == "__main__":
    unittest.main()
