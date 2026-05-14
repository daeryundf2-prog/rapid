from __future__ import annotations

import unittest
from pathlib import Path

from rapidtriage.core.visible_capabilities import CAPABILITY_GROUPS, build_visible_capability_response, validate_visible_capability_contract


REPO_ROOT = Path(__file__).resolve().parents[1]


class RapidTriageWebStaticTests(unittest.TestCase):
    def test_web_artifact_workbench_exposes_ntfs_replay_review_cards(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")

        self.assertIn("ntfsArtifactPreviewText", app_js)
        self.assertIn("renderNtfsReplayPreviewArtifactCard", app_js)
        self.assertIn("usn_replay_inventory_profile", app_js)
        self.assertIn("bounded_mft_replay_preview", app_js)
        self.assertIn("mft_bounded_path_cache_profile", app_js)
        self.assertIn("MFT cache quality", app_js)
        self.assertIn("MFT partial path warnings", app_js)
        self.assertIn("usn_path_reliability_profile", app_js)
        self.assertIn("Path reliability", app_js)
        self.assertIn("Reliability wording", app_js)
        self.assertIn("rename_pair_preview", app_js)
        self.assertIn("delete_lifecycle_preview", app_js)
        self.assertIn("bounded_state_replay_preview", app_js)
        self.assertIn("usn_state_replay_validation_profile", app_js)
        self.assertIn("State replay validation", app_js)
        self.assertIn("State validation wording", app_js)
        self.assertIn("Delete lifecycle", app_js)
        self.assertIn("State transitions", app_js)
        self.assertIn("Bounded state replay", app_js)
        self.assertIn("STATE paired OLD", app_js)
        self.assertIn("USN replay preview", app_js)
        self.assertIn("renderNtfsSourceLocatorLinks", app_js)
        self.assertIn("Source locators", app_js)
        self.assertIn("source-hex-range", app_js)
        self.assertIn("include_hashes=true", app_js)
        self.assertIn("errorMessageFromDetail", app_js)
        self.assertIn("renderSourceResolutionDiagnostics", app_js)
        self.assertIn("source_path_resolution", app_js)
        self.assertIn("Source path resolution diagnostics", app_js)
        self.assertIn("Court-grade rename/delete replay still requires full-journal ordering", app_js)

    def test_web_workbench_exposes_run_validation_diff_inventory_panel(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        styles = (REPO_ROOT / "rapidtriage" / "web" / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("data-testid=\"run-validation-diff-panel\"", app_js)
        self.assertIn("loadRunValidationPackageSummary", app_js)
        self.assertIn("renderRunValidationPackageSummary", app_js)
        self.assertIn("diff_inventory", app_js)
        self.assertIn("usn_state_replay_diff_attached", app_js)
        self.assertIn("usn_state_replay_diff_pass_count", app_js)
        self.assertIn("usn_state_replay_status", app_js)
        self.assertIn("Run validation diff inventory", app_js)
        self.assertIn("run-validation-diff-panel", styles)
        self.assertIn("validation-diff-card", styles)
        self.assertIn("validation-diff-list", styles)
        self.assertIn("compact-dl", styles)

    def test_search_results_expose_review_facets_for_fast_triage(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        styles = (REPO_ROOT / "rapidtriage" / "web" / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("renderSearchFacets", app_js)
        self.assertIn("review facets", app_js)
        self.assertIn("search-facet-chip[data-filter]", app_js)
        self.assertIn("aria-label=\"Filter results by", app_js)
        self.assertIn("search-facet-panel", styles)
        self.assertIn("search-facet-chip", styles)

    def test_workbench_review_queue_and_schema_visibility_contracts(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        config_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app_workbench_config.js").read_text(encoding="utf-8")
        state_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app_state.js").read_text(encoding="utf-8")
        index_html = (REPO_ROOT / "rapidtriage" / "web" / "static" / "index.html").read_text(encoding="utf-8")
        styles = (REPO_ROOT / "rapidtriage" / "web" / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn('/assets/app_workbench_config.js', index_html)
        self.assertIn('/assets/app_state.js', index_html)
        self.assertLess(index_html.index('/assets/app_workbench_config.js'), index_html.index('/assets/app.js'))
        self.assertLess(index_html.index('/assets/app_workbench_config.js'), index_html.index('/assets/app_state.js'))
        self.assertLess(index_html.index('/assets/app_state.js'), index_html.index('/assets/app.js'))
        self.assertIn("function persistWorkbenchSession", state_js)
        self.assertIn("function renderVirtualizationNotice", state_js)
        self.assertIn("function getSearchDraft", state_js)
        self.assertIn("data-testid=\"artifact-tree-lane-find\"", app_js)
        self.assertIn("data-testid=\"artifact-tree-lane-deliver\"", app_js)
        self.assertIn("tab: \"summary\", label: \"Overview\"", config_js)
        self.assertIn("tab: \"indicators\", label: \"Indicators\"", config_js)
        self.assertIn("data-testid=\"forensic-view-mode-bar\"", app_js)
        self.assertIn("aria-current=\"${mode.tab === tab ? \"page\" : \"false\"}\"", app_js)
        self.assertIn("aria-live=\"polite\"", app_js)
        self.assertIn("viewer.setAttribute(\"aria-busy\", \"true\")", app_js)
        self.assertIn("viewer.setAttribute(\"aria-busy\", \"false\")", app_js)
        self.assertIn("data-artifact-filter", app_js)
        self.assertIn("applyArtifactTreeFilter", app_js)
        self.assertIn("data-testid=\"review-bulk-queue\"", app_js)
        self.assertIn("review-bulk-toolbar", app_js)
        self.assertIn("Find related", app_js)
        self.assertIn("Prepare report", app_js)
        self.assertIn("renderSqliteSchemaPanel", app_js)
        self.assertIn("data-testid=\"sqlite-schema-panel\"", app_js)
        self.assertIn("Schema visibility", app_js)
        self.assertIn("artifact-tree-lane", styles)
        self.assertIn("review-bulk-toolbar", styles)
        self.assertIn("sqlite-schema-panel", styles)
        self.assertIn("sqlite-column-chip", styles)

    def test_lazyweb_command_center_is_connected_to_workbench_tabs(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        config_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app_workbench_config.js").read_text(encoding="utf-8")
        styles = (REPO_ROOT / "rapidtriage" / "web" / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("LAZYWEB_WORKBENCH_MODEL", config_js)
        self.assertIn("lazyweb-command-center-model-v1", config_js)
        self.assertIn("https://www.lazyweb.com/canvas/flows/raycast/manage-models", config_js)
        self.assertIn("Evidence intake", config_js)
        self.assertIn("Unified search", config_js)
        self.assertIn("Source verify", config_js)
        self.assertIn("Review board", config_js)
        self.assertIn("Report bundle", config_js)
        self.assertIn("renderLazywebCommandCenter", app_js)
        self.assertIn("data-testid=\"lazyweb-command-center\"", app_js)
        self.assertIn("data-open-tab=\"search\"", app_js)
        self.assertIn("data-artifact-filter=\"${escapeHtml(command.filter || \"\")}\"", app_js)
        self.assertIn(".lazyweb-command-center", styles)
        self.assertIn(".lazyweb-command-grid", styles)
        self.assertIn("body.analysis-active .lazyweb-command-center", styles)

    def test_forensic_feature_catalog_makes_available_functions_discoverable(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        config_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app_workbench_config.js").read_text(encoding="utf-8")
        styles = (REPO_ROOT / "rapidtriage" / "web" / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("FORENSIC_FEATURE_CATALOG", config_js)
        self.assertIn("증거 입력 / 케이스", config_js)
        self.assertIn("Windows 핵심 아티팩트", config_js)
        self.assertIn("웹 / AI 사용 기록", config_js)
        self.assertIn("메신저 / 이메일", config_js)
        self.assertIn("문서 / DB / 본문 검색", config_js)
        self.assertIn("이미지 / 영상 / OCR", config_js)
        self.assertIn("타임라인 / IOC / DFIR", config_js)
        self.assertIn("모바일 / 클라우드", config_js)
        self.assertIn("리뷰 / 보고서 / 제출", config_js)
        self.assertIn("renderForensicFeatureCatalog", app_js)
        self.assertIn("data-testid=\"forensic-feature-catalog\"", app_js)
        self.assertIn("지원 기능을 먼저 보고 시작하세요", app_js)
        self.assertIn("feature-catalog-card", app_js)
        self.assertIn("data-open-tab=\"${escapeHtml(item.tab)}\"", app_js)
        self.assertIn("data-artifact-filter=\"${escapeHtml(filterTerm)}\"", app_js)
        self.assertIn(".forensic-feature-catalog", styles)
        self.assertIn(".feature-catalog-grid", styles)
        self.assertIn("body.analysis-active .forensic-feature-catalog", styles)

    def test_hidden_forensic_capabilities_are_exposed_as_visible_steps(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        config_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app_workbench_config.js").read_text(encoding="utf-8")
        styles = (REPO_ROOT / "rapidtriage" / "web" / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("VISIBLE_FORENSIC_CAPABILITY_GROUPS", config_js)
        self.assertIn("VISIBLE_CAPABILITY_STATUS_LABELS", config_js)
        self.assertIn("browser-history", config_js)
        self.assertIn("브라우저 방문 기록", config_js)
        self.assertIn("browser-ai-usage", config_js)
        self.assertIn("AI 서비스 방문 기록", config_js)
        self.assertIn("browser-ai-conversation", config_js)
        self.assertIn("AI 질문/답변 후보", config_js)
        self.assertIn("browser-storage-inventory", config_js)
        self.assertIn("eventlog-chunk", config_js)
        self.assertIn("registry-user-activity", config_js)
        self.assertIn("windows-search-edb-row-candidate", config_js)
        self.assertIn("windows-search-edb-page-candidate", config_js)
        self.assertIn("virtual-disk-workflow", config_js)
        self.assertIn("qemu_img_info_profile", config_js)
        self.assertIn("virtual_disk_chain_profile", config_js)
        self.assertIn("browser_analyst_review_profile", config_js)
        self.assertIn("mobile-message", config_js)
        self.assertIn("kakaotalk-windows-app-database", config_js)
        self.assertIn("kakaotalk-macos-database", config_js)
        self.assertIn("chat_app_forensic_review", config_js)
        self.assertIn("messenger-export-framework-manifest", config_js)
        self.assertIn("cloud-message", config_js)
        self.assertIn("icloud_export_review_profile", config_js)
        self.assertIn("icloud_export_parser_manifest", config_js)
        self.assertIn("m365_export_review_profile", config_js)
        self.assertIn("m365_export_parser_manifest", config_js)
        self.assertIn("media-audio", config_js)
        self.assertIn("waveform_preview", config_js)
        self.assertIn("transcript_sidecars", config_js)
        self.assertIn("media-cue-proof-manifest", config_js)
        self.assertIn("memory-dump-indicators", config_js)
        self.assertIn("dfir-webshell-log", config_js)
        self.assertIn("webshell-source-candidate", config_js)
        self.assertIn("web-server-log", config_js)
        self.assertIn("webshell_semantic_profile", config_js)
        self.assertIn("webshell_log_correlation", config_js)
        self.assertIn("webshell_report_citation_package", config_js)
        self.assertIn("ai-service-export-conversation", config_js)
        self.assertIn("ai_service_export_parser_manifest", config_js)
        for capability_id in (
            "evidence-vss-apfs-snapshot",
            "evidence-fde-unlock",
            "evidence-unallocated-carving",
            "ntfs-logfile-transactions",
            "timestamp-stomping-detection",
            "signature-mismatch-detection",
            "etl-trace-parser",
            "eventlog-clearing-alert",
            "usb-external-device-history",
            "autoruns-persistence-view",
            "lnk-jumplist-analysis",
            "windows-timeline-activities",
            "webcachev01-ese-parser",
            "local-llm-ollama-lmstudio-gpt4all",
            "windows-copilot-recall",
            "print-spooler-spl-shd",
            "geo-location-map-viewer",
            "aws-cloudtrail-parser",
            "exif-gps-map",
            "hiberfil-pagefile-carving",
            "remote-control-anydesk-teamviewer-rustdesk",
            "super-timeline-plaso-style",
            "denisting-nsrl-whitelist",
            "yara-ioc-scanner",
        ):
            self.assertIn(capability_id, config_js)
        self.assertIn("renderVisibleCapabilityGroups", app_js)
        self.assertIn("visibleCapabilityGroupsForRun", app_js)
        self.assertIn("loadRunCapabilities", app_js)
        self.assertIn("/capabilities", app_js)
        self.assertIn("group.catalogId || group.catalog_id", app_js)
        self.assertIn("capability.artifactTypes || capability.artifact_types", app_js)
        self.assertIn("capability.nextAction || capability.next_action", app_js)
        self.assertIn("data-workflow-stage", app_js)
        self.assertIn("data-viewer", app_js)
        self.assertIn("capabilitySignalLookup", app_js)
        self.assertIn("matched signals", app_js)
        self.assertIn("visible steps", app_js)
        self.assertIn("feature-capability-chip", app_js)
        self.assertIn("data-capability-filter", app_js)
        self.assertIn("data-signal-count", app_js)
        self.assertIn("capability?.dataset.capabilityFilter", app_js)
        self.assertIn("safeCssToken", app_js)
        self.assertIn(".feature-capability-groups", styles)
        self.assertIn(".feature-capability-chip.has-signals", styles)
        self.assertIn(".feature-capability-chip.status-validation-required", styles)
        self.assertIn("body.analysis-active .feature-capability-group", styles)

    def test_visible_forensic_capability_ids_stay_synced_between_api_and_gui(self) -> None:
        config_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app_workbench_config.js").read_text(encoding="utf-8")

        python_ids = [
            capability["id"]
            for group in CAPABILITY_GROUPS
            for capability in group["capabilities"]
        ]
        self.assertGreaterEqual(len(python_ids), 80)
        for capability_id in python_ids:
            self.assertIn(capability_id, config_js)

    def test_visible_capability_registry_has_gui_contract_for_every_feature(self) -> None:
        issues = validate_visible_capability_contract()
        payload = build_visible_capability_response()
        capabilities = {
            capability["id"]: capability
            for group in payload["groups"]
            for capability in group["capabilities"]
        }

        self.assertEqual(issues, [])
        self.assertTrue(payload["summary"]["gui_contract_pass"])
        self.assertEqual(payload["gui_contract"]["issue_count"], 0)
        self.assertEqual(capabilities["media-audio"]["status"], "partial")
        self.assertIn("media-audio", capabilities["media-audio"]["artifact_types"])
        self.assertEqual(capabilities["dfir-webshell-log"]["status"], "partial")
        self.assertIn("webshell-source-candidate", capabilities["dfir-webshell-log"]["artifact_types"])
        self.assertIn("web-server-log", capabilities["dfir-webshell-log"]["artifact_types"])
        for capability_id in (
            "windows-search-edb-row-candidate",
            "browser-storage-inventory",
            "kakaotalk-macos-inventory",
            "messenger-whatsapp-telegram-signal-line",
            "cloud-icloud-export",
            "cloud-message",
            "image-vm-disk",
            "browser-ai-export-parser",
        ):
            self.assertEqual(capabilities[capability_id]["status"], "partial")
        self.assertIn("virtual-disk-workflow", capabilities["image-vm-disk"]["artifact_types"])
        self.assertIn("ai-service-export-conversation", capabilities["browser-ai-export-parser"]["artifact_types"])
        for group in payload["groups"]:
            self.assertIn("tab", group)
            self.assertIn("workflow_stage", group)
            for capability in group["capabilities"]:
                self.assertTrue(capability["id"])
                self.assertTrue(capability["tab"])
                self.assertTrue(capability["viewer"])
                self.assertTrue(capability["artifact_types"])
                self.assertTrue(capability["workflow_stage"])
                self.assertTrue(capability["next_action"])
                self.assertTrue(capability["gui_surfaces"])

    def test_core_three_step_evidence_workflow_is_visually_primary(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        config_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app_workbench_config.js").read_text(encoding="utf-8")
        index_html = (REPO_ROOT / "rapidtriage" / "web" / "static" / "index.html").read_text(encoding="utf-8")
        styles = (REPO_ROOT / "rapidtriage" / "web" / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("CORE_EVIDENCE_WORKFLOW", config_js)
        self.assertIn("이미지/E01 안을 읽고 분류", config_js)
        self.assertIn("필요한 파일을 해시와 함께 꺼내기", config_js)
        self.assertIn("키워드로 찾고 원본에서 재확인", config_js)
        self.assertIn("data-testid=\"core-evidence-workflow\"", index_html)
        self.assertIn("renderCoreEvidenceWorkflow", app_js)
        self.assertIn("coreEvidenceWorkflowStatuses", app_js)
        self.assertIn("payload.workflow?.stages", app_js)
        self.assertIn("renderRunWorkflowContract", app_js)
        self.assertIn("renderRunWorkflowOutputLinks", app_js)
        self.assertIn("renderRunWorkflowChecklistSummary", app_js)
        self.assertIn("renderRunWorkflowChecklist", app_js)
        self.assertIn("runWorkflowChecklistStatusLabel", app_js)
        self.assertIn("loadRunOutputPreview", app_js)
        self.assertIn("renderRunOutputViewer", app_js)
        self.assertIn("data-testid=\"run-workflow-contract\"", app_js)
        self.assertIn("data-testid=\"run-workflow-output-links\"", app_js)
        self.assertIn("data-testid=\"run-workflow-checklist-summary\"", app_js)
        self.assertIn("data-testid=\"run-workflow-checklist\"", app_js)
        self.assertIn("data-testid=\"run-output-viewer-header\"", app_js)
        self.assertIn("single-case workflow contract", app_js)
        self.assertIn("handoff_outputs", app_js)
        self.assertIn("analyst_checklist", app_js)
        self.assertIn("analyst_checklist_summary", app_js)
        self.assertIn("분석관 체크리스트", app_js)
        self.assertIn("data-preview-output-name", app_js)
        self.assertIn("/preview", app_js)
        self.assertIn("/outputs/${encodeURIComponent(name)}/file", app_js)
        self.assertIn("data-core-workflow-step", app_js)
        self.assertIn("data-testid=\"core-workflow-step-${escapeHtml(step.id)}\"", app_js)
        self.assertIn("분석 완료", app_js)
        self.assertIn("추출 완료", app_js)
        self.assertIn("검색 가능", app_js)
        self.assertIn("docs_extracted_count", app_js)
        self.assertIn("files_extracted_count", app_js)
        self.assertIn(".core-evidence-workflow", styles)
        self.assertIn(".core-workflow-step", styles)
        self.assertIn(".run-workflow-contract", styles)
        self.assertIn(".run-workflow-stage", styles)
        self.assertIn(".run-workflow-stage-main", styles)
        self.assertIn(".run-workflow-output-links", styles)
        self.assertIn(".run-workflow-output-card", styles)
        self.assertIn(".run-workflow-output-actions", styles)
        self.assertIn(".run-workflow-checklist-summary", styles)
        self.assertIn(".run-workflow-checklist", styles)
        self.assertIn(".run-workflow-checklist-row", styles)
        self.assertIn(".sr-only", styles)
        self.assertIn("body.analysis-active .completed-core-workflow", styles)

    def test_file_triage_controls_are_exposed_in_gui_and_files_tab(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        index_html = (REPO_ROOT / "rapidtriage" / "web" / "static" / "index.html").read_text(encoding="utf-8")
        styles = (REPO_ROOT / "rapidtriage" / "web" / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("knownGoodHashFeedInput", index_html)
        self.assertIn("hideKnownGoodInput", index_html)
        self.assertIn("knownGoodMaxHashMbInput", index_html)
        self.assertIn("Known-good suppression and extension spoofing checks", index_html)
        self.assertIn("parseKnownGoodHashFeeds", app_js)
        self.assertIn("knownGoodMaxHashBytes", app_js)
        self.assertIn("known_good_hash_feeds: parseKnownGoodHashFeeds()", app_js)
        self.assertIn("renderFileTriageSummary", app_js)
        self.assertIn("file_signature_profile", app_js)
        self.assertIn("known_good_suppression_profile", app_js)
        self.assertIn("signature_mismatch_candidates", app_js)
        self.assertIn("data-testid=\"file-triage-summary\"", app_js)
        self.assertIn(".file-triage-summary", styles)
        self.assertIn(".file-triage-badge", styles)
        self.assertIn(".file-triage-table tr.risk-row", styles)

    def test_command_palette_connects_lazyweb_actions_to_forensic_workbench(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        config_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app_workbench_config.js").read_text(encoding="utf-8")
        styles = (REPO_ROOT / "rapidtriage" / "web" / "static" / "styles.css").read_text(encoding="utf-8")

        self.assertIn("quick_actions", config_js)
        self.assertIn("Filter visible rows", config_js)
        self.assertIn("Search current file", config_js)
        self.assertIn("renderCommandPalette", app_js)
        self.assertIn("data-testid=\"command-palette\"", app_js)
        self.assertIn("data-command-palette-open", app_js)
        self.assertIn("bindCommandPaletteActions", app_js)
        self.assertIn("openCommandPalette", app_js)
        self.assertIn("executeCommandPaletteButton", app_js)
        self.assertIn("COMMAND_PALETTE_RESULT_LIMIT", app_js)
        self.assertIn("data-command-tab", app_js)
        self.assertIn("data-command-filter", app_js)
        self.assertIn("data-command-action", app_js)
        self.assertIn("Open command palette", config_js)
        self.assertIn(".command-palette", styles)
        self.assertIn(".command-palette-command", styles)
        self.assertIn("body.analysis-active .command-palette-shell", styles)

    def test_row_filter_text_is_bounded_for_large_records(self) -> None:
        app_js = (REPO_ROOT / "rapidtriage" / "web" / "static" / "app.js").read_text(encoding="utf-8")

        row_text_body = app_js.split("function rowText(value) {", 1)[1].split("function compactRowFilterText", 1)[0]
        self.assertIn("ROW_FILTER_TEXT_LIMIT", app_js)
        self.assertIn("ROW_FILTER_KEYS", app_js)
        self.assertIn("compactRowFilterText(value)", row_text_body)
        self.assertNotIn("JSON.stringify", row_text_body)
        self.assertIn("slice(0, ROW_FILTER_TEXT_LIMIT)", app_js)
        self.assertIn("filter text bounded to ${ROW_FILTER_TEXT_LIMIT} chars/row", app_js)


if __name__ == "__main__":
    unittest.main()
