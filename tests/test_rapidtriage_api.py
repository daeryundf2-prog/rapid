from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
import wave
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from rapidtriage.api.app import create_app
from rapidtriage.cli import build_web_parser
from rapidtriage.core.jobs import RunJobStore
from tests.schema_validation import validate
from tests.test_rapidtriage_run import build_run_fixture
from tests.windows_artifact_fixtures import build_windows_artifact_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent


def hash_file(path: Path, algorithm: str) -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


class RapidTriageApiTests(unittest.TestCase):
    def test_web_entrypoint_parser_supports_direct_launch_options(self) -> None:
        args = build_web_parser().parse_args(["--host", "0.0.0.0", "--port", "9000"])

        self.assertEqual(args.host, "0.0.0.0")
        self.assertEqual(args.port, 9000)
        self.assertEqual(args.reload, False)
        self.assertIsNone(args.crash_log_dir)

    def test_health_and_index_are_available(self) -> None:
        client = TestClient(create_app(RunJobStore()))

        self.assertEqual(client.get("/api/health").json(), {"status": "ok"})
        self.assertFalse(client.get("/api/enterprise/policy").json()["telemetry"]["enabled"])
        keyword_packs = client.get("/api/keyword-packs").json()
        self.assertIn("#62", keyword_packs["keyword_pack_library_assessment"]["commercial_gap_ids"])
        self.assertIn("#62", keyword_packs["packs"][0]["commercial_gap_ids"])
        index_response = client.get("/")

        self.assertEqual(index_response.status_code, 200)
        self.assertIn("rapidtriage", index_response.text)

    def test_sample_case_api_creates_and_imports_practice_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            client = TestClient(create_app(RunJobStore()))
            response = client.post(
                "/api/sample-case/run",
                json={
                    "output_dir": str(Path(tmp_dir) / "sample"),
                    "mode": "fraud",
                    "overwrite": True,
                    "read_only": True,
                },
            )

            self.assertEqual(response.status_code, 201, response.text)
            payload = response.json()
            self.assertEqual(payload["command"], "sample-case.run")
            self.assertEqual(payload["run"]["status"], "completed")
            self.assertEqual(payload["run"]["origin"], "imported")
            self.assertTrue((Path(tmp_dir) / "sample" / "run-output" / "rapidtriage-run-summary.json").is_file())

    def test_evidence_identify_api_reports_extended_container_support(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "phone-export.ad1"
            source.write_bytes(b"fixture")
            client = TestClient(create_app(RunJobStore()))

            response = client.post("/api/evidence/identify", json={"path": str(source)})

            self.assertEqual(response.status_code, 200, response.text)
            payload = response.json()
            self.assertEqual(payload["command"], "evidence.identify")
            self.assertEqual(payload["result"]["adapter"], "forensic-container")
            self.assertEqual(payload["result"]["detected_format"], "ad1")
            self.assertEqual(payload["result"]["supported"], True)
            self.assertEqual(payload["result"]["can_extract"], False)
            self.assertTrue(any(".ad1" in item["suffixes"] for item in payload["formats"]))

    def test_collect_plan_api_previews_profile_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            build_windows_artifact_fixture(root)
            client = TestClient(create_app(RunJobStore()))

            profiles_response = client.get("/api/collect/profiles")
            plan_response = client.post(
                "/api/collect/plan",
                json={"root": str(root), "profile": "intrusion", "input_kind": "mounted-image"},
            )

            self.assertEqual(profiles_response.status_code, 200)
            self.assertIn("intrusion", profiles_response.json()["profiles"])
            self.assertEqual(plan_response.status_code, 200, plan_response.text)
            payload = plan_response.json()
            self.assertEqual(payload["command"], "collect-plan")
            self.assertEqual(payload["profile"], "intrusion")
            self.assertGreater(payload["summary"]["present_count"], 0)
            self.assertIn("EventLogs", payload["summary"]["category_counts"])

    def test_create_run_waits_and_exposes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            sqlite_path = root / "viewer.sqlite"
            connection = sqlite3.connect(sqlite_path)
            try:
                connection.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)")
                connection.execute("INSERT INTO notes (body) VALUES (?)", ("password in sqlite viewer",))
                connection.commit()
            finally:
                connection.close()
            json_path = root / "structured.json"
            json_path.write_text(json.dumps({"case": "CASE-001", "hit": {"keyword": "password"}}), encoding="utf-8")
            xml_path = root / "structured.xml"
            xml_path.write_text("<root><event id='1'>password xml hit</event></root>", encoding="utf-8")
            eml_path = root / "message.eml"
            eml_path.write_text(
                "From: alice@example.com\n"
                "To: bob@example.com\n"
                "Subject: Password review\n"
                "Date: Mon, 27 Apr 2026 12:00:00 +0900\n"
                "\n"
                "password email body\n",
                encoding="utf-8",
            )
            binary_path = root / "binary.bin"
            binary_path.write_bytes(b"\x00\x01RapidTriage\xff" * 300)
            image_path = root / "screen.png"
            from PIL import Image

            Image.new("RGB", (16, 12), "white").save(image_path)
            image_path.with_name("screen.ocr.txt").write_text("image OCR password", encoding="utf-8")
            image_path.with_name("screen.translation.txt").write_text("translated OCR password", encoding="utf-8")
            media_path = root / "call.wav"
            with wave.open(str(media_path), "wb") as wav_file:
                wav_file.setnchannels(1)
                wav_file.setsampwidth(2)
                wav_file.setframerate(8000)
                wav_file.writeframes(b"\x00\x00" * 8000)
            media_path.with_suffix(".wav.srt").write_text("1\n00:00:00,000 --> 00:00:01,000\npassword spoken\n", encoding="utf-8")
            client = TestClient(create_app(RunJobStore()))

            response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )

            self.assertEqual(response.status_code, 202, response.text)
            run_payload = response.json()
            self.assertEqual(run_payload["status"], "completed")
            self.assertEqual(run_payload["summary"]["mode"], "fraud")

            run_id = run_payload["run_id"]
            summary_response = client.get(f"/api/runs/{run_id}/summary")
            files_response = client.get(f"/api/runs/{run_id}/files")
            timeline_response = client.get(f"/api/runs/{run_id}/timeline")
            indicators_response = client.get(f"/api/runs/{run_id}/indicators", params={"offset": 0, "limit": 5})
            search_response = client.get(f"/api/runs/{run_id}/search", params={"keyword": "password", "ocr": "false"})

            self.assertEqual(summary_response.status_code, 200)
            self.assertEqual(files_response.status_code, 200)
            self.assertEqual(timeline_response.status_code, 200)
            self.assertEqual(indicators_response.status_code, 200)
            self.assertEqual(search_response.status_code, 200)
            self.assertEqual(files_response.json()["command"], "files")
            self.assertEqual(timeline_response.json()["command"], "timeline")
            self.assertEqual(indicators_response.json()["command"], "indicators")
            self.assertEqual(indicators_response.json()["pagination"]["collection"], "indicators")
            self.assertGreaterEqual(indicators_response.json()["summary"]["indicator_count"], 1)
            indicator_bookmark_response = client.post(
                f"/api/runs/{run_id}/bookmarks",
                json={
                    "source": "indicators",
                    "pointer": "/indicators/0",
                    "tag": "ioc",
                    "review_status": "needs-review",
                },
            )
            self.assertEqual(indicator_bookmark_response.status_code, 200, indicator_bookmark_response.text)
            self.assertEqual(
                indicator_bookmark_response.json()["case"]["bookmarks"][0]["reference"]["command"],
                "indicators",
            )
            self.assertEqual(search_response.json()["command"], "search")
            self.assertGreaterEqual(search_response.json()["summary"]["match_count"], 1)
            document_match = next(
                item
                for item in search_response.json()["matches"]
                if item["source"] == "documents" and item["path"].endswith(".txt")
            )
            self.assertIn("metadata", document_match)
            source_response = client.get(f"/api/runs/{run_id}/source-file", params={"path": document_match["path"]})
            self.assertEqual(source_response.status_code, 200)
            self.assertIn("password", source_response.text)
            preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": document_match["path"]})
            self.assertEqual(preview_response.status_code, 200)
            preview_payload = preview_response.json()
            self.assertEqual(preview_payload["preview_type"], "text")
            self.assertIn("password", preview_payload["text"])
            self.assertEqual(preview_payload["viewer_metadata"]["parser_version"], "2")
            self.assertIn("source-search", preview_payload["search_url"])
            self.assertIn("Preview is read-only", preview_payload["viewer_limitations"][0])
            self.assertIn("#51", preview_payload["review_workflow"]["commercial_gap_ids"])
            self.assertIn("#52", preview_payload["compare_workflow"]["commercial_gap_ids"])
            self.assertEqual(
                {action["id"] for action in preview_payload["viewer_actions"]},
                {"download", "hash", "search-current-file", "pin-compare", "save-review"},
            )
            compare_action = next(action for action in preview_payload["viewer_actions"] if action["id"] == "pin-compare")
            review_action = next(action for action in preview_payload["viewer_actions"] if action["id"] == "save-review")
            self.assertEqual(compare_action["max_pinned_items"], 3)
            self.assertIn("#51", review_action["commercial_gap_ids"])
            metadata_response = client.get(
                f"/api/runs/{run_id}/source-metadata",
                params={"path": document_match["path"], "hash": "true"},
            )
            self.assertEqual(metadata_response.status_code, 200)
            metadata_payload = metadata_response.json()
            self.assertEqual(metadata_payload["command"], "source-metadata")
            self.assertEqual(metadata_payload["hash_status"], "computed")
            self.assertEqual(metadata_payload["hashes"]["sha256"], hash_file(Path(document_match["path"]), "sha256"))
            file_search_response = client.get(
                f"/api/runs/{run_id}/source-search",
                params={"path": document_match["path"], "keyword": "password"},
            )
            self.assertEqual(file_search_response.status_code, 200)
            file_search_payload = file_search_response.json()
            self.assertEqual(file_search_payload["command"], "source-search")
            self.assertEqual(file_search_payload["summary"]["match_count"], 1)
            self.assertEqual(file_search_payload["matches"][0]["keyword"], "password")
            self.assertIn("password", file_search_payload["matches"][0]["snippet"].lower())
            self.assertEqual(len(file_search_payload["matches"][0]["match_id"]), 16)
            self.assertEqual(file_search_payload["matches"][0]["pointer"], "source-search:/matches/0")
            self.assertIn("line", file_search_payload["matches"][0]["citation"])
            self.assertEqual(file_search_payload["matches"][0]["locator"]["keyword"], "password")
            self.assertIn("verify source hashes", file_search_payload["matches"][0]["review_hint"])
            sqlite_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(sqlite_path)})
            self.assertEqual(sqlite_preview_response.status_code, 200, sqlite_preview_response.text)
            sqlite_preview = sqlite_preview_response.json()
            self.assertEqual(sqlite_preview["preview_type"], "sqlite")
            self.assertEqual(sqlite_preview["sqlite"]["tables"][0]["name"], "notes")
            self.assertEqual(sqlite_preview["sqlite"]["tables"][0]["rows"][0]["values"]["body"], "password in sqlite viewer")
            self.assertIn("database_metadata", sqlite_preview["sqlite"])
            self.assertTrue(
                any(column["name"] == "body" for column in sqlite_preview["sqlite"]["tables"][0]["column_details"])
            )
            self.assertIn("CREATE TABLE notes", sqlite_preview["sqlite"]["tables"][0]["schema_sql"])
            self.assertIn("schema-sql", sqlite_preview["sqlite"]["review_features"])
            self.assertIn("#54", sqlite_preview["sqlite"]["sqlite_viewer_assessment"]["commercial_gap_ids"])
            self.assertEqual(sqlite_preview["sqlite"]["table_profiles"][0]["name"], "notes")
            self.assertGreaterEqual(sqlite_preview["sqlite"]["table_profiles"][0]["searchable_text_column_count"], 1)
            self.assertTrue(any("SQLite previews show bounded" in item for item in sqlite_preview["viewer_limitations"]))
            sqlite_search_response = client.get(
                f"/api/runs/{run_id}/source-search",
                params={"path": str(sqlite_path), "keyword": "password"},
            )
            self.assertEqual(sqlite_search_response.status_code, 200, sqlite_search_response.text)
            sqlite_search = sqlite_search_response.json()
            self.assertEqual(sqlite_search["summary"]["match_count"], 1)
            self.assertEqual(sqlite_search["matches"][0]["table"], "notes")
            self.assertEqual(sqlite_search["matches"][0]["locator"]["table"], "notes")
            self.assertIn("table notes", sqlite_search["matches"][0]["citation"])
            json_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(json_path)})
            self.assertEqual(json_preview_response.status_code, 200, json_preview_response.text)
            json_preview = json_preview_response.json()
            self.assertEqual(json_preview["preview_type"], "json")
            self.assertEqual(json_preview["viewer_metadata"]["strategy"], "bounded-json-parse")
            self.assertEqual(json_preview["json"]["summary"]["type"], "object")
            xml_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(xml_path)})
            self.assertEqual(xml_preview_response.status_code, 200, xml_preview_response.text)
            xml_preview = xml_preview_response.json()
            self.assertEqual(xml_preview["preview_type"], "xml")
            self.assertEqual(xml_preview["xml"]["root_tag"], "root")
            self.assertTrue(any(node["tag"] == "event" for node in xml_preview["xml"]["nodes"]))
            eml_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(eml_path)})
            self.assertEqual(eml_preview_response.status_code, 200, eml_preview_response.text)
            eml_preview = eml_preview_response.json()
            self.assertEqual(eml_preview["preview_type"], "email")
            self.assertEqual(eml_preview["email"]["messages"][0]["subject"], "Password review")
            self.assertIn("password email body", eml_preview["email"]["messages"][0]["body_preview"])
            self.assertEqual(eml_preview["email"]["thread_count"], 1)
            self.assertEqual(eml_preview["email"]["threads"][0]["message_count"], 1)
            self.assertIn("#55", eml_preview["email"]["email_conversation_viewer_assessment"]["commercial_gap_ids"])
            self.assertEqual(eml_preview["email"]["conversation_view"]["thread_count"], 1)
            self.assertEqual(
                eml_preview["email"]["conversation_view"]["threads"][0]["message_order"][0]["subject"],
                "Password review",
            )
            binary_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(binary_path)})
            self.assertEqual(binary_preview_response.status_code, 200, binary_preview_response.text)
            binary_preview = binary_preview_response.json()
            self.assertEqual(binary_preview["preview_type"], "hex")
            self.assertEqual(binary_preview["hex"]["rows"][0]["offset_hex"], "0x00000000")
            self.assertIn("52 61 70 69 64", binary_preview["hex"]["rows"][0]["hex"])
            self.assertTrue(binary_preview["hex"]["truncated"])
            self.assertEqual(len(binary_preview["hex"]["preview_sha256"]), 64)
            self.assertIn("#53", binary_preview["hex"]["hex_viewer_assessment"]["commercial_gap_ids"])
            self.assertTrue(binary_preview["hex"]["offset_navigation"]["supports_keyword_byte_hits"])
            binary_search_response = client.get(
                f"/api/runs/{run_id}/source-search",
                params={"path": str(binary_path), "keyword": "RapidTriage"},
            )
            self.assertEqual(binary_search_response.status_code, 200, binary_search_response.text)
            binary_search = binary_search_response.json()
            self.assertEqual(binary_search["message"], "Binary/hex byte search completed.")
            self.assertEqual(binary_search["matches"][0]["offset_hex"], "0x00000002")
            self.assertIn("byte offset", binary_search["matches"][0]["citation"])
            image_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(image_path)})
            self.assertEqual(image_preview_response.status_code, 200, image_preview_response.text)
            image_preview = image_preview_response.json()
            self.assertEqual(image_preview["preview_type"], "image")
            self.assertEqual(image_preview["image"]["width"], 16)
            self.assertEqual(len(image_preview["image"]["perceptual_hash"]), 16)
            self.assertIn("#56", image_preview["image"]["gallery_review"]["commercial_gap_ids"])
            self.assertIn("#56", image_preview["image"]["gallery_review_assessment"]["commercial_gap_ids"])
            self.assertIn("#58", image_preview["image"]["ocr_queue_assessment"]["commercial_gap_ids"])
            self.assertIn("#59", image_preview["image"]["korean_ocr_translation_workflow"]["commercial_gap_ids"])
            self.assertIn("similarity-bucketed", image_preview["image"]["gallery_review"]["tag_suggestions"])
            self.assertEqual(image_preview["image"]["ocr_plan"]["status"], "sidecar-imported")
            self.assertEqual(image_preview["image"]["translation_plan"]["status"], "sidecar-imported")
            self.assertIn("translated OCR", image_preview["image"]["translation_sidecar"]["text"])
            media_preview_response = client.get(f"/api/runs/{run_id}/source-preview", params={"path": str(media_path)})
            self.assertEqual(media_preview_response.status_code, 200, media_preview_response.text)
            media_preview = media_preview_response.json()
            self.assertEqual(media_preview["preview_type"], "media")
            self.assertEqual(len(media_preview["media"]["source_hashes"]["sha256"]), 64)
            self.assertEqual(media_preview["media"]["review"]["transcript_alignment"], "sidecar-cue-based")
            self.assertIn("#57", media_preview["media"]["review"]["commercial_gap_ids"])
            self.assertTrue(media_preview["media"]["review"]["cue_navigation_available"])
            self.assertIn("#57", media_preview["media"]["media_transcript_assessment"]["commercial_gap_ids"])
            self.assertEqual(media_preview["media"]["media_transcript_assessment"]["cue_count"], 1)
            self.assertEqual(media_preview["media"]["transcript_sidecars"][0]["cues"][0]["start"], "00:00:00,000")
            self.assertIn("#57", media_preview["media"]["transcript_sidecars"][0]["commercial_gap_ids"])
            self.assertEqual(media_preview["media"]["transcript_sidecars"][0]["cue_count"], 1)
            self.assertEqual(media_preview["media"]["transcript_sidecars"][0]["validation_status"], "sidecar-review-required")
            self.assertEqual(media_preview["media"]["metadata"]["duration_seconds"], 1.0)
            self.assertEqual(media_preview["media"]["transcript_sidecar_count"], 1)
            self.assertIn("password spoken", media_preview["media"]["transcript_sidecars"][0]["preview"])
            filtered_search_response = client.get(
                f"/api/runs/{run_id}/search",
                params={
                    "keyword": "password",
                    "ocr": "false",
                    "source": "documents",
                    "extension": ".txt",
                    "path_contains": "case-root",
                },
            )
            self.assertEqual(filtered_search_response.status_code, 200)
            filtered_search_payload = filtered_search_response.json()
            self.assertGreaterEqual(filtered_search_payload["summary"]["match_count"], 1)
            self.assertEqual(filtered_search_payload["options"]["sources"], ["documents"])
            self.assertEqual(filtered_search_payload["options"]["extensions"], [".txt"])
            self.assertTrue(all(item["source"] == "documents" for item in filtered_search_payload["matches"]))
            self.assertTrue(all(Path(item["path"]).suffix == ".txt" for item in filtered_search_payload["matches"]))
            paged_files_response = client.get(f"/api/runs/{run_id}/files", params={"offset": 1, "limit": 2})
            self.assertEqual(paged_files_response.status_code, 200)
            paged_files = paged_files_response.json()
            self.assertEqual(paged_files["pagination"]["collection"], "candidates")
            self.assertEqual(paged_files["pagination"]["offset"], 1)
            self.assertEqual(paged_files["pagination"]["limit"], 2)
            self.assertEqual(len(paged_files["candidates"]), 2)
            self.assertGreaterEqual(paged_files["pagination"]["total"], 2)
            self.assertIn("next_cursor", paged_files["pagination"])
            cursor_files_response = client.get(
                f"/api/runs/{run_id}/files",
                params={"cursor": paged_files["pagination"]["cursor"], "limit": 2},
            )
            self.assertEqual(cursor_files_response.status_code, 200)
            self.assertEqual(cursor_files_response.json()["pagination"]["offset"], 1)
            paged_docs_response = client.get(f"/api/runs/{run_id}/docs", params={"offset": 0, "limit": 1})
            self.assertEqual(paged_docs_response.status_code, 200)
            paged_docs = paged_docs_response.json()
            self.assertEqual(paged_docs["pagination"]["collection"], "results")
            self.assertLessEqual(len(paged_docs["results"]), 1)
            self.assertIn("candidates", paged_docs["omitted_fields"])
            self.assertTrue((output_dir / "rapidtriage-run-summary.json").is_file())

            persisted = json.loads((output_dir / "rapidtriage-run-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["mode"], "fraud")

            report_response = client.get(f"/api/runs/{run_id}/report")
            artifacts_response = client.get(f"/api/runs/{run_id}/artifacts")
            paged_artifacts_response = client.get(f"/api/runs/{run_id}/artifacts", params={"offset": 0, "limit": 1})

            self.assertEqual(report_response.status_code, 200)
            self.assertIn("rapidtriage run report", report_response.text)
            self.assertEqual(artifacts_response.status_code, 200)
            self.assertIn("artifacts", artifacts_response.json())
            self.assertEqual(paged_artifacts_response.status_code, 200)
            paged_artifacts = paged_artifacts_response.json()["artifacts"]
            first_artifact_group = next(iter(paged_artifacts.values()))
            self.assertEqual(first_artifact_group["pagination"]["collection"], "artifacts")
            self.assertLessEqual(len(first_artifact_group["artifacts"]), 1)

    def test_create_run_rejects_detected_image_that_cannot_be_scanned_directly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "case.ad1"
            source.write_bytes(b"fixture")
            client = TestClient(create_app(RunJobStore()))

            response = client.post(
                "/api/runs",
                json={
                    "root": str(source),
                    "mode": "fraud",
                    "read_only": True,
                    "wait": True,
                },
            )

            self.assertEqual(response.status_code, 400)
            self.assertIn("Mount or export the evidence first", response.json()["detail"])

    def test_bookmark_api_writes_run_case_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            client = TestClient(create_app(RunJobStore()))

            run_response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )
            run_id = run_response.json()["run_id"]

            bookmark_response = client.post(
                f"/api/runs/{run_id}/bookmarks",
                json={
                    "source": "files",
                    "pointer": "/candidates/0",
                    "tag": "review",
                    "tags": ["credential", "report"],
                    "note": (
                        "Check this file.\n\n"
                        "Current-file hit: credentials.txt line 3 offset 12 keyword password\n"
                        "Snippet: admin password found\n"
                        "Review hint: verify source hashes before report inclusion"
                    ),
                    "review_status": "relevant",
                    "include_in_report": True,
                },
            )

            self.assertEqual(bookmark_response.status_code, 200, bookmark_response.text)
            indicator_bookmark_response = client.post(
                f"/api/runs/{run_id}/bookmarks",
                json={
                    "source": "indicators",
                    "pointer": "/indicators/0",
                    "tag": "ioc",
                    "note": "Review this indicator pivot.",
                    "review_status": "needs-review",
                    "include_in_report": False,
                },
            )
            self.assertEqual(indicator_bookmark_response.status_code, 200, indicator_bookmark_response.text)
            case_path = output_dir / "rapidtriage-case.json"
            self.assertTrue(case_path.is_file())

            case_response = client.get(f"/api/runs/{run_id}/case")
            self.assertEqual(case_response.status_code, 200)
            payload = case_response.json()
            self.assertEqual(payload["exists"], True)
            self.assertEqual(payload["case"]["summary"]["bookmark_count"], 2)
            self.assertEqual(payload["case"]["summary"]["report_item_count"], 1)
            self.assertEqual(payload["case"]["summary"]["review_status_counts"]["relevant"], 1)
            self.assertEqual(payload["case"]["summary"]["review_status_counts"]["needs-review"], 1)
            self.assertEqual(payload["case"]["summary"]["review_revision_count"], 2)
            self.assertEqual(payload["case"]["bookmarks"][0]["tags"], ["review", "credential", "report"])
            self.assertEqual(payload["case"]["bookmarks"][0]["review"]["status"], "relevant")
            self.assertEqual(payload["case"]["bookmarks"][0]["review"]["include_in_report"], True)
            self.assertEqual(payload["case"]["bookmarks"][0]["review_history"][0]["action"], "created")

            manifest_response = client.get(f"/api/runs/{run_id}/submission-manifest")
            self.assertEqual(manifest_response.status_code, 200, manifest_response.text)
            manifest = manifest_response.json()
            self.assertEqual(manifest["command"], "submission-manifest")
            validate(
                manifest,
                json.loads((REPO_ROOT / "rapidtriage" / "schemas" / "submission-manifest.schema.json").read_text(encoding="utf-8")),
            )
            self.assertEqual(manifest["summary"]["hashed_item_count"], 1)
            self.assertEqual(manifest["hash_algorithms"], ["md5", "sha1", "sha256"])
            evidence = manifest["items"][0]["evidence"]
            evidence_path = Path(evidence["path"])
            self.assertEqual(evidence["hashes"]["md5"], hash_file(evidence_path, "md5"))
            self.assertEqual(evidence["hashes"]["sha1"], hash_file(evidence_path, "sha1"))
            self.assertEqual(evidence["hashes"]["sha256"], hash_file(evidence_path, "sha256"))
            self.assertTrue((output_dir / "rapidtriage-submission-manifest.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-submission-manifest.audit.json").is_file())

            manifest_file_response = client.get(f"/api/runs/{run_id}/submission-manifest/file")
            self.assertEqual(manifest_file_response.status_code, 200)
            self.assertIn("submission-manifest", manifest_file_response.text)

            report_response = client.post(
                f"/api/runs/{run_id}/case-report",
                json={
                    "template": "technical-appendix",
                    "title": "Incident report",
                    "case_number": "CASE-001",
                    "investigator": "Analyst A",
                    "organization": "Forensic Lab",
                    "requester": "Legal Team",
                    "scope": "Review report-candidate evidence and hashes.",
                    "conclusion": "The listed evidence was reviewed and hashed.",
                },
            )
            self.assertEqual(report_response.status_code, 200, report_response.text)
            report_payload = report_response.json()
            self.assertIn("디지털 포렌식 분석 보고서", report_payload["markdown"])
            self.assertIn("Report template: `technical-appendix`", report_payload["markdown"])
            self.assertIn("Noise policy:", report_payload["markdown"])
            self.assertIn("Technical appendix", report_payload["markdown"])
            self.assertIn("Max extract bytes", report_payload["markdown"])
            self.assertIn("Source path", report_payload["markdown"])
            self.assertIn("IOC/Indicator review pivots", report_payload["markdown"])
            self.assertIn("Review this indicator pivot.", report_payload["markdown"])
            self.assertIn("Source-search cited hits", report_payload["markdown"])
            self.assertIn("credentials.txt line 3 offset 12 keyword password", report_payload["markdown"])
            self.assertIn("Snippet: admin password found", report_payload["markdown"])
            self.assertIn("Review hint: verify source hashes before report inclusion", report_payload["markdown"])
            self.assertIn("CASE-001", report_payload["markdown"])
            self.assertIn(evidence["hashes"]["sha256"], report_payload["markdown"])
            self.assertIn("html", report_payload["exports"])
            self.assertIn("docx", report_payload["exports"])
            self.assertIn("pdf", report_payload["exports"])
            self.assertIn("manifest", report_payload["exports"])
            self.assertTrue((output_dir / "rapidtriage-case-report.md").is_file())
            self.assertTrue((output_dir / "rapidtriage-case-report.html").is_file())
            self.assertTrue((output_dir / "rapidtriage-case-report.docx").is_file())
            self.assertTrue((output_dir / "rapidtriage-case-report.pdf").is_file())
            self.assertTrue((output_dir / "rapidtriage-case-report.exports.json").is_file())
            self.assertTrue((output_dir / "rapidtriage-case-report.audit.md").is_file())
            self.assertIn("case-report-docx", (output_dir / "rapidtriage-case-report.audit.md").read_text(encoding="utf-8"))
            self.assertIn("case-report-pdf", (output_dir / "rapidtriage-case-report.audit.md").read_text(encoding="utf-8"))
            export_manifest = json.loads((output_dir / "rapidtriage-case-report.exports.json").read_text(encoding="utf-8"))
            self.assertIn("sha256", export_manifest["files"]["pdf"])
            self.assertEqual(export_manifest["files"]["pdf"]["filename"], "rapidtriage-case-report.pdf")
            with zipfile.ZipFile(output_dir / "rapidtriage-case-report.docx") as report_docx:
                self.assertIn("word/document.xml", report_docx.namelist())
            self.assertEqual((output_dir / "rapidtriage-case-report.pdf").read_bytes()[:5], b"%PDF-")

            report_file_response = client.get(f"/api/runs/{run_id}/case-report/file")
            self.assertEqual(report_file_response.status_code, 200)
            self.assertIn("디지털 포렌식 분석 보고서", report_file_response.text)
            html_report_response = client.get(f"/api/runs/{run_id}/case-report/file/html")
            self.assertEqual(html_report_response.status_code, 200)
            self.assertIn("<h1>디지털 포렌식 분석 보고서</h1>", html_report_response.text)
            docx_report_response = client.get(f"/api/runs/{run_id}/case-report/file/docx")
            self.assertEqual(docx_report_response.status_code, 200)
            self.assertGreater(len(docx_report_response.content), 500)
            pdf_report_response = client.get(f"/api/runs/{run_id}/case-report/file/pdf")
            self.assertEqual(pdf_report_response.status_code, 200)
            self.assertEqual(pdf_report_response.content[:5], b"%PDF-")
            export_manifest_response = client.get(f"/api/runs/{run_id}/case-report/file/manifest")
            self.assertEqual(export_manifest_response.status_code, 200)
            self.assertIn("case-report.exports", export_manifest_response.text)

            bundle_response = client.post(
                f"/api/runs/{run_id}/reviewer-bundle",
                json={"title": "Reviewer handoff", "max_items": 50},
            )
            self.assertEqual(bundle_response.status_code, 200, bundle_response.text)
            bundle_payload = bundle_response.json()
            self.assertEqual(bundle_payload["command"], "bundle")
            self.assertTrue((output_dir / "rapidtriage-reviewer-bundle" / "rapidtriage-reviewer.html").is_file())
            self.assertTrue((output_dir / "rapidtriage-reviewer-bundle.zip").is_file())
            self.assertIn("sha256", bundle_payload["archive_hashes"])
            with zipfile.ZipFile(output_dir / "rapidtriage-reviewer-bundle.zip") as reviewer_zip:
                self.assertIn("rapidtriage-reviewer.html", reviewer_zip.namelist())
                self.assertIn("rapidtriage-selected-evidence.json", reviewer_zip.namelist())
                self.assertIn("rapidtriage-bundle-manifest.json", reviewer_zip.namelist())

            bundle_file_response = client.get(f"/api/runs/{run_id}/reviewer-bundle/file")
            self.assertEqual(bundle_file_response.status_code, 200)
            self.assertEqual(bundle_file_response.content[:2], b"PK")

    def test_run_catalog_persists_and_imports_existing_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            root = tmp_path / "case-root"
            output_dir = tmp_path / "run-out"
            state_path = tmp_path / "state" / "runs.json"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)

            store = RunJobStore(state_path=state_path)
            client = TestClient(create_app(store))
            run_response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )
            run_id = run_response.json()["run_id"]

            restored_client = TestClient(create_app(RunJobStore(state_path=state_path)))
            restored_response = restored_client.get(f"/api/runs/{run_id}")

            self.assertEqual(restored_response.status_code, 200)
            self.assertEqual(restored_response.json()["status"], "completed")

            import_response = restored_client.post("/api/runs/import", json={"output_dir": str(output_dir)})
            self.assertEqual(import_response.status_code, 201, import_response.text)
            self.assertEqual(import_response.json()["status"], "completed")
            self.assertEqual(import_response.json()["origin"], "imported")

            output_files_response = restored_client.get(f"/api/runs/{run_id}/output-files")
            self.assertEqual(output_files_response.status_code, 200)
            names = {item["name"] for item in output_files_response.json()["files"]}
            self.assertIn("report", names)
            self.assertIn("summary", names)

            report_download = restored_client.get(f"/api/runs/{run_id}/outputs/report/file")
            self.assertEqual(report_download.status_code, 200)
            self.assertIn("rapidtriage run report", report_download.text)

            delete_response = restored_client.delete(f"/api/runs/{run_id}")
            self.assertEqual(delete_response.status_code, 204)
            self.assertEqual(restored_client.get(f"/api/runs/{run_id}").status_code, 404)

    def test_case_db_api_imports_searches_and_marks_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            db_path = Path(tmp_dir) / "case.db"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            client = TestClient(create_app(RunJobStore()))

            run_response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )
            self.assertEqual(run_response.status_code, 202, run_response.text)

            import_response = client.post(
                "/api/case-db/import-run",
                json={
                    "database": str(db_path),
                    "run_output": str(output_dir),
                    "case_id": "CASE-API-DB",
                    "name": "API Case DB",
                },
            )
            self.assertEqual(import_response.status_code, 200, import_response.text)
            self.assertGreaterEqual(import_response.json()["summary"]["indexed_document_count"], 1)

            search_response = client.post(
                "/api/case-db/search",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "keywords": ["password"],
                    "sources": ["documents"],
                    "save_as": "Password review",
                },
            )
            self.assertEqual(search_response.status_code, 200, search_response.text)
            search_payload = search_response.json()
            self.assertGreaterEqual(search_payload["summary"]["match_count"], 1)
            self.assertEqual(search_payload["saved_search"]["name"], "Password review")
            target = search_payload["matches"][0]

            review_response = client.post(
                "/api/case-db/review",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "target_type": target["target_type"],
                    "target_id": target["target_id"],
                    "status": "relevant",
                    "verification_status": "source_opened",
                    "tags": ["credential"],
                    "note": "Opened in viewer.",
                    "reviewer": "api-test",
                    "assignee": "analyst-a",
                    "priority": "high",
                    "due_at": "2026-04-30T09:00:00+09:00",
                    "include_in_report": True,
                },
            )
            self.assertEqual(review_response.status_code, 200, review_response.text)
            self.assertEqual(review_response.json()["verification_status"], "source_opened")
            self.assertEqual(review_response.json()["assignee"], "analyst-a")
            self.assertEqual(review_response.json()["priority"], "high")
            self.assertEqual(review_response.json()["due_at"], "2026-04-30T09:00:00+09:00")
            self.assertIn("#51", review_response.json()["review_workflow"]["commercial_gap_ids"])

            saved_searches_response = client.post(
                "/api/case-db/saved-searches/list",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                },
            )
            self.assertEqual(saved_searches_response.status_code, 200, saved_searches_response.text)
            self.assertEqual(saved_searches_response.json()["saved_searches"][0]["name"], "Password review")

            batch_response = client.post(
                "/api/case-db/review-batch",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "targets": [
                        {
                            "target_type": target["target_type"],
                            "target_id": target["target_id"],
                        }
                    ],
                    "status": "relevant",
                    "verification_status": "verified",
                    "tags": ["credential", "batch"],
                    "note": "Batch verified.",
                    "reviewer": "api-test",
                    "assignee": "lead-reviewer",
                    "priority": "urgent",
                    "include_in_report": True,
                },
            )
            self.assertEqual(batch_response.status_code, 200, batch_response.text)
            self.assertEqual(batch_response.json()["updated_count"], 1)
            self.assertEqual(batch_response.json()["marks"][0]["assignee"], "lead-reviewer")
            self.assertEqual(batch_response.json()["marks"][0]["priority"], "urgent")
            self.assertTrue(batch_response.json()["marks"][0]["review_workflow"]["assignment_present"])

            export_response = client.post(
                "/api/case-db/report-export",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                },
            )
            self.assertEqual(export_response.status_code, 200, export_response.text)
            export_payload = export_response.json()
            self.assertEqual(export_payload["command"], "case-db-report-export")
            self.assertGreaterEqual(export_payload["summary"]["exported_item_count"], 1)
            self.assertEqual(export_payload["items"][0]["review"]["include_in_report"], True)
            self.assertIn("target_citation_id", export_payload["items"][0])

            filtered_response = client.post(
                "/api/case-db/search",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-API-DB",
                    "keywords": ["password"],
                    "sources": ["documents"],
                    "review_status": "relevant",
                    "verification_status": "verified",
                },
            )
            self.assertEqual(filtered_response.status_code, 200, filtered_response.text)
            filtered_payload = filtered_response.json()
            self.assertGreaterEqual(filtered_payload["summary"]["match_count"], 1)
            self.assertEqual(filtered_payload["matches"][0]["review"]["status"], "relevant")

    def test_run_case_db_ensure_imports_once_for_default_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "case-root"
            output_dir = Path(tmp_dir) / "run-out"
            db_path = Path(tmp_dir) / "case-default.db"
            root.mkdir(parents=True, exist_ok=True)
            build_run_fixture(root)
            client = TestClient(create_app(RunJobStore()))

            run_response = client.post(
                "/api/runs",
                json={
                    "root": str(root),
                    "mode": "fraud",
                    "output_dir": str(output_dir),
                    "read_only": True,
                    "wait": True,
                },
            )
            self.assertEqual(run_response.status_code, 202, run_response.text)
            run_id = run_response.json()["run_id"]

            first_ensure = client.post(
                f"/api/runs/{run_id}/case-db/ensure",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-DEFAULT-WORKFLOW",
                    "name": "Default Case DB Workflow",
                },
            )
            self.assertEqual(first_ensure.status_code, 200, first_ensure.text)
            first_payload = first_ensure.json()
            self.assertEqual(first_payload["command"], "case-db.ensure-run")
            self.assertEqual(first_payload["case_id"], "CASE-DEFAULT-WORKFLOW")
            self.assertEqual(first_payload["database"], str(db_path.resolve()))
            self.assertEqual(first_payload["imported"], True)
            self.assertGreaterEqual(first_payload["storage"]["summary"]["indexed_document_count"], 1)

            second_ensure = client.post(
                f"/api/runs/{run_id}/case-db/ensure",
                json={
                    "database": str(db_path),
                    "case_id": "CASE-DEFAULT-WORKFLOW",
                },
            )
            self.assertEqual(second_ensure.status_code, 200, second_ensure.text)
            second_payload = second_ensure.json()
            self.assertEqual(second_payload["imported"], False)
            self.assertEqual(
                second_payload["storage"]["summary"]["indexed_document_count"],
                first_payload["storage"]["summary"]["indexed_document_count"],
            )

            search_response = client.post(
                "/api/case-db/search",
                json={
                    "database": second_payload["database"],
                    "case_id": second_payload["case_id"],
                    "keywords": ["password"],
                    "sources": ["documents"],
                },
            )
            self.assertEqual(search_response.status_code, 200, search_response.text)
            self.assertGreaterEqual(search_response.json()["summary"]["match_count"], 1)

    def test_imported_summary_cannot_expose_files_outside_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            output_dir = tmp_path / "run-out"
            output_dir.mkdir()
            outside_file = tmp_path / "outside.txt"
            outside_file.write_text("do not expose", encoding="utf-8")
            summary_path = output_dir / "rapidtriage-run-summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "mode": "fraud",
                        "root": str(tmp_path / "case-root"),
                        "output_dir": str(output_dir),
                        "input_kind": "folder",
                        "summary": {},
                        "outputs": {
                            "summary": str(summary_path),
                            "report": str(outside_file),
                        },
                    }
                ),
                encoding="utf-8",
            )

            client = TestClient(create_app(RunJobStore()))
            import_response = client.post("/api/runs/import", json={"output_dir": str(output_dir)})
            self.assertEqual(import_response.status_code, 201, import_response.text)
            run_id = import_response.json()["run_id"]

            report_response = client.get(f"/api/runs/{run_id}/outputs/report/file")
            self.assertEqual(report_response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
