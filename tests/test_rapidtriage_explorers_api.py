"""탐색기 API (plan r4 §2.2 V2): fs-tree + files path filter, registry tree/values, media similar/groups."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

try:
    from fastapi.testclient import TestClient

    from rapidtriage.api.app import create_app, fs_tree, media_similar, registry_tree

    HAS_FASTAPI = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    HAS_FASTAPI = False

from rapidtriage.artifacts.windows.registry import NativeRegistryHive
from rapidtriage.core.jobs import RunJobStore
from tests.test_parser_quality_registry import (
    REG_DWORD,
    REG_MULTI_SZ,
    REG_SZ,
    HiveWriter,
    Key,
    sz,
)

TOKEN = "explorers-test-token"


def system_hive() -> bytes:
    root = Key("ROOT")
    root.path("Select").value("Current", REG_DWORD, (1).to_bytes(4, "little")).value("LastKnownGood", REG_DWORD, (2).to_bytes(4, "little"))
    control = root.path(r"ControlSet001\Control\ComputerName\ComputerName")
    control.value("ComputerName", REG_SZ, sz("분석-PC")).value("", REG_SZ, sz("mnmsrvc"))
    root.path(r"ControlSet001\Services\Tcpip").value("Multi", REG_MULTI_SZ, "a\x00b\x00\x00".encode("utf-16-le"))
    return HiveWriter().build(root)


def key_tree_rows(hive_bytes: bytes, hive_path: str, mount: str) -> list[dict[str, object]]:
    hive = NativeRegistryHive.from_bytes(hive_bytes)
    assert hive is not None
    rows: list[dict[str, object]] = []
    for parts, key in hive.iter_keys():
        rows.append(
            {
                "provider": "windows-registry",
                "artifact_type": "registry-key-tree-node",
                "path": hive_path,
                "details": {
                    "key_path": "\\".join((mount, *parts)),
                    "key_depth": len(parts),
                    "is_root_key": not parts,
                    "name": key.name,
                    "last_written_filetime": 133847925753805780,
                    "subkey_count": key.subkey_count,
                    "value_count": key.value_count,
                    "value_names": [str(value.name) for value in hive.values(key)],
                    "cell_offset": key.offset,
                },
            }
        )
    return rows


def file_row(root: Path, relative: str, size: int, **extra: object) -> dict[str, object]:
    path = root.joinpath(*relative.split("/"))
    return {"path": str(path), "name": path.name, "relative_path": relative, "size": size, "categories": ["documents"], **extra}


@unittest.skipUnless(HAS_FASTAPI, "fastapi is required for explorer API tests")
class ExplorersApiTests(unittest.TestCase):
    def setUp(self) -> None:
        fs_tree.clear_fs_index_cache()
        registry_tree.clear_registry_index_cache()
        media_similar.clear_media_index_cache()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.evidence = base / "evidence"
        self.run_dir = base / "run"
        self.run_dir.mkdir()
        config = self.evidence / "Windows" / "System32" / "config"
        config.mkdir(parents=True)
        self.hive_bytes = system_hive()
        self.hive_path = config / "SYSTEM"
        self.hive_path.write_bytes(self.hive_bytes)
        ev = self.evidence
        candidates = [
            file_row(ev, "Users/alice/Desktop/a.jpg", 100),
            file_row(ev, "Users/alice/Desktop/b.jpg", 200),
            file_row(ev, "Users/alice/Desktop/sub/c.txt", 50),
            file_row(ev, "Users/bob/d.txt", 5),
            file_row(ev, "top.txt", 1),
            file_row(ev, "users/ALICE/desktop/e.txt", 7),  # same folders, other spelling
            {"path": r"Z:\elsewhere\x.txt", "name": "x.txt", "size": 9},  # outside the evidence root
            file_row(ev, "Users/alice/orphan.bin", 3, recovery={"candidate_kind": "orphan-record"}),
            file_row(ev, "$Carved/f001.jpg", 4, recovery={"candidate_kind": "carved", "deletion_state": "unallocated-candidate"}),
        ]
        inventory = [
            {"path": str(ev / "Windows" / "System32" / "config" / "SYSTEM"), "relative_path": "Windows/System32/config/SYSTEM", "size": len(self.hive_bytes), "categories": ["other"]},
            {"path": str(ev / "Users" / "alice" / "Desktop" / "z.log"), "size": 10, "categories": ["other"]},  # no relative_path
        ]
        hive_rows = key_tree_rows(self.hive_bytes, str(self.hive_path), r"HKLM\SYSTEM")
        linked = {
            "provider": "windows-registry",
            "artifact_type": "windows-control-set",
            "path": str(self.hive_path),
            "details": {"key_path": r"HKLM\SYSTEM\Select", "label": "현재 컨트롤 세트"},
        }
        unlinked = {"provider": "windows-registry", "artifact_type": "windows-timezone", "path": str(self.hive_path), "details": {"key_path": r"HKLM\SYSTEM\Nope"}}
        registry_records = [*hive_rows, linked, unlinked]
        self.registry_records = registry_records
        records_path = self.run_dir / "registry.jsonl"
        records_path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in registry_records), encoding="utf-8")

        def image(name: str, phash: str | None, sha: str, **details: object) -> dict[str, object]:
            path = str(ev / "Users" / "alice" / "Desktop" / name)
            return {
                "artifact_type": "media-image",
                "path": path,
                "details": {"source_path": path, "perceptual_hash": phash, "hashes": {"sha256": sha}, **details},
            }

        images = [
            image("a.jpg", "0000000000000000", "aa", exif_make="Apple", exif_model="iPhone 13 Pro", exif_datetime_original="2024:05:01 10:00:00"),
            image("copy.jpg", "0000000000000000", "aa", exif_make="Apple", exif_model="iPhone 13 Pro", exif_datetime_original="2024:05:01 11:00:00"),
            image("near.jpg", "00000000000000ff", "bb", timestamp="2024-05-02T00:00:00+00:00"),
            image("nine.jpg", "00000000000001ff", "cc"),
            image("far.jpg", "ffffffffffffffff", "dd"),
            image("nophash.jpg", None, "ee"),
        ]
        outputs: dict[str, object] = {
            "files": {"root": str(ev), "scan_scope_root": str(ev), "candidates": candidates, "inventory": inventory},
            "artifacts_windows-registry": {
                "records_path": str(records_path),
                "record_count": len(registry_records),
                "artifacts": [],
                "summary": {"artifact_count": len(registry_records)},
            },
            "artifacts_media-image": {"artifacts": images, "record_count": len(images), "summary": {"artifact_count": len(images)}},
        }
        summary_outputs: dict[str, str] = {}
        for name, payload in outputs.items():
            path = self.run_dir / f"{name}.json"
            path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            summary_outputs[name] = str(path)
        summary_path = self.run_dir / "rapidtriage-run-summary.json"
        summary_outputs["summary"] = str(summary_path)
        summary_path.write_text(
            json.dumps(
                {
                    "profile_version": "rapidtriage-run-summary-v1",
                    "mode": "hacking",
                    "root": str(ev),
                    "output_dir": str(self.run_dir),
                    "source": {"type": "directory", "analysis_root": str(ev)},
                    "outputs": summary_outputs,
                    "summary": {"counts": {"files": len(candidates)}},
                }
            ),
            encoding="utf-8",
        )
        self.store = RunJobStore()
        self.run_id = self.store.import_completed_run(self.run_dir).run_id
        self.client = TestClient(create_app(self.store, auth_token=TOKEN), headers={"X-RapidTriage-Token": TOKEN})

    def get(self, endpoint: str, expect: int = 200, **params: object) -> dict[str, object]:
        response = self.client.get(f"/api/runs/{self.run_id}{endpoint}", params=params)
        self.assertEqual(response.status_code, expect, response.text)
        return response.json()

    # --- file system --------------------------------------------------------------------

    def test_fs_tree_root_counts_and_special_nodes(self) -> None:
        root = self.get("/fs-tree")
        self.assertEqual([child["name"] for child in root["children"]], ["$Carved", "Users"])
        self.assertEqual(root["node"]["direct_file_count"], 1)  # top.txt
        self.assertEqual(root["node"]["file_count"], 8)  # every candidate but the outside one
        self.assertEqual(root["index"]["outside_root"], 1)
        self.assertTrue(root["index"]["outside_root_reason"])
        self.assertEqual(root["scope_counts"], {"candidates": 8, "inventory": 2})
        users = next(child for child in root["children"] if child["name"] == "Users")
        self.assertEqual((users["file_count"], users["size"], users["direct_file_count"]), (6, 365, 0))
        shown = {node["id"]: node for node in root["special_nodes"]}
        self.assertEqual(shown["orphan"]["count"], 1)
        self.assertEqual(shown["orphan"]["files_query"], {"special": "orphan"})
        self.assertEqual(shown["unallocated"]["count"], 1)
        hidden = {node["id"]: node["reason"] for node in root["hidden_special_nodes"]}
        self.assertIn("슬랙", hidden["slack"])
        self.assertEqual(root["volume"]["label"], "볼륨 1 (스캔 루트)")

    def test_folders_group_case_insensitively_with_breadcrumb(self) -> None:
        desktop = self.get("/fs-tree", path="Users/alice/Desktop")
        self.assertEqual(desktop["node"]["direct_file_count"], 3)  # a.jpg, b.jpg, e.txt (other spelling)
        self.assertEqual(desktop["node"]["file_count"], 4)
        self.assertEqual([crumb["name"] for crumb in desktop["breadcrumb"]], ["Users", "alice", "Desktop"])
        self.assertEqual(desktop["breadcrumb"][-1]["path"], "Users/alice/Desktop")
        self.assertNotIn("special_nodes", desktop)
        same = self.get("/fs-tree", path="\\users\\ALICE\\desktop\\")
        self.assertEqual(same["node"]["path"], "Users/alice/Desktop")

    def test_folder_counts_equal_files_filter_totals(self) -> None:
        folders = ["", "Users", "Users/alice", "Users/alice/Desktop", "Users/alice/Desktop/sub", "Users/bob", "Windows/System32/config"]
        for scope in ("candidates", "inventory"):
            for folder in folders:
                tree = self.get("/fs-tree", path=folder, scope=scope)["node"]
                for recursive, expected in (("0", tree["direct_file_count"]), ("1", tree["file_count"])):
                    page = self.get("/files", path_prefix=folder, recursive=recursive, scope=scope, limit=1000)
                    self.assertEqual(page["matched"], expected, (scope, folder, recursive))
                    self.assertEqual(len(page[scope]), expected)
                    self.assertEqual(page["path_filter"], {"path": folder, "recursive": recursive == "1", "special": None, "rows": expected})
        page = self.get("/files", path_prefix="Users/alice/Desktop", limit=1, offset=1)
        self.assertEqual(page["pagination"]["total"], 3)
        self.assertEqual(page["candidates"][0]["record_index"], 1)  # position in the full candidates list
        inventory = self.get("/fs-tree", path="Users/alice/Desktop", scope="inventory")["node"]
        self.assertEqual(inventory["direct_file_count"], 1)  # z.log placed by its absolute path

    def test_files_path_filter_composes_with_category_and_special(self) -> None:
        page = self.get("/files", path_prefix="Users", recursive="1", category="documents", limit=50)
        self.assertEqual(page["matched"], 6)
        self.assertEqual(self.get("/files", path_prefix="Users", recursive="1", category="images", limit=50)["matched"], 0)
        orphan = self.get("/files", special="orphan", limit=50)
        self.assertEqual([row["name"] for row in orphan["candidates"]], ["orphan.bin"])
        both = self.get("/files", special="unallocated", path_prefix="Users", recursive="1", limit=50)
        self.assertEqual(both["matched"], 0)
        self.assertEqual(self.get("/files", path_prefix="Users", limit=0, expect=400)["detail"], "필터는 limit>0에서만 지원합니다")

    def test_children_paging_has_no_gaps(self) -> None:
        names: list[str] = []
        after = None
        for _ in range(5):
            params = {"path": "Users/alice", "limit": "1", **({"after": after} if after else {})}
            page = self.get("/fs-tree", **params)
            names.extend(child["name"] for child in page["children"])
            self.assertEqual(page["child_total"], 1)
            after = page["next_after"]
            if after is None:
                break
        self.assertEqual(names, ["Desktop"])
        root_names: list[str] = []
        after = None
        for _ in range(5):
            page = self.get("/fs-tree", limit="1", **({"after": after} if after else {}))
            root_names.extend(child["name"] for child in page["children"])
            after = page["next_after"]
            if after is None:
                break
        self.assertEqual(root_names, ["$Carved", "Users"])

    def test_bad_parameters_are_korean_and_paths_are_confined(self) -> None:
        cases = [
            ({"path": "../Windows"}, 422, "'..'"),
            ({"path": "Users/../../x"}, 422, "'..'"),
            ({"path": "Users\x01"}, 422, "제어 문자"),
            ({"limit": "0"}, 422, "limit"),
            ({"limit": "abc"}, 422, "limit"),
            ({"limit": "1001"}, 422, "limit"),
            ({"scope": "all"}, 422, "scope"),
            ({"after": "!!!"}, 422, "커서"),
            ({"path": r"C:\Windows"}, 403, "증거 루트 밖"),
            ({"path": "Nope/Folder"}, 404, "폴더를 찾을 수 없습니다"),
        ]
        for params, status, text in cases:
            detail = self.get("/fs-tree", expect=status, **params)["detail"]
            self.assertIn(text, detail, params)
        inside = self.get("/fs-tree", path=str(self.evidence / "Users"))
        self.assertEqual(inside["node"]["path"], "Users")
        self.assertEqual(self.get("/fs-tree", path=str(self.evidence))["node"]["path"], "")
        self.assertIn("true 또는 false", self.get("/files", path_prefix="Users", recursive="maybe", limit=5, expect=422)["detail"])
        self.assertIn("path_prefix와 함께", self.get("/files", recursive="1", limit=5, expect=422)["detail"])
        self.assertIn("special", self.get("/files", special="trash", limit=5, expect=422)["detail"])
        self.assertIn("'..'", self.get("/files", path_prefix="..", limit=5, expect=422)["detail"])

    def test_fs_index_caps(self) -> None:
        with mock.patch.object(fs_tree, "FS_TREE_MAX_ROWS", 3):
            fs_tree.clear_fs_index_cache()
            root = self.get("/fs-tree")
            self.assertTrue(root["index"]["truncated"])
            self.assertIn("3", root["index"]["reason"])
            self.assertEqual(root["node"]["file_count"], 3)
        with mock.patch.object(fs_tree, "FS_TREE_MAX_DIRS", 2):
            fs_tree.clear_fs_index_cache()
            root = self.get("/fs-tree")
            self.assertTrue(root["index"]["truncated"])
            self.assertIn("폴더", root["index"]["reason"])

    def test_rewritten_files_output_rebuilds_the_index(self) -> None:
        self.assertEqual(self.get("/fs-tree")["node"]["file_count"], 8)
        path = self.run_dir / "files.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["candidates"] = payload["candidates"][:2]
        path.write_text(json.dumps(payload, ensure_ascii=False) + " ", encoding="utf-8")
        self.store.import_completed_run(self.run_dir)
        self.assertEqual(self.get("/fs-tree")["node"]["file_count"], 2)

    # --- registry -----------------------------------------------------------------------

    def hive(self) -> dict[str, object]:
        hives = self.get("/registry-tree")["hives"]
        self.assertEqual(len(hives), 1)
        return hives[0]

    def test_registry_hives_and_key_levels(self) -> None:
        listing = self.get("/registry-tree")
        hive = listing["hives"][0]
        self.assertEqual((hive["name"], hive["mount"]), ("SYSTEM", r"HKLM\SYSTEM"))
        self.assertEqual(listing["index"]["linked_rows"], 1)
        self.assertEqual(listing["index"]["unresolved_links"], 1)
        root = self.get("/registry-tree", hive=hive["id"])
        self.assertEqual(root["key"]["key_path"], r"HKLM\SYSTEM")
        self.assertEqual([child["name"] for child in root["children"]], ["ControlSet001", "Select"])
        select = root["children"][1]
        self.assertEqual((select["value_count"], select["has_children"], select["linked_row_count"]), (2, False, 1))
        self.assertEqual(select["last_written_at"], "2025-02-23T13:56:15.3805780+00:00")
        deep = self.get("/registry-tree", hive=hive["id"], key=r"hklm\system\controlset001\control")
        self.assertEqual(deep["key"]["key_path"], r"HKLM\SYSTEM\ControlSet001\Control")
        self.assertEqual([crumb["name"] for crumb in deep["breadcrumb"]], [r"HKLM\SYSTEM", "ControlSet001", "Control"])
        paged = self.get("/registry-tree", hive=hive["id"], limit="1")
        self.assertEqual(len(paged["children"]), 1)
        rest = self.get("/registry-tree", hive=hive["id"], limit="1", after=paged["next_after"])
        self.assertEqual([child["name"] for child in rest["children"]], ["Select"])
        self.assertIsNone(rest["next_after"])

    def test_registry_values_decoded_with_citation_and_jump_rows(self) -> None:
        hive = self.hive()
        select = self.get("/registry-values", hive=hive["id"], key=r"HKLM\SYSTEM\Select")
        self.assertEqual(select["values_status"], "parsed")
        self.assertEqual([(v["name"], v["type"], v["decoded"]) for v in select["values"]], [("Current", "REG_DWORD", 1), ("LastKnownGood", "REG_DWORD", 2)])
        self.assertIn(r"HKLM\SYSTEM\Select", select["citation"]["text"])
        self.assertIn("셀 오프셋 0x", select["citation"]["text"])
        self.assertEqual(select["citation"]["locator"], f"/artifacts/{select['key']['record_index']}")
        self.assertEqual(select["artifact_row_total"], 1)
        jump = select["artifact_rows"][0]
        self.assertEqual((jump["kind"], jump["artifact_type"], jump["label"]), ("windows-registry", "windows-control-set", "현재 컨트롤 세트"))
        self.assertEqual(self.registry_records[jump["record_index"]]["artifact_type"], "windows-control-set")
        name = self.get("/registry-values", hive=hive["id"], key=r"HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName")
        decoded = {value["display_name"]: value["decoded"] for value in name["values"]}
        self.assertEqual(decoded["ComputerName"], "분석-PC")
        self.assertEqual(decoded["(기본값)"], "mnmsrvc")
        multi = self.get("/registry-values", hive=hive["id"], key=r"HKLM\SYSTEM\ControlSet001\Services\Tcpip")
        self.assertEqual((multi["values"][0]["decoded_kind"], multi["values"][0]["decoded"]), ("list", ["a", "b"]))

    def test_registry_values_fall_back_to_names_without_the_hive_file(self) -> None:
        hive = self.hive()
        self.hive_path.unlink()
        select = self.get("/registry-values", hive=hive["id"], key=r"HKLM\SYSTEM\Select")
        self.assertEqual(select["values_status"], "names-only")
        self.assertIn("수집된 값 이름만", select["reason"])
        self.assertEqual([value["name"] for value in select["values"]], ["Current", "LastKnownGood"])
        self.assertEqual(select["value_total"], 2)

    def test_registry_errors_are_korean(self) -> None:
        hive = self.hive()
        self.assertIn("하이브를 찾을 수 없습니다", self.get("/registry-tree", hive="nope", expect=404)["detail"])
        self.assertIn("키를 찾을 수 없습니다", self.get("/registry-tree", hive=hive["id"], key=r"HKLM\SYSTEM\Nope", expect=404)["detail"])
        self.assertIn("키를 찾을 수 없습니다", self.get("/registry-values", hive=hive["id"], key=r"HKLM\SOFTWARE", expect=404)["detail"])
        self.assertIn("hive", self.get("/registry-tree", key=r"HKLM\SYSTEM", expect=422)["detail"])
        self.assertIn("hive", self.get("/registry-values", expect=422)["detail"])
        self.assertIn("limit", self.get("/registry-tree", hive=hive["id"], limit="-1", expect=422)["detail"])
        self.assertIn("제어 문자", self.get("/registry-values", hive=hive["id"], key="HKLM\x02", expect=422)["detail"])

    def test_registry_index_cap(self) -> None:
        with mock.patch.object(registry_tree, "REGISTRY_TREE_MAX_NODES", 3):
            registry_tree.clear_registry_index_cache()
            listing = self.get("/registry-tree")
            self.assertTrue(listing["index"]["truncated"])
            self.assertIn("3", listing["index"]["reason"])
            self.assertLessEqual(listing["index"]["keys"], 3)

    def test_run_without_registry_rows_says_why(self) -> None:
        with mock.patch.object(registry_tree, "registry_sources", return_value=[]):
            listing = self.get("/registry-tree")
        self.assertEqual(listing["hives"], [])
        self.assertIn("레지스트리 키 트리", listing["reason"])

    # --- media --------------------------------------------------------------------------

    def ref(self, name: str) -> str:
        return str(self.evidence / "Users" / "alice" / "Desktop" / name)

    def test_similar_media_by_phash_distance(self) -> None:
        page = self.get("/media/similar", ref=self.ref("a.jpg"))
        self.assertEqual([(item["name"], item["distance"], item["same_hash"]) for item in page["items"]], [("copy.jpg", 0, True), ("near.jpg", 8, False)])
        self.assertEqual(page["counts"]["same_hash"], 1)
        self.assertEqual(page["counts"]["near"], 1)
        self.assertEqual(page["counts"]["matched"], 2)
        self.assertEqual(page["ref"]["perceptual_hash"], "0000000000000000")
        wider = self.get("/media/similar", ref=self.ref("a.jpg").upper(), max_distance="9")
        self.assertEqual([item["name"] for item in wider["items"]], ["copy.jpg", "near.jpg", "nine.jpg"])
        first = self.get("/media/similar", ref=self.ref("a.jpg"), max_distance="16", limit="1")
        self.assertEqual((first["counts"]["matched"], first["counts"]["returned"]), (3, 1))

    def test_similar_media_errors(self) -> None:
        self.assertIn("max_distance", self.get("/media/similar", ref=self.ref("a.jpg"), max_distance="17", expect=422)["detail"])
        self.assertIn("max_distance", self.get("/media/similar", ref=self.ref("a.jpg"), max_distance="x", expect=422)["detail"])
        self.assertIn("ref", self.get("/media/similar", expect=422)["detail"])
        self.assertIn("목록에 없습니다", self.get("/media/similar", ref=self.ref("missing.jpg"), expect=404)["detail"])
        self.assertIn("pHash", self.get("/media/similar", ref=self.ref("nophash.jpg"), expect=409)["detail"])

    def test_media_groups_by_camera_and_date(self) -> None:
        cameras = self.get("/media/groups", by="camera")
        self.assertEqual([(g["label"], g["count"]) for g in cameras["groups"]], [("Apple iPhone 13 Pro", 2), ("카메라 정보 없음", 4)])
        members = self.get("/media/groups", by="camera", key="Apple iPhone 13 Pro")
        self.assertEqual(sorted(Path(path).name for path in members["paths"]), ["a.jpg", "copy.jpg"])
        self.assertEqual(members["path_total"], 2)
        dates = self.get("/media/groups", by="date")
        self.assertEqual([(g["key"], g["count"]) for g in dates["groups"]], [("2024-05-02", 1), ("2024-05-01", 2), ("", 3)])
        self.assertEqual(dates["groups"][-1]["label"], "촬영일 없음")
        self.assertIn("by", self.get("/media/groups", by="size", expect=422)["detail"])
        self.assertIn("그룹을 찾을 수 없습니다", self.get("/media/groups", by="camera", key="Nikon", expect=404)["detail"])

    def test_media_index_cap(self) -> None:
        with mock.patch.object(media_similar, "MEDIA_INDEX_MAX_ROWS", 2):
            media_similar.clear_media_index_cache()
            groups = self.get("/media/groups", by="camera")
            self.assertTrue(groups["index"]["truncated"])
            self.assertEqual(groups["index"]["indexed"], 2)


if __name__ == "__main__":
    unittest.main()
