"""탐색기 routes (plan r4 §2.2 V2): file system, registry and media explorers.

* ``GET /api/runs/{run_id}/fs-tree?path=&scope=&limit=&after=`` -- one folder
  level of the files output (``fs_tree``).
* ``GET /api/runs/{run_id}/registry-tree?hive=&key=&limit=&after=`` -- hives,
  or one key's child keys (``registry_tree``).
* ``GET /api/runs/{run_id}/registry-values?hive=&key=&limit=`` -- a key's
  values, citation and linked artifact rows.
* ``GET /api/runs/{run_id}/media/similar?ref=&max_distance=&limit=`` -- pHash
  neighbours of one image (``media_similar``).
* ``GET /api/runs/{run_id}/media/groups?by=camera|date&key=`` -- EXIF camera /
  capture-day groups (``key`` = that group's paths).

Every parameter is parsed here (not by FastAPI) so a bad value is a Korean 422.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping

from fastapi import APIRouter, HTTPException, Query

from ...core.jobs import RunJobStore
from .analyses import ANALYSIS_RUNNER, run_scope
from .files_ntfs import latest_parsed_ntfs_analysis
from .fs_tree import (
    FS_INDEX_CACHE,
    SCOPES,
    decode_cursor,
    files_output_key,
    files_roots,
    folder_children,
    folder_summary,
    index_info,
    parse_folder_path,
    parse_limit,
    parse_scope,
    require_folder,
    special_counts,
    special_nodes,
)
from .helpers import (
    get_job,
    get_named_output,
    get_output_path,
    resolve_allowed_source_file,
)
from .media_similar import (
    load_media_index,
    media_groups,
    parse_distance,
    parse_group_by,
    parse_media_limit,
    require_ref,
    similar_media,
)
from .registry_tree import (
    NO_REGISTRY_REASON,
    REGISTRY_KIND,
    REGISTRY_TREE_DEFAULT_LIMIT,
    REGISTRY_TREE_MAX_LIMIT,
    REGISTRY_VALUES_DEFAULT_LIMIT,
    REGISTRY_VALUES_MAX_LIMIT,
    collected_value_names,
    key_children,
    key_summary,
    linked_rows,
    load_registry_index,
    read_key_values,
    require_hive,
    require_key,
)
from .registry_tree import index_info as registry_index_info


def _newest_completed(output_dir: object, kind: str) -> Mapping[str, object] | None:
    for state in ANALYSIS_RUNNER.list_states(output_dir):  # type: ignore[arg-type]
        if state.get("kind") == kind and state.get("status") == "completed":
            return state
    return None


def build_explorers_router(store: RunJobStore) -> APIRouter:
    router = APIRouter()

    def _completed(run_id: str) -> None:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail="완료된 런이 아닙니다")

    @router.get("/api/runs/{run_id}/fs-tree")
    def get_fs_tree(
        run_id: str,
        path: str | None = Query(default=None),
        scope: str | None = Query(default=None),
        limit: str | None = Query(default=None),
        after: str | None = Query(default=None),
    ) -> dict[str, object]:
        """One folder level of the run's files: ``{run_id, scope, volume, node, breadcrumb, children,
        child_total, limit, next_after, special_nodes, hidden_special_nodes, index}``.

        ``path`` = folder relative to the volume root (``/`` separators, ``""`` = root); an absolute
        path is accepted inside the run's evidence roots (else a Korean 403). ``scope`` =
        ``candidates`` (default) | ``inventory`` -- the list ``GET /files?scope=`` pages. Every folder
        reports ``direct_file_count``/``direct_size`` (files directly in it) and
        ``file_count``/``size`` (recursive): they equal the ``matched`` of ``GET /files?path_prefix=
        <path>&recursive=0|1`` for the same scope. ``children`` = child folders sorted by name
        (case-insensitive), ``limit`` 1–1000 (default 200), ``after`` = the previous ``next_after``.
        ``special_nodes`` (root only) = 고아 파일·미할당 공간·슬랙 when the files output (``files_query``)
        or a completed ntfs-meta / carve analysis (``analysis``) has them; the others are listed in
        ``hidden_special_nodes`` with a Korean ``reason``. Bad parameters are a Korean 422, an unknown
        folder a 404."""
        _completed(run_id)
        wanted_scope = parse_scope(scope)
        page_limit = parse_limit(limit)
        cursor = decode_cursor(after)
        payload = get_named_output(store, run_id, "files")
        files_path = get_output_path(store, run_id, "files")
        index = FS_INDEX_CACHE.get(files_output_key(run_id, files_path), payload)
        roots = files_roots(payload)
        parts = parse_folder_path(path, roots)
        node = require_folder(index, parts)
        children, next_after, child_total = folder_children(index, node, wanted_scope, limit=page_limit, after=cursor)
        try:
            scope_info = run_scope(store, run_id, require_ready=False)
        except HTTPException:
            scope_info = None
        ntfs_state = latest_parsed_ntfs_analysis(scope_info) if scope_info is not None else None
        volume: dict[str, object] = {
            "id": "volume-1",
            "label": "볼륨 1",
            "root": roots[0] if roots else None,
            "filesystem": None,
            "partition_start_sector": None,
            "source_image": None,
        }
        if scope_info is not None:
            source = scope_info.source
            if str(source.get("type") or "") not in {"", "folder", "directory"}:
                volume["source_image"] = source.get("source_path")
            if ntfs_state is not None:
                summary = ntfs_state.get("summary") if isinstance(ntfs_state.get("summary"), Mapping) else {}
                partition = summary.get("partition") if isinstance(summary.get("partition"), Mapping) else {}
                volume["filesystem"] = "NTFS"
                volume["partition_start_sector"] = partition.get("start_sector")
        volume["label"] = (
            f"볼륨 1 · 파티션 시작 섹터 {volume['partition_start_sector']}"
            if volume["partition_start_sector"] is not None
            else "볼륨 1 (스캔 루트)"
        )
        response: dict[str, object] = {
            "run_id": run_id,
            "scope": wanted_scope,
            "scope_counts": {item: int(index.total_n[item][0]) for item in SCOPES},
            "volume": volume,
            "node": folder_summary(index, node, wanted_scope),
            "breadcrumb": index.breadcrumb(node),
            "children": children,
            "child_total": child_total,
            "limit": page_limit,
            "next_after": next_after,
            "index": index_info(index, wanted_scope),
        }
        if node == 0:
            carve_state = _newest_completed(scope_info.output_dir, "carve") if scope_info is not None else None
            shown, hidden = special_nodes(special_counts(payload), ntfs_state, carve_state)
            response["special_nodes"] = shown
            response["hidden_special_nodes"] = hidden
        return response

    @router.get("/api/runs/{run_id}/registry-tree")
    def get_registry_tree(
        run_id: str,
        hive: str | None = Query(default=None),
        key: str | None = Query(default=None),
        limit: str | None = Query(default=None),
        after: str | None = Query(default=None),
    ) -> dict[str, object]:
        """Registry explorer level. Without ``hive``: ``{run_id, hives: [{id, name, path, mount, label,
        key_count, root_last_written_at}], index, reason?}`` (``hives = []`` with a Korean ``reason`` when
        the run has no ``registry-key-tree-node`` rows). With ``hive``: ``{hive, key, breadcrumb,
        children, child_total, limit, next_after, index}`` where ``key`` (full key path incl. the mount,
        ``""`` = the hive root) and each child carry ``key_path``, ``last_written_at``, ``value_count``,
        ``subkey_count``, ``child_count``, ``record_index`` (its key-tree row, null for a ``synthetic``
        parent the collector did not emit) and ``linked_row_count``. Children are sorted by name;
        ``limit`` 1–1000 (default 200), ``after`` = the previous ``next_after``. Unknown hive / key: 404;
        bad parameters: Korean 422."""
        _completed(run_id)
        page_limit = parse_limit(limit, default=REGISTRY_TREE_DEFAULT_LIMIT, maximum=REGISTRY_TREE_MAX_LIMIT)
        cursor = decode_cursor(after)
        index = load_registry_index(store, run_id)
        if hive is None or not hive.strip():
            if key:
                raise HTTPException(status_code=422, detail="key를 쓰려면 hive(하이브 id)를 함께 지정하세요")
            if index is None:
                return {"run_id": run_id, "hives": [], "reason": NO_REGISTRY_REASON, "index": None}
            hives = sorted(index.hives.values(), key=lambda item: (item.mount.casefold(), item.path.casefold()))
            described = [item.describe(index) for item in hives]
            names = Counter(str(item["label"]).casefold() for item in described)
            for item in described:
                if names[str(item["label"]).casefold()] > 1:
                    # Two hives with one name and mount (BBI, bbimigrate\BBI): add the folder.
                    folder = str(item["path"]).replace("\\", "/").rsplit("/", 2)[-2:-1]
                    item["label"] = f"{item['name']} — {folder[0] if folder else ''} ({item['mount']})"
            return {"run_id": run_id, "hives": described, "index": registry_index_info(index)}
        if index is None:
            raise HTTPException(status_code=404, detail=NO_REGISTRY_REASON)
        hive_info = require_hive(index, hive)
        node = require_key(index, hive_info, key)
        children, next_after, child_total = key_children(index, hive_info, node, limit=page_limit, after=cursor)
        return {
            "run_id": run_id,
            "hive": hive_info.describe(index),
            "key": key_summary(index, hive_info, node),
            "breadcrumb": index.breadcrumb(hive_info, node),
            "children": children,
            "child_total": child_total,
            "limit": page_limit,
            "next_after": next_after,
            "index": registry_index_info(index),
        }

    @router.get("/api/runs/{run_id}/registry-values")
    def get_registry_values(
        run_id: str,
        hive: str | None = Query(default=None),
        key: str | None = Query(default=None),
        limit: str | None = Query(default=None),
    ) -> dict[str, object]:
        """Values of one key: ``{hive, key, values: [{name, display_name, type, type_code, data_size,
        data_hex, data_truncated, decoded, decoded_kind: text|number|list|binary|empty|too-large,
        decoded_hex?}], value_total, values_status: parsed|names-only, reason?, citation,
        artifact_rows: [{kind, record_index, artifact_type, label, locator}], artifact_row_total,
        artifact_types}``. Values are read from the hive file (inside the run's evidence roots only);
        when it cannot be read the collected value names are returned (``names-only``) with a Korean
        reason. ``citation.text`` = hive path, key path, last-written time and cell offset.
        ``artifact_rows`` = rows of ``windows-registry``/``windows-shellbags``/``windows-os-account``
        produced from this key (jump targets; ≤ 50, ``artifact_row_total`` counts all)."""
        _completed(run_id)
        page_limit = parse_limit(limit, default=REGISTRY_VALUES_DEFAULT_LIMIT, maximum=REGISTRY_VALUES_MAX_LIMIT)
        index = load_registry_index(store, run_id)
        if index is None:
            raise HTTPException(status_code=404, detail=NO_REGISTRY_REASON)
        hive_info = require_hive(index, hive)
        node = require_key(index, hive_info, key)
        summary = key_summary(index, hive_info, node)
        values: list[dict[str, object]] = []
        value_total = 0
        status = "parsed"
        reason: str | None = None
        try:
            hive_file = resolve_allowed_source_file(store, run_id, hive_info.path)
        except HTTPException:
            hive_file = None
            reason = "하이브 원본 파일을 런의 증거 루트에서 찾을 수 없어 수집된 값 이름만 보여 줍니다"
        if hive_file is not None:
            try:
                values, value_total, reason = read_key_values(index, hive_info, node, hive_file, limit=page_limit)
            except OSError as exc:
                reason = f"하이브 파일을 읽지 못했습니다: {exc.__class__.__name__}"
        if hive_file is None or reason is not None:
            status = "names-only"
            names = collected_value_names(store, run_id, index, node)
            value_total = len(names)
            values = [
                {"name": name, "display_name": name or "(기본값)", "type": None, "type_code": None, "data_size": None,
                 "data_hex": None, "data_truncated": False, "decoded": None, "decoded_kind": "unavailable"}
                for name in names[:page_limit]
            ]
        cell_offset = int(index.cell_offsets[node])
        citation_parts = [hive_info.path, str(summary["key_path"])]
        if summary.get("last_written_at"):
            citation_parts.append(f"마지막 기록 {summary['last_written_at']}")
        if cell_offset >= 0:
            citation_parts.append(f"셀 오프셋 0x{cell_offset:X}")
        response: dict[str, object] = {
            "run_id": run_id,
            "hive": hive_info.describe(index),
            "key": summary,
            "values": values,
            "value_total": value_total,
            "values_status": status,
            "limit": page_limit,
            "citation": {
                "text": " › ".join(citation_parts),
                "hive_path": hive_info.path,
                "key_path": summary["key_path"],
                "last_written_at": summary.get("last_written_at"),
                "cell_offset": cell_offset if cell_offset >= 0 else None,
                "kind": REGISTRY_KIND,
                "record_index": summary.get("record_index"),
                "locator": f"/artifacts/{summary['record_index']}" if summary.get("record_index") is not None else None,
            },
            **linked_rows(index, node),
        }
        if reason:
            response["reason"] = reason
        return response

    @router.get("/api/runs/{run_id}/media/similar")
    def get_media_similar(
        run_id: str,
        ref: str | None = Query(default=None),
        max_distance: str | None = Query(default=None),
        limit: str | None = Query(default=None),
    ) -> dict[str, object]:
        """유사 사진 찾기: ``media-image`` rows whose pHash is within ``max_distance`` (0–16, default 8)
        bits of the reference image ``ref`` (its source path): ``{ref, max_distance, limit, items: [{path,
        name, kind, record_index, locator, distance, same_hash, sha256, camera, captured_at}], counts:
        {indexed, with_phash, same_hash, near, matched, returned}, index}``. Sorted by distance then
        path; ``limit`` 1–500 (default 100). ``ref`` not in the image rows: 404; without a pHash: 409;
        bad parameters: Korean 422."""
        _completed(run_id)
        distance = parse_distance(max_distance)
        page_limit = parse_media_limit(limit)
        index = load_media_index(store, run_id)
        entry = require_ref(index, ref)
        return {"run_id": run_id, **similar_media(index, entry, max_distance=distance, limit=page_limit)}

    @router.get("/api/runs/{run_id}/media/groups")
    def get_media_groups(
        run_id: str,
        by: str | None = Query(default=None),
        key: str | None = Query(default=None),
    ) -> dict[str, object]:
        """EXIF groups of the run's images: ``by=camera`` (make + model) or ``by=date`` (capture day)
        -> ``{by, groups: [{key, label, count, sample_paths}], index}``; the group without EXIF data has
        ``key = ""`` and comes last. ``key=`` adds ``paths``/``records`` (≤ 2000), ``path_total`` and
        ``paths_truncated`` of that group (unknown key: 404). Bad ``by``: Korean 422."""
        _completed(run_id)
        group_by = parse_group_by(by)
        index = load_media_index(store, run_id)
        return {"run_id": run_id, **media_groups(index, group_by, key)}

    return router
