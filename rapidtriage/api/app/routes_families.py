"""계열·중복·예외 항목 routes (R7 갈래 A): one item's family, the selection expansion and the dedup /
irregular summaries. Read-only: every route is a GET over the run's derivation
(:mod:`.families`)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

from ...core.dedup import DEDUP_MODE_LABELS, DEDUP_MODES
from ...core.families import (
    ENTRY_MARK,
    RELATION_LABELS,
    base_ref,
    is_virtual,
    parse_ref,
)
from ...core.jobs import RunJobStore, run_output_dir
from ...core.source_reader import ARCHIVED_SOURCE_SEPARATOR
from .families import FAMILIES_SERVICE, RunDerived
from .helpers import get_job

DIRECTIONS = ("up", "down", "family")
EXPAND_MAX_REFS = 500
TREE_MAX_NODES = 2000
NOT_FINISHED = "런이 끝난 뒤에 계열·중복·예외 항목을 볼 수 있습니다"
BAD_REF = "항목 참조 형식이 잘못되었습니다 — 예: artifacts:email:/artifacts/3, files::/candidates/12"


def _node(derived: RunDerived, ref: str, *, depth_children: bool = True) -> dict[str, object]:
    families = derived.families
    parsed = parse_ref(ref)
    collection, kind, locator = parsed if parsed is not None else ("", "", ref)
    info = families.info(ref)
    relation = families.relation(ref)
    children = families.children.get(ref) or []
    virtual = is_virtual(ref)
    node: dict[str, object] = {
        "ref": ref,
        "collection": collection,
        "kind": kind,
        "locator": locator,
        "title": info.title if info else "",
        "artifact_type": info.artifact_type if info else "",
        "relation": relation,
        "relation_label": RELATION_LABELS.get(relation or "", None),
        "material": info.material if info else True,
        "virtual": virtual,
        # A real row the grid can list; a virtual entry / attachment opens in the viewer only.
        "navigable": collection in ("artifacts", "files", "analysis") and not virtual,
        "row_ref": base_ref(ref) if virtual and collection != "source" else ref if collection != "source" else None,
        "children": len(children) if depth_children else 0,
    }
    if collection == "source":
        node["source_path"] = locator
    return node


def _archive_entry_source(derived: RunDerived, ref: str, parent_path: str | None) -> str | None:
    """``<zip>::<entry>`` preview path of a ZIP archive entry (other containers: none)."""
    if ENTRY_MARK not in ref or not parent_path or not parent_path.lower().endswith(".zip"):
        return None
    info = derived.families.info(ref)
    name = (info.title if info else "").strip().replace("\\", "/")
    if not name or name.endswith("/") or name.endswith("…"):
        return None
    return f"{parent_path}{ARCHIVED_SOURCE_SEPARATOR}{name}"


def _tree(derived: RunDerived, root: str, budget: list[int]) -> dict[str, object]:
    node = _node(derived, root)
    kids: list[dict[str, object]] = []
    for child in derived.families.children.get(root) or []:
        if budget[0] <= 0:
            node["truncated"] = True
            break
        budget[0] -= 1
        kids.append(_tree(derived, child, budget))
    node["items"] = kids
    return node


def build_families_router(store: RunJobStore) -> APIRouter:
    router = APIRouter()

    def _derived(run_id: str) -> RunDerived:
        job = get_job(store, run_id)
        if job.summary is None:
            raise HTTPException(status_code=409, detail=NOT_FINISHED)
        outputs = job.summary.get("outputs")
        if not isinstance(outputs, dict):
            raise HTTPException(status_code=409, detail="런 요약에 출력 목록이 없습니다")
        try:
            output_dir: Path | None = run_output_dir(job.summary)
        except RuntimeError:
            output_dir = None
        try:
            return FAMILIES_SERVICE.get(run_id, outputs, output_dir)
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=f"계열·중복·예외 항목을 만들지 못했습니다: {type(exc).__name__}") from exc

    def _require_ref(ref: str) -> str:
        text = (ref or "").strip()
        if parse_ref(text) is None:
            raise HTTPException(status_code=422, detail=BAD_REF)
        return text

    @router.get("/api/runs/{run_id}/families/{ref:path}")
    def get_run_family(
        run_id: str,
        ref: str,
        direction: str = Query(default="family"),
        source_path: str | None = Query(default=None, max_length=4096),
    ) -> dict[str, object]:
        """계열 of one item (``ref`` = ``<collection>:<kind>:<locator>``, URL-encoded).

        ``direction``: ``up`` (parent chain, nearest first), ``down`` (``ref`` and its descendants as a
        tree), ``family`` (default: the top-level item's tree, the parent and the siblings).
        ``source_path`` (the row's own path, optional) lets a ZIP archive's entries carry their
        ``<zip>::<entry>`` preview path. Every node: ``ref``, ``collection``, ``kind``,
        ``locator``, ``title``, ``artifact_type``, ``relation`` (+ Korean ``relation_label``),
        ``material``, ``virtual`` (an archive entry / embedded attachment / source file that is no
        row), ``navigable`` (a row the listings show), ``row_ref`` and ``children`` (count)."""
        wanted = direction.strip().lower()
        if wanted not in DIRECTIONS:
            raise HTTPException(status_code=422, detail="direction 값은 up(상위)·down(하위)·family(계열) 중 하나여야 합니다")
        item = _require_ref(ref)
        derived = _derived(run_id)
        families = derived.families
        known = item in families.parent or item in families.children
        top = families.top(item)
        link = families.parent.get(item)
        response: dict[str, object] = {
            "ref": item,
            "direction": wanted,
            "has_family": known,
            "item": _node(derived, item),
            "parent": _node(derived, link[0]) if link else None,
            "top": _node(derived, top),
            "is_top": top == item,
            "source": derived.source,
        }
        if wanted in ("up", "family"):
            response["ancestors"] = [_node(derived, ref_) for ref_ in families.ancestors(item)]
        if wanted == "family":
            siblings = [child for child in (families.children.get(link[0]) or []) if child != item] if link else []
            response["siblings"] = [_node(derived, ref_) for ref_ in siblings]
        root = item if wanted == "down" else top
        if wanted in ("down", "family"):
            budget = [TREE_MAX_NODES]
            tree = _tree(derived, root, budget)
            response["tree"] = tree
            members = [root, *families.descendants(root)]
            response["counts"] = {
                "members": len(members),
                "descendants": len(members) - 1,
                "material": sum(1 for ref_ in members if (families.info(ref_).material if families.info(ref_) else True)),
                "rows": sum(1 for ref_ in members if not is_virtual(ref_)),
            }
            response["tree_truncated"] = budget[0] <= 0
            parent_path = (source_path or "").strip() or None
            if parent_path:
                _attach_entry_sources(derived, tree, parent_path, item)
        return response

    def _attach_entry_sources(derived: RunDerived, tree: dict[str, object], parent_path: str, item: str) -> None:
        """ZIP entries of ``item`` (the archive row the caller named the path of) get ``source_path``."""
        if tree.get("ref") == base_ref(item):
            for child in tree.get("items") or []:
                if isinstance(child, dict):
                    path = _archive_entry_source(derived, str(child.get("ref") or ""), parent_path)
                    if path:
                        child["source_path"] = path
            return
        for child in tree.get("items") or []:
            if isinstance(child, dict):
                _attach_entry_sources(derived, child, parent_path, item)

    @router.get("/api/runs/{run_id}/family-expansion")
    def get_family_expansion(run_id: str, ref: list[str] = Query(default=[])) -> dict[str, object]:
        """상위 항목+하위 항목으로 확장: every given item plus its family (top-level item and all
        descendants), rows only (virtual entries dropped), first-seen order. At most
        :data:`EXPAND_MAX_REFS` refs in."""
        refs = [item.strip() for item in ref if item.strip()]
        if not refs:
            raise HTTPException(status_code=422, detail="ref를 하나 이상 지정하세요")
        if len(refs) > EXPAND_MAX_REFS:
            raise HTTPException(status_code=422, detail=f"한 번에 {EXPAND_MAX_REFS}개 항목까지 확장할 수 있습니다")
        for item in refs:
            _require_ref(item)
        derived = _derived(run_id)
        seen: dict[str, None] = {}
        added = 0
        for item in refs:
            row = base_ref(item)
            if row.startswith("source::"):
                continue
            seen.setdefault(row, None)
            for member in derived.families.family(row):
                if is_virtual(member) or member in seen:
                    continue
                seen[member] = None
                added += 1
        out = []
        for item in seen:
            parsed = parse_ref(item)
            if parsed is None:
                continue
            collection, kind, locator = parsed
            out.append({"ref": item, "collection": collection, "kind": kind, "locator": locator})
        return {"requested": len(refs), "added": added, "count": len(out), "items": out}

    @router.get("/api/runs/{run_id}/dedup/summary")
    def get_dedup_summary(run_id: str) -> dict[str, object]:
        """중복 제거 요약: per mode (``item``·``family``·``custodian``) items, groups, originals and
        duplicates, with the Korean mode label. ``custodian`` ranks by evidence until custodians are
        assigned (one run = one evidence source: equal to ``item``)."""
        derived = _derived(run_id)
        modes = []
        for name in DEDUP_MODES:
            summary = derived.dedup.mode(name).summary()
            modes.append({"id": name, "label": DEDUP_MODE_LABELS[name], **summary})
        return {"modes": modes, "custodians_assigned": False, "source": derived.source}

    @router.get("/api/runs/{run_id}/irregular/summary")
    def get_irregular_summary(run_id: str) -> dict[str, object]:
        """예외 항목 요약: the nine categories (``id``, Korean ``label`` / ``help``, ``count`` =
        ``candidates`` + ``inventory`` + ``artifacts`` rows, ``files`` = the two files lanes),
        ``total`` (sum of the categories) and ``unique_items`` (rows in at least one category).
        ``irregular=<id>`` lists exactly ``candidates`` rows on ``/files``, ``inventory`` rows on
        ``/files?scope=inventory`` and ``artifacts`` rows on ``/artifacts``."""
        derived = _derived(run_id)
        return {**derived.irregular.summary(), "source": derived.source}

    return router
