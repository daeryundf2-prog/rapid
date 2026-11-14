"""Search lists of a run (``list:<id>``, R7 lane B): ``<run>/search/lists/<id>.json``.

A list is a keyword or IOC list the analyst uploads (one item per line, ``#`` comments):
keywords, ``/regex/`` (checked by :mod:`.regex_guard` at upload and at query time), hashes,
IPs/CIDRs, e-mail addresses, hosts and personal numbers. ``list:<id>`` matches a row holding
any item; with aggregates the response counts every item (``lists``). The built-in keyword
packs (``core.keyword_packs``) are lists too (``list:credentials``).

Items are stored as typed: a list of personal numbers is the analyst's own input (the index
never holds them); the API echoes items masked (:func:`.patterns.mask_sensitive`).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import uuid
from collections import Counter
from pathlib import Path

from .patterns import mask_sensitive, whole_entity
from .regex_guard import RegexRejected, analyze_regex
from .textutil import normalize_hash

LIST_DIR = Path("search") / "lists"
LIST_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
LIST_KINDS = ("keyword", "ioc")
MAX_LIST_BYTES = 10 * 1024 * 1024
MAX_LIST_ITEMS = 100_000
MAX_ITEM_CHARS = 512
MAX_REJECTED = 100
NAME_MAX_CHARS = 200


class SearchListError(ValueError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def list_dir(output_dir: Path) -> Path:
    return Path(output_dir) / LIST_DIR


def item_type(item: str) -> str:
    """``regex`` / ``hash`` / ``ip`` / an entity kind / ``keyword`` (what ``list:`` compiles it to)."""
    if len(item) > 2 and item.startswith("/") and item.endswith("/"):
        return "regex"
    if normalize_hash(item) is not None:
        return "hash"
    import ipaddress

    try:
        ipaddress.ip_network(item, strict=False)
        return "ip"
    except ValueError:
        pass
    entity = whole_entity(item)
    return entity.kind if entity is not None else "keyword"


def parse_items(text: str) -> tuple[list[str], list[dict[str, object]], int]:
    items: list[str] = []
    rejected: list[dict[str, object]] = []
    rejected_count = 0
    seen: set[str] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        item = line.strip()
        if not item or item.startswith("#") or item in seen:
            continue
        reason = ""
        if len(item) > MAX_ITEM_CHARS:
            reason = f"항목이 너무 깁니다(최대 {MAX_ITEM_CHARS}자)"
        elif item_type(item) == "regex":
            try:
                analyze_regex(item[1:-1])
            except RegexRejected as exc:
                reason = exc.reason
            except re.error as exc:
                reason = f"정규식이 올바르지 않습니다: {exc.msg}"
            except (RecursionError, OverflowError):
                reason = "정규식이 너무 복잡합니다(구조가 너무 깊습니다)"
        if reason:
            rejected_count += 1
            if len(rejected) < MAX_REJECTED:
                rejected.append({"line": number, "reason": reason, "text": mask_sensitive(item)[:120]})
            continue
        seen.add(item)
        items.append(item)
        if len(items) > MAX_LIST_ITEMS:
            raise SearchListError(f"검색 목록 항목이 너무 많습니다(최대 {MAX_LIST_ITEMS:,}개)", status=413)
    return items, rejected, rejected_count


def _summary(payload: dict[str, object]) -> dict[str, object]:
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    return {
        "id": payload.get("id"),
        "kind": payload.get("kind"),
        "name": payload.get("name"),
        "item_count": len(items),
        "by_type": dict(sorted(Counter(item_type(str(item)) for item in items).items())),
        "sha256": payload.get("sha256"),
        "created_at": payload.get("created_at"),
        "builtin": False,
    }


def create_list(output_dir: Path, *, name: str, kind: str, text: str, list_id: str | None = None) -> dict[str, object]:
    clean_name = " ".join(str(name or "").split())[:NAME_MAX_CHARS]
    if not clean_name:
        raise SearchListError("검색 목록 이름이 필요합니다")
    if kind not in LIST_KINDS:
        raise SearchListError(f"검색 목록 종류는 {', '.join(LIST_KINDS)} 중 하나여야 합니다")
    data = text.encode("utf-8")
    if len(data) > MAX_LIST_BYTES:
        raise SearchListError("검색 목록이 너무 큽니다(최대 10 MB)", status=413)
    if list_id is not None:
        if not LIST_ID_RE.fullmatch(list_id):
            raise SearchListError("검색 목록 id는 영문 소문자·숫자·-·_ 64자 이내여야 합니다")
    else:
        list_id = f"ls-{uuid.uuid4().hex[:10]}"
    if builtin_list(list_id) is not None:
        raise SearchListError("기본 키워드 팩과 같은 id는 쓸 수 없습니다")
    items, rejected, rejected_count = parse_items(text)
    if not items:
        raise SearchListError("검색 목록에 유효한 항목이 없습니다")
    directory = list_dir(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{list_id}.json"
    if target.exists():
        raise SearchListError("같은 id의 검색 목록이 있습니다", status=409)
    payload: dict[str, object] = {
        "id": list_id,
        "kind": kind,
        "name": clean_name,
        "items": items,
        "sha256": hashlib.sha256(data).hexdigest(),
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
    }
    temporary = directory / f"{list_id}.json.tmp"
    temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, target)
    return {**_summary(payload), "rejected": rejected, "rejected_count": rejected_count}


def _read(output_dir: Path, list_id: str) -> dict[str, object] | None:
    if not LIST_ID_RE.fullmatch(list_id or ""):
        return None
    path = list_dir(output_dir) / f"{list_id}.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) and isinstance(payload.get("items"), list) else None


def builtin_list(list_id: str) -> dict[str, object] | None:
    from ..keyword_packs import BUILTIN_KEYWORD_PACKS

    items = BUILTIN_KEYWORD_PACKS.get(list_id)
    if items is None:
        return None
    return {"id": list_id, "kind": "keyword", "name": list_id, "items": list(items), "builtin": True}


def read_list(output_dir: Path, list_id: str) -> dict[str, object] | None:
    """A run list, else a built-in keyword pack, else ``None``."""
    return _read(output_dir, list_id) or builtin_list(list_id)


def list_lists(output_dir: Path) -> list[dict[str, object]]:
    from ..keyword_packs import BUILTIN_KEYWORD_PACKS

    found: list[dict[str, object]] = []
    try:
        paths = sorted(list_dir(output_dir).glob("*.json"))
    except OSError:
        paths = []
    for path in paths:
        payload = _read(output_dir, path.stem)
        if payload is not None:
            found.append(_summary(payload))
    for name, items in sorted(BUILTIN_KEYWORD_PACKS.items()):
        found.append({"id": name, "kind": "keyword", "name": name, "item_count": len(items), "by_type": {"keyword": len(items)}, "builtin": True})
    return found


def list_detail(output_dir: Path, list_id: str) -> dict[str, object]:
    payload = read_list(output_dir, list_id)
    if payload is None:
        raise SearchListError("검색 목록을 찾을 수 없습니다", status=404)
    summary = _summary(payload) if not payload.get("builtin") else {
        "id": list_id, "kind": "keyword", "name": list_id, "item_count": len(payload["items"]), "builtin": True,  # type: ignore[arg-type]
    }
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    return {**summary, "items": [{"item": mask_sensitive(str(item)), "type": item_type(str(item))} for item in items[:1000]]}


def delete_list(output_dir: Path, list_id: str) -> None:
    if builtin_list(list_id) is not None:
        raise SearchListError("기본 키워드 팩은 지울 수 없습니다", status=409)
    if _read(output_dir, list_id) is None:
        raise SearchListError("검색 목록을 찾을 수 없습니다", status=404)
    (list_dir(output_dir) / f"{list_id}.json").unlink()
