"""The triage catalogue: ``catalog/*.yaml`` families (columns) and rules (plan viewer-families §3.1).

One YAML file per family group, each ``{families: [...], rules: [...]}``.
The loaded catalogue is cached per (file names, sizes, mtimes); its
``version`` is the first 16 hex digits of the SHA-256 over the files (sorted
by name), so a flag written with one catalogue can be cited as
``<rule id>@<rule version>`` and the summary records which catalogue made it
(``rule_set.files`` = SHA-256 per YAML file).

A rule belongs to exactly one family (``rule.family``, the prefix of its id
names the module), but a family's ``rules`` list may also *cross-list* rules
of another family whose rows it shows, so that family's grid offers the
filter chip. 15 rules are cross-listed this way, e.g. ``sam-account`` lists
``accounts.new_account`` (family ``eventlog-event``), ``prefetch-file`` lists
four ``execution.*`` rules, ``registry`` lists ``rdp.enabled`` and
``accounts.task_mismatch``, ``mounted-device`` lists
``registry.usb_serial_cross``; the plan §5.1 has the full list. Counts are
per rule, never per listing family.
"""

from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .base import GRADES

CATALOG_DIR = Path(__file__).with_name("catalog")
RULE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]*\.[a-z0-9_]+$")
FAMILY_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")
STATUSES = ("verified", "provisional")
COLUMN_KEYS = frozenset(
    {"key", "label", "format", "ts_kind", "width", "aliases", "semantic", "semantic_when", "derive", "value_labels"}
)
# Column meaning tags (plan axiom-adoption §3.2; research axiom-case-model §3): the derived engine
# (``core/derived``) gathers every column with one of these tags into the 통합 보기 tables.
SEMANTIC_TAGS = frozenset(
    {
        "person",
        "person_sender",
        "person_recipient",
        "account",
        "device",
        "path",
        "url",
        "hash",
        "geo",
        "search_term",
        "attachment",
        "credential",
    }
)
# Display-only columns the console computes from the row's own fields (no stored value):
# event-log summary sentence, RDP direction, image EXIF state, account auto-logon (plan §3.2).
DERIVE_IDS = frozenset({"event_summary_ko", "rdp_direction", "exif_status", "auto_logon"})


class CatalogError(ValueError):
    """The catalogue YAML is malformed (Korean message)."""

def _yaml():
    """Import PyYAML lazily so importing rapidtriage (CLI, run pipeline) never
    needs it; only loading the catalog does. A missing module becomes a
    CatalogError in Korean instead of an import-time crash."""
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - environment dependent
        raise CatalogError("특이사항 카탈로그를 읽으려면 PyYAML이 필요합니다 (pip install pyyaml)") from exc
    return yaml


@dataclass(frozen=True)
class RuleSpec:
    id: str
    family: str
    grade: str
    label_ko: str
    rationale_ko: str
    false_positive_ko: str
    sources: tuple[str, ...]
    version: int
    status: str
    params: Mapping[str, Any]

    @property
    def citation(self) -> str:
        return f"{self.id}@{self.version}"


@dataclass(frozen=True)
class Catalog:
    version: str
    families: tuple[dict[str, Any], ...]
    rules: tuple[dict[str, Any], ...]
    specs: Mapping[str, RuleSpec] = field(default_factory=dict)
    # YAML file name -> SHA-256 of its bytes (the summary's ``rule_set`` block).
    file_hashes: Mapping[str, str] = field(default_factory=dict)

    def payload(self) -> dict[str, object]:
        """``GET /api/meta/families`` body."""
        return {"version": self.version, "families": list(self.families), "rules": list(self.rules)}

    def family_for(self, artifact_type: str, kind: str = "") -> str | None:
        """Family id of an artifact type: suffix, exact type, prefix, then the kind (frontend ``sheetForType`` order)."""
        if artifact_type:
            for family in self.families:
                if any(artifact_type.endswith(suffix) for suffix in family.get("suffixes") or ()):
                    return str(family["id"])
            for family in self.families:
                if artifact_type in (family.get("types") or ()):
                    return str(family["id"])
            for family in self.families:
                if any(artifact_type.startswith(prefix) for prefix in family.get("prefixes") or ()):
                    return str(family["id"])
        if kind:
            for family in self.families:
                if kind in (family.get("kinds") or ()):
                    return str(family["id"])
        return None


def _fail(source: str, message: str) -> CatalogError:
    return CatalogError(f"특이사항 카탈로그 오류({source}): {message}")


def _check_columns(source: str, family_id: str, columns: object, name: str) -> None:
    if not isinstance(columns, list):
        raise _fail(source, f"계열 {family_id}의 {name}가 목록이 아닙니다")
    for column in columns:
        if not isinstance(column, Mapping) or not column.get("key") or not column.get("label"):
            raise _fail(source, f"계열 {family_id}의 {name} 항목에 key/label이 없습니다")
        unknown = set(column) - COLUMN_KEYS
        if unknown:
            raise _fail(source, f"계열 {family_id}의 열에 알 수 없는 키가 있습니다: {sorted(unknown)}")
        _check_semantic(source, family_id, column)
        _check_value_labels(source, family_id, column)


def _check_value_labels(source: str, family_id: str, column: Mapping[str, Any]) -> None:
    """``value_labels`` (optional) = ``{raw value: 한국어 표시}``: the console shows the Korean
    reading (grid cell, viewer, citation) and keeps the raw value in the tooltip; a column
    filter on the Korean reading matches every raw spelling mapped to it."""
    labels = column.get("value_labels")
    if labels is None:
        return
    valid = isinstance(labels, Mapping) and bool(labels) and all(
        isinstance(raw, str) and raw != "" and isinstance(text, str) and text.strip() != ""
        for raw, text in labels.items()
    )
    if not valid:
        raise _fail(
            source,
            f"계열 {family_id}의 열 {column.get('key')}: value_labels는 {{원래 값: 한국어 표시}} 형식(빈 값 없이)이어야 합니다",
        )


def _check_semantic(source: str, family_id: str, column: Mapping[str, Any]) -> None:
    """``semantic`` ∈ SEMANTIC_TAGS; ``semantic_when`` = ``{field: [values]}`` (only with ``semantic``);
    ``derive`` ∈ DERIVE_IDS."""
    key = column.get("key")
    semantic = column.get("semantic")
    if semantic is not None and semantic not in SEMANTIC_TAGS:
        raise _fail(source, f"계열 {family_id}의 열 {key}의 semantic이 알 수 없는 값입니다: {semantic!r}")
    when = column.get("semantic_when")
    if when is not None:
        if semantic is None:
            raise _fail(source, f"계열 {family_id}의 열 {key}: semantic_when은 semantic과 함께만 쓸 수 있습니다")
        valid = isinstance(when, Mapping) and bool(when) and all(
            isinstance(name, str) and isinstance(values, list) and values and all(isinstance(item, str) for item in values)
            for name, values in when.items()
        )
        if not valid:
            raise _fail(source, f"계열 {family_id}의 열 {key}: semantic_when은 {{필드: [값 …]}} 형식이어야 합니다")
    derive = column.get("derive")
    if derive is not None and derive not in DERIVE_IDS:
        raise _fail(source, f"계열 {family_id}의 열 {key}의 derive가 알 수 없는 값입니다: {derive!r}")


def _check_rule(source: str, rule: Mapping[str, Any]) -> RuleSpec:
    rule_id = str(rule.get("id") or "")
    if not RULE_ID_PATTERN.fullmatch(rule_id):
        raise _fail(source, f"규칙 id 형식이 아닙니다: {rule_id!r} (<계열>.<이름>)")
    for key in ("family", "grade", "label_ko", "rationale_ko", "false_positive_ko", "status"):
        if not isinstance(rule.get(key), str) or not rule.get(key):
            raise _fail(source, f"규칙 {rule_id}에 {key} 값이 없습니다")
    if rule["grade"] not in GRADES:
        raise _fail(source, f"규칙 {rule_id}의 등급은 A/B/C 중 하나여야 합니다: {rule['grade']!r}")
    if rule["status"] not in STATUSES:
        raise _fail(source, f"규칙 {rule_id}의 상태는 verified/provisional 중 하나여야 합니다: {rule['status']!r}")
    sources = rule.get("sources")
    if not isinstance(sources, list) or not sources or not all(isinstance(url, str) and url.startswith("https://") for url in sources):
        raise _fail(source, f"규칙 {rule_id}의 출처(sources)는 https URL 목록이어야 합니다")
    version = rule.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise _fail(source, f"규칙 {rule_id}의 version은 1 이상 정수여야 합니다")
    params = rule.get("params") if rule.get("params") is not None else {}
    if not isinstance(params, Mapping):
        raise _fail(source, f"규칙 {rule_id}의 params는 객체여야 합니다")
    return RuleSpec(
        id=rule_id,
        family=str(rule["family"]),
        grade=str(rule["grade"]),
        label_ko=str(rule["label_ko"]),
        rationale_ko=str(rule["rationale_ko"]),
        false_positive_ko=str(rule["false_positive_ko"]),
        sources=tuple(sources),
        version=version,
        status=str(rule["status"]),
        params=dict(params),
    )


def parse_catalog(files: list[tuple[str, bytes]]) -> Catalog:
    """Validate and merge ``(name, yaml bytes)`` files into one :class:`Catalog`."""
    digest = hashlib.sha256()
    families: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    specs: dict[str, RuleSpec] = {}
    family_ids: set[str] = set()
    file_hashes: dict[str, str] = {}
    for name, data in sorted(files):
        digest.update(name.encode("utf-8") + b"\0" + data + b"\0")
        file_hashes[name] = hashlib.sha256(data).hexdigest()
        try:
            document = _yaml().safe_load(data.decode("utf-8")) or {}
        except (_yaml().YAMLError, UnicodeDecodeError) as exc:
            raise _fail(name, f"YAML을 읽을 수 없습니다: {exc}") from exc
        if not isinstance(document, Mapping) or set(document) - {"families", "rules"}:
            raise _fail(name, "최상위는 families/rules 두 키만 가질 수 있습니다")
        for family in document.get("families") or []:
            family_id = str(family.get("id") or "") if isinstance(family, Mapping) else ""
            if not FAMILY_ID_PATTERN.fullmatch(family_id):
                raise _fail(name, f"계열 id 형식이 아닙니다: {family_id!r}")
            if family_id in family_ids:
                raise _fail(name, f"계열 id가 중복됩니다: {family_id}")
            if not family.get("label"):
                raise _fail(name, f"계열 {family_id}에 label이 없습니다")
            _check_columns(name, family_id, family.get("core_columns"), "core_columns")
            _check_columns(name, family_id, family.get("aux_columns") or [], "aux_columns")
            family_ids.add(family_id)
            families.append(dict(family))
        for rule in document.get("rules") or []:
            if not isinstance(rule, Mapping):
                raise _fail(name, "규칙 항목이 객체가 아닙니다")
            spec = _check_rule(name, rule)
            if spec.id in specs:
                raise _fail(name, f"규칙 id가 중복됩니다: {spec.id}")
            specs[spec.id] = spec
            rules.append(dict(rule))
    for spec in specs.values():
        if spec.family not in family_ids:
            raise _fail("catalog", f"규칙 {spec.id}의 계열 {spec.family}이(가) 없습니다")
    for family in families:
        listed = family.get("rules") or []
        unknown = [rule_id for rule_id in listed if rule_id not in specs]
        if unknown:
            raise _fail("catalog", f"계열 {family['id']}이(가) 없는 규칙을 가리킵니다: {unknown}")
        family["rules"] = list(listed)
    return Catalog(
        version=digest.hexdigest()[:16], families=tuple(families), rules=tuple(rules), specs=specs, file_hashes=file_hashes
    )


_LOCK = threading.Lock()
_CACHE: dict[str, tuple[tuple[object, ...], Catalog]] = {}


def load_catalog(directory: Path | None = None) -> Catalog:
    """The catalogue of ``directory`` (default: the packaged ``catalog/``), cached until a file changes."""
    root = Path(directory) if directory is not None else CATALOG_DIR
    paths = sorted(root.glob("*.yaml"))
    signature = tuple((path.name, path.stat().st_size, path.stat().st_mtime_ns) for path in paths)
    key = str(root.resolve())
    with _LOCK:
        cached = _CACHE.get(key)
        if cached is not None and cached[0] == signature:
            return cached[1]
    if not paths:
        raise _fail(str(root), "YAML 파일이 없습니다")
    catalog = parse_catalog([(path.name, path.read_bytes()) for path in paths])
    with _LOCK:
        _CACHE[key] = (signature, catalog)
    return catalog
