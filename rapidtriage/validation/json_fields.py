from __future__ import annotations

from rapidtriage.validation.known_answer_types import JsonObject, JsonValue


def object_field(document: JsonObject, field: str) -> JsonObject:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, dict) else {}


def list_field(document: JsonObject, field: str) -> list[JsonValue]:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, list) else []


def int_field(document: JsonObject, field: str) -> int:
    value: JsonValue | None = document.get(field)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
