from __future__ import annotations

import datetime as dt
from typing import Any, Iterable


class SchemaValidationError(AssertionError):
    """Raised when an instance fails lightweight JSON Schema validation."""


def validate(instance: Any, schema: dict[str, Any], path: str = "$") -> None:
    if "const" in schema and instance != schema["const"]:
        raise SchemaValidationError(f"{path}: expected const {schema['const']!r}, got {instance!r}")

    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaValidationError(f"{path}: expected one of {schema['enum']!r}, got {instance!r}")

    schema_type = schema.get("type")
    if schema_type is not None:
        allowed_types = schema_type if isinstance(schema_type, list) else [schema_type]
        if not any(_matches_type(instance, item) for item in allowed_types):
            raise SchemaValidationError(f"{path}: expected type {allowed_types!r}, got {type(instance).__name__}")

    if schema.get("format") == "date-time" and isinstance(instance, str):
        _validate_datetime(instance, path)

    if isinstance(instance, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in instance:
                raise SchemaValidationError(f"{path}: missing required property {key!r}")

        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                validate(value, properties[key], f"{path}.{key}")
                continue
            additional = schema.get("additionalProperties", True)
            if additional is False:
                raise SchemaValidationError(f"{path}: unexpected property {key!r}")
            if isinstance(additional, dict):
                validate(value, additional, f"{path}.{key}")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < int(schema["minItems"]):
            raise SchemaValidationError(f"{path}: expected at least {schema['minItems']} items, got {len(instance)}")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(instance):
                validate(item, item_schema, f"{path}[{index}]")


def _matches_type(instance: Any, schema_type: str) -> bool:
    if schema_type == "object":
        return isinstance(instance, dict)
    if schema_type == "array":
        return isinstance(instance, list)
    if schema_type == "string":
        return isinstance(instance, str)
    if schema_type == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if schema_type == "number":
        return (isinstance(instance, int) or isinstance(instance, float)) and not isinstance(instance, bool)
    if schema_type == "boolean":
        return isinstance(instance, bool)
    if schema_type == "null":
        return instance is None
    return True


def _validate_datetime(value: str, path: str) -> None:
    normalized = value.replace("Z", "+00:00")
    try:
        dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SchemaValidationError(f"{path}: invalid date-time string {value!r}") from exc
