from __future__ import annotations

import re
from dataclasses import dataclass

from rapidtriage.validation.known_answer_types import JsonObject, JsonValue, ManifestValidationError


@dataclass(frozen=True, slots=True)
class SchemaContext:
    root: JsonObject


def validate_with_builtin(
    document: JsonValue | None,
    schema_object: JsonObject,
) -> list[ManifestValidationError]:
    return _validate(document, schema_object, "$", SchemaContext(root=schema_object))


def _validate(
    value: JsonValue | None,
    schema: JsonObject,
    path: str,
    context: SchemaContext,
) -> list[ManifestValidationError]:
    ref_schema = _resolved_ref(schema, context)
    if ref_schema is not None:
        return _validate(value, ref_schema, path, context)

    type_error = _type_error(value, schema, path)
    if type_error is not None:
        return [type_error]

    errors: list[ManifestValidationError] = []
    errors.extend(_const_errors(value, schema, path))
    errors.extend(_enum_errors(value, schema, path))
    errors.extend(_combined_schema_errors(value, schema, path, context))
    errors.extend(_conditional_errors(value, schema, path, context))

    if isinstance(value, dict):
        errors.extend(_object_errors(value, schema, path, context))
    if isinstance(value, list):
        errors.extend(_array_errors(value, schema, path, context))
    if isinstance(value, str):
        errors.extend(_string_errors(value, schema, path))
    number_value = _number_value(value)
    if number_value is not None:
        errors.extend(_number_errors(number_value, schema, path))
    return errors


def _resolved_ref(schema: JsonObject, context: SchemaContext) -> JsonObject | None:
    ref_value = schema.get("$ref")
    if not isinstance(ref_value, str):
        return None
    if not ref_value.startswith("#/"):
        return None

    current: JsonValue = context.root
    for raw_part in ref_value[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current if isinstance(current, dict) else None


def _type_error(value: JsonValue | None, schema: JsonObject, path: str) -> ManifestValidationError | None:
    type_rule = schema.get("type")
    if isinstance(type_rule, list):
        allowed_types = _string_list(type_rule)
    elif isinstance(type_rule, str):
        allowed_types = [type_rule]
    else:
        return None
    if any(_matches_type(value, allowed_type) for allowed_type in allowed_types):
        return None
    return ManifestValidationError(path=path, message=f"{value!r} is not of type {allowed_types!r}", validator="type")


def _matches_type(value: JsonValue | None, type_rule: str) -> bool:
    if type_rule == "object":
        return isinstance(value, dict)
    if type_rule == "array":
        return isinstance(value, list)
    if type_rule == "string":
        return isinstance(value, str)
    if type_rule == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_rule == "number":
        return _is_number(value)
    if type_rule == "boolean":
        return isinstance(value, bool)
    if type_rule == "null":
        return value is None
    return True


def _const_errors(value: JsonValue | None, schema: JsonObject, path: str) -> list[ManifestValidationError]:
    if "const" not in schema or value == schema.get("const"):
        return []
    return [ManifestValidationError(path=path, message=f"{value!r} was not the expected constant", validator="const")]


def _enum_errors(value: JsonValue | None, schema: JsonObject, path: str) -> list[ManifestValidationError]:
    enum_value = schema.get("enum")
    if not isinstance(enum_value, list) or value in enum_value:
        return []
    return [ManifestValidationError(path=path, message=f"{value!r} is not one of the allowed values", validator="enum")]


def _combined_schema_errors(
    value: JsonValue | None,
    schema: JsonObject,
    path: str,
    context: SchemaContext,
) -> list[ManifestValidationError]:
    errors: list[ManifestValidationError] = []
    all_of_value = schema.get("allOf")
    if isinstance(all_of_value, list):
        for child_schema in _schema_list(all_of_value):
            errors.extend(_validate(value, child_schema, path, context))

    any_of_value = schema.get("anyOf")
    if isinstance(any_of_value, list) and not _matches_any(value, any_of_value, path, context):
        errors.append(ManifestValidationError(path=path, message="value does not match any allowed schema", validator="anyOf"))

    one_of_value = schema.get("oneOf")
    if isinstance(one_of_value, list):
        matches = sum(1 for child_schema in _schema_list(one_of_value) if _matches(value, child_schema, path, context))
        if matches != 1:
            errors.append(
                ManifestValidationError(
                    path=path,
                    message=f"value matches {matches} oneOf schemas instead of exactly one",
                    validator="oneOf",
                ),
            )
    return errors


def _conditional_errors(
    value: JsonValue | None,
    schema: JsonObject,
    path: str,
    context: SchemaContext,
) -> list[ManifestValidationError]:
    if_schema = schema.get("if")
    then_schema = schema.get("then")
    if not isinstance(if_schema, dict) or not isinstance(then_schema, dict):
        return []
    if not _matches(value, if_schema, path, context):
        return []
    return _validate(value, then_schema, path, context)


def _object_errors(
    value: JsonObject,
    schema: JsonObject,
    path: str,
    context: SchemaContext,
) -> list[ManifestValidationError]:
    errors: list[ManifestValidationError] = []
    required_value = schema.get("required")
    if isinstance(required_value, list):
        for field_name in _string_list(required_value):
            if field_name not in value:
                errors.append(
                    ManifestValidationError(
                        path=path,
                        message=f"'{field_name}' is a required property",
                        validator="required",
                    ),
                )

    properties_value = schema.get("properties")
    properties = properties_value if isinstance(properties_value, dict) else {}
    for field_name, field_schema in properties.items():
        if field_name in value and isinstance(field_schema, dict):
            errors.extend(_validate(value[field_name], field_schema, _join_path(path, field_name), context))

    if schema.get("additionalProperties") is False:
        allowed = set(properties)
        for field_name in value:
            if field_name not in allowed:
                errors.append(
                    ManifestValidationError(
                        path=_join_path(path, field_name),
                        message=f"additional property '{field_name}' is not allowed",
                        validator="additionalProperties",
                    ),
                )
    return errors


def _array_errors(
    value: list[JsonValue],
    schema: JsonObject,
    path: str,
    context: SchemaContext,
) -> list[ManifestValidationError]:
    errors: list[ManifestValidationError] = []
    min_items = schema.get("minItems")
    if isinstance(min_items, int) and len(value) < min_items:
        errors.append(ManifestValidationError(path=path, message=f"array has fewer than {min_items} items", validator="minItems"))
    max_items = schema.get("maxItems")
    if isinstance(max_items, int) and len(value) > max_items:
        errors.append(ManifestValidationError(path=path, message=f"array has more than {max_items} items", validator="maxItems"))

    items_schema = schema.get("items")
    if isinstance(items_schema, dict):
        for index, item in enumerate(value):
            errors.extend(_validate(item, items_schema, _join_path(path, str(index)), context))
    return errors


def _string_errors(value: str, schema: JsonObject, path: str) -> list[ManifestValidationError]:
    errors: list[ManifestValidationError] = []
    min_length = schema.get("minLength")
    if isinstance(min_length, int) and len(value) < min_length:
        errors.append(ManifestValidationError(path=path, message=f"{value!r} is too short", validator="minLength"))
    pattern = schema.get("pattern")
    if isinstance(pattern, str) and re.search(pattern, value) is None:
        errors.append(ManifestValidationError(path=path, message=f"{value!r} does not match pattern {pattern!r}", validator="pattern"))
    return errors


def _number_errors(value: int | float, schema: JsonObject, path: str) -> list[ManifestValidationError]:
    errors: list[ManifestValidationError] = []
    minimum = _number_value(schema.get("minimum"))
    if minimum is not None and value < minimum:
        errors.append(ManifestValidationError(path=path, message=f"{value!r} is less than {minimum!r}", validator="minimum"))
    maximum = _number_value(schema.get("maximum"))
    if maximum is not None and value > maximum:
        errors.append(ManifestValidationError(path=path, message=f"{value!r} is greater than {maximum!r}", validator="maximum"))
    return errors


def _matches(value: JsonValue | None, schema: JsonObject, path: str, context: SchemaContext) -> bool:
    return not _validate(value, schema, path, context)


def _matches_any(value: JsonValue | None, schemas: list[JsonValue], path: str, context: SchemaContext) -> bool:
    return any(_matches(value, schema, path, context) for schema in _schema_list(schemas))


def _schema_list(values: list[JsonValue]) -> list[JsonObject]:
    return [value for value in values if isinstance(value, dict)]


def _string_list(values: list[JsonValue]) -> list[str]:
    return [value for value in values if isinstance(value, str)]


def _join_path(path: str, part: str) -> str:
    escaped = part.replace("~", "~0").replace("/", "~1")
    return f"{path}/{escaped}" if path != "$" else f"$/{escaped}"


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _number_value(value: object) -> int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    return None
