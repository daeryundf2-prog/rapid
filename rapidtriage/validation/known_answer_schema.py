from __future__ import annotations

import importlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from typing import Final, Protocol, runtime_checkable

from rapidtriage.validation.known_answer_types import JsonObject, JsonValue, ManifestValidationError


DEFAULT_SCHEMA_PATH: Final[Path] = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "validation"
    / "known-answer-corpus"
    / "truth-manifest-schema-v1.schema.json"
)
DEFAULT_RESULT_SCHEMA_PATH: Final[Path] = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "validation"
    / "known-answer-corpus"
    / "validation-result-schema-v1.schema.json"
)


@runtime_checkable
class JsonSchemaValidator(Protocol):
    def iter_errors(self, _instance: JsonValue | None) -> Iterable[object]: ...


@runtime_checkable
class JsonSchemaValidatorFactory(Protocol):
    def __call__(self, schema: JsonObject) -> JsonSchemaValidator: ...

    def check_schema(self, schema: JsonObject) -> None: ...


@runtime_checkable
class HasAbsolutePath(Protocol):
    @property
    def absolute_path(self) -> Iterable[object]: ...


@runtime_checkable
class BuiltinSchemaModule(Protocol):
    def validate_with_builtin(
        self,
        document: JsonValue | None,
        schema_object: JsonObject,
    ) -> list[ManifestValidationError]: ...


@dataclass(frozen=True, slots=True)
class JsonSchemaRuntime:
    validator_factory: JsonSchemaValidatorFactory
    schema_error_type: type[Exception]


def load_json_document(path: Path, label: str) -> tuple[JsonValue | None, ManifestValidationError | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return None, ManifestValidationError(
            path="$",
            message=f"{label} file does not exist: {path}",
            validator="file",
        )
    except JSONDecodeError as exc:
        return None, ManifestValidationError(
            path=f"$:{exc.lineno}:{exc.colno}",
            message=f"{label} JSON parse error: {exc.msg}",
            validator="json",
        )
    except OSError as exc:
        return None, ManifestValidationError(
            path="$",
            message=f"{label} file could not be read: {exc}",
            validator="file",
        )


def validate_schema_document(
    manifest_data: JsonValue | None,
    schema_object: JsonObject,
) -> list[ManifestValidationError]:
    jsonschema_runtime, jsonschema_error = _load_jsonschema_runtime()
    if jsonschema_error is not None:
        return _validate_with_builtin(manifest_data, schema_object)
    if jsonschema_runtime is None:
        return [
            ManifestValidationError(
                path="$",
                message="jsonschema runtime could not be loaded",
                validator="dependency",
            ),
        ]

    schema_error_type = jsonschema_runtime.schema_error_type
    try:
        jsonschema_runtime.validator_factory.check_schema(schema_object)
        validator = jsonschema_runtime.validator_factory(schema_object)
    except schema_error_type as exc:
        return [_schema_exception_error(exc)]

    return _schema_errors(validator, manifest_data)


def _load_jsonschema_runtime() -> tuple[JsonSchemaRuntime | None, ManifestValidationError | None]:
    try:
        jsonschema_module = importlib.import_module("jsonschema")
        exceptions_module = importlib.import_module("jsonschema.exceptions")
    except ImportError as exc:
        return None, ManifestValidationError(
            path="$",
            message=f"jsonschema dependency is not available: {exc}",
            validator="dependency",
        )

    validator_factory: object = getattr(jsonschema_module, "Draft202012Validator", None)
    schema_error_type: object = getattr(exceptions_module, "SchemaError", None)
    if not isinstance(validator_factory, JsonSchemaValidatorFactory):
        return None, ManifestValidationError(
            path="$",
            message="jsonschema Draft202012Validator is not available",
            validator="dependency",
        )
    if not isinstance(schema_error_type, type) or not issubclass(schema_error_type, Exception):
        return None, ManifestValidationError(
            path="$",
            message="jsonschema SchemaError type is not available",
            validator="dependency",
        )

    return JsonSchemaRuntime(validator_factory=validator_factory, schema_error_type=schema_error_type), None


def _validate_with_builtin(
    manifest_data: JsonValue | None,
    schema_object: JsonObject,
) -> list[ManifestValidationError]:
    module = importlib.import_module("rapidtriage.validation.known_answer_schema_builtin")
    if isinstance(module, BuiltinSchemaModule):
        return module.validate_with_builtin(manifest_data, schema_object)
    return [
        ManifestValidationError(
            path="$",
            message="built-in schema validator could not be loaded",
            validator="dependency",
        ),
    ]


def _schema_errors(
    validator: JsonSchemaValidator,
    manifest_data: JsonValue | None,
) -> list[ManifestValidationError]:
    errors = sorted(validator.iter_errors(manifest_data), key=_schema_error_sort_key)
    return [
        ManifestValidationError(
            path=_schema_error_path(error),
            message=_schema_error_message(error),
            validator=_schema_error_validator(error),
        )
        for error in errors
    ]


def _schema_exception_error(exc: BaseException) -> ManifestValidationError:
    return ManifestValidationError(
        path=_schema_error_path(exc),
        message=_schema_error_message(exc),
        validator="schema",
    )


def _schema_error_sort_key(error: object) -> tuple[str, str]:
    return _schema_error_path(error), _schema_error_message(error)


def _schema_error_path(error: object) -> str:
    if not isinstance(error, HasAbsolutePath) or isinstance(error.absolute_path, str):
        return "$"
    return _json_pointer(error.absolute_path)


def _schema_error_message(error: object) -> str:
    message_value: object = getattr(error, "message", None)
    return message_value if isinstance(message_value, str) else str(error)


def _schema_error_validator(error: object) -> str | None:
    validator_value: object = getattr(error, "validator", None)
    return str(validator_value) if validator_value is not None else None


def _json_pointer(path_parts: Iterable[object]) -> str:
    path = [_escape_pointer_part(path_part) for path_part in path_parts]
    return "$" if not path else "$/" + "/".join(path)


def _escape_pointer_part(path_part: object) -> str:
    return str(path_part).replace("~", "~0").replace("/", "~1")
