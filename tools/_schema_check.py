"""Minimal JSON Schema validator for the asset-free attestation boundary.

The repository gate runs from a bare standard-library Python installation. This
module implements and checks exactly this draft 2020-12 subset:
``$schema``, ``$id``, ``title``, ``description``, ``type``, ``properties``,
``required``, ``additionalProperties``, ``enum``, ``const``, and ``pattern``.
Boolean schemas are supported only as ``additionalProperties`` values. Every
other keyword or schema form fails closed with :class:`SchemaError`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator


SUPPORTED = frozenset({
    "$schema", "$id", "title", "description", "type", "properties",
    "required", "additionalProperties", "enum", "const", "pattern",
})

_TYPES: dict[str, type | tuple[type, ...]] = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


class SchemaError(Exception):
    """The schema is malformed or uses a keyword this validator cannot check."""


def load_schema(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        schema = json.load(handle)
    if not isinstance(schema, dict):
        raise SchemaError("schema root is not an object")
    _assert_supported(schema, "#")
    return schema


def _assert_supported(node: Any, loc: str, allow_boolean: bool = False) -> None:
    """Reject every keyword that this module does not implement."""
    if isinstance(node, bool):
        if not allow_boolean:
            raise SchemaError(f"{loc}: boolean schemas are unsupported here")
        return
    if not isinstance(node, dict):
        raise SchemaError(f"{loc}: schema is not an object")
    for key in node:
        if key not in SUPPORTED:
            raise SchemaError(f"{loc}: unsupported schema keyword {key!r}")
    if "type" in node:
        names = node["type"]
        names = [names] if isinstance(names, str) else names
        if not isinstance(names, list) or not names:
            raise SchemaError(f"{loc}/type: type is not a non-empty string/list")
        if any(not isinstance(name, str) or name not in _TYPES for name in names):
            raise SchemaError(f"{loc}/type: unknown or malformed type")
    if "properties" in node:
        properties = node["properties"]
        if not isinstance(properties, dict):
            raise SchemaError(f"{loc}/properties: expected an object")
        for name, child in properties.items():
            _assert_supported(child, f"{loc}/properties/{name}")
    if "additionalProperties" in node:
        _assert_supported(
            node["additionalProperties"],
            f"{loc}/additionalProperties",
            allow_boolean=True,
        )
    if "required" in node and (
        not isinstance(node["required"], list)
        or any(not isinstance(name, str) for name in node["required"])
    ):
        raise SchemaError(f"{loc}/required: expected a string array")
    if "enum" in node and (not isinstance(node["enum"], list) or not node["enum"]):
        raise SchemaError(f"{loc}/enum: expected a non-empty array")
    if "pattern" in node:
        if not isinstance(node["pattern"], str):
            raise SchemaError(f"{loc}/pattern: expected a string")
        try:
            re.compile(node["pattern"])
        except re.error as exc:
            raise SchemaError(f"{loc}/pattern: invalid regular expression") from exc


def _is_type(value: Any, name: str) -> bool:
    expected = _TYPES.get(name)
    if expected is None:
        raise SchemaError(f"unknown type {name!r}")
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, expected) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    return isinstance(value, expected)


def _json_equal(left: Any, right: Any) -> bool:
    """Compare values with JSON type semantics rather than Python bool/int equality."""
    return json.dumps(left, sort_keys=True, separators=(",", ":")) == json.dumps(
        right, sort_keys=True, separators=(",", ":")
    )


def validate(document: Any, schema: dict) -> list[str]:
    """Return human-readable violations; an empty list means valid."""
    if not isinstance(schema, dict):
        raise SchemaError("schema must be an object")
    _assert_supported(schema, "#")
    return list(_validate(document, schema, "$"))


def _validate(value: Any, schema: dict, loc: str) -> Iterator[str]:
    if "type" in schema:
        names = schema["type"]
        names = [names] if isinstance(names, str) else names
        if not any(_is_type(value, name) for name in names):
            yield f"{loc}: expected type {'|'.join(names)}, got {type(value).__name__}"
            return

    if "const" in schema and not _json_equal(value, schema["const"]):
        yield f"{loc}: expected const {schema['const']!r}, got {value!r}"
    if "enum" in schema and not any(
        _json_equal(value, member) for member in schema["enum"]
    ):
        yield f"{loc}: {value!r} not in enum {schema['enum']!r}"

    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            yield f"{loc}: {value!r} does not match /{schema['pattern']}/"

    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                yield f"{loc}: missing required property {name!r}"
        props = schema.get("properties", {})
        for key, sub_schema in value.items():
            if key in props:
                yield from _validate(sub_schema, props[key], f"{loc}.{key}")
            else:
                extra = schema.get("additionalProperties", True)
                if extra is False:
                    yield f"{loc}: unexpected property {key!r}"
                elif isinstance(extra, dict):
                    yield from _validate(sub_schema, extra, f"{loc}.{key}")
