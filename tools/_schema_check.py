"""Minimal JSON Schema validator for the repository's asset-free boundary.

The repository gate runs from a bare standard-library Python installation.  This
module implements the small, explicit draft 2020-12 subset used by checked-in
schemas and rejects unsupported keywords instead of silently ignoring them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator


SUPPORTED = frozenset({
    "$schema", "$id", "$defs", "$ref", "title", "description", "examples",
    "type", "properties", "patternProperties", "required",
    "additionalProperties", "items", "enum", "const", "pattern",
    "minimum", "maximum", "minItems", "minLength", "uniqueItems", "oneOf",
    "dependentRequired",
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


NAME_MAPS = ("properties", "$defs", "patternProperties", "dependentRequired")


def load_schema(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        schema = json.load(handle)
    if not isinstance(schema, dict):
        raise SchemaError("schema root is not an object")
    _assert_supported(schema, "#", in_name_map=False)
    return schema


def _assert_supported(node: Any, loc: str, in_name_map: bool) -> None:
    """Reject every keyword that this module does not implement."""
    if isinstance(node, dict):
        if not in_name_map:
            for key in node:
                if key not in SUPPORTED:
                    raise SchemaError(
                        f"{loc}: unsupported schema keyword {key!r}")
            if "type" in node:
                names = node["type"]
                names = [names] if isinstance(names, str) else names
                if not isinstance(names, list):
                    raise SchemaError(f"{loc}/type: type is not a string/list")
                for name in names:
                    if name not in _TYPES:
                        raise SchemaError(f"{loc}/type: unknown type {name!r}")
        for key, value in node.items():
            _assert_supported(
                value,
                f"{loc}/{key}",
                in_name_map=not in_name_map and key in NAME_MAPS,
            )
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _assert_supported(value, f"{loc}/{index}", in_name_map=False)


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
    return list(_validate(document, schema, schema, "$"))


def _resolve(ref: str, root: dict) -> dict:
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise SchemaError(f"only local $ref is supported, got {ref!r}")
    node: Any = root
    for part in ref[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            raise SchemaError(f"unresolvable $ref {ref!r}")
        node = node[part]
    if not isinstance(node, dict):
        raise SchemaError(f"$ref {ref!r} does not resolve to an object")
    return node


def _validate(value: Any, schema: dict, root: dict, loc: str) -> Iterator[str]:
    if "$ref" in schema:
        yield from _validate(value, _resolve(schema["$ref"], root), root, loc)
        return

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
        if "minLength" in schema and len(value) < schema["minLength"]:
            yield f"{loc}: shorter than minLength {schema['minLength']}"

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            yield f"{loc}: {value} < minimum {schema['minimum']}"
        if "maximum" in schema and value > schema["maximum"]:
            yield f"{loc}: {value} > maximum {schema['maximum']}"

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            yield f"{loc}: {len(value)} items < minItems {schema['minItems']}"
        if schema.get("uniqueItems") and len(
            {json.dumps(item, sort_keys=True) for item in value}
        ) != len(value):
            yield f"{loc}: items are not unique"
        if "items" in schema:
            for index, item in enumerate(value):
                yield from _validate(item, schema["items"], root, f"{loc}[{index}]")

    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                yield f"{loc}: missing required property {name!r}"
        for trigger, dependencies in schema.get("dependentRequired", {}).items():
            if trigger not in value:
                continue
            for dependency in dependencies:
                if dependency not in value:
                    yield (
                        f"{loc}: property {trigger!r} requires "
                        f"property {dependency!r}"
                    )
        props = schema.get("properties", {})
        pattern_props = schema.get("patternProperties", {})
        for key, sub_schema in value.items():
            matched = False
            if key in props:
                matched = True
                yield from _validate(sub_schema, props[key], root, f"{loc}.{key}")
            for pattern, pattern_schema in pattern_props.items():
                if re.search(pattern, key):
                    matched = True
                    yield from _validate(
                        sub_schema, pattern_schema, root, f"{loc}.{key}"
                    )
            if not matched:
                extra = schema.get("additionalProperties", True)
                if extra is False:
                    yield f"{loc}: unexpected property {key!r}"
                elif isinstance(extra, dict):
                    yield from _validate(sub_schema, extra, root, f"{loc}.{key}")

    if "oneOf" in schema:
        matches = [
            index for index, sub_schema in enumerate(schema["oneOf"])
            if not list(_validate(value, sub_schema, root, loc))
        ]
        if len(matches) != 1:
            yield (
                f"{loc}: matched {len(matches)} of {len(schema['oneOf'])} "
                "oneOf branches, expected exactly 1"
            )


def crosscheck(document: Any, schema: dict) -> str | None:
    """Return an optional real-jsonschema disagreement, if installed."""
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return None
    ours = bool(validate(document, schema))
    try:
        jsonschema.validate(document, schema)
        theirs = False
    except jsonschema.ValidationError:
        theirs = True
    except jsonschema.SchemaError as error:
        return f"jsonschema rejects the schema itself: {error.message}"
    if ours != theirs:
        return (
            f"interpreter says {'invalid' if ours else 'valid'}, "
            f"jsonschema says {'invalid' if theirs else 'valid'}"
        )
    return None
