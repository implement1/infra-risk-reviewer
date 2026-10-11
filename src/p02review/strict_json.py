"""Strict, bounded JSON loading for supplied artifacts (e.g. Terraform plan JSON).

Rejects duplicate keys, NaN/Infinity, integers beyond the interpreter digit limit, unpaired
surrogates, nesting deeper than ``max_depth`` (checked by a pre-scan, so the parser never
recurses deeply) and documents with more than ``max_nodes`` values.
"""

from __future__ import annotations

import json
from typing import Optional


class StrictJsonError(Exception):
    def __init__(self, code: str, message: str, line: Optional[int] = None):
        super().__init__(code)
        self.code, self.message, self.line = code, message, line


def _prescan_depth(text: str, max_depth: int) -> None:
    depth, in_string, escape, line = 0, False, False, 1
    for ch in text:
        if ch == "\n":
            line += 1
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                raise StrictJsonError("JSON_TOO_DEEP", f"JSON nesting exceeds {max_depth} levels.", line)
        elif ch in "]}":
            depth -= 1


def _dup_hook(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise StrictJsonError("JSON_DUPLICATE_KEY", "JSON object repeats a key.")
        obj[k] = v
    return obj


def _no_constant(name):
    raise StrictJsonError("JSON_NON_FINITE", "JSON uses a non-finite number.")


def _count_and_check(value, max_nodes: int) -> None:
    stack, count = [value], 0
    while stack:
        item = stack.pop()
        count += 1
        if count > max_nodes:
            raise StrictJsonError("JSON_TOO_LARGE", f"JSON has more than {max_nodes} values.")
        if isinstance(item, str):
            if any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                raise StrictJsonError("JSON_BAD_STRING", "JSON string contains an unpaired surrogate.")
        elif isinstance(item, dict):
            for k, v in item.items():
                if any(0xD800 <= ord(c) <= 0xDFFF for c in k):
                    raise StrictJsonError("JSON_BAD_STRING", "JSON key contains an unpaired surrogate.")
                stack.append(v)
        elif isinstance(item, list):
            stack.extend(item)


def load_strict(text: str, max_depth: int = 64, max_nodes: int = 200_000):
    _prescan_depth(text, max_depth)
    try:
        value = json.loads(text, object_pairs_hook=_dup_hook, parse_constant=_no_constant)
    except StrictJsonError:
        raise
    except json.JSONDecodeError as exc:
        raise StrictJsonError("JSON_SYNTAX", f"Invalid JSON (line {exc.lineno}, column {exc.colno}).",
                              exc.lineno) from None
    except (ValueError, RecursionError):
        raise StrictJsonError("JSON_SYNTAX", "Invalid or unparseable JSON value.") from None
    _count_and_check(value, max_nodes)
    return value
