from __future__ import annotations

import ipaddress
from typing import Any


def parse_attributes(obj: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    attrs = obj.get("attributes", {}).get("attribute", []) if isinstance(obj, dict) else []
    if isinstance(attrs, dict):
        attrs = [attrs]
    for attr in attrs:
        if not isinstance(attr, dict):
            continue
        name = str(attr.get("name", "")).casefold()
        value = str(attr.get("value", "")).strip()
        if name and value:
            result.setdefault(name, []).append(value)
    return result


def parse_text_objects(text: str) -> list[dict[str, list[str]]]:
    objects: list[dict[str, list[str]]] = []
    current: dict[str, list[str]] = {}
    last_key = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("%") or line.startswith("#"):
            if current:
                objects.append(current)
                current = {}
                last_key = ""
            continue
        if line[:1].isspace() and last_key:
            current[last_key][-1] += " " + line.strip()
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        last_key = key.strip().casefold()
        current.setdefault(last_key, []).append(value.strip())
    if current:
        objects.append(current)
    return objects


def ranges_to_cidrs(attrs: dict[str, list[str]]) -> list[str]:
    values = attrs.get("inetnum", []) + attrs.get("inet6num", [])
    result: list[str] = []
    for value in values:
        try:
            if " - " in value:
                start, end = (part.strip() for part in value.split(" - ", 1))
                result.extend(str(net) for net in ipaddress.summarize_address_range(
                    ipaddress.ip_address(start), ipaddress.ip_address(end)
                ))
            else:
                result.append(str(ipaddress.ip_network(value, strict=False)))
        except ValueError:
            continue
    return result


def first(attrs: dict[str, list[str]], *keys: str) -> str:
    for key in keys:
        values = attrs.get(key, [])
        if values:
            return values[0]
    return ""
