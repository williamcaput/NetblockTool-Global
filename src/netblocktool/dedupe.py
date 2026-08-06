from __future__ import annotations

import ipaddress

from .models import Netblock


def deduplicate(items: list[Netblock]) -> list[Netblock]:
    """Merge exact duplicate records without hiding legitimate more-specific prefixes."""
    merged: dict[tuple[str, str], Netblock] = {}
    for item in items:
        try:
            item.cidr = str(ipaddress.ip_network(item.cidr, strict=False))
        except ValueError:
            continue
        key = (item.cidr, item.handle or item.organization.casefold())
        previous = merged.get(key)
        if previous is None or item.confidence > previous.confidence:
            merged[key] = item
    return list(merged.values())


def filter_ip_version(items: list[Netblock], version: int | None) -> list[Netblock]:
    if version is None:
        return items
    result: list[Netblock] = []
    for item in items:
        try:
            if ipaddress.ip_network(item.cidr, strict=False).version == version:
                result.append(item)
        except ValueError:
            continue
    return result
