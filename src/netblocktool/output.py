from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import TextIO

from .models import Netblock


def write_json(items: list[Netblock], target: Path | None) -> None:
    data = json.dumps([item.to_dict() for item in items], indent=2)
    _write_text(data + "\n", target)


def write_csv(items: list[Netblock], target: Path | None) -> None:
    stream, should_close = _stream(target)
    try:
        writer = csv.writer(stream)
        writer.writerow(
            [
                "Network",
                "Organization",
                "Handle",
                "Source",
                "Confidence",
                "Rationale",
                "Resource URL",
            ]
        )
        for item in items:
            writer.writerow([
                item.cidr,
                item.organization,
                item.handle,
                item.source,
                item.confidence,
                "; ".join(part.detail for part in item.evidence),
                item.resource_url,
            ])
    finally:
        if should_close:
            stream.close()


def write_table(items: list[Netblock], target: Path | None) -> None:
    lines = [f"{'Confidence':>10}  {'Network':<24}  Organization"]
    lines.append("-" * 78)
    lines.extend(f"{item.confidence:>10}  {item.cidr:<24}  {item.organization}" for item in items)
    _write_text("\n".join(lines) + "\n", target)


def _write_text(text: str, target: Path | None) -> None:
    if target:
        target.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _stream(target: Path | None) -> tuple[TextIO, bool]:
    if target:
        return target.open("w", encoding="utf-8", newline=""), True
    return sys.stdout, False
