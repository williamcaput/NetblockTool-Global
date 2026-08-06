from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Evidence:
    kind: str
    detail: str
    weight: int


@dataclass(slots=True)
class Netblock:
    cidr: str
    organization: str
    handle: str = ""
    source: str = "ARIN Whois-RWS"
    resource_url: str = ""
    address: str = ""
    confidence: int = 0
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["evidence"] = [asdict(item) for item in self.evidence]
        return result
