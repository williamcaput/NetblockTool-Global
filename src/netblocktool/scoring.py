from __future__ import annotations

from collections import Counter

from .models import Evidence, Netblock
from .names import name_similarity


def score_netblocks(items: list[Netblock], query: str) -> list[Netblock]:
    prefix_sources = Counter(item.cidr for item in items)
    for item in items:
        evidence: list[Evidence] = []
        similarity = name_similarity(query, item.organization)
        if similarity >= 95:
            evidence.append(Evidence("organization", "Exact normalized organization match", 70))
        elif similarity >= 80:
            evidence.append(Evidence("organization", "Strong organization-name match", 55))
        elif similarity >= 45:
            evidence.append(Evidence("organization", "Partial organization-name match", 30))
        else:
            evidence.append(Evidence("organization", "Weak organization-name match", 5))

        if item.handle:
            evidence.append(Evidence("registry", f"Registry handle {item.handle}", 10))
        if item.address:
            evidence.append(Evidence("address", "Registry address present", 5))
        if prefix_sources[item.cidr] > 1:
            evidence.append(Evidence("corroboration", "Prefix returned by multiple records", 15))

        item.evidence = evidence
        item.confidence = min(99, sum(part.weight for part in evidence))
    return sorted(items, key=lambda item: (-item.confidence, item.cidr, item.organization))
