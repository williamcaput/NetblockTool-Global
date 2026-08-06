from __future__ import annotations

import re

_SUFFIXES = {
    "inc", "incorporated", "corp", "corporation", "company", "co", "llc", "ltd",
    "limited", "plc", "group", "holdings", "bank", "na", "n a", "sa", "ag", "gmbh",
}


def normalize_name(value: str) -> str:
    text = value.casefold().replace("&", " and ")
    text = re.sub(r"[^a-z0-9]+", " ", text)
    tokens = [token for token in text.split() if token not in _SUFFIXES]
    return " ".join(tokens)


def name_similarity(query: str, candidate: str) -> int:
    q = normalize_name(query)
    c = normalize_name(candidate)
    if not q or not c:
        return 0
    if q == c:
        return 100
    if q in c or c in q:
        return 85
    q_tokens, c_tokens = set(q.split()), set(c.split())
    union = q_tokens | c_tokens
    return round(100 * len(q_tokens & c_tokens) / len(union)) if union else 0
