from __future__ import annotations

import logging
from urllib.parse import quote

from ..models import Netblock
from ..rpsl import first, parse_text_objects, ranges_to_cidrs
from ..whois import WhoisClient

LOG = logging.getLogger(__name__)


class LacnicProvider:
    """LACNIC public Whois provider using bounded TCP/43 queries."""

    HOST = "whois.lacnic.net"

    def __init__(self, whois: WhoisClient) -> None:
        self.whois = whois

    def search(self, query: str) -> list[Netblock]:
        text = self.whois.query(self.HOST, query)
        results: list[Netblock] = []
        for attrs in parse_text_objects(text):
            if "inetnum" not in attrs and "inet6num" not in attrs:
                continue
            owner = first(attrs, "owner", "org-name", "netname", "responsible", "descr") or query
            owner_id = first(attrs, "ownerid", "owner-c", "netname", "mnt-by")
            address = ", ".join(attrs.get("address", []))
            for cidr in ranges_to_cidrs(attrs):
                results.append(
                    Netblock(cidr, owner, owner_id, "LACNIC Whois", self._url(cidr), address)
                )
        LOG.info("LACNIC returned %d candidate records", len(results))
        return results

    @staticmethod
    def _url(resource: str) -> str:
        return f"https://query.milacnic.lacnic.net/home?query={quote(resource)}"
