from __future__ import annotations

import logging
from urllib.parse import quote

from ..http import HttpClient
from ..models import Netblock
from ..rpsl import first, parse_text_objects, ranges_to_cidrs
from ..whois import WhoisClient

LOG = logging.getLogger(__name__)


class AfrinicProvider:
    """AFRINIC Whois provider with organisation inverse expansion."""

    HOST = "whois.afrinic.net"

    def __init__(self, whois: WhoisClient, http: HttpClient | None = None) -> None:
        self.whois = whois
        self.http = http

    def search(self, query: str) -> list[Netblock]:
        initial = self.whois.query(
            self.HOST, f"-r -B -T organisation,inetnum,inet6num,aut-num {query}"
        )
        results: list[Netblock] = []
        orgs: dict[str, str] = {}
        asns: set[str] = set()
        self._consume(initial, query, results, orgs, asns)

        for handle, name in orgs.items():
            related = self.whois.query(
                self.HOST, f"-i org {handle} -r -B -T inetnum,inet6num,aut-num"
            )
            self._consume(related, name or query, results, {}, asns)

        if self.http:
            for asn in sorted(asns):
                payload = self.http.get_json(
                    "https://stat.ripe.net/data/announced-prefixes/data.json",
                    params={"resource": asn},
                )
                for item in payload.get("data", {}).get("prefixes", []):
                    prefix = item.get("prefix")
                    if prefix:
                        results.append(
                            Netblock(
                                str(prefix), query, asn,
                                "AFRINIC Whois + RIPEstat", self._url(asn)
                            )
                        )
        LOG.info(
            "AFRINIC returned %d candidate records from %d organizations and %d ASNs",
            len(results), len(orgs), len(asns),
        )
        return results

    def _consume(
        self,
        text: str,
        fallback_name: str,
        results: list[Netblock],
        orgs: dict[str, str],
        asns: set[str],
    ) -> None:
        for attrs in parse_text_objects(text):
            if "organisation" in attrs:
                handle = first(attrs, "organisation")
                if handle:
                    orgs[handle] = first(attrs, "org-name", "descr") or fallback_name
            if "inetnum" in attrs or "inet6num" in attrs:
                name = first(attrs, "org-name", "netname", "descr") or fallback_name
                handle = first(attrs, "org", "netname", "mnt-by")
                address = ", ".join(attrs.get("address", []))
                for cidr in ranges_to_cidrs(attrs):
                    results.append(
                        Netblock(cidr, name, handle, "AFRINIC Whois", self._url(cidr), address)
                    )
            if "aut-num" in attrs:
                asn = first(attrs, "aut-num")
                if asn:
                    asns.add(asn)

    @staticmethod
    def _url(resource: str) -> str:
        return f"https://afrinic.net/whois.html?query={quote(resource)}"
