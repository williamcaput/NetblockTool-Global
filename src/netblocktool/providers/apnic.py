from __future__ import annotations

import logging
from urllib.parse import quote

from ..http import HttpClient
from ..models import Netblock
from ..rpsl import first, parse_text_objects, ranges_to_cidrs
from ..whois import WhoisClient

LOG = logging.getLogger(__name__)


class ApnicProvider:
    HOST = "whois.apnic.net"

    def __init__(self, whois: WhoisClient, http: HttpClient | None = None) -> None:
        self.whois = whois
        self.http = http

    def search(self, query: str) -> list[Netblock]:
        # -r disables recursive contact expansion; -T bounds returned object types.
        text = self.whois.query(self.HOST, f"-r -T inetnum,inet6num,aut-num {query}")
        results: list[Netblock] = []
        asns: set[str] = set()
        for attrs in parse_text_objects(text):
            if "inetnum" in attrs or "inet6num" in attrs:
                name = first(attrs, "org-name", "netname", "descr") or query
                handle = first(attrs, "netname", "mnt-by")
                address = ", ".join(attrs.get("address", []))
                for cidr in ranges_to_cidrs(attrs):
                    results.append(Netblock(
                        cidr, name, handle, "APNIC Whois", self._url(cidr), address
                    ))
            if "aut-num" in attrs:
                asns.add(first(attrs, "aut-num"))
        if self.http:
            for asn in asns:
                payload = self.http.get_json(
                    "https://stat.ripe.net/data/announced-prefixes/data.json",
                    params={"resource": asn},
                )
                for item in payload.get("data", {}).get("prefixes", []):
                    prefix = item.get("prefix")
                    if prefix:
                        results.append(Netblock(
                            str(prefix), query, asn, "APNIC Whois + RIPEstat", self._url(asn)
                        ))
        LOG.info("APNIC returned %d candidate records and %d ASNs", len(results), len(asns))
        return results

    @staticmethod
    def _url(resource: str) -> str:
        return f"https://wq.apnic.net/static/search.html?query={quote(resource)}"
