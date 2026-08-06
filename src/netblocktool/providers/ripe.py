from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

from ..http import HttpClient
from ..models import Netblock
from ..rpsl import first, parse_attributes, ranges_to_cidrs

LOG = logging.getLogger(__name__)


class RipeProvider:
    BASE = "https://rest.db.ripe.net/search.json"

    def __init__(self, http: HttpClient) -> None:
        self.http = http

    def search(self, query: str) -> list[Netblock]:
        initial = self._search(query, ["organisation", "inetnum", "inet6num", "aut-num"])
        results: list[Netblock] = []
        orgs: list[tuple[str, str]] = []
        asns: set[str] = set()
        for obj in initial:
            attrs = parse_attributes(obj)
            object_type = str(obj.get("type", "")).casefold()
            if object_type == "organisation":
                handle = first(attrs, "organisation")
                if handle:
                    orgs.append((handle, first(attrs, "org-name", "descr") or query))
            elif object_type in {"inetnum", "inet6num"}:
                results.extend(self._netblocks(attrs))
            elif object_type == "aut-num":
                asn = first(attrs, "aut-num")
                if asn:
                    asns.add(asn)

        for handle, name in orgs:
            related = self._search(handle, ["inetnum", "inet6num", "aut-num"], inverse="org")
            for obj in related:
                attrs = parse_attributes(obj)
                object_type = str(obj.get("type", "")).casefold()
                if object_type in {"inetnum", "inet6num"}:
                    results.extend(self._netblocks(attrs, fallback_name=name))
                elif object_type == "aut-num":
                    asn = first(attrs, "aut-num")
                    if asn:
                        asns.add(asn)
        for asn in asns:
            results.extend(self._asn_prefixes(asn, query))
        LOG.info(
            "RIPE returned %d candidate records from %d organizations", len(results), len(orgs)
        )
        return results

    def _search(
        self, query: str, types: list[str], inverse: str | None = None
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {
            "source": "ripe", "query-string": query, "flags": "no-referenced", "limit": "1000"
        }
        params["type-filter"] = types
        if inverse:
            params["inverse-attribute"] = inverse
        payload = self.http.get_json(self.BASE, params=params)
        objects = payload.get("objects", {}).get("object", [])
        if isinstance(objects, dict):
            objects = [objects]
        return [obj for obj in objects if isinstance(obj, dict)]

    def _netblocks(self, attrs: dict[str, list[str]], fallback_name: str = "") -> list[Netblock]:
        name = first(attrs, "org-name", "netname", "descr") or fallback_name
        handle = first(attrs, "org", "netname", "mnt-by")
        address = ", ".join(attrs.get("address", []))
        return [Netblock(cidr, name, handle, "RIPE Database", self._url(cidr), address)
                for cidr in ranges_to_cidrs(attrs)]

    def _asn_prefixes(self, asn: str, fallback_name: str) -> list[Netblock]:
        payload = self.http.get_json(
            "https://stat.ripe.net/data/announced-prefixes/data.json", params={"resource": asn}
        )
        return [Netblock(str(p.get("prefix")), fallback_name, asn, "RIPE Database + RIPEstat",
                         f"https://apps.db.ripe.net/db-web-ui/query?searchtext={quote(asn)}")
                for p in payload.get("data", {}).get("prefixes", []) if p.get("prefix")]

    @staticmethod
    def _url(resource: str) -> str:
        return f"https://apps.db.ripe.net/db-web-ui/query?searchtext={quote(resource)}"
