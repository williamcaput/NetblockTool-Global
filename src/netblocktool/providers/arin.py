from __future__ import annotations

import ipaddress
import logging
from typing import Any, Iterable
from urllib.parse import quote

from ..http import HttpClient
from ..models import Netblock

LOG = logging.getLogger(__name__)


class ArinProvider:
    """ARIN Whois-RWS provider using JSON endpoints rather than HTML scraping."""

    BASE = "https://whois.arin.net/rest"

    def __init__(self, http: HttpClient) -> None:
        self.http = http

    def search(self, query: str) -> list[Netblock]:
        organizations = self._search_orgs(query)
        direct_nets = self._search_nets(query)
        results = list(direct_nets)
        LOG.info(
            "ARIN matched %d organizations and %d direct network records",
            len(organizations),
            len(direct_nets),
        )
        for org in organizations:
            handle = org.get("handle", "")
            if handle:
                results.extend(self._org_nets(handle, fallback_name=org.get("name", query)))
                for asn in self._org_asns(handle):
                    results.extend(self._asn_nets(asn, fallback_name=org.get("name", query)))
        return results

    def _search_orgs(self, query: str) -> list[dict[str, str]]:
        payload = self.http.get_json(f"{self.BASE}/orgs;name={quote(query)}*")
        return self._refs(payload, "orgRef")

    def _search_nets(self, query: str) -> list[Netblock]:
        payload = self.http.get_json(f"{self.BASE}/nets;name={quote(query)}*")
        refs = self._refs(payload, "netRef")
        results: list[Netblock] = []
        for ref in refs:
            handle = ref.get("handle", "")
            if handle:
                results.extend(self._net_details(handle, fallback_name=ref.get("name", query)))
        return results

    def _org_nets(self, handle: str, *, fallback_name: str) -> list[Netblock]:
        payload = self.http.get_json(f"{self.BASE}/org/{quote(handle)}/nets")
        results: list[Netblock] = []
        for ref in self._refs(payload, "netRef"):
            net_handle = ref.get("handle", "")
            if net_handle:
                results.extend(
                    self._net_details(net_handle, fallback_name=ref.get("name", fallback_name))
                )
        return results

    def _org_asns(self, handle: str) -> list[str]:
        payload = self.http.get_json(f"{self.BASE}/org/{quote(handle)}/asns")
        return [ref["handle"] for ref in self._refs(payload, "asnRef") if ref.get("handle")]

    def _asn_nets(self, asn: str, *, fallback_name: str) -> list[Netblock]:
        # ARIN does not expose all announced routes for an ASN. RIPEstat is used only
        # for route-origin data; registry ownership remains sourced from ARIN.
        payload = self.http.get_json(
            "https://stat.ripe.net/data/announced-prefixes/data.json",
            params={"resource": asn},
        )
        prefixes = payload.get("data", {}).get("prefixes", [])
        return [
            Netblock(
                cidr=str(item.get("prefix", "")),
                organization=fallback_name,
                handle=asn,
                source="ARIN + RIPEstat",
                resource_url=f"https://search.arin.net/rdap/?query={quote(asn)}",
            )
            for item in prefixes
            if item.get("prefix")
        ]

    def _net_details(self, handle: str, *, fallback_name: str) -> list[Netblock]:
        payload = self.http.get_json(f"{self.BASE}/net/{quote(handle)}")
        net = payload.get("net", payload)
        name = self._value(net.get("name")) or fallback_name
        net_handle = self._value(net.get("handle")) or handle
        resource_url = f"{self.BASE}/net/{quote(net_handle)}"
        address = self._org_name(net)
        results: list[Netblock] = []
        blocks = net.get("netBlocks", {}).get("netBlock", []) if isinstance(net, dict) else []
        for block in self._as_list(blocks):
            start = self._value(block.get("startAddress"))
            length = self._value(block.get("cidrLength"))
            if not start or not length:
                continue
            try:
                cidr = str(ipaddress.ip_network(f"{start}/{length}", strict=False))
            except ValueError:
                continue
            results.append(
                Netblock(cidr, name, net_handle, "ARIN Whois-RWS", resource_url, address)
            )
        return results

    @classmethod
    def _refs(cls, payload: dict[str, Any], key: str) -> list[dict[str, str]]:
        found: list[dict[str, str]] = []

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                if key in value:
                    for raw in cls._as_list(value[key]):
                        if isinstance(raw, dict):
                            found.append({
                                "handle": str(raw.get("@handle", raw.get("handle", ""))),
                                "name": str(raw.get("@name", raw.get("name", ""))),
                                "href": str(raw.get("$", raw.get("@href", ""))),
                            })
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(payload)
        unique: dict[str, dict[str, str]] = {}
        for item in found:
            unique[item.get("handle") or item.get("href") or repr(item)] = item
        return list(unique.values())

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    @staticmethod
    def _value(value: Any) -> str:
        if isinstance(value, dict):
            return str(value.get("$", ""))
        return str(value or "")

    @classmethod
    def _org_name(cls, net: dict[str, Any]) -> str:
        for key in ("orgRef", "customerRef"):
            ref = net.get(key)
            if isinstance(ref, dict):
                return str(ref.get("@name", ""))
        return ""
