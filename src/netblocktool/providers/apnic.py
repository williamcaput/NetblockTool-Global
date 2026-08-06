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
    INITIAL_TYPES = "organisation,inetnum,inet6num,aut-num"
    RESOURCE_TYPES = "inetnum,inet6num,aut-num"

    def __init__(self, whois: WhoisClient, http: HttpClient | None = None) -> None:
        self.whois = whois
        self.http = http

    def search(self, query: str) -> list[Netblock]:
        """Search APNIC by network key or organization name.

        APNIC marks ``org-name`` as a lookup key, but an organization-name query
        returns an ``organisation`` object rather than the related inetnum/aut-num
        objects.  The related resources are therefore expanded with an inverse
        ``org`` query.  Descriptive fields are preserved as candidate names so the
        confidence scorer can match the user's company name even when the netname
        is an abbreviated registry identifier.
        """
        # -r disables recursive contact expansion. Include organisation objects so
        # human-readable company names can resolve to their APNIC organization ID.
        text = self.whois.query(
            self.HOST, f"-r -T {self.INITIAL_TYPES} {query}"
        )
        initial = parse_text_objects(text)

        results: list[Netblock] = []
        asns: set[str] = set()
        organisations: dict[str, str] = {}

        for attrs in initial:
            if "organisation" in attrs:
                handle = first(attrs, "organisation")
                name = first(attrs, "org-name", "descr") or query
                if handle:
                    organisations[handle] = name
            self._collect_object(attrs, "", results, asns)

        # Expand organization-name matches into their registered networks and ASNs.
        for handle, organization_name in organisations.items():
            related_text = self.whois.query(
                self.HOST,
                f"-r -T {self.RESOURCE_TYPES} -i org {handle}",
            )
            for attrs in parse_text_objects(related_text):
                self._collect_object(
                    attrs, organization_name, results, asns
                )

        if self.http:
            for asn in asns:
                payload = self.http.get_json(
                    "https://stat.ripe.net/data/announced-prefixes/data.json",
                    params={"resource": asn},
                )
                for item in payload.get("data", {}).get("prefixes", []):
                    prefix = item.get("prefix")
                    if prefix:
                        results.append(
                            Netblock(
                                str(prefix),
                                query,
                                asn,
                                "APNIC Whois + RIPEstat",
                                self._url(asn),
                            )
                        )

        LOG.info(
            "APNIC returned %d candidate records from %d organizations and %d ASNs",
            len(results),
            len(organisations),
            len(asns),
        )
        return results

    def _collect_object(
        self,
        attrs: dict[str, list[str]],
        fallback_name: str,
        results: list[Netblock],
        asns: set[str],
    ) -> None:
        if "inetnum" in attrs or "inet6num" in attrs:
            # Prefer the human-readable org-name/description over abbreviated
            # netnames such as BAY-TH when available.
            name = first(attrs, "org-name") or fallback_name or first(attrs, "descr", "netname")
            handle = first(attrs, "org", "netname", "mnt-by")
            address = ", ".join(attrs.get("address", []))
            for cidr in ranges_to_cidrs(attrs):
                results.append(
                    Netblock(
                        cidr,
                        name,
                        handle,
                        "APNIC Whois",
                        self._url(cidr),
                        address,
                    )
                )

        if "aut-num" in attrs:
            asn = first(attrs, "aut-num")
            if asn:
                asns.add(asn)

    @staticmethod
    def _url(resource: str) -> str:
        return f"https://wq.apnic.net/static/search.html?query={quote(resource)}"
