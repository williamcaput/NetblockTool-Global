from netblocktool.providers.apnic import ApnicProvider


class FakeWhois:
    def __init__(self) -> None:
        self.queries: list[str] = []

    def query(self, host: str, query: str, *, port: int = 43) -> str:
        self.queries.append(query)
        if "-i org ORG-BOAP1-AP" in query:
            return """inetnum: 103.216.96.0 - 103.216.97.255
netname: BAY-TH
descr: 1222 Rama III Road
org: ORG-BOAP1-AP
country: TH

aut-num: AS18256
as-name: BAY-AS-AP
descr: Bank of Ayudhya Public Company Limited.
org: ORG-BOAP1-AP
"""
        return """organisation: ORG-BOAP1-AP
org-name: Bank of Ayudhya Public Company Limited.
descr: Bank of Ayudhya
country: TH
"""


def test_apnic_organization_name_expands_related_resources() -> None:
    whois = FakeWhois()
    items = ApnicProvider(whois).search("Bank of Ayudhya")

    assert len(items) == 1
    assert items[0].cidr == "103.216.96.0/23"
    assert items[0].organization == "Bank of Ayudhya Public Company Limited."
    assert items[0].handle == "ORG-BOAP1-AP"
    assert any("-T organisation,inetnum,inet6num,aut-num" in q for q in whois.queries)
    assert any("-i org ORG-BOAP1-AP" in q for q in whois.queries)


def test_apnic_direct_result_uses_description_field() -> None:
    class DirectWhois:
        def query(self, host: str, query: str, *, port: int = 43) -> str:
            return """inetnum: 203.0.113.0 - 203.0.113.255
netname: SHORT-NAME-AP
descr: Example Financial Services Limited
country: AP
"""

    items = ApnicProvider(DirectWhois()).search("SHORT-NAME-AP")
    assert items[0].organization == "Example Financial Services Limited"
