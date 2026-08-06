from netblocktool.providers.afrinic import AfrinicProvider


class FakeWhois:
    def query(self, host: str, query: str, *, port: int = 43) -> str:
        if "-i org" in query:
            return """inetnum: 196.10.0.0 - 196.10.0.255
netname: EXAMPLE-AF
org: ORG-EX1-AFRINIC
address: Nairobi

aut-num: AS37200
"""
        return """organisation: ORG-EX1-AFRINIC
org-name: Example Africa Ltd
"""


def test_afrinic_inverse_org_expansion():
    items = AfrinicProvider(FakeWhois()).search("Example")
    assert len(items) == 1
    assert items[0].cidr == "196.10.0.0/24"
    assert items[0].handle == "ORG-EX1-AFRINIC"
