from netblocktool.providers.lacnic import LacnicProvider


class FakeWhois:
    def query(self, host: str, query: str, *, port: int = 43) -> str:
        return """owner: Example Latin America SA
ownerid: BR-EXAM-LACNIC
inetnum: 200.0.0.0/24
address: Montevideo
"""


def test_lacnic_parses_owner_and_prefix():
    items = LacnicProvider(FakeWhois()).search("Example")
    assert len(items) == 1
    assert items[0].cidr == "200.0.0.0/24"
    assert items[0].organization == "Example Latin America SA"
    assert items[0].handle == "BR-EXAM-LACNIC"
