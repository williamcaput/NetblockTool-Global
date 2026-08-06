from netblocktool.providers.ripe import RipeProvider


class FakeHttp:
    def get_json(self, url, params=None):
        if params and params.get("inverse-attribute") == "org":
            return {"objects": {"object": [{"type": "inetnum", "attributes": {"attribute": [
                {"name": "inetnum", "value": "192.0.2.0 - 192.0.2.255"},
                {"name": "netname", "value": "EXAMPLE"},
                {"name": "org", "value": "ORG-EX1-RIPE"},
            ]}}]}}
        return {"objects": {"object": [{"type": "organisation", "attributes": {"attribute": [
            {"name": "organisation", "value": "ORG-EX1-RIPE"},
            {"name": "org-name", "value": "Example Ltd"},
        ]}}]}}


def test_ripe_org_expansion() -> None:
    results = RipeProvider(FakeHttp()).search("Example")
    assert results[0].cidr == "192.0.2.0/24"
    assert results[0].source == "RIPE Database"
