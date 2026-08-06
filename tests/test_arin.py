from netblocktool.providers.arin import ArinProvider


def test_extract_refs_from_whois_rws_shape() -> None:
    payload = {"orgs": {"orgRef": [{"@handle": "EXAMPLE-1", "@name": "Example Inc", "$": "url"}]}}
    assert ArinProvider._refs(payload, "orgRef") == [
        {"handle": "EXAMPLE-1", "name": "Example Inc", "href": "url"}
    ]
