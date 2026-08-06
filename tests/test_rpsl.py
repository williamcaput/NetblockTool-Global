from netblocktool.rpsl import parse_attributes, parse_text_objects, ranges_to_cidrs


def test_parse_ripe_json_attributes() -> None:
    obj = {"attributes": {"attribute": [
        {"name": "inetnum", "value": "192.0.2.0 - 192.0.2.255"},
        {"name": "netname", "value": "EXAMPLE-NET"},
    ]}}
    attrs = parse_attributes(obj)
    assert attrs["netname"] == ["EXAMPLE-NET"]
    assert ranges_to_cidrs(attrs) == ["192.0.2.0/24"]


def test_parse_apnic_text_objects() -> None:
    text = "inetnum: 203.0.113.0 - 203.0.113.255\nnetname: EXAMPLE-AP\ndescr: Example Ltd\n\n"
    objects = parse_text_objects(text)
    assert objects[0]["netname"] == ["EXAMPLE-AP"]
    assert ranges_to_cidrs(objects[0]) == ["203.0.113.0/24"]
