from netblocktool.dedupe import deduplicate, filter_ip_version
from netblocktool.models import Netblock


def test_deduplicate_normalizes_cidr() -> None:
    items = [
        Netblock("192.0.2.1/24", "Example", "NET-X"),
        Netblock("192.0.2.0/24", "Example", "NET-X"),
    ]
    assert [item.cidr for item in deduplicate(items)] == ["192.0.2.0/24"]


def test_filter_version() -> None:
    items = [Netblock("192.0.2.0/24", "A"), Netblock("2001:db8::/32", "B")]
    assert len(filter_ip_version(items, 4)) == 1
